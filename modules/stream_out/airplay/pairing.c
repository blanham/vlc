/*****************************************************************************
 * pairing.c: HAP TLV8 pair-setup / pair-verify for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "pairing.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef AIRPLAY_PAIRING_STANDALONE
# include <vlc_common.h>
# include <vlc_dialog.h>
# include <vlc_threads.h>
#else
# define VLC_SUCCESS 0
# define VLC_EGENERIC (-1)
#endif

#include "crypto.h"
#include "tlv.h"

#include <gcrypt.h>

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
typedef SOCKET airplay_sock_t;
# define AIRPLAY_SOCK_INVALID INVALID_SOCKET
# define airplay_sock_close(s) closesocket(s)
#else
# include <sys/socket.h>
# include <sys/time.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <unistd.h>
typedef int airplay_sock_t;
# define AIRPLAY_SOCK_INVALID (-1)
# define airplay_sock_close(s) close(s)
#endif

#define HAP_MIME_TLV8 "application/pairing+tlv8"
#define HAP_CTRL_PACKET_MAX 0x400

#ifndef AIRPLAY_PAIRING_STANDALONE
/*
 * Receivers keep their pairing backoff across reboots, and /pair-pin-start
 * still puts a code on the TV while the penalty is active. Remember the
 * deadline per device so a retry inside the window fails immediately instead
 * of displaying a PIN that cannot work.
 */
# define AIRPLAY_BACKOFF_SLOTS 8

static struct
{
    char *device_id;
    vlc_tick_t deadline;
} backoff_table[AIRPLAY_BACKOFF_SLOTS];

static vlc_mutex_t backoff_lock = VLC_STATIC_MUTEX;

static unsigned
backoff_seconds_left(const char *device_id)
{
    if (device_id == NULL)
        return 0;

    unsigned left = 0;
    vlc_tick_t now = vlc_tick_now();

    vlc_mutex_lock(&backoff_lock);
    for (size_t i = 0; i < AIRPLAY_BACKOFF_SLOTS; ++i)
        if (backoff_table[i].device_id != NULL
         && strcmp(backoff_table[i].device_id, device_id) == 0)
        {
            if (backoff_table[i].deadline > now)
                left = (unsigned)SEC_FROM_VLC_TICK(backoff_table[i].deadline - now);
            break;
        }
    vlc_mutex_unlock(&backoff_lock);
    return left;
}

static void
backoff_remember(const char *device_id, unsigned delay_sec)
{
    if (device_id == NULL || delay_sec == 0)
        return;

    vlc_tick_t deadline = vlc_tick_now() + vlc_tick_from_sec(delay_sec);
    size_t victim = 0;

    vlc_mutex_lock(&backoff_lock);
    for (size_t i = 0; i < AIRPLAY_BACKOFF_SLOTS; ++i)
    {
        if (backoff_table[i].device_id != NULL
         && strcmp(backoff_table[i].device_id, device_id) == 0)
        {
            backoff_table[i].deadline = deadline;
            vlc_mutex_unlock(&backoff_lock);
            return;
        }
        if (backoff_table[i].device_id == NULL
         || backoff_table[i].deadline < backoff_table[victim].deadline)
            victim = i;
    }

    free(backoff_table[victim].device_id);
    backoff_table[victim].device_id = strdup(device_id);
    backoff_table[victim].deadline =
        backoff_table[victim].device_id != NULL ? deadline : 0;
    vlc_mutex_unlock(&backoff_lock);
}
#endif

typedef int (*airplay_tlv_exchange_fn)(void *opaque, const char *path,
                                       const uint8_t *req, size_t req_len,
                                       uint8_t **resp, size_t *resp_len);

struct airplay_pairing
{
    vlc_object_t *obj;
    char *ip;
    uint16_t port;
    char *device_id;
    char *device_name;

    uint8_t accessory_ltpk[32];
    bool has_accessory_ltpk;
    char *accessory_pairing_id;

    enum airplay_pair_state state;

    char *last_error;
    uint8_t last_hap_error; /* 0 = none; set when a HAP TLV error is received */
    char *test_pin;

    airplay_pair_transport_cb transport_cb;
    void *transport_opaque;

    airplay_pair_identity_load_cb identity_load_cb;
    airplay_pair_identity_store_cb identity_store_cb;
    airplay_pair_identity_remove_cb identity_remove_cb;
    void *identity_opaque;

    struct airplay_identity identity;

    airplay_sock_t persistent_fd;

    bool has_session_keys;
    bool verify_rejected;
    uint8_t control_write_key[32];
    uint8_t control_read_key[32];
    uint8_t event_out_key[32];
    uint8_t event_in_key[32];
    uint64_t write_nonce;
    uint64_t read_nonce;
    uint64_t event_write_nonce;
    uint64_t event_read_nonce;

    airplay_sock_t control_fd;
    bool control_connected;
    /* Bytes already read past the end of the pair-verify response. */
    uint8_t *control_prefetch;
    size_t control_prefetch_len;
    airplay_sock_t event_fd;
#ifndef AIRPLAY_PAIRING_STANDALONE
    vlc_thread_t event_thread;
    bool event_thread_started;
#endif
    bool event_stop;

    airplay_pair_control_exchange_cb control_exchange_cb;
    void *control_exchange_opaque;
};

static void event_channel_stop(airplay_pairing *p);

static void
secure_clear(void *buf, size_t len)
{
    volatile uint8_t *cursor = buf;
    while (len-- > 0)
        *cursor++ = 0;
}

static int
buf_cat(uint8_t **out, size_t *out_len,
        const uint8_t *a, size_t a_len,
        const uint8_t *b, size_t b_len,
        const uint8_t *c, size_t c_len)
{
    size_t total = a_len + b_len + c_len;
    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return -1;

    size_t off = 0;
    if (a_len > 0)
    {
        memcpy(buf + off, a, a_len);
        off += a_len;
    }
    if (b_len > 0)
    {
        memcpy(buf + off, b, b_len);
        off += b_len;
    }
    if (c_len > 0)
        memcpy(buf + off, c, c_len);

    *out = buf;
    *out_len = total;
    return 0;
}

static void
ensure_controller_pairing_id(struct airplay_identity *id)
{
    if (id->controller_pairing_id[0] != '\0')
        return;

    uint8_t rnd[16];
    airplay_random_bytes(rnd, sizeof rnd);

    rnd[6] = (rnd[6] & 0x0f) | 0x40;
    rnd[8] = (rnd[8] & 0x3f) | 0x80;
    snprintf(id->controller_pairing_id, sizeof id->controller_pairing_id,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14],
             rnd[15]);
}

/* -- construction / teardown ---------------------------------------------- */

airplay_pairing *
airplay_pairing_new(vlc_object_t *obj, const char *ip, uint16_t port,
                    const char *device_id, const char *device_name)
{
    if (ip == NULL || ip[0] == '\0' || device_id == NULL ||
        device_id[0] == '\0')
        return NULL;

    airplay_pairing *p = calloc(1, sizeof(*p));
    if (p == NULL)
        return NULL;

    p->obj = obj;
    p->port = port;
    p->ip = strdup(ip);
    p->device_id = strdup(device_id);
    p->device_name = strdup(device_name != NULL ? device_name : device_id);
    if (p->ip == NULL || p->device_id == NULL || p->device_name == NULL)
    {
        airplay_pairing_release(p);
        return NULL;
    }

    p->persistent_fd = AIRPLAY_SOCK_INVALID;
    p->control_fd = AIRPLAY_SOCK_INVALID;
    p->event_fd = AIRPLAY_SOCK_INVALID;
    p->state = AIRPLAY_PAIR_IDLE;
    airplay_crypto_init();
    return p;
}

void
airplay_pairing_set_accessory_info(airplay_pairing *p,
                                   const uint8_t accessory_ltpk[32],
                                   const char *accessory_pairing_id)
{
    if (p == NULL || accessory_ltpk == NULL)
        return;

    memcpy(p->accessory_ltpk, accessory_ltpk, 32);
    p->has_accessory_ltpk = true;

    free(p->accessory_pairing_id);
    p->accessory_pairing_id = accessory_pairing_id != NULL ?
        strdup(accessory_pairing_id) : NULL;
}

void
airplay_pairing_release(airplay_pairing *p)
{
    if (p == NULL)
        return;

    free(p->last_error);
    if (p->test_pin != NULL)
    {
        secure_clear(p->test_pin, strlen(p->test_pin));
        free(p->test_pin);
    }
    secure_clear(&p->identity, sizeof p->identity);
    secure_clear(p->control_write_key, sizeof p->control_write_key);
    secure_clear(p->control_read_key, sizeof p->control_read_key);
    secure_clear(p->event_out_key, sizeof p->event_out_key);
    secure_clear(p->event_in_key, sizeof p->event_in_key);

    free(p->ip);
    free(p->device_id);
    free(p->device_name);
    free(p->accessory_pairing_id);
    event_channel_stop(p);
    if (p->persistent_fd != AIRPLAY_SOCK_INVALID)
        airplay_sock_close(p->persistent_fd);
    airplay_pairing_control_disconnect(p);
    free(p);
}

enum airplay_pair_state
airplay_pairing_state(const airplay_pairing *p)
{
    return p != NULL ? p->state : AIRPLAY_PAIR_FAILED;
}

const char *
airplay_pairing_error(const airplay_pairing *p)
{
    return p != NULL ? p->last_error : NULL;
}

static void
pairing_set_error(airplay_pairing *p, const char *fmt, ...)
{
    if (p == NULL || fmt == NULL)
        return;

    free(p->last_error);
    p->last_error = NULL;

    va_list args;
    va_start(args, fmt);
    if (vasprintf(&p->last_error, fmt, args) == -1)
        p->last_error = NULL;
    va_end(args);
}

/* -- test seams ------------------------------------------------------------ */

void
airplay_pairing_set_pin_for_tests(airplay_pairing *p, const char *pin)
{
    if (p == NULL)
        return;
    if (p->test_pin != NULL)
    {
        secure_clear(p->test_pin, strlen(p->test_pin));
        free(p->test_pin);
    }
    p->test_pin = pin != NULL ? strdup(pin) : NULL;
}

void
airplay_pairing_set_transport_for_tests(airplay_pairing *p,
                                        airplay_pair_transport_cb cb,
                                        void *opaque)
{
    if (p == NULL)
        return;
    p->transport_cb = cb;
    p->transport_opaque = opaque;
}

void
airplay_pairing_set_identity_ops_for_tests(airplay_pairing *p,
                                           airplay_pair_identity_load_cb load,
                                           airplay_pair_identity_store_cb store,
                                           airplay_pair_identity_remove_cb remove,
                                           void *opaque)
{
    if (p == NULL)
        return;
    p->identity_load_cb = load;
    p->identity_store_cb = store;
    p->identity_remove_cb = remove;
    p->identity_opaque = opaque;
}

void
airplay_pairing_set_control_exchange_for_tests(airplay_pairing *p,
                                               airplay_pair_control_exchange_cb cb,
                                               void *opaque)
{
    if (p == NULL)
        return;
    p->control_exchange_cb = cb;
    p->control_exchange_opaque = opaque;
}

/* -- identity persistence (real keystore, or test seam) -------------------- */

static int
identity_load(airplay_pairing *p, struct airplay_identity *out)
{
    if (p->identity_load_cb != NULL)
        return p->identity_load_cb(p->identity_opaque, out);
#ifndef AIRPLAY_PAIRING_STANDALONE
    return airplay_identity_load(p->obj, p->device_id, out);
#else
    (void) out;
    return VLC_EGENERIC;
#endif
}

static int
identity_store(airplay_pairing *p, const struct airplay_identity *id)
{
    if (p->identity_store_cb != NULL)
        return p->identity_store_cb(p->identity_opaque, id);
#ifndef AIRPLAY_PAIRING_STANDALONE
    return airplay_identity_store(p->obj, p->device_id, p->device_name, id);
#else
    (void) id;
    return VLC_EGENERIC;
#endif
}

static int
identity_remove(airplay_pairing *p)
{
    if (p->identity_remove_cb != NULL)
        return p->identity_remove_cb(p->identity_opaque);
#ifndef AIRPLAY_PAIRING_STANDALONE
    return airplay_identity_remove(p->obj, p->device_id);
#else
    return VLC_EGENERIC;
#endif
}

/* -- PIN acquisition (real dialog, or test seam) ---------------------------- */

static char *
obtain_pin(airplay_pairing *p)
{
#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj == NULL)
        return NULL;

    char *pin = NULL;
    const char *name = p->device_name != NULL ? p->device_name : _("your Apple TV");
    int d = vlc_dialog_wait_pin(p->obj, &pin, _("AirPlay PIN"),
                                _("Enter the 4-digit code shown on %s."), name);
    if (d != 1)
    {
        free(pin);
        return NULL;
    }
    return pin;
#else
    (void) p;
    return NULL;
#endif
}

/* -- default TCP/HTTP control transport ------------------------------------ */

static int
http_response_status(const uint8_t *buf, size_t len)
{
    if (len < 12 || memcmp(buf, "HTTP/1.", 7) != 0)
        return -1;

    const char *cursor = (const char *)buf + 9;
    while (cursor < (const char *)buf + len && *cursor == ' ')
        cursor++;
    return atoi(cursor);
}

static airplay_sock_t
persistent_connect(airplay_pairing *p)
{
    if (p->persistent_fd != AIRPLAY_SOCK_INVALID)
        return p->persistent_fd;

#ifdef _WIN32
    static bool wsa_ready = false;
    if (!wsa_ready)
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return AIRPLAY_SOCK_INVALID;
        wsa_ready = true;
    }
#endif

    char port_str[6];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)p->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(p->ip, port_str, &hints, &res) != 0 || res == NULL)
        return AIRPLAY_SOCK_INVALID;

    airplay_sock_t fd = AIRPLAY_SOCK_INVALID;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == AIRPLAY_SOCK_INVALID)
            continue;
        if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        airplay_sock_close(fd);
        fd = AIRPLAY_SOCK_INVALID;
    }
    freeaddrinfo(res);

    p->persistent_fd = fd;
    return fd;
}

static int
http_read_content_length(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 16 < len; ++i)
    {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r')
            return 0;
        if (i > 0 && buf[i-1] == '\n' &&
            memcmp(buf + i, "Content-Length:", 15) == 0)
        {
            const char *v = (const char *)buf + i + 15;
            while (*v == ' ') v++;
            return atoi(v);
        }
    }
    return -1;
}

static int
default_http_transport(airplay_pairing *p, const char *path,
                       const uint8_t *req, size_t req_len,
                       uint8_t **out_resp, size_t *out_resp_len)
{
    airplay_sock_t fd = persistent_connect(p);
    if (fd == AIRPLAY_SOCK_INVALID)
        return -1;

    char header[384];
    int header_len;
    if (strcmp(path, "/pair-pin-start") == 0)
    {
        header_len = snprintf(header, sizeof header,
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%u\r\n"
            "User-Agent: AirPlay/870.14.1\r\n"
            "Content-Length: %lu\r\n"
            "X-Apple-HKP: 3\r\n"
            "Connection: keep-alive\r\n\r\n",
            path, p->ip, (unsigned)p->port, (unsigned long)req_len);
    }
    else
    {
        header_len = snprintf(header, sizeof header,
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%u\r\n"
            "User-Agent: AirPlay/870.14.1\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %lu\r\n"
            "X-Apple-HKP: 3\r\n"
            "Connection: keep-alive\r\n\r\n",
            path, p->ip, (unsigned)p->port, HAP_MIME_TLV8,
            (unsigned long)req_len);
    }
    if (header_len < 0 || (size_t)header_len >= sizeof header)
    {
        airplay_sock_close(fd);
        p->persistent_fd = AIRPLAY_SOCK_INVALID;
        return -1;
    }

    if (send(fd, header, (size_t)header_len, 0) != header_len ||
        (req_len > 0 &&
         send(fd, (const char *)req, req_len, 0) != (long)req_len))
    {
        airplay_sock_close(fd);
        p->persistent_fd = AIRPLAY_SOCK_INVALID;
        return -1;
    }

    size_t capacity = 4096, length = 0;
    uint8_t *buffer = malloc(capacity);
    if (buffer == NULL)
    {
        airplay_sock_close(fd);
        p->persistent_fd = AIRPLAY_SOCK_INVALID;
        return -1;
    }

    int content_length = -1;
    size_t header_end = 0;

    for (;;)
    {
        if (length == capacity)
        {
            capacity *= 2;
            uint8_t *grown = realloc(buffer, capacity);
            if (grown == NULL)
            {
                free(buffer);
                airplay_sock_close(fd);
                p->persistent_fd = AIRPLAY_SOCK_INVALID;
                return -1;
            }
            buffer = grown;
        }
        long n = recv(fd, (char *)buffer + length, capacity - length, 0);
        if (n < 0)
        {
            free(buffer);
            airplay_sock_close(fd);
            p->persistent_fd = AIRPLAY_SOCK_INVALID;
            return -1;
        }
        if (n == 0)
        {
            p->persistent_fd = AIRPLAY_SOCK_INVALID;
            break;
        }
        length += (size_t)n;

        if (header_end == 0)
        {
            for (size_t i = 0; i + 4 <= length; ++i)
                if (memcmp(buffer + i, "\r\n\r\n", 4) == 0)
                {
                    header_end = i + 4;
                    content_length = http_read_content_length(buffer, header_end);
                    break;
                }
        }

        if (header_end > 0 && content_length >= 0 &&
            length >= header_end + (size_t)content_length)
            break;
    }

    /* Check if server wants to close the connection */
    if (header_end > 0)
    {
        for (size_t i = 0; i + 18 < header_end; ++i)
            if (i > 0 && buffer[i-1] == '\n' &&
                memcmp(buffer + i, "Connection: close", 17) == 0)
            {
                airplay_sock_close(fd);
                p->persistent_fd = AIRPLAY_SOCK_INVALID;
                break;
            }
    }

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay HTTP %d for %s (%zu body bytes, fd=%s)",
                http_response_status(buffer, length), path,
                content_length >= 0 ? (size_t)content_length : 0,
                p->persistent_fd != AIRPLAY_SOCK_INVALID ? "open" : "closed");
#endif

    int status = http_response_status(buffer, length);
    if (status != 200)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj != NULL)
        {
            if (status == 470)
            {
                msg_Err(p->obj,
                        "AirPlay HTTP 470 during %s (authorization required).",
                        path);
                pairing_set_error(p,
                    _("Could not pair with %s. The Apple TV rejected the "
                      "pairing request (HTTP 470 — connection authorization "
                      "required). Check that AirPlay access allows this "
                      "device, then try once."),
                    p->device_name != NULL ? p->device_name : p->device_id);
            }
            else
            {
                msg_Err(p->obj, "AirPlay HTTP %d during %s",
                        status > 0 ? status : 0, path);
                pairing_set_error(p, _("Could not pair with %s (HTTP %d)."),
                                p->device_name != NULL ? p->device_name
                                                       : p->device_id,
                                status > 0 ? status : 0);
            }
        }
#endif
        free(buffer);
        return -1;
    }

    const char *separator = "\r\n\r\n";
    uint8_t *body = NULL;
    for (size_t i = 0; i + 4 <= length; ++i)
        if (memcmp(buffer + i, separator, 4) == 0)
        {
            body = buffer + i + 4;
            break;
        }
    if (body == NULL)
    {
        free(buffer);
        return -1;
    }

    size_t body_len = length - (size_t)(body - buffer);
    uint8_t *resp = body_len != 0 ? malloc(body_len) : NULL;
    if (body_len != 0 && resp == NULL)
    {
        free(buffer);
        return -1;
    }
    if (body_len != 0)
        memcpy(resp, body, body_len);
    free(buffer);

    *out_resp = resp;
    *out_resp_len = body_len;
    return 0;
}

static int
transport_send(airplay_pairing *p, const char *path, const uint8_t *req,
              size_t req_len, uint8_t **resp, size_t *resp_len)
{
    if (p->transport_cb != NULL)
        return p->transport_cb(p->transport_opaque, path, req, req_len,
                               resp, resp_len);
    return default_http_transport(p, path, req, req_len, resp, resp_len);
}

static int
send_recv_tlv_ex(airplay_pairing *pairing, airplay_tlv_exchange_fn exchange,
                 void *opaque, const char *path, const uint8_t *req,
                 size_t req_len, uint8_t **resp, size_t *resp_len)
{
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (exchange(opaque, path, req, req_len, &raw, &raw_len) != 0)
        return -1;

    if (hap_tlv_has(raw, raw_len, HAP_TLV_ERROR))
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        bool ok = false;
        uint8_t err = hap_tlv_get_u8(raw, raw_len, HAP_TLV_ERROR, &ok);
        if (pairing != NULL && ok)
            pairing->last_hap_error = err;
        if (pairing != NULL && pairing->obj != NULL)
        {
            if (ok && err == 3)
            {
                /* HAP kTLVType_RetryDelay is 0x08; value is seconds (LE). */
                unsigned delay_sec = 0;
                uint8_t *delay = NULL;
                size_t delay_len = 0;
                if (hap_tlv_get(raw, raw_len, 0x08, &delay, &delay_len) == 0 &&
                    delay_len >= 1)
                {
                    delay_sec = delay[0];
                    if (delay_len >= 2)
                        delay_sec |= ((unsigned)delay[1]) << 8;
                    if (delay_len >= 4)
                    {
                        delay_sec |= ((unsigned)delay[2]) << 16;
                        delay_sec |= ((unsigned)delay[3]) << 24;
                    }
                }
                free(delay);

                msg_Err(pairing->obj,
                        "AirPlay receiver pairing backoff"
                        "%s%u%s — the penalty survives a reboot; wait it out.",
                        delay_sec > 0 ? " (" : "",
                        delay_sec,
                        delay_sec > 0 ? "s)" : "");
                backoff_remember(pairing->device_id, delay_sec);
                if (delay_sec > 0)
                {
                    unsigned mins = (delay_sec + 59) / 60;
                    pairing_set_error(pairing,
                        _("Could not pair with %s. The Apple TV is refusing new "
                          "pairing attempts for about %u more minutes. This "
                          "countdown survives a reboot, so wait it out before "
                          "trying again. Any code shown on the TV right now "
                          "will not work."),
                        pairing->device_name != NULL ? pairing->device_name
                                                     : pairing->device_id,
                        mins);
                }
                else
                    pairing_set_error(pairing,
                        _("Could not pair with %s. The Apple TV is refusing new "
                          "pairing attempts; wait before trying again."),
                        pairing->device_name != NULL ? pairing->device_name
                                                     : pairing->device_id);
            }
            else
            {
                msg_Err(pairing->obj,
                        "AirPlay HAP error %u during %s",
                        ok ? (unsigned)err : 0U, path);
                pairing_set_error(pairing,
                    _("Could not pair with %s (HAP error %u)."),
                    pairing->device_name != NULL ? pairing->device_name
                                                 : pairing->device_id,
                    ok ? (unsigned)err : 0U);
            }
        }
#endif
        free(raw);
        return -1;
    }

    *resp = raw;
    *resp_len = raw_len;
    return 0;
}

static int
transport_exchange_wrapper(void *opaque, const char *path,
                           const uint8_t *req, size_t req_len,
                           uint8_t **resp, size_t *resp_len)
{
    airplay_pairing *p = opaque;
    return transport_send(p, path, req, req_len, resp, resp_len);
}

static int
send_recv_tlv(airplay_pairing *p, const char *path,
              const uint8_t *req, size_t req_len,
              uint8_t **resp, size_t *resp_len)
{
    return send_recv_tlv_ex(p, transport_exchange_wrapper, p, path, req, req_len,
                            resp, resp_len);
}

static bool
tlv_state_is(const uint8_t *tlv, size_t tlv_len, uint8_t expected)
{
    bool ok = false;
    uint8_t state = hap_tlv_get_u8(tlv, tlv_len, HAP_TLV_STATE, &ok);
    return ok && state == expected;
}

/* -- pair-setup (M1-M6) ---------------------------------------------------- */

static int
request_pin_display(airplay_pairing *p)
{
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int ret = transport_send(p, "/pair-pin-start", NULL, 0, &resp, &resp_len);
    free(resp);
    if (ret != 0)
    {
        if (p->last_error == NULL)
            pairing_set_error(p, _("Could not request a PIN from %s."),
                            p->device_name != NULL ? p->device_name
                                                   : p->device_id);
        return -1;
    }
    return 0;
}

static int
pair_setup_send_m1(airplay_pairing *p, uint8_t **m2, size_t *m2_len)
{
    hap_tlv_buf req1;
    hap_tlv_buf_init(&req1);
    static const uint8_t method_pair = 0;
    if (hap_tlv_buf_add(&req1, HAP_TLV_METHOD, &method_pair, 1) != 0 ||
        hap_tlv_buf_add(&req1, HAP_TLV_STATE, (const uint8_t[]){ 1 }, 1) != 0)
    {
        hap_tlv_buf_clear(&req1);
        return -1;
    }
    uint8_t *req1_raw = NULL;
    size_t req1_len = 0;
    if (hap_tlv_buf_finish(&req1, &req1_raw, &req1_len) != 0)
        return -1;
    int rc = send_recv_tlv(p, "/pair-setup", req1_raw, req1_len, m2, m2_len);
    free(req1_raw);
    return rc;
}

static int
do_setup(airplay_pairing *p, const char *pin_preset)
{
    int ret = -1;
    airplay_srp_ctx *srp = NULL;
    char *pin_owned = NULL;
    const char *pin = pin_preset;

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (pin == NULL)
    {
        unsigned left = backoff_seconds_left(p->device_id);
        if (left > 0)
        {
            pairing_set_error(p,
                _("Could not pair with %s. The Apple TV is refusing new "
                  "pairing attempts for about %u more minutes."),
                p->device_name != NULL ? p->device_name : p->device_id,
                (left + 59) / 60);
            goto out_early;
        }
    }
#endif

    /* pair-pin-start before M1 (Apple protocol). Single M1 only — an extra
     * probe M1 before pin-start caused duplicate setup attempts and TV backoff
     * while pin-start had already put a code on screen. */
    if (pin == NULL && request_pin_display(p) != 0)
        goto out_early;

    srp = airplay_srp_client_new(NULL);
    if (srp == NULL)
        goto out_early;

    uint8_t *A = NULL;
    size_t A_len = 0;
    uint8_t *m1_proof = NULL;
    size_t m1_len = 0;
    uint8_t shared_key[64];
    uint8_t *m2 = NULL, *m4 = NULL, *m6 = NULL;
    size_t m2_len = 0, m4_len = 0, m6_len = 0;
    uint8_t *peer_pk = NULL, *peer_sig = NULL, *peer_id = NULL;
    size_t peer_pk_len = 0, peer_sig_len = 0, peer_id_len = 0;

    if (airplay_srp_client_start(srp, &A, &A_len) != 0)
        goto out;

    if (pair_setup_send_m1(p, &m2, &m2_len) != 0)
        goto out;

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay M2 received: %zu bytes", m2_len);
#endif

    if (!tlv_state_is(m2, m2_len, 2))
        goto out;

    uint8_t *salt = NULL, *B = NULL;
    size_t salt_len = 0, B_len = 0;
    if (hap_tlv_get(m2, m2_len, HAP_TLV_SALT, &salt, &salt_len) != 0 ||
        hap_tlv_get(m2, m2_len, HAP_TLV_PUBLIC_KEY, &B, &B_len) != 0)
    {
        free(salt);
        free(B);
        goto out;
    }

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay M2 salt=%zu B=%zu", salt_len, B_len);
#endif

    if (pin == NULL)
    {
        p->state = AIRPLAY_PAIR_NEED_PIN;
        pin_owned = obtain_pin(p);
        pin = pin_owned;
        if (pin == NULL)
        {
            free(salt);
            free(B);
            goto out;
        }
        p->state = AIRPLAY_PAIR_SETUP;
    }

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay PIN len=%zu first='%c'",
                strlen(pin), pin[0]);
#endif

    if (airplay_srp_client_set_pin(srp, pin) != 0)
    {
        free(salt);
        free(B);
        goto out;
    }

    int rc = airplay_srp_client_finish(srp, salt, salt_len, B, B_len, &m1_proof,
                                       &m1_len, shared_key);
    free(salt);
    free(B);
    if (rc != 0)
        goto out;

    hap_tlv_buf req3;
    hap_tlv_buf_init(&req3);
    if (hap_tlv_buf_add(&req3, HAP_TLV_STATE, (const uint8_t[]){ 3 }, 1) != 0 ||
        hap_tlv_buf_add(&req3, HAP_TLV_PUBLIC_KEY, A, A_len) != 0 ||
        hap_tlv_buf_add(&req3, HAP_TLV_PROOF, m1_proof, m1_len) != 0)
    {
        hap_tlv_buf_clear(&req3);
        goto out;
    }
    uint8_t *req3_raw = NULL;
    size_t req3_len = 0;
#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay sending M3: A=%zu proof=%zu total=%zu",
                A_len, m1_len, req3_len);
#endif
    if (hap_tlv_buf_finish(&req3, &req3_raw, &req3_len) != 0 ||
        send_recv_tlv(p, "/pair-setup", req3_raw, req3_len, &m4, &m4_len) != 0)
    {
        free(req3_raw);
        goto out;
    }
    free(req3_raw);

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay M4 received: %zu bytes", m4_len);
#endif
    if (!tlv_state_is(m4, m4_len, 4))
        goto out;

    uint8_t *m2proof = NULL;
    size_t m2proof_len = 0;
    if (hap_tlv_get(m4, m4_len, HAP_TLV_PROOF, &m2proof, &m2proof_len) != 0)
        goto out;
    rc = airplay_srp_client_verify_proof(srp, m2proof, m2proof_len);
    free(m2proof);
    if (rc != 0)
        goto out;

    uint8_t setup_key[32];
    static const char setup_salt[] = "Pair-Setup-Encrypt-Salt";
    static const char setup_info[] = "Pair-Setup-Encrypt-Info";
    if (airplay_hkdf_sha512(setup_key, sizeof setup_key, shared_key,
                            sizeof shared_key, (const uint8_t *)setup_salt,
                            sizeof setup_salt - 1, (const uint8_t *)setup_info,
                            sizeof setup_info - 1) != 0)
        goto out;

    if (airplay_ed25519_keypair(p->identity.our_ed25519_sk,
                                p->identity.our_ed25519_pk) != 0)
        goto out;
    ensure_controller_pairing_id(&p->identity);

    static const char ctrl_sign_salt[] = "Pair-Setup-Controller-Sign-Salt";
    static const char ctrl_sign_info[] = "Pair-Setup-Controller-Sign-Info";
    uint8_t ctrl_x[32];
    if (airplay_hkdf_sha512(ctrl_x, sizeof ctrl_x, shared_key,
                            sizeof shared_key, (const uint8_t *)ctrl_sign_salt,
                            sizeof ctrl_sign_salt - 1,
                            (const uint8_t *)ctrl_sign_info,
                            sizeof ctrl_sign_info - 1) != 0)
        goto out;

    const char *ctrl_id = p->identity.controller_pairing_id;
    size_t ctrl_id_len = strlen(ctrl_id);
    uint8_t *sign_msg = NULL;
    size_t sign_msg_len = 0;
    if (buf_cat(&sign_msg, &sign_msg_len, ctrl_x, sizeof ctrl_x,
                (const uint8_t *)ctrl_id, ctrl_id_len,
                p->identity.our_ed25519_pk, 32) != 0)
        goto out;

    uint8_t sig5[64];
    rc = airplay_ed25519_sign(sig5, sign_msg, sign_msg_len,
                               p->identity.our_ed25519_sk);
    free(sign_msg);
    if (rc != 0)
        goto out;

    hap_tlv_buf inner5;
    hap_tlv_buf_init(&inner5);
    if (hap_tlv_buf_add(&inner5, HAP_TLV_IDENTIFIER, ctrl_id, ctrl_id_len) != 0 ||
        hap_tlv_buf_add(&inner5, HAP_TLV_PUBLIC_KEY, p->identity.our_ed25519_pk,
                        32) != 0 ||
        hap_tlv_buf_add(&inner5, HAP_TLV_SIGNATURE, sig5, sizeof sig5) != 0)
    {
        hap_tlv_buf_clear(&inner5);
        goto out;
    }
    uint8_t *inner5_raw = NULL;
    size_t inner5_len = 0;
    if (hap_tlv_buf_finish(&inner5, &inner5_raw, &inner5_len) != 0)
        goto out;

    uint8_t *enc5 = malloc(inner5_len + 16);
    size_t enc5_len = 0;
    static const uint8_t nonce5[12] = "\0\0\0\0PS-Msg05";
    if (enc5 == NULL ||
        airplay_chacha_encrypt(enc5, &enc5_len, inner5_raw, inner5_len,
                               setup_key, nonce5, NULL, 0) != 0)
    {
        free(inner5_raw);
        free(enc5);
        goto out;
    }
    free(inner5_raw);

    hap_tlv_buf req5;
    hap_tlv_buf_init(&req5);
    if (hap_tlv_buf_add(&req5, HAP_TLV_STATE, (const uint8_t[]){ 5 }, 1) != 0 ||
        hap_tlv_buf_add(&req5, HAP_TLV_ENCRYPTED_DATA, enc5, enc5_len) != 0)
    {
        free(enc5);
        hap_tlv_buf_clear(&req5);
        goto out;
    }
    free(enc5);
    uint8_t *req5_raw = NULL;
    size_t req5_len = 0;
    if (hap_tlv_buf_finish(&req5, &req5_raw, &req5_len) != 0)
    {
        free(req5_raw);
        goto out;
    }
#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay sending M5: %zu bytes (inner=%zu enc=%zu)",
                req5_len, inner5_len, enc5_len);
#endif
    if (send_recv_tlv(p, "/pair-setup", req5_raw, req5_len, &m6, &m6_len) != 0)
    {
        free(req5_raw);
        goto out;
    }
    free(req5_raw);
#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay M6 received: %zu bytes", m6_len);
#endif

    if (!tlv_state_is(m6, m6_len, 6))
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay M6: bad state TLV");
#endif
        goto out;
    }

    uint8_t *enc6 = NULL;
    size_t enc6_len = 0;
    if (hap_tlv_get(m6, m6_len, HAP_TLV_ENCRYPTED_DATA, &enc6, &enc6_len) != 0 ||
        enc6_len < 16)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay M6: no encrypted data (enc6_len=%zu)", enc6_len);
#endif
        free(enc6);
        goto out;
    }
    uint8_t *dec6 = malloc(enc6_len - 16 > 0 ? enc6_len - 16 : 1);
    size_t dec6_len = 0;
    static const uint8_t nonce6[12] = "\0\0\0\0PS-Msg06";
    rc = dec6 == NULL ? -1 :
        airplay_chacha_decrypt(dec6, &dec6_len, enc6, enc6_len, setup_key,
                               nonce6, NULL, 0);
    free(enc6);
    if (rc != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay M6: decryption failed");
#endif
        free(dec6);
        goto out;
    }

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj) msg_Dbg(p->obj, "AirPlay M6 decrypted: %zu bytes", dec6_len);
#endif

    rc = -1;
    if (hap_tlv_get(dec6, dec6_len, HAP_TLV_PUBLIC_KEY, &peer_pk, &peer_pk_len) == 0 &&
        peer_pk_len == 32 &&
        hap_tlv_get(dec6, dec6_len, HAP_TLV_SIGNATURE, &peer_sig, &peer_sig_len) == 0 &&
        peer_sig_len == 64 &&
        hap_tlv_get(dec6, dec6_len, HAP_TLV_IDENTIFIER, &peer_id, &peer_id_len) == 0)
    {
        static const char acc_sign_salt[] = "Pair-Setup-Accessory-Sign-Salt";
        static const char acc_sign_info[] = "Pair-Setup-Accessory-Sign-Info";
        uint8_t acc_x[32];
        if (airplay_hkdf_sha512(acc_x, sizeof acc_x, shared_key,
                                sizeof shared_key,
                                (const uint8_t *)acc_sign_salt,
                                sizeof acc_sign_salt - 1,
                                (const uint8_t *)acc_sign_info,
                                sizeof acc_sign_info - 1) == 0)
        {
            uint8_t *acc_msg = NULL;
            size_t acc_msg_len = 0;
            if (buf_cat(&acc_msg, &acc_msg_len, acc_x, sizeof acc_x,
                        peer_id, peer_id_len, peer_pk, 32) == 0 &&
                airplay_ed25519_verify(peer_sig, acc_msg, acc_msg_len,
                                       peer_pk) == 0)
            {
                if (p->has_accessory_ltpk &&
                    memcmp(peer_pk, p->accessory_ltpk, 32) != 0)
                {
#ifndef AIRPLAY_PAIRING_STANDALONE
                    if (p->obj) msg_Warn(p->obj, "AirPlay M6: accessory LTPK differs "
                                         "from discovery pk (expected for AirPlay)");
#endif
                }
                if (p->accessory_pairing_id != NULL &&
                    (peer_id_len != strlen(p->accessory_pairing_id) ||
                     memcmp(peer_id, p->accessory_pairing_id,
                            peer_id_len) != 0))
                {
#ifndef AIRPLAY_PAIRING_STANDALONE
                    if (p->obj) msg_Warn(p->obj, "AirPlay M6: pairing ID mismatch "
                                        "(got %.*s, expected %s) — accepting anyway",
                                        (int)peer_id_len, (const char *)peer_id,
                                        p->accessory_pairing_id);
#endif
                }
                /* Accept the pair-setup peer key regardless of discovery metadata. */
                memcpy(p->identity.peer_ed25519_pk, peer_pk, 32);
                p->identity.has_peer = 1;
                rc = 0;
            }
            free(acc_msg);
        }
    }
    free(dec6);
    if (rc != 0)
        goto out;

    ret = 0;

out:
    secure_clear(pin_owned, pin_owned != NULL ? strlen(pin_owned) : 0);
    free(pin_owned);
    free(A);
    free(m1_proof);
    free(peer_pk);
    free(peer_sig);
    free(peer_id);
    free(m2);
    free(m4);
    free(m6);
    airplay_srp_client_release(srp);
    return ret;

out_early:
    airplay_srp_client_release(srp);
    return -1;
}

/* -- pair-verify (M1-M4) --------------------------------------------------- */

static int
do_verify_ex(airplay_pairing *p, airplay_tlv_exchange_fn exchange, void *opaque);

static int
do_verify(airplay_pairing *p)
{
    return do_verify_ex(p, transport_exchange_wrapper, p);
}

static int
do_verify_ex(airplay_pairing *p, airplay_tlv_exchange_fn exchange, void *opaque)
{
    int ret = -1;
    p->verify_rejected = false;
    uint8_t eph_sk[32], eph_pk[32];
    uint8_t *m2 = NULL, *m4 = NULL;
    size_t m2_len = 0, m4_len = 0;
    uint8_t *peer_eph_pk = NULL, *enc = NULL, *peer_sig = NULL, *peer_id = NULL;
    size_t peer_eph_pk_len = 0, enc_len = 0, peer_sig_len = 0, peer_id_len = 0;

    ensure_controller_pairing_id(&p->identity);

    if (airplay_x25519_keypair(eph_sk, eph_pk) != 0)
        return -1;

    hap_tlv_buf req1;
    hap_tlv_buf_init(&req1);
    if (hap_tlv_buf_add(&req1, HAP_TLV_STATE, (const uint8_t[]){ 1 }, 1) != 0 ||
        hap_tlv_buf_add(&req1, HAP_TLV_PUBLIC_KEY, eph_pk, sizeof eph_pk) != 0)
    {
        hap_tlv_buf_clear(&req1);
        goto out;
    }
    uint8_t *req1_raw = NULL;
    size_t req1_len = 0;
    if (hap_tlv_buf_finish(&req1, &req1_raw, &req1_len) != 0 ||
        send_recv_tlv_ex(p, exchange, opaque, "/pair-verify", req1_raw, req1_len,
                         &m2, &m2_len) != 0)
    {
        free(req1_raw);
        goto out;
    }
    free(req1_raw);

    if (!tlv_state_is(m2, m2_len, 2))
        goto out;

    if (hap_tlv_get(m2, m2_len, HAP_TLV_PUBLIC_KEY, &peer_eph_pk,
                    &peer_eph_pk_len) != 0 ||
        peer_eph_pk_len != 32 ||
        hap_tlv_get(m2, m2_len, HAP_TLV_ENCRYPTED_DATA, &enc, &enc_len) != 0 ||
        enc_len < 16)
        goto out;

    uint8_t shared[32];
    if (airplay_x25519(shared, eph_sk, peer_eph_pk) != 0)
        goto out;

    uint8_t verify_key[32];
    static const char v_salt[] = "Pair-Verify-Encrypt-Salt";
    static const char v_info[] = "Pair-Verify-Encrypt-Info";
    if (airplay_hkdf_sha512(verify_key, sizeof verify_key, shared,
                            sizeof shared, (const uint8_t *)v_salt,
                            sizeof v_salt - 1, (const uint8_t *)v_info,
                            sizeof v_info - 1) != 0)
        goto out;

    uint8_t *dec = malloc(enc_len - 16 > 0 ? enc_len - 16 : 1);
    size_t dec_len = 0;
    static const uint8_t nonce2[12] = "\0\0\0\0PV-Msg02";
    int rc = dec == NULL ? -1 :
        airplay_chacha_decrypt(dec, &dec_len, enc, enc_len, verify_key,
                               nonce2, NULL, 0);
    if (rc != 0)
    {
        free(dec);
        goto out;
    }

    rc = -1;
    if (p->identity.has_peer &&
        hap_tlv_get(dec, dec_len, HAP_TLV_SIGNATURE, &peer_sig,
                    &peer_sig_len) == 0 &&
        peer_sig_len == 64 &&
        hap_tlv_get(dec, dec_len, HAP_TLV_IDENTIFIER, &peer_id,
                    &peer_id_len) == 0)
    {
        uint8_t *msg = NULL;
        size_t msg_len = 0;
        if (buf_cat(&msg, &msg_len, peer_eph_pk, 32, peer_id, peer_id_len,
                    eph_pk, 32) == 0 &&
            airplay_ed25519_verify(peer_sig, msg, msg_len,
                                   p->identity.peer_ed25519_pk) == 0)
            rc = 0;
        free(msg);
    }
    free(dec);
    if (rc != 0)
    {
        p->verify_rejected = true;
        goto out;
    }

    const char *ctrl_id = p->identity.controller_pairing_id;
    size_t ctrl_id_len = strlen(ctrl_id);
    uint8_t *msg3 = NULL;
    size_t msg3_len = 0;
    if (buf_cat(&msg3, &msg3_len, eph_pk, 32, (const uint8_t *)ctrl_id,
                ctrl_id_len, peer_eph_pk, 32) != 0)
        goto out;

    uint8_t sig3[64];
    if (airplay_ed25519_sign(sig3, msg3, msg3_len, p->identity.our_ed25519_sk) != 0)
    {
        free(msg3);
        goto out;
    }
    free(msg3);

    hap_tlv_buf inner3;
    hap_tlv_buf_init(&inner3);
    if (hap_tlv_buf_add(&inner3, HAP_TLV_IDENTIFIER, ctrl_id, ctrl_id_len) != 0 ||
        hap_tlv_buf_add(&inner3, HAP_TLV_SIGNATURE, sig3, sizeof sig3) != 0)
    {
        hap_tlv_buf_clear(&inner3);
        goto out;
    }
    uint8_t *inner3_raw = NULL;
    size_t inner3_len = 0;
    if (hap_tlv_buf_finish(&inner3, &inner3_raw, &inner3_len) != 0)
        goto out;

    uint8_t *enc3 = malloc(inner3_len + 16);
    size_t enc3_len = 0;
    static const uint8_t nonce3[12] = "\0\0\0\0PV-Msg03";
    rc = enc3 == NULL ? -1 :
        airplay_chacha_encrypt(enc3, &enc3_len, inner3_raw, inner3_len,
                               verify_key, nonce3, NULL, 0);
    free(inner3_raw);
    if (rc != 0)
    {
        free(enc3);
        goto out;
    }

    hap_tlv_buf req3;
    hap_tlv_buf_init(&req3);
    if (hap_tlv_buf_add(&req3, HAP_TLV_STATE, (const uint8_t[]){ 3 }, 1) != 0 ||
        hap_tlv_buf_add(&req3, HAP_TLV_ENCRYPTED_DATA, enc3, enc3_len) != 0)
    {
        free(enc3);
        hap_tlv_buf_clear(&req3);
        goto out;
    }
    free(enc3);
    uint8_t *req3_raw = NULL;
    size_t req3_len = 0;
    if (hap_tlv_buf_finish(&req3, &req3_raw, &req3_len) != 0 ||
        send_recv_tlv_ex(p, exchange, opaque, "/pair-verify", req3_raw, req3_len,
                         &m4, &m4_len) != 0)
    {
        free(req3_raw);
        goto out;
    }
    free(req3_raw);

    if (!tlv_state_is(m4, m4_len, 4))
    {
        p->verify_rejected = true;
        goto out;
    }

    static const char c_salt[] = "Control-Salt";
    static const char c_write[] = "Control-Write-Encryption-Key";
    static const char c_read[] = "Control-Read-Encryption-Key";
    static const char e_salt[] = "Events-Salt";
    static const char e_write[] = "Events-Write-Encryption-Key";
    static const char e_read[] = "Events-Read-Encryption-Key";
    if (airplay_hkdf_sha512(p->control_write_key, sizeof p->control_write_key,
                            shared, sizeof shared, (const uint8_t *)c_salt,
                            sizeof c_salt - 1, (const uint8_t *)c_write,
                            sizeof c_write - 1) != 0 ||
        airplay_hkdf_sha512(p->control_read_key, sizeof p->control_read_key,
                            shared, sizeof shared, (const uint8_t *)c_salt,
                            sizeof c_salt - 1, (const uint8_t *)c_read,
                            sizeof c_read - 1) != 0 ||
        /* Event channel is reversed: encrypt with the read key. */
        airplay_hkdf_sha512(p->event_out_key, sizeof p->event_out_key,
                            shared, sizeof shared, (const uint8_t *)e_salt,
                            sizeof e_salt - 1, (const uint8_t *)e_read,
                            sizeof e_read - 1) != 0 ||
        airplay_hkdf_sha512(p->event_in_key, sizeof p->event_in_key,
                            shared, sizeof shared, (const uint8_t *)e_salt,
                            sizeof e_salt - 1, (const uint8_t *)e_write,
                            sizeof e_write - 1) != 0)
        goto out;
    p->write_nonce = 0;
    p->read_nonce = 0;
    p->event_write_nonce = 0;
    p->event_read_nonce = 0;
    p->has_session_keys = true;

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj)
        msg_Dbg(p->obj, "AirPlay pair-verify complete");
#endif
    ret = 0;

out:
    free(peer_eph_pk);
    free(enc);
    free(peer_sig);
    free(peer_id);
    free(m2);
    free(m4);
    return ret;
}

/* -- top-level FSM --------------------------------------------------------- */

int
airplay_pairing_ensure(airplay_pairing *p)
{
    if (p == NULL)
        return VLC_EGENERIC;
    if (p->state == AIRPLAY_PAIR_PAIRED || p->state == AIRPLAY_PAIR_READY)
        return VLC_SUCCESS;

    struct airplay_identity loaded;
    memset(&loaded, 0, sizeof loaded);
    if (identity_load(p, &loaded) == 0 && loaded.has_peer)
    {
        p->identity = loaded;
        ensure_controller_pairing_id(&p->identity);
        p->state = AIRPLAY_PAIR_PAIRED;
        return VLC_SUCCESS;
    }

    p->state = AIRPLAY_PAIR_SETUP;
    int ret = do_setup(p, p->test_pin);
    if (ret != 0)
    {
        p->state = AIRPLAY_PAIR_FAILED;
        return VLC_EGENERIC;
    }

    if (identity_store(p, &p->identity) != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj)
            msg_Warn(p->obj, "AirPlay pairing was not saved; the PIN will be "
                     "required again next time");
#endif
    }
#ifndef AIRPLAY_PAIRING_STANDALONE
    else if (p->obj)
        msg_Dbg(p->obj, "AirPlay pairing saved for %s", p->device_id);
#endif

    if (p->persistent_fd != AIRPLAY_SOCK_INVALID)
    {
        airplay_sock_close(p->persistent_fd);
        p->persistent_fd = AIRPLAY_SOCK_INVALID;
    }
    p->has_session_keys = false;
    p->state = AIRPLAY_PAIR_PAIRED;
    return VLC_SUCCESS;
}

/* -- control channel AEAD --------------------------------------------------- */

int
airplay_pairing_encrypt(airplay_pairing *p, const uint8_t *in, size_t in_len,
                        uint8_t **out, size_t *out_len)
{
    if (p == NULL || !p->has_session_keys || p->state != AIRPLAY_PAIR_READY ||
        in == NULL || out == NULL || out_len == NULL)
        return -1;

    uint8_t *buf = malloc(in_len + 16);
    if (buf == NULL)
        return -1;

    uint8_t nonce[12] = { 0 };
    memcpy(nonce + 4, &p->write_nonce, sizeof p->write_nonce);

    size_t len = 0;
    if (airplay_chacha_encrypt(buf, &len, in, in_len, p->control_write_key,
                               nonce, NULL, 0) != 0)
    {
        free(buf);
        return -1;
    }
    p->write_nonce++;
    *out = buf;
    *out_len = len;
    return 0;
}

int
airplay_pairing_decrypt(airplay_pairing *p, const uint8_t *in, size_t in_len,
                        uint8_t **out, size_t *out_len)
{
    if (p == NULL || !p->has_session_keys || p->state != AIRPLAY_PAIR_READY ||
        in == NULL || out == NULL || out_len == NULL || in_len < 16)
        return -1;

    uint8_t *buf = malloc(in_len - 16 > 0 ? in_len - 16 : 1);
    if (buf == NULL)
        return -1;

    uint8_t nonce[12] = { 0 };
    memcpy(nonce + 4, &p->read_nonce, sizeof p->read_nonce);

    size_t len = 0;
    if (airplay_chacha_decrypt(buf, &len, in, in_len, p->control_read_key,
                               nonce, NULL, 0) != 0)
    {
        free(buf);
        return -1;
    }
    p->read_nonce++;
    *out = buf;
    *out_len = len;
    return 0;
}

/* -- persistent encrypted control connection -------------------------------- */

static int
socket_wsa_init(void)
{
#ifdef _WIN32
    static bool wsa_ready = false;
    if (!wsa_ready)
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return -1;
        wsa_ready = true;
    }
#endif
    return 0;
}

static int
pairing_open_socket(airplay_pairing *p, airplay_sock_t *out_fd)
{
    if (socket_wsa_init() != 0)
        return -1;

    char port_str[6];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)p->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(p->ip, port_str, &hints, &res) != 0 || res == NULL)
        return -1;

    airplay_sock_t fd = AIRPLAY_SOCK_INVALID;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == AIRPLAY_SOCK_INVALID)
            continue;
        if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        airplay_sock_close(fd);
        fd = AIRPLAY_SOCK_INVALID;
    }
    freeaddrinfo(res);
    if (fd == AIRPLAY_SOCK_INVALID)
        return -1;

    *out_fd = fd;
#ifdef _WIN32
    DWORD timeout_ms = 8000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
               sizeof timeout_ms);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
               sizeof timeout_ms);
#else
    struct timeval timeout = { 8, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
#endif
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay,
               sizeof nodelay);
    return 0;
}

static ssize_t http_body_length(const uint8_t *msg, size_t header_end);

static int
http_tlv_post_fd(airplay_pairing *p, airplay_sock_t fd, const char *host,
                   uint16_t port, const char *path, const uint8_t *req,
                   size_t req_len, uint8_t **out_resp, size_t *out_resp_len)
{
    char header[320];
    int header_len = snprintf(header, sizeof header,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "X-Apple-HKP: 3\r\n"
        "Connection: keep-alive\r\n\r\n",
        path, host, (unsigned)port, HAP_MIME_TLV8,
        (unsigned long)req_len);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
        return -1;

    if (send(fd, header, (size_t)header_len, 0) != header_len ||
        (req_len > 0 &&
         send(fd, (const char *)req, req_len, 0) != (long)req_len))
        return -1;

    size_t capacity = 4096, length = 0;
    uint8_t *buffer = malloc(capacity);
    if (buffer == NULL)
        return -1;

    size_t header_end = 0;
    ssize_t content_length = -1;
    for (;;)
    {
        if (length == capacity)
        {
            capacity *= 2;
            uint8_t *grown = realloc(buffer, capacity);
            if (grown == NULL)
            {
                free(buffer);
                return -1;
            }
            buffer = grown;
        }
        long n = recv(fd, (char *)buffer + length, capacity - length, 0);
        if (n < 0)
        {
            free(buffer);
            return -1;
        }
        if (n == 0)
            break;
        length += (size_t)n;

        if (header_end == 0)
        {
            for (size_t i = 0; i + 4 <= length; ++i)
                if (memcmp(buffer + i, "\r\n\r\n", 4) == 0)
                {
                    header_end = i + 4;
                    content_length = http_body_length(buffer, header_end);
                    if (content_length < 0)
                        content_length = 0;
                    break;
                }
        }
        if (header_end > 0 && length >= header_end + (size_t)content_length)
            break;
    }

    int status = http_response_status(buffer, length);
    if (status != 200)
    {
        free(buffer);
        return -1;
    }

    if (header_end == 0)
    {
        free(buffer);
        return -1;
    }

    size_t body_len = length - header_end;
    if ((ssize_t)body_len > content_length && content_length >= 0)
        body_len = (size_t)content_length;
    uint8_t *resp = body_len != 0 ? malloc(body_len) : NULL;
    if (body_len != 0 && resp == NULL)
    {
        free(buffer);
        return -1;
    }
    if (body_len != 0)
        memcpy(resp, buffer + header_end, body_len);

    size_t used = header_end + (size_t)(content_length > 0 ? content_length : 0);
    if (p != NULL && length > used)
    {
        size_t extra = length - used;
        uint8_t *kept = malloc(extra);
        if (kept != NULL)
        {
            memcpy(kept, buffer + used, extra);
            free(p->control_prefetch);
            p->control_prefetch = kept;
            p->control_prefetch_len = extra;
#ifndef AIRPLAY_PAIRING_STANDALONE
            if (p->obj)
                msg_Dbg(p->obj, "AirPlay: kept %zu bytes past %s response",
                        extra, path);
#endif
        }
    }
    free(buffer);

    *out_resp = resp;
    *out_resp_len = body_len;
    return 0;
}

typedef struct tlv_fd_ctx
{
    airplay_pairing *pairing;
    airplay_sock_t fd;
} tlv_fd_ctx;

static int
fd_tlv_exchange(void *opaque, const char *path, const uint8_t *req,
                size_t req_len, uint8_t **resp, size_t *resp_len)
{
    tlv_fd_ctx *ctx = opaque;
    return http_tlv_post_fd(ctx->pairing, ctx->fd, ctx->pairing->ip,
                            ctx->pairing->port, path, req, req_len, resp,
                            resp_len);
}

static ssize_t
http_body_length(const uint8_t *msg, size_t header_end)
{
    static const char needle[] = "Content-Length:";
    for (size_t i = 0; i + sizeof needle - 1 <= header_end; ++i)
    {
        if (memcmp(msg + i, needle, sizeof needle - 1) != 0)
            continue;
        const char *cursor = (const char *)msg + i + sizeof needle - 1;
        while (cursor < (const char *)msg + header_end && *cursor == ' ')
            cursor++;
        char *end = NULL;
        long value = strtol(cursor, &end, 10);
        if (end == cursor || value < 0)
            return -1;
        return (ssize_t)value;
    }
    return 0;
}

static bool
http_response_complete(const uint8_t *buf, size_t len, size_t *out_total)
{
    static const char separator[] = "\r\n\r\n";
    size_t header_end = 0;
    for (size_t i = 0; i + 4 <= len; ++i)
        if (memcmp(buf + i, separator, 4) == 0)
        {
            header_end = i + 4;
            break;
        }
    if (header_end == 0)
        return false;

    ssize_t body_len = http_body_length(buf, header_end);
    if (body_len < 0)
        return false;

    *out_total = header_end + (size_t)body_len;
    return len >= *out_total;
}

static int
control_recv(airplay_pairing *p, uint8_t *buf, size_t len)
{
    size_t got = 0;
    if (p->control_prefetch_len > 0)
    {
        size_t n = p->control_prefetch_len < len ? p->control_prefetch_len : len;
        memcpy(buf, p->control_prefetch, n);
        p->control_prefetch_len -= n;
        if (p->control_prefetch_len == 0)
        {
            free(p->control_prefetch);
            p->control_prefetch = NULL;
        }
        else
            memmove(p->control_prefetch, p->control_prefetch + n,
                    p->control_prefetch_len);
        got = n;
    }
    while (got < len)
    {
        long n = recv(p->control_fd, (char *)buf + got, len - got, 0);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

static int
sock_recv_full(airplay_sock_t fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len)
    {
        long n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

static int
frame_encrypt(const uint8_t key[32], uint64_t *counter,
              const uint8_t *in, size_t in_len,
              uint8_t **out, size_t *out_len)
{
    uint8_t aad[2] = {
        (uint8_t)(in_len & 0xff),
        (uint8_t)((in_len >> 8) & 0xff),
    };
    uint8_t nonce[12] = { 0 };
    memcpy(nonce + 4, counter, sizeof(*counter));

    uint8_t *buf = malloc(in_len + 16);
    if (buf == NULL)
        return -1;

    size_t len = 0;
    if (airplay_chacha_encrypt(buf, &len, in, in_len, key, nonce, aad, 2) != 0)
    {
        free(buf);
        return -1;
    }
    (*counter)++;
    *out = buf;
    *out_len = len;
    return 0;
}

static int
frame_decrypt(const uint8_t key[32], uint64_t *counter,
              const uint8_t *in, size_t in_len,
              uint8_t **out, size_t *out_len)
{
    if (in_len < 16)
        return -1;

    size_t plain_len = in_len - 16;
    uint8_t aad[2] = {
        (uint8_t)(plain_len & 0xff),
        (uint8_t)((plain_len >> 8) & 0xff),
    };
    uint8_t nonce[12] = { 0 };
    memcpy(nonce + 4, counter, sizeof(*counter));

    uint8_t *buf = malloc(plain_len > 0 ? plain_len : 1);
    if (buf == NULL)
        return -1;

    size_t len = 0;
    if (airplay_chacha_decrypt(buf, &len, in, in_len, key, nonce, aad, 2) != 0)
    {
        free(buf);
        return -1;
    }
    (*counter)++;
    *out = buf;
    *out_len = len;
    return 0;
}

static int
control_read_frame(airplay_pairing *p, uint8_t **out, size_t *out_len)
{
    uint8_t hdr[2];
    if (control_recv(p, hdr, sizeof hdr) != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj)
        {
#ifdef _WIN32
            msg_Err(p->obj, "AirPlay control: frame header read failed (wsa=%d)",
                    WSAGetLastError());
#else
            msg_Err(p->obj, "AirPlay control: frame header read failed (errno=%d)",
                    errno);
#endif
        }
#endif
        return -1;
    }

    size_t plain_len = hdr[0] | ((size_t)hdr[1] << 8);
    if (plain_len == 0 || plain_len > HAP_CTRL_PACKET_MAX)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay control: invalid frame length %zu",
                            plain_len);
#endif
        return -1;
    }

    uint8_t *wire = malloc(plain_len + 16);
    if (wire == NULL)
        return -1;
    if (control_recv(p, wire, plain_len + 16) != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay control: frame body read failed");
#endif
        free(wire);
        return -1;
    }

    int rc = frame_decrypt(p->control_read_key, &p->read_nonce,
                           wire, plain_len + 16, out, out_len);
    free(wire);
    if (rc != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay control: decrypt failed");
#endif
    }
    return rc;
}

static int
control_write_plain(airplay_pairing *p, const uint8_t *data, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        size_t chunk = len - offset;
        if (chunk > HAP_CTRL_PACKET_MAX)
            chunk = HAP_CTRL_PACKET_MAX;

        uint8_t *enc = NULL;
        size_t enc_len = 0;
        if (frame_encrypt(p->control_write_key, &p->write_nonce,
                          data + offset, chunk, &enc, &enc_len) != 0)
        {
#ifndef AIRPLAY_PAIRING_STANDALONE
            if (p->obj) msg_Err(p->obj, "AirPlay control: encrypt failed");
#endif
            return -1;
        }

        uint8_t hdr[2] = {
            (uint8_t)(chunk & 0xff),
            (uint8_t)((chunk >> 8) & 0xff),
        };
        size_t wire_len = sizeof hdr + enc_len;
        uint8_t *wire = malloc(wire_len);
        int rc = -1;
        if (wire != NULL)
        {
            memcpy(wire, hdr, sizeof hdr);
            memcpy(wire + sizeof hdr, enc, enc_len);
            rc = send(p->control_fd, (const char *)wire, wire_len, 0)
                     == (long)wire_len ? 0 : -1;
            free(wire);
        }
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (rc == 0 && p->obj)
            msg_Dbg(p->obj, "AirPlay control: sent frame plain=%zu wire=%zu",
                    chunk, wire_len);
#endif
        free(enc);
        if (rc != 0)
        {
#ifndef AIRPLAY_PAIRING_STANDALONE
            if (p->obj) msg_Err(p->obj, "AirPlay control: send failed");
#endif
            return -1;
        }
        offset += chunk;
    }
    return 0;
}

static int
control_read_http(airplay_pairing *p, uint8_t **out, size_t *out_len)
{
    size_t cap = 4096, len = 0;
    uint8_t *buf = malloc(cap);
    if (buf == NULL)
        return -1;

    for (;;)
    {
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        if (control_read_frame(p, &chunk, &chunk_len) != 0)
        {
            free(buf);
            free(chunk);
            return -1;
        }

        if (len + chunk_len > cap)
        {
            cap = (len + chunk_len) * 2;
            uint8_t *grown = realloc(buf, cap);
            if (grown == NULL)
            {
                free(buf);
                free(chunk);
                return -1;
            }
            buf = grown;
        }
        memcpy(buf + len, chunk, chunk_len);
        len += chunk_len;
        free(chunk);

        size_t total = 0;
        if (http_response_complete(buf, len, &total))
        {
            uint8_t *trimmed = realloc(buf, total);
            if (trimmed != NULL)
                buf = trimmed;
            *out = buf;
            *out_len = total;
            return 0;
        }
    }
}

static int
default_control_exchange(airplay_pairing *p, const uint8_t *req, size_t req_len,
                         uint8_t **resp, size_t *resp_len)
{
    if (!p->control_connected)
        return -1;
    if (control_write_plain(p, req, req_len) != 0)
        return -1;
    return control_read_http(p, resp, resp_len);
}

#ifndef AIRPLAY_PAIRING_STANDALONE
static void *
event_thread(void *data)
{
    airplay_pairing *p = data;

    for (;;)
    {
        if (p->event_stop)
            break;

        uint8_t hdr[2];
        if (sock_recv_full(p->event_fd, hdr, sizeof hdr) != 0)
            break;

        size_t plain_len = hdr[0] | ((size_t)hdr[1] << 8);
        if (plain_len == 0 || plain_len > HAP_CTRL_PACKET_MAX)
            break;

        uint8_t *wire = malloc(plain_len + 16);
        if (wire == NULL)
            break;
        if (sock_recv_full(p->event_fd, wire, plain_len + 16) != 0)
        {
            free(wire);
            break;
        }

        uint8_t *plain = NULL;
        size_t plain_out = 0;
        int rc = frame_decrypt(p->event_in_key, &p->event_read_nonce,
                               wire, plain_len + 16, &plain, &plain_out);
        free(wire);
        if (rc != 0)
        {
            free(plain);
            break;
        }

        if (p->obj != NULL && plain_out > 0)
        {
            char text[480];
            size_t n = 0;
            size_t i = 0;
            while (i < plain_out && n + 1 < sizeof text)
            {
                unsigned char c = plain[i];
                if (c >= 32 && c < 127)
                {
                    size_t start = i;
                    while (i < plain_out && plain[i] >= 32 && plain[i] < 127)
                        i++;
                    if (i - start >= 4)
                    {
                        for (size_t j = start; j < i && n + 1 < sizeof text; ++j)
                            text[n++] = (char)plain[j];
                        if (n + 1 < sizeof text)
                            text[n++] = ' ';
                    }
                }
                else
                    i++;
            }
            text[n] = '\0';
            if (n > 0)
                msg_Dbg(p->obj, "AirPlay event text: %s", text);
        }

        char cseq[16] = "0";
        for (size_t i = 0; plain != NULL && i + 5 < plain_out; ++i)
        {
            if (memcmp(plain + i, "CSeq:", 5) != 0)
                continue;
            const char *cursor = (const char *)plain + i + 5;
            while (*cursor == ' ')
                cursor++;
            size_t n = 0;
            while (n + 1 < sizeof cseq && cursor[n] >= '0' && cursor[n] <= '9')
            {
                cseq[n] = cursor[n];
                n++;
            }
            cseq[n] = '\0';
            break;
        }
        free(plain);

        char reply[160];
        int reply_len = snprintf(reply, sizeof reply,
                                 "RTSP/1.0 200 OK\r\n"
                                 "CSeq: %s\r\n"
                                 "Audio-Latency: 0\r\n"
                                 "Content-Length: 0\r\n"
                                 "\r\n", cseq);
        if (reply_len < 0 || (size_t)reply_len >= sizeof reply)
            break;

        uint8_t *enc = NULL;
        size_t enc_len = 0;
        if (frame_encrypt(p->event_out_key, &p->event_write_nonce,
                          (const uint8_t *)reply, (size_t)reply_len,
                          &enc, &enc_len) != 0)
            break;

        uint8_t oh[2] = {
            (uint8_t)(reply_len & 0xff),
            (uint8_t)((reply_len >> 8) & 0xff),
        };
        int sent = send(p->event_fd, (const char *)oh, sizeof oh, 0) ==
                        (long)sizeof oh &&
                    send(p->event_fd, (const char *)enc, enc_len, 0) ==
                        (long)enc_len;
        free(enc);
        if (!sent)
            break;
    }
    return NULL;
}
#endif

static void
event_channel_stop(airplay_pairing *p)
{
    if (p == NULL)
        return;
    p->event_stop = true;
#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->event_fd != AIRPLAY_SOCK_INVALID)
    {
#ifdef _WIN32
        shutdown(p->event_fd, SD_BOTH);
#else
        shutdown(p->event_fd, SHUT_RDWR);
#endif
    }
    if (p->event_thread_started)
    {
        vlc_join(p->event_thread, NULL);
        p->event_thread_started = false;
    }
#endif
    if (p->event_fd != AIRPLAY_SOCK_INVALID)
    {
        airplay_sock_close(p->event_fd);
        p->event_fd = AIRPLAY_SOCK_INVALID;
    }
}

int
airplay_pairing_event_listen(airplay_pairing *p, uint16_t port)
{
    if (p == NULL || port == 0 || !p->has_session_keys)
        return -1;

    event_channel_stop(p);
    p->event_stop = false;
    p->event_write_nonce = 0;
    p->event_read_nonce = 0;

    int opened = -1;
    for (int attempt = 0; attempt < 8 && opened != 0; ++attempt)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (attempt > 0)
            vlc_tick_wait(vlc_tick_now() + VLC_TICK_FROM_MS(200));
#else
        if (attempt > 0)
            break;
#endif
        uint16_t saved = p->port;
        p->port = port;
        opened = pairing_open_socket(p, &p->event_fd);
        p->port = saved;
    }
    if (opened != 0)
        return -1;

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (vlc_clone(&p->event_thread, event_thread, p) != 0)
    {
        airplay_sock_close(p->event_fd);
        p->event_fd = AIRPLAY_SOCK_INVALID;
        return -1;
    }
    p->event_thread_started = true;
    if (p->obj != NULL)
        msg_Dbg(p->obj, "AirPlay event channel connected on port %u",
                (unsigned)port);
#endif
    return 0;
}

void
airplay_pairing_control_disconnect(airplay_pairing *p)
{
    if (p == NULL || !p->control_connected)
        return;
    event_channel_stop(p);
    if (p->control_fd != AIRPLAY_SOCK_INVALID)
        airplay_sock_close(p->control_fd);
    p->control_fd = AIRPLAY_SOCK_INVALID;
    free(p->control_prefetch);
    p->control_prefetch = NULL;
    p->control_prefetch_len = 0;
    p->control_connected = false;
    p->has_session_keys = false;
    p->write_nonce = 0;
    p->read_nonce = 0;
    if (p->state == AIRPLAY_PAIR_READY)
        p->state = AIRPLAY_PAIR_PAIRED;
}

int
airplay_pairing_control_connect(airplay_pairing *p)
{
    if (p == NULL ||
        (p->state != AIRPLAY_PAIR_PAIRED && p->state != AIRPLAY_PAIR_READY))
        return -1;
    if (p->control_connected)
        return 0;

    if (p->transport_cb != NULL)
    {
        if (do_verify_ex(p, transport_exchange_wrapper, p) != 0)
        {
            if (p->verify_rejected && p->identity.has_peer)
            {
                identity_remove(p);
                secure_clear(&p->identity, sizeof p->identity);
                p->state = AIRPLAY_PAIR_NEED_PIN;
            }
            return -1;
        }
        p->control_connected = true;
        p->state = AIRPLAY_PAIR_READY;
        return 0;
    }

    if (pairing_open_socket(p, &p->control_fd) != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay control: socket open failed");
#endif
        return -1;
    }

    tlv_fd_ctx ctx = { p, p->control_fd };
    if (do_verify_ex(p, fd_tlv_exchange, &ctx) != 0)
    {
#ifndef AIRPLAY_PAIRING_STANDALONE
        if (p->obj) msg_Err(p->obj, "AirPlay control: pair-verify failed on control channel");
#endif
        airplay_sock_close(p->control_fd);
        p->control_fd = AIRPLAY_SOCK_INVALID;
        if (p->verify_rejected && p->identity.has_peer)
        {
            identity_remove(p);
            secure_clear(&p->identity, sizeof p->identity);
            p->state = AIRPLAY_PAIR_NEED_PIN;
        }
        return -1;
    }

    p->control_connected = true;
    p->state = AIRPLAY_PAIR_READY;
    return 0;
}

int
airplay_pairing_control_exchange(airplay_pairing *p, const uint8_t *req,
                               size_t req_len, uint8_t **resp, size_t *resp_len)
{
    if (p == NULL || req == NULL || resp == NULL || resp_len == NULL)
        return -1;
    if (p->control_exchange_cb != NULL)
        return p->control_exchange_cb(p->control_exchange_opaque, req, req_len,
                                      resp, resp_len);
    return default_control_exchange(p, req, req_len, resp, resp_len);
}
