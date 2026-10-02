/*****************************************************************************
 * session.c: AirPlay receiver control session (play/pause/seek/stop)
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

#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#include <vlc_common.h>
#include <vlc_threads.h>

#include <time.h>

#ifndef _WIN32
# include <sys/socket.h>
# include <netinet/in.h>
# include <unistd.h>
#endif

#include <gcrypt.h>

#include "pairing.h"
#include "plist.h"
#include "crypto.h"

struct airplay_session
{
    vlc_object_t *obj;
    airplay_pairing *pair;
    char *ip;
    uint16_t port;
    char session_id[37];
    char dacp_id[17];
    uint32_t active_remote;
    uint32_t rtsp_id;
    uint32_t cseq;
#ifdef _WIN32
    SOCKET timing_fd;
#else
    int timing_fd;
#endif
    vlc_thread_t timing_thread;
    bool timing_thread_started;
    bool timing_stop;
    vlc_mutex_t exchange_lock;
    vlc_thread_t feedback_thread;
    bool feedback_started;
    bool feedback_stop;
    int url_stream_id;
    char item_uuid[37];
    char rtsp_target[160];
    double start_scrub_seconds;
    vlc_tick_t start_scrub_at;
    bool start_scrub_pending;
};

static int
format_host(char *out, size_t out_len, const char *host);

static void
generate_session_id(char out[37])
{
    uint8_t rnd[16];
    airplay_random_bytes(rnd, sizeof rnd);
    rnd[6] = (rnd[6] & 0x0f) | 0x40;
    rnd[8] = (rnd[8] & 0x3f) | 0x80;
    snprintf(out, 37,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14],
             rnd[15]);
}

int
airplay_session_build_play_body(const char *content_location,
                                double start_position,
                                uint8_t **out, size_t *out_len)
{
    if (content_location == NULL || out == NULL || out_len == NULL)
        return -1;
    if (start_position < 0.0 || start_position > 1.0)
        return -1;

    airplay_plist *pl = airplay_plist_new();
    if (pl == NULL)
        return -1;

    int rc = -1;
    if (airplay_plist_set_string(pl, "Content-Location", content_location) == 0 &&
        airplay_plist_set_real(pl, "Start-Position", start_position) == 0 &&
        airplay_plist_serialize(pl, out, out_len) == 0)
        rc = 0;

    airplay_plist_release(pl);
    return rc;
}

airplay_session *
airplay_session_new(vlc_object_t *obj, airplay_pairing *pair,
                    const char *ip, uint16_t port)
{
    if (pair == NULL || ip == NULL || ip[0] == '\0')
        return NULL;

    airplay_session *s = calloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;

    s->obj = obj;
    s->pair = pair;
    s->port = port;
    s->ip = strdup(ip);
    if (s->ip == NULL)
    {
        free(s);
        return NULL;
    }
    generate_session_id(s->session_id);
    s->url_stream_id = -1;

    uint8_t dacp[8];
    airplay_random_bytes(dacp, sizeof dacp);
    snprintf(s->dacp_id, sizeof s->dacp_id,
             "%02X%02X%02X%02X%02X%02X%02X%02X",
             dacp[0], dacp[1], dacp[2], dacp[3],
             dacp[4], dacp[5], dacp[6], dacp[7]);
    airplay_random_bytes(&s->active_remote, sizeof s->active_remote);
    airplay_random_bytes(&s->rtsp_id, sizeof s->rtsp_id);
#ifdef _WIN32
    s->timing_fd = INVALID_SOCKET;
#else
    s->timing_fd = -1;
#endif
    vlc_mutex_init(&s->exchange_lock);
    return s;
}

static void timing_stop(airplay_session *s);
static void feedback_stop(airplay_session *s);

void
airplay_session_release(airplay_session *s)
{
    if (s == NULL)
        return;
    feedback_stop(s);
    timing_stop(s);
    airplay_session_teardown(s);
    free(s->ip);
    free(s);
}

static int
ensure_control(airplay_session *s)
{
    if (airplay_pairing_state(s->pair) != AIRPLAY_PAIR_PAIRED &&
        airplay_pairing_state(s->pair) != AIRPLAY_PAIR_READY)
    {
        if (s->obj) msg_Err(s->obj, "AirPlay session: pairing not ready (state %d)",
                            (int)airplay_pairing_state(s->pair));
        return -1;
    }
    int rc = airplay_pairing_control_connect(s->pair);
    if (rc != 0 && s->obj)
        msg_Err(s->obj, "AirPlay session: control connect failed");
    return rc;
}

static int
http_status_ok(const uint8_t *resp, size_t resp_len)
{
    if (resp_len < 12)
        return -1;
    return memcmp(resp, "HTTP/1.1 200", 12) == 0 ||
           memcmp(resp, "HTTP/1.0 200", 12) == 0 ||
           memcmp(resp, "RTSP/1.0 200", 12) == 0 ? 0 : -1;
}

static int
session_exchange(airplay_session *s, const char *request, size_t request_len,
                 uint8_t **out_resp, size_t *out_resp_len)
{
    vlc_mutex_lock(&s->exchange_lock);
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int rc = airplay_pairing_control_exchange(s->pair,
                                              (const uint8_t *)request,
                                              request_len, &resp, &resp_len);
    if (rc != 0)
    {
        if (s->obj)
            msg_Err(s->obj, "AirPlay session: exchange failed (rc=%d)", rc);
        free(resp);
        vlc_mutex_unlock(&s->exchange_lock);
        return -1;
    }
    rc = http_status_ok(resp, resp_len);
    if (rc != 0 && s->obj && resp_len > 0)
        msg_Err(s->obj, "AirPlay session: response %.*s",
                (int)(resp_len < 80 ? resp_len : 80), (const char *)resp);
    else if (rc == 0 && s->obj && resp_len > 0)
        msg_Dbg(s->obj, "AirPlay session: response %.*s",
                (int)(resp_len < 48 ? resp_len : 48), (const char *)resp);
    if (out_resp != NULL)
    {
        *out_resp = resp;
        if (out_resp_len != NULL)
            *out_resp_len = resp_len;
    }
    else
        free(resp);
    vlc_mutex_unlock(&s->exchange_lock);
    return rc;
}

static int
session_post_plist(airplay_session *s, const char *path,
                   const uint8_t *body, size_t body_len)
{
    char header[512];
    int header_len = snprintf(header, sizeof header,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: VLC/4.0 AirPlay\r\n"
        "X-Apple-Session-ID: %s\r\n"
        "Content-Type: application/x-apple-binary-plist\r\n"
        "Content-Length: %lu\r\n"
        "CSeq: %u\r\n"
        "\r\n",
        path, s->ip, (unsigned)s->port, s->session_id,
        (unsigned long)body_len, ++s->cseq);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
        return -1;

    size_t total = (size_t)header_len + body_len;
    char *wire = malloc(total);
    if (wire == NULL)
        return -1;
    memcpy(wire, header, (size_t)header_len);
    memcpy(wire + header_len, body, body_len);

    int rc = session_exchange(s, wire, total, NULL, NULL);
    free(wire);
    return rc;
}

static int
session_post_empty(airplay_session *s, const char *path_query)
{
    char request[512];
    int n = snprintf(request, sizeof request,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: VLC/4.0 AirPlay\r\n"
        "X-Apple-Session-ID: %s\r\n"
        "Content-Length: 0\r\n"
        "CSeq: %u\r\n"
        "\r\n",
        path_query, s->ip, (unsigned)s->port, s->session_id, ++s->cseq);
    if (n < 0 || (size_t)n >= sizeof request)
        return -1;

    return session_exchange(s, request, (size_t)n, NULL, NULL);
}

static void
ntp_now(uint8_t out[8])
{
    uint64_t unix_us;
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    unix_us = ticks / 10 - 11644473600ULL * 1000000ULL;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unix_us = (uint64_t)ts.tv_sec * 1000000ULL
            + (uint64_t)ts.tv_nsec / 1000ULL;
#endif
    uint32_t seconds = (uint32_t)(unix_us / 1000000ULL + 2208988800ULL);
    uint32_t frac = (uint32_t)(((unix_us % 1000000ULL) << 32) / 1000000ULL);
    out[0] = (uint8_t)(seconds >> 24);
    out[1] = (uint8_t)(seconds >> 16);
    out[2] = (uint8_t)(seconds >> 8);
    out[3] = (uint8_t)seconds;
    out[4] = (uint8_t)(frac >> 24);
    out[5] = (uint8_t)(frac >> 16);
    out[6] = (uint8_t)(frac >> 8);
    out[7] = (uint8_t)frac;
}

static void *
timing_thread(void *data)
{
    airplay_session *s = data;

    for (;;)
    {
        uint8_t packet[64];
        struct sockaddr_storage from;
#ifdef _WIN32
        int from_len = sizeof from;
        int n = recvfrom(s->timing_fd, (char *)packet, sizeof packet, 0,
                         (struct sockaddr *)&from, &from_len);
#else
        socklen_t from_len = sizeof from;
        ssize_t n = recvfrom(s->timing_fd, packet, sizeof packet, 0,
                             (struct sockaddr *)&from, &from_len);
#endif
        if (n < 0 || s->timing_stop)
            break;
        /* 8-byte RTP header (no SSRC), payload type 82, then three NTP
         * timestamps. A 32-byte query used to be dropped as "too short". */
        if (n < 32 || packet[0] != 0x80 || (packet[1] & 0x7f) != 82)
        {
            msg_Dbg(s->obj, "AirPlay timing: ignored %d bytes (type 0x%02x)",
                    (int)n, n > 1 ? packet[1] : 0);
            continue;
        }

        uint8_t reply[32];
        memcpy(reply, packet, 8);
        reply[1] = (uint8_t)(0x80 | 83);
        memcpy(reply + 8, packet + 24, 8); /* origin = query transmit time */
        ntp_now(reply + 16);
        ntp_now(reply + 24);
#ifdef _WIN32
        int sent = sendto(s->timing_fd, (const char *)reply, sizeof reply, 0,
                          (struct sockaddr *)&from, from_len);
#else
        ssize_t sent = sendto(s->timing_fd, reply, sizeof reply, 0,
                              (struct sockaddr *)&from, from_len);
#endif
        if (sent != (int)sizeof reply)
            msg_Warn(s->obj, "AirPlay timing: reply send failed");
        else
            msg_Info(s->obj, "AirPlay timing: replied to query (%d bytes)",
                     (int)n);
    }
    return NULL;
}

static void
timing_stop(airplay_session *s)
{
    if (s == NULL)
        return;
    s->timing_stop = true;
#ifdef _WIN32
    if (s->timing_fd != INVALID_SOCKET)
    {
        shutdown(s->timing_fd, SD_BOTH);
        if (s->timing_thread_started)
        {
            vlc_join(s->timing_thread, NULL);
            s->timing_thread_started = false;
        }
        closesocket(s->timing_fd);
        s->timing_fd = INVALID_SOCKET;
    }
#else
    if (s->timing_fd != -1)
    {
        shutdown(s->timing_fd, SHUT_RDWR);
        if (s->timing_thread_started)
        {
            vlc_join(s->timing_thread, NULL);
            s->timing_thread_started = false;
        }
        close(s->timing_fd);
        s->timing_fd = -1;
    }
#endif
}

static int
timing_start(airplay_session *s, uint16_t *port)
{
    timing_stop(s);
#ifdef _WIN32
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCKET)
        return -1;
#else
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
    {
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }

    struct sockaddr_in bound;
#ifdef _WIN32
    int bound_len = sizeof bound;
#else
    socklen_t bound_len = sizeof bound;
#endif
    if (getsockname(fd, (struct sockaddr *)&bound, &bound_len) != 0)
    {
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }

    s->timing_stop = false;
    s->timing_fd = fd;
    if (vlc_clone(&s->timing_thread, timing_thread, s) != 0)
    {
        timing_stop(s);
        return -1;
    }
    s->timing_thread_started = true;
    *port = ntohs(bound.sin_port);
    return 0;
}

/* IPv6 literals need brackets in URLs and Host headers. */
static int
format_host(char *out, size_t out_len, const char *host)
{
    int n;
    if (host != NULL && strchr(host, ':') != NULL)
        n = snprintf(out, out_len, "[%s]", host);
    else
        n = snprintf(out, out_len, "%s", host != NULL ? host : "");
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}

static int
host_from_http_url(const char *url, char *host, size_t host_len)
{
    const char *start = strstr(url, "://");
    if (start == NULL)
        return -1;
    start += 3;
    if (*start == '[')
    {
        const char *end = strchr(start, ']');
        if (end == NULL || (size_t)(end - start - 1) >= host_len)
            return -1;
        memcpy(host, start + 1, (size_t)(end - start - 1));
        host[end - start - 1] = '\0';
        return 0;
    }

    const char *end = start;
    while (*end != '\0' && *end != ':' && *end != '/')
        end++;
    if (end == start || (size_t)(end - start) >= host_len)
        return -1;
    memcpy(host, start, (size_t)(end - start));
    host[end - start] = '\0';
    return 0;
}

static int
session_command(airplay_session *s, const char *method, const char *target,
                const char *protocol, const uint8_t *body, size_t body_len,
                const char *extra_headers, const char *content_type,
                uint8_t **out_resp, size_t *out_len)
{
    char host_lit[128];
    if (format_host(host_lit, sizeof host_lit, s->ip) < 0)
        return -1;

    char header[1280];
    int header_len = snprintf(header, sizeof header,
        "%s %s %s\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: AirPlay/550.10\r\n"
        "CSeq: %u\r\n"
        "DACP-ID: %s\r\n"
        "Active-Remote: %u\r\n"
        "Client-Instance: %s\r\n"
        "X-Apple-ProtocolVersion: 1\r\n"
        "X-Apple-Stream-ID: 1\r\n"
        "X-Apple-Session-ID: %s\r\n"
        "%s"
        "%s%s%s"
        "Content-Length: %lu\r\n"
        "\r\n",
        method, target, protocol, host_lit, (unsigned)s->port, ++s->cseq, s->dacp_id,
        s->active_remote, s->dacp_id, s->session_id,
        extra_headers != NULL ? extra_headers : "",
        content_type != NULL ? "Content-Type: " : "",
        content_type != NULL ? content_type : "",
        content_type != NULL ? "\r\n" : "",
        (unsigned long)body_len);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
        return -1;

    size_t total = (size_t)header_len + body_len;
    char *wire = malloc(total);
    if (wire == NULL)
        return -1;
    memcpy(wire, header, (size_t)header_len);
    if (body_len > 0)
        memcpy(wire + header_len, body, body_len);

    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: %s %s %s (%lu bytes)",
                method, target, protocol, (unsigned long)body_len);
    int rc = session_exchange(s, wire, total, out_resp, out_len);
    free(wire);
    return rc;
}

static void *
feedback_thread(void *data)
{
    airplay_session *s = data;
    int loops = 0;

    for (;;)
    {
        vlc_mutex_lock(&s->exchange_lock);
        bool stop = s->feedback_stop;
        vlc_mutex_unlock(&s->exchange_lock);
        if (stop)
            break;

        if (session_command(s, "POST", "/feedback", "RTSP/1.0",
                            NULL, 0, NULL, NULL, NULL, NULL) != 0)
        {
            if (s->obj)
                msg_Warn(s->obj, "AirPlay session: receiver closed the control channel");
            break;
        }

        if (loops == 2)
        {
            uint8_t *resp = NULL;
            size_t resp_len = 0;
            if (session_command(s, "GET", "/playback-info", "RTSP/1.0",
                                NULL, 0, NULL, NULL, &resp, &resp_len) == 0 &&
                s->obj && resp != NULL)
                msg_Dbg(s->obj, "AirPlay playback-info: %.*s",
                        (int)(resp_len < 400 ? resp_len : 400), (const char *)resp);
            free(resp);
        }
        loops++;

        for (int i = 0; i < 10; ++i)
        {
            vlc_mutex_lock(&s->exchange_lock);
            stop = s->feedback_stop;
            vlc_mutex_unlock(&s->exchange_lock);
            if (stop)
                return NULL;
            vlc_tick_sleep(VLC_TICK_FROM_MS(200));
        }
    }
    return NULL;
}

static int
feedback_start(airplay_session *s)
{
    if (s->feedback_started)
        feedback_stop(s);
    s->feedback_stop = false;
    if (vlc_clone(&s->feedback_thread, feedback_thread, s) != 0)
        return -1;
    s->feedback_started = true;
    return 0;
}

static void
feedback_stop(airplay_session *s)
{
    if (s == NULL || !s->feedback_started)
        return;
    vlc_mutex_lock(&s->exchange_lock);
    s->feedback_stop = true;
    vlc_mutex_unlock(&s->exchange_lock);
    vlc_join(s->feedback_thread, NULL);
    s->feedback_started = false;
}

static int
response_body(const uint8_t *msg, size_t len, const uint8_t **body, size_t *body_len)
{
    for (size_t i = 0; i + 4 <= len; ++i)
    {
        if (memcmp(msg + i, "\r\n\r\n", 4) != 0)
            continue;
        *body = msg + i + 4;
        *body_len = len - (i + 4);
        return 0;
    }
    return -1;
}

static int
wrap_params_data(airplay_plist *command, uint8_t **out, size_t *out_len)
{
    uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (airplay_plist_serialize(command, &inner, &inner_len) != 0)
        return -1;

    airplay_plist *nested = airplay_plist_new();
    airplay_plist *outer = airplay_plist_new();
    int rc = -1;
    if (nested != NULL && outer != NULL &&
        airplay_plist_set_data(nested, "data", inner, inner_len) == 0)
    {
        if (airplay_plist_set_dict(outer, "params", nested) == 0)
        {
            nested = NULL;
            rc = airplay_plist_serialize(outer, out, out_len);
        }
        else
            nested = NULL;
    }
    free(inner);
    airplay_plist_release(nested);
    airplay_plist_release(outer);
    return rc;
}

static int
session_send_command(airplay_session *s, const char *label, airplay_plist *command)
{
    uint8_t *body = NULL;
    size_t body_len = 0;
    int rc = wrap_params_data(command, &body, &body_len);
    airplay_plist_release(command);
    if (rc != 0)
    {
        free(body);
        return -1;
    }

    char host_lit[128];
    if (format_host(host_lit, sizeof host_lit, s->ip) < 0)
    {
        free(body);
        return -1;
    }

    char header[1024];
    int header_len = snprintf(header, sizeof header,
        "POST /command HTTP/1.1\r\n"
        "Content-Length: %lu\r\n"
        "CSeq: %u\r\n"
        "DACP-ID: %s\r\n"
        "Active-Remote: %u\r\n"
        "Client-Instance: %s\r\n"
        "User-Agent: AirPlay/870.14.1\r\n"
        "X-Apple-ProtocolVersion: 1\r\n"
        "X-Apple-Session-ID: %s\r\n"
        "X-Apple-StreamID: %d\r\n"
        "Content-Type: application/x-apple-binary-plist\r\n"
        "Host: %s:%u\r\n"
        "\r\n",
        (unsigned long)body_len, ++s->cseq, s->dacp_id, s->active_remote,
        s->dacp_id, s->session_id, s->url_stream_id, host_lit,
        (unsigned)s->port);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
    {
        free(body);
        return -1;
    }

    size_t total = (size_t)header_len + body_len;
    char *wire = malloc(total);
    if (wire == NULL)
    {
        free(body);
        return -1;
    }
    memcpy(wire, header, (size_t)header_len);
    memcpy(wire + header_len, body, body_len);
    free(body);
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: command %s", label);
    rc = session_exchange(s, wire, total, NULL, NULL);
    free(wire);
    return rc;
}

static int
send_scrub_command(airplay_session *s, double seconds)
{
    char path[96];
    snprintf(path, sizeof path, "/scrub?position=%.6f", seconds);

    char host_lit[128];
    if (format_host(host_lit, sizeof host_lit, s->ip) < 0)
        return -1;

    char header[1024];
    int header_len = snprintf(header, sizeof header,
        "POST %s HTTP/1.1\r\n"
        "Content-Length: 0\r\n"
        "CSeq: %u\r\n"
        "DACP-ID: %s\r\n"
        "Active-Remote: %u\r\n"
        "Client-Instance: %s\r\n"
        "User-Agent: AirPlay/870.14.1\r\n"
        "X-Apple-ProtocolVersion: 1\r\n"
        "X-Apple-Session-ID: %s\r\n"
        "X-Apple-StreamID: %d\r\n"
        "Host: %s:%u\r\n"
        "\r\n",
        path, ++s->cseq, s->dacp_id, s->active_remote,
        s->dacp_id, s->session_id, s->url_stream_id, host_lit,
        (unsigned)s->port);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
        return -1;

    char *wire = malloc((size_t)header_len);
    if (wire == NULL)
        return -1;
    memcpy(wire, header, (size_t)header_len);
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: scrub %.3f s", seconds);
    int rc = session_exchange(s, wire, (size_t)header_len, NULL, NULL);
    free(wire);
    return rc;
}

static int
set_cmtime(airplay_plist *parent, const char *key, double seconds)
{
    airplay_plist *time = airplay_plist_new();
    uint64_t value = 0;
    if (seconds > 0.0)
        value = (uint64_t)(seconds * 1000.0 + 0.5);
    if (time == NULL ||
        airplay_plist_set_integer(time, "epoch", 0) != 0 ||
        airplay_plist_set_integer(time, "flags", 1) != 0 ||
        airplay_plist_set_integer(time, "timescale", 1000) != 0 ||
        airplay_plist_set_integer(time, "value", value) != 0)
    {
        airplay_plist_release(time);
        return -1;
    }
    return airplay_plist_set_dict(parent, key, time);
}

static int
send_position_command(airplay_session *s, double seconds)
{
    airplay_plist *command = airplay_plist_new();
    airplay_plist *ref = airplay_plist_new();
    if (command == NULL || ref == NULL ||
        airplay_plist_set_string(command, "type", "scrub") != 0 ||
        set_cmtime(command, "position", seconds) != 0 ||
        airplay_plist_set_string(ref, "uuid", s->item_uuid) != 0)
    {
        airplay_plist_release(command);
        airplay_plist_release(ref);
        return -1;
    }
    if (airplay_plist_set_dict(command, "item", ref) != 0)
    {
        airplay_plist_release(command);
        return -1;
    }
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: command scrub %.3f s", seconds);
    return session_send_command(s, "scrub", command);
}

static int
send_rate_command(airplay_session *s, double rate)
{
    airplay_plist *command = airplay_plist_new();
    if (command == NULL ||
        airplay_plist_set_string(command, "type", "setRate") != 0 ||
        airplay_plist_set_real(command, "rate", rate) != 0)
    {
        airplay_plist_release(command);
        return -1;
    }
    return session_send_command(s, "setRate", command);
}

static int
setup_url_stream(airplay_session *s, const char *target)
{
    char client_uuid[37];
    generate_session_id(client_uuid);

    airplay_plist *stream = airplay_plist_new();
    if (stream == NULL ||
        airplay_plist_set_string(stream, "clientUUID", client_uuid) != 0 ||
        airplay_plist_set_string(stream, "clientTypeUUID",
                                 "A6B27562-B43A-4F2D-B75F-82391E250194") != 0 ||
        airplay_plist_set_string(stream, "channelID",
                                 "02:00:00:00:00:01-RCS-1") != 0 ||
        airplay_plist_set_integer(stream, "controlType", 1) != 0 ||
        airplay_plist_set_integer(stream, "type", 130) != 0)
    {
        airplay_plist_release(stream);
        return -1;
    }

    airplay_plist *body = airplay_plist_new();
    if (body == NULL)
    {
        airplay_plist_release(stream);
        return -1;
    }
    if (airplay_plist_set_dict_array(body, "streams", stream) != 0)
    {
        airplay_plist_release(body);
        return -1;
    }

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = airplay_plist_serialize(body, &raw, &raw_len);
    airplay_plist_release(body);
    if (rc != 0)
        return -1;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    rc = session_command(s, "SETUP", target, "RTSP/1.0", raw, raw_len, NULL,
                         "application/x-apple-binary-plist", &resp, &resp_len);
    free(raw);
    if (rc != 0)
    {
        free(resp);
        if (s->obj) msg_Err(s->obj, "AirPlay session: URL stream SETUP failed");
        return -1;
    }

    const uint8_t *plist_bytes = NULL;
    size_t plist_len = 0;
    uint64_t stream_id = 0;
    int found = -1;
    if (response_body(resp, resp_len, &plist_bytes, &plist_len) == 0)
        found = airplay_plist_find_integer(plist_bytes, plist_len, "streamID",
                                           &stream_id);
    free(resp);
    if (found != 0 || stream_id > 1000000)
    {
        if (s->obj) msg_Err(s->obj, "AirPlay session: URL stream has no streamID");
        return -1;
    }
    s->url_stream_id = (int)stream_id;
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: URL stream id %d", s->url_stream_id);
    return 0;
}

static int
remove_play_queue_item(airplay_session *s, const char *uuid)
{
    airplay_plist *ref = airplay_plist_new();
    if (ref == NULL ||
        airplay_plist_set_string(ref, "uuid", uuid) != 0)
    {
        airplay_plist_release(ref);
        return -1;
    }
    airplay_plist *remove = airplay_plist_new();
    if (remove == NULL ||
        airplay_plist_set_string(remove, "type", "removePlayQueueItem") != 0)
    {
        airplay_plist_release(ref);
        airplay_plist_release(remove);
        return -1;
    }
    if (airplay_plist_set_dict(remove, "item", ref) != 0)
    {
        airplay_plist_release(remove);
        return -1;
    }
    return session_send_command(s, "removePlayQueueItem", remove);
}

static int
queue_media(airplay_session *s, const char *content_location,
            double start_seconds, double duration_seconds)
{
    char previous[37];
    memcpy(previous, s->item_uuid, sizeof previous);
    generate_session_id(s->item_uuid);

    double start_fraction = 0.0;
    if (duration_seconds > 1.0 && start_seconds > 0.0 &&
        start_seconds < duration_seconds)
        start_fraction = start_seconds / duration_seconds;

    /* POST /play returns 200 on this Apple TV and never fetches the file.
     * insertPlayQueueItem is the request that actually starts download. */
    airplay_plist *item = airplay_plist_new();
    if (item == NULL ||
        airplay_plist_set_string(item, "uuid", s->item_uuid) != 0 ||
        airplay_plist_set_string(item, "mediaType", "file") != 0 ||
        airplay_plist_set_string(item, "Content-Location", content_location) != 0 ||
        airplay_plist_set_real(item, "Start-Position", start_fraction) != 0 ||
        airplay_plist_set_real(item, "Start-Position-Seconds", start_seconds) != 0)
    {
        airplay_plist_release(item);
        return -1;
    }
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: queue start %.3f s (fraction %.4f)",
                start_seconds, start_fraction);

    airplay_plist *insert = airplay_plist_new();
    if (insert == NULL ||
        airplay_plist_set_string(insert, "type", "insertPlayQueueItem") != 0)
    {
        airplay_plist_release(item);
        airplay_plist_release(insert);
        return -1;
    }
    if (airplay_plist_set_dict(insert, "item", item) != 0)
    {
        airplay_plist_release(insert);
        return -1;
    }
    /* A second insert is queued behind the item already on screen. Drop that
     * item first so the new file becomes the one that plays. */
    if (previous[0] != '\0' && remove_play_queue_item(s, previous) != 0 && s->obj)
        msg_Warn(s->obj, "AirPlay session: could not remove the current item");
    if (session_send_command(s, "insertPlayQueueItem", insert) != 0)
        return -1;

    airplay_plist *ref = airplay_plist_new();
    if (ref == NULL ||
        airplay_plist_set_string(ref, "uuid", s->item_uuid) != 0)
    {
        airplay_plist_release(ref);
        return -1;
    }
    airplay_plist *interested = airplay_plist_new();
    if (interested == NULL ||
        airplay_plist_set_string(interested, "type", "setProperty") != 0 ||
        airplay_plist_set_bool(interested, "value", true) != 0 ||
        airplay_plist_set_string(interested, "property",
                                 "isInterestedInDateRange") != 0)
    {
        airplay_plist_release(ref);
        airplay_plist_release(interested);
        return -1;
    }
    if (airplay_plist_set_dict(interested, "item", ref) != 0)
    {
        airplay_plist_release(interested);
        return -1;
    }
    if (session_send_command(s, "isInterestedInDateRange", interested) != 0)
        return -1;

    airplay_plist *action = airplay_plist_new();
    if (action == NULL ||
        airplay_plist_set_string(action, "type", "setProperty") != 0 ||
        airplay_plist_set_integer(action, "value", 1) != 0 ||
        airplay_plist_set_string(action, "property", "actionAtItemEnd") != 0)
    {
        airplay_plist_release(action);
        return -1;
    }
    if (session_send_command(s, "actionAtItemEnd", action) != 0)
        return -1;
    if (send_rate_command(s, 1.0) != 0)
        return -1;
    return 0;
}

int
airplay_session_requeue(airplay_session *s, const char *content_location,
                        double start_seconds)
{
    if (s == NULL || content_location == NULL)
        return -1;
    if (ensure_control(s) != 0)
        return -1;
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: reload at %.3f s from %s",
                start_seconds, content_location);
    return queue_media(s, content_location, start_seconds, 0.0);
}

void
airplay_session_quiesce(airplay_session *s)
{
    if (s == NULL)
        return;
    feedback_stop(s);
    timing_stop(s);
}

int
airplay_session_play(airplay_session *s, const char *content_location,
                     double start_seconds, double duration_seconds)
{
    if (s == NULL || content_location == NULL)
        return -1;
    if (start_seconds < 0.0 || start_seconds > 48.0 * 3600.0)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    airplay_session_quiesce(s);

    char local_ip[64];
    if (host_from_http_url(content_location, local_ip, sizeof local_ip) != 0)
    {
        if (s->obj) msg_Err(s->obj, "AirPlay session: bad media URL");
        return -1;
    }

    uint16_t timing_port = 0;
    if (timing_start(s, &timing_port) != 0)
    {
        if (s->obj) msg_Err(s->obj, "AirPlay session: timing socket failed");
        return -1;
    }

    char session_uuid[37];
    char correlation_uuid[37];
    snprintf(session_uuid, sizeof session_uuid, "%s", s->session_id);
    for (char *c = session_uuid; *c != '\0'; ++c)
        if (*c >= 'a' && *c <= 'z')
            *c = (char)(*c - 'a' + 'A');
    generate_session_id(correlation_uuid);

    airplay_plist *setup = airplay_plist_new();
    if (setup == NULL)
        return -1;
    int setup_rc = -1;
    if (        airplay_plist_set_string(setup, "deviceID", "02:00:00:00:00:01") == 0 &&
        airplay_plist_set_string(setup, "sessionUUID", session_uuid) == 0 &&
        airplay_plist_set_string(setup, "sessionCorrelationUUID", correlation_uuid) == 0 &&
        airplay_plist_set_integer(setup, "timingPort", timing_port) == 0 &&
        airplay_plist_set_string(setup, "timingProtocol", "NTP") == 0 &&
        airplay_plist_set_bool(setup, "isMultiSelectAirPlay", true) == 0 &&
        airplay_plist_set_bool(setup, "groupContainsGroupLeader", false) == 0 &&
        airplay_plist_set_string(setup, "macAddress", "02:00:00:00:00:01") == 0 &&
        airplay_plist_set_string(setup, "model", "iPhone14,3") == 0 &&
        airplay_plist_set_string(setup, "name", "VLC") == 0 &&
        airplay_plist_set_string(setup, "osName", "iPhone OS") == 0 &&
        airplay_plist_set_string(setup, "osVersion", "16.5") == 0 &&
        airplay_plist_set_string(setup, "osBuildVersion", "20F66") == 0 &&
        airplay_plist_set_string(setup, "sourceVersion", "690.7.1") == 0 &&
        airplay_plist_set_bool(setup, "senderSupportsRelay", false) == 0 &&
        airplay_plist_set_bool(setup, "statsCollectionEnabled", false) == 0)
        setup_rc = 0;

    uint8_t *setup_body = NULL;
    size_t setup_len = 0;
    if (setup_rc == 0)
        setup_rc = airplay_plist_serialize(setup, &setup_body, &setup_len);
    airplay_plist_release(setup);
    if (setup_rc != 0)
    {
        free(setup_body);
        if (s->obj) msg_Err(s->obj, "AirPlay session: SETUP body failed");
        return -1;
    }

    char local_lit[128];
    if (format_host(local_lit, sizeof local_lit, local_ip) < 0)
        return -1;
    char target[160];
    snprintf(target, sizeof target, "rtsp://%s/%u", local_lit, s->rtsp_id);
    memcpy(s->rtsp_target, target, sizeof s->rtsp_target);
    uint8_t *setup_resp = NULL;
    size_t setup_resp_len = 0;
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: SETUP %s timing=%u",
                target, (unsigned)timing_port);
    int rc = session_command(s, "SETUP", target, "RTSP/1.0",
                             setup_body, setup_len, NULL,
                             "application/x-apple-binary-plist",
                             &setup_resp, &setup_resp_len);
    free(setup_body);
    if (rc != 0)
    {
        free(setup_resp);
        if (s->obj) msg_Err(s->obj, "AirPlay session: SETUP failed");
        return -1;
    }

    const uint8_t *plist_bytes = NULL;
    size_t plist_len = 0;
    if (response_body(setup_resp, setup_resp_len, &plist_bytes, &plist_len) == 0 &&
        plist_len > 0)
    {
        airplay_plist *reply = airplay_plist_parse(plist_bytes, plist_len);
        uint64_t event_port = 0;
        int got = reply != NULL
            ? airplay_plist_get_integer(reply, "eventPort", &event_port) : -1;
        if (got != 0)
            got = airplay_plist_find_integer(plist_bytes, plist_len, "eventPort",
                                             &event_port);
        if (got == 0 && event_port > 0 && event_port < 65536)
        {
            if (airplay_pairing_event_listen(s->pair, (uint16_t)event_port) != 0 &&
                s->obj)
                msg_Warn(s->obj, "AirPlay session: event channel on %u failed",
                         (unsigned)event_port);
        }
        airplay_plist_release(reply);
    }
    free(setup_resp);

    if (feedback_start(s) != 0 && s->obj)
        msg_Warn(s->obj, "AirPlay session: feedback thread failed");

    session_command(s, "GET", "/info", "RTSP/1.0", NULL, 0, NULL, NULL,
                    NULL, NULL);

    if (session_command(s, "RECORD", target, "RTSP/1.0", NULL, 0, NULL, NULL,
                        NULL, NULL) != 0)
    {
        if (s->obj) msg_Err(s->obj, "AirPlay session: RECORD failed");
        return -1;
    }

    if (setup_url_stream(s, target) != 0)
        return -1;
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: queue %s at %.3f s",
                content_location, start_seconds);
    if (queue_media(s, content_location, start_seconds, duration_seconds) != 0)
    {
        if (s->obj) msg_Err(s->obj, "AirPlay session: play queue failed");
        return -1;
    }
    return 0;
}

int
airplay_session_rate(airplay_session *s, double rate)
{
    if (s == NULL)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    if (s->url_stream_id >= 0)
        return send_rate_command(s, rate);

    char path[64];
    snprintf(path, sizeof path, "/rate?value=%.6f", rate);
    return session_post_empty(s, path);
}

int
airplay_session_scrub(airplay_session *s, double seconds)
{
    if (s == NULL || seconds < 0.0 || seconds > 48.0 * 3600.0)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    s->start_scrub_pending = false;
    char path[96];
    snprintf(path, sizeof path, "/scrub?position=%.6f", seconds);
    if (s->obj)
        msg_Dbg(s->obj, "AirPlay session: POST %s", path);
    return session_command(s, "POST", path, "HTTP/1.1", NULL, 0, NULL, NULL,
                           NULL, NULL);
}

void
airplay_session_arm_start_scrub(airplay_session *s, double seconds)
{
    if (s == NULL || seconds <= 0.05)
        return;
    s->start_scrub_seconds = seconds;
    s->start_scrub_at = vlc_tick_now() + VLC_TICK_FROM_SEC(3);
    s->start_scrub_pending = true;
}

bool
airplay_session_take_start_scrub(airplay_session *s, double *seconds)
{
    if (s == NULL || seconds == NULL || !s->start_scrub_pending)
        return false;
    if (vlc_tick_now() < s->start_scrub_at)
        return false;
    s->start_scrub_pending = false;
    *seconds = s->start_scrub_seconds;
    return true;
}

int
airplay_session_stop(airplay_session *s)
{
    if (s == NULL)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    /* This Apple TV ignores an empty POST /stop. Removing the item that is
     * actually playing, then tearing down the RTSP session, is what ends it. */
    if (s->item_uuid[0] != '\0')
    {
        char uuid[37];
        memcpy(uuid, s->item_uuid, sizeof uuid);
        s->item_uuid[0] = '\0';
        if (remove_play_queue_item(s, uuid) != 0 && s->obj)
            msg_Warn(s->obj, "AirPlay session: could not remove the playing item");
    }

    if (s->rtsp_target[0] != '\0')
    {
        char target[160];
        memcpy(target, s->rtsp_target, sizeof target);
        s->rtsp_target[0] = '\0';
        if (s->obj)
            msg_Dbg(s->obj, "AirPlay session: TEARDOWN %s", target);
        if (session_command(s, "TEARDOWN", target, "RTSP/1.0",
                            NULL, 0, NULL, NULL, NULL, NULL) != 0 && s->obj)
            msg_Warn(s->obj, "AirPlay session: TEARDOWN failed");
    }
    return 0;
}

int
airplay_session_teardown(airplay_session *s)
{
    if (s == NULL)
        return -1;
    if (airplay_pairing_state(s->pair) == AIRPLAY_PAIR_PAIRED ||
        airplay_pairing_state(s->pair) == AIRPLAY_PAIR_READY)
        airplay_session_stop(s);
    airplay_pairing_control_disconnect(s->pair);
    return 0;
}
