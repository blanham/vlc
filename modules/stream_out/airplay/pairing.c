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

#ifndef AIRPLAY_PAIRING_STANDALONE
# include <vlc_common.h>
# include <vlc_dialog.h>
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
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <unistd.h>
typedef int airplay_sock_t;
# define AIRPLAY_SOCK_INVALID (-1)
# define airplay_sock_close(s) close(s)
#endif

#define HAP_MIME_TLV8 "application/pairing+tlv8"

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

    char *test_pin;

    airplay_pair_transport_cb transport_cb;
    void *transport_opaque;

    airplay_pair_identity_load_cb identity_load_cb;
    airplay_pair_identity_store_cb identity_store_cb;
    airplay_pair_identity_remove_cb identity_remove_cb;
    void *identity_opaque;

    struct airplay_identity identity;

    bool has_session_keys;
    uint8_t control_write_key[32];
    uint8_t control_read_key[32];
    uint64_t write_nonce;
    uint64_t read_nonce;
};

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
    gcry_randomize(rnd, sizeof rnd, GCRY_STRONG_RANDOM);

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

    if (p->test_pin != NULL)
    {
        secure_clear(p->test_pin, strlen(p->test_pin));
        free(p->test_pin);
    }
    secure_clear(&p->identity, sizeof p->identity);
    secure_clear(p->control_write_key, sizeof p->control_write_key);
    secure_clear(p->control_read_key, sizeof p->control_read_key);

    free(p->ip);
    free(p->device_id);
    free(p->device_name);
    free(p->accessory_pairing_id);
    free(p);
}

enum airplay_pair_state
airplay_pairing_state(const airplay_pairing *p)
{
    return p != NULL ? p->state : AIRPLAY_PAIR_FAILED;
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
    if (p->test_pin != NULL)
        return strdup(p->test_pin);

#ifndef AIRPLAY_PAIRING_STANDALONE
    if (p->obj == NULL)
        return NULL;

    char *user = NULL, *pin = NULL;
    bool store = false;
    int d = vlc_dialog_wait_login(p->obj, &user, &pin, &store, "",
        _("AirPlay Pairing"),
        _("Enter the pairing PIN shown on %s"), p->device_name);
    free(user);
    if (d != 1)
    {
        free(pin);
        return NULL;
    }
    return pin;
#else
    return NULL;
#endif
}

/* -- default TCP/HTTP control transport ------------------------------------ */

static int
default_http_transport(airplay_pairing *p, const char *path,
                       const uint8_t *req, size_t req_len,
                       uint8_t **out_resp, size_t *out_resp_len)
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

    char header[320];
    int header_len = snprintf(header, sizeof header,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lu\r\n"
        "X-Apple-HKP: 3\r\n"
        "Connection: close\r\n\r\n",
        path, p->ip, (unsigned)p->port, HAP_MIME_TLV8,
        (unsigned long)req_len);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
    {
        airplay_sock_close(fd);
        return -1;
    }

    if (send(fd, header, (size_t)header_len, 0) != header_len ||
        (req_len > 0 &&
         send(fd, (const char *)req, req_len, 0) != (long)req_len))
    {
        airplay_sock_close(fd);
        return -1;
    }

    size_t capacity = 4096, length = 0;
    uint8_t *buffer = malloc(capacity);
    if (buffer == NULL)
    {
        airplay_sock_close(fd);
        return -1;
    }

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
                return -1;
            }
            buffer = grown;
        }
        long n = recv(fd, (char *)buffer + length, capacity - length, 0);
        if (n < 0)
        {
            free(buffer);
            airplay_sock_close(fd);
            return -1;
        }
        if (n == 0)
            break;
        length += (size_t)n;
    }
    airplay_sock_close(fd);

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
send_recv_tlv(airplay_pairing *p, const char *path,
              const uint8_t *req, size_t req_len,
              uint8_t **resp, size_t *resp_len)
{
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (transport_send(p, path, req, req_len, &raw, &raw_len) != 0)
        return -1;

    if (hap_tlv_has(raw, raw_len, HAP_TLV_ERROR))
    {
        free(raw);
        return -1;
    }

    *resp = raw;
    *resp_len = raw_len;
    return 0;
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
do_setup(airplay_pairing *p, const char *pin)
{
    int ret = -1;
    airplay_srp_ctx *srp = airplay_srp_client_new(pin);
    if (srp == NULL)
        return -1;

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

    hap_tlv_buf req1;
    hap_tlv_buf_init(&req1);
    static const uint8_t method_pair = 0;
    if (hap_tlv_buf_add(&req1, HAP_TLV_METHOD, &method_pair, 1) != 0 ||
        hap_tlv_buf_add(&req1, HAP_TLV_STATE, (const uint8_t[]){ 1 }, 1) != 0)
    {
        hap_tlv_buf_clear(&req1);
        goto out;
    }
    uint8_t *req1_raw = NULL;
    size_t req1_len = 0;
    if (hap_tlv_buf_finish(&req1, &req1_raw, &req1_len) != 0 ||
        send_recv_tlv(p, "/pair-setup", req1_raw, req1_len, &m2, &m2_len) != 0)
    {
        free(req1_raw);
        goto out;
    }
    free(req1_raw);

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
    if (hap_tlv_buf_finish(&req3, &req3_raw, &req3_len) != 0 ||
        send_recv_tlv(p, "/pair-setup", req3_raw, req3_len, &m4, &m4_len) != 0)
    {
        free(req3_raw);
        goto out;
    }
    free(req3_raw);

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
    static const uint8_t nonce5[12] = "PS-Msg05\0\0\0";
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
    if (hap_tlv_buf_finish(&req5, &req5_raw, &req5_len) != 0 ||
        send_recv_tlv(p, "/pair-setup", req5_raw, req5_len, &m6, &m6_len) != 0)
    {
        free(req5_raw);
        goto out;
    }
    free(req5_raw);

    if (!tlv_state_is(m6, m6_len, 6))
        goto out;

    uint8_t *enc6 = NULL;
    size_t enc6_len = 0;
    if (hap_tlv_get(m6, m6_len, HAP_TLV_ENCRYPTED_DATA, &enc6, &enc6_len) != 0 ||
        enc6_len < 16)
    {
        free(enc6);
        goto out;
    }
    uint8_t *dec6 = malloc(enc6_len - 16 > 0 ? enc6_len - 16 : 1);
    size_t dec6_len = 0;
    static const uint8_t nonce6[12] = "PS-Msg06\0\0\0";
    rc = dec6 == NULL ? -1 :
        airplay_chacha_decrypt(dec6, &dec6_len, enc6, enc6_len, setup_key,
                               nonce6, NULL, 0);
    free(enc6);
    if (rc != 0)
    {
        free(dec6);
        goto out;
    }

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
                    rc = -1;
                else if (p->accessory_pairing_id != NULL &&
                         (peer_id_len != strlen(p->accessory_pairing_id) ||
                          memcmp(peer_id, p->accessory_pairing_id,
                                 peer_id_len) != 0))
                    rc = -1;
                else
                {
                    memcpy(p->identity.peer_ed25519_pk, peer_pk, 32);
                    p->identity.has_peer = 1;
                    rc = 0;
                }
            }
            free(acc_msg);
        }
    }
    free(dec6);
    if (rc != 0)
        goto out;

    ret = 0;

out:
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
}

/* -- pair-verify (M1-M4) --------------------------------------------------- */

static int
do_verify(airplay_pairing *p)
{
    int ret = -1;
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
        send_recv_tlv(p, "/pair-verify", req1_raw, req1_len, &m2, &m2_len) != 0)
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
    static const uint8_t nonce2[12] = "PV-Msg02\0\0\0";
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
        goto out;

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
    static const uint8_t nonce3[12] = "PV-Msg03\0\0\0";
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
        send_recv_tlv(p, "/pair-verify", req3_raw, req3_len, &m4, &m4_len) != 0)
    {
        free(req3_raw);
        goto out;
    }
    free(req3_raw);

    if (!tlv_state_is(m4, m4_len, 4))
        goto out;

    static const char c_salt[] = "Control-Salt";
    static const char c_write[] = "Control-Write-Encryption-Key";
    static const char c_read[] = "Control-Read-Encryption-Key";
    if (airplay_hkdf_sha512(p->control_write_key, sizeof p->control_write_key,
                            shared, sizeof shared, (const uint8_t *)c_salt,
                            sizeof c_salt - 1, (const uint8_t *)c_write,
                            sizeof c_write - 1) != 0 ||
        airplay_hkdf_sha512(p->control_read_key, sizeof p->control_read_key,
                            shared, sizeof shared, (const uint8_t *)c_salt,
                            sizeof c_salt - 1, (const uint8_t *)c_read,
                            sizeof c_read - 1) != 0)
        goto out;
    p->write_nonce = 0;
    p->read_nonce = 0;
    p->has_session_keys = true;

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
    if (p->state == AIRPLAY_PAIR_READY)
        return VLC_SUCCESS;

    struct airplay_identity loaded;
    memset(&loaded, 0, sizeof loaded);
    if (identity_load(p, &loaded) == 0 && loaded.has_peer)
    {
        p->identity = loaded;
        ensure_controller_pairing_id(&p->identity);
        p->state = AIRPLAY_PAIR_VERIFY;
        if (do_verify(p) == 0)
        {
            p->state = AIRPLAY_PAIR_READY;
            return VLC_SUCCESS;
        }
        identity_remove(p);
        secure_clear(&p->identity, sizeof p->identity);
    }

    p->state = AIRPLAY_PAIR_NEED_PIN;
    char *pin = obtain_pin(p);
    if (pin == NULL)
        return VLC_EGENERIC;

    p->state = AIRPLAY_PAIR_SETUP;
    int ret = do_setup(p, pin);
    secure_clear(pin, strlen(pin));
    free(pin);
    if (ret != 0)
    {
        p->state = AIRPLAY_PAIR_FAILED;
        return VLC_EGENERIC;
    }

    identity_store(p, &p->identity);

    p->state = AIRPLAY_PAIR_VERIFY;
    if (do_verify(p) != 0)
    {
        p->state = AIRPLAY_PAIR_FAILED;
        return VLC_EGENERIC;
    }

    p->state = AIRPLAY_PAIR_READY;
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
