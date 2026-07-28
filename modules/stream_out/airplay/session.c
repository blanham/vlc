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

#include <gcrypt.h>

#include "pairing.h"
#include "plist.h"

struct airplay_session
{
    vlc_object_t *obj;
    airplay_pairing *pair;
    char *ip;
    uint16_t port;
    char session_id[37];
    uint32_t cseq;
};

static void
generate_session_id(char out[37])
{
    uint8_t rnd[16];
    gcry_randomize(rnd, sizeof rnd, GCRY_STRONG_RANDOM);
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
    return s;
}

void
airplay_session_release(airplay_session *s)
{
    if (s == NULL)
        return;
    airplay_session_teardown(s);
    free(s->ip);
    free(s);
}

static int
ensure_control(airplay_session *s)
{
    if (airplay_pairing_state(s->pair) != AIRPLAY_PAIR_READY)
        return -1;
    return airplay_pairing_control_connect(s->pair);
}

static int
http_status_ok(const uint8_t *resp, size_t resp_len)
{
    if (resp_len < 12)
        return -1;
    return memcmp(resp, "HTTP/1.1 200", 12) == 0 ||
           memcmp(resp, "HTTP/1.0 200", 12) == 0 ? 0 : -1;
}

static int
session_exchange(airplay_session *s, const char *request, size_t request_len)
{
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int rc = airplay_pairing_control_exchange(s->pair,
                                              (const uint8_t *)request,
                                              request_len, &resp, &resp_len);
    if (rc != 0)
    {
        free(resp);
        return -1;
    }
    rc = http_status_ok(resp, resp_len);
    free(resp);
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
        "Content-Length: %zu\r\n"
        "CSeq: %u\r\n"
        "\r\n",
        path, s->ip, (unsigned)s->port, s->session_id, body_len,
        ++s->cseq);
    if (header_len < 0 || (size_t)header_len >= sizeof header)
        return -1;

    size_t total = (size_t)header_len + body_len;
    char *wire = malloc(total);
    if (wire == NULL)
        return -1;
    memcpy(wire, header, (size_t)header_len);
    memcpy(wire + header_len, body, body_len);

    int rc = session_exchange(s, wire, total);
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

    return session_exchange(s, request, (size_t)n);
}

int
airplay_session_play(airplay_session *s, const char *content_location,
                     double start_position)
{
    if (s == NULL || content_location == NULL)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    uint8_t *body = NULL;
    size_t body_len = 0;
    if (airplay_session_build_play_body(content_location, start_position,
                                        &body, &body_len) != 0)
        return -1;

    int rc = session_post_plist(s, "/play", body, body_len);
    free(body);
    return rc;
}

int
airplay_session_rate(airplay_session *s, double rate)
{
    if (s == NULL)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    char path[64];
    snprintf(path, sizeof path, "/rate?value=%.6f", rate);
    return session_post_empty(s, path);
}

int
airplay_session_scrub(airplay_session *s, double position)
{
    if (s == NULL || position < 0.0 || position > 1.0)
        return -1;
    if (ensure_control(s) != 0)
        return -1;

    char path[64];
    snprintf(path, sizeof path, "/scrub?position=%.6f", position);
    return session_post_empty(s, path);
}

int
airplay_session_stop(airplay_session *s)
{
    if (s == NULL)
        return -1;
    if (ensure_control(s) != 0)
        return -1;
    return session_post_empty(s, "/stop");
}

int
airplay_session_teardown(airplay_session *s)
{
    if (s == NULL)
        return -1;
    if (airplay_pairing_state(s->pair) == AIRPLAY_PAIR_READY)
        airplay_session_stop(s);
    airplay_pairing_control_disconnect(s->pair);
    return 0;
}
