/*****************************************************************************
 * session.h: AirPlay receiver control session (play/pause/seek/stop)
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_SESSION_H
#define VLC_AIRPLAY_SESSION_H

#include <stddef.h>
#include <stdint.h>

typedef struct vlc_object_t vlc_object_t;
typedef struct airplay_pairing airplay_pairing;
typedef struct airplay_session airplay_session;

airplay_session *airplay_session_new(vlc_object_t *obj, airplay_pairing *pair,
                                     const char *ip, uint16_t port);
void airplay_session_release(airplay_session *);

int airplay_session_play(airplay_session *, const char *content_location,
                         double start_seconds, double duration_seconds);
int airplay_session_requeue(airplay_session *, const char *content_location,
                            double start_seconds);
int airplay_session_rate(airplay_session *, double rate); /* 0 pause, 1 play */
int airplay_session_scrub(airplay_session *, double seconds);
void airplay_session_arm_start_scrub(airplay_session *, double seconds);
bool airplay_session_take_start_scrub(airplay_session *, double *seconds);
int airplay_session_stop(airplay_session *);
void airplay_session_quiesce(airplay_session *);
int airplay_session_teardown(airplay_session *);

/** Builds the binary plist body for POST /play (also used by unit tests). */
int airplay_session_build_play_body(const char *content_location,
                                    double start_position,
                                    uint8_t **out, size_t *out_len);

#endif
