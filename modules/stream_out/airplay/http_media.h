/*****************************************************************************
 * http_media.h: tokenized HTTP media server for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_HTTP_MEDIA_H
#define VLC_AIRPLAY_HTTP_MEDIA_H

#include <stdbool.h>
#include <stdint.h>

typedef struct vlc_object_t vlc_object_t;
typedef struct airplay_http_media airplay_http_media;

airplay_http_media *airplay_http_media_start(vlc_object_t *obj,
                                             uint16_t http_port,
                                             const char *filepath);
void airplay_http_media_stop(airplay_http_media *);
void airplay_http_media_unpublish(airplay_http_media *);
int airplay_http_media_republish(airplay_http_media *);
void airplay_http_media_set_start(airplay_http_media *, double start_seconds);
char *airplay_http_media_reissue(airplay_http_media *, const char *lan_ip,
                                 double start_seconds);
const char *airplay_http_media_token(const airplay_http_media *);
char *airplay_http_media_url(const airplay_http_media *, const char *lan_ip);

bool airplay_http_token_valid(const char *expected, const char *got);
char *airplay_http_generate_token(void);

#endif
