/*****************************************************************************
 * plist.h: minimal binary property list helper for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_PLIST_H
#define VLC_AIRPLAY_PLIST_H

#include <stddef.h>
#include <stdint.h>

typedef struct airplay_plist airplay_plist;

airplay_plist *airplay_plist_new(void);
void airplay_plist_release(airplay_plist *);
int airplay_plist_set_string(airplay_plist *, const char *key, const char *val);
int airplay_plist_set_real(airplay_plist *, const char *key, double val);
int airplay_plist_set_data(airplay_plist *, const char *key, const void *data,
                           size_t len);
int airplay_plist_get_string(const airplay_plist *, const char *key, char **out);
int airplay_plist_get_data(const airplay_plist *, const char *key, uint8_t **out,
                           size_t *len);
int airplay_plist_serialize(const airplay_plist *, uint8_t **out, size_t *len);
airplay_plist *airplay_plist_parse(const uint8_t *data, size_t len);

#endif
