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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct airplay_plist airplay_plist;

airplay_plist *airplay_plist_new(void);
void airplay_plist_release(airplay_plist *);
int airplay_plist_set_string(airplay_plist *, const char *key, const char *val);
int airplay_plist_set_real(airplay_plist *, const char *key, double val);
int airplay_plist_set_integer(airplay_plist *, const char *key, uint64_t val);
int airplay_plist_set_bool(airplay_plist *, const char *key, bool val);
int airplay_plist_get_integer(const airplay_plist *, const char *key,
                              uint64_t *out);
int airplay_plist_set_data(airplay_plist *, const char *key, const void *data,
                           size_t len);
/* Takes ownership of child, including when this call fails. */
int airplay_plist_set_dict(airplay_plist *, const char *key, airplay_plist *child);
/* One-element array of dicts. Takes ownership of item, including on failure. */
int airplay_plist_set_dict_array(airplay_plist *, const char *key,
                                 airplay_plist *item);
/* First integer anywhere under key, including nested dicts and arrays. */
int airplay_plist_find_integer(const uint8_t *data, size_t len, const char *key,
                               uint64_t *out);
int airplay_plist_get_string(const airplay_plist *, const char *key, char **out);
int airplay_plist_get_data(const airplay_plist *, const char *key, uint8_t **out,
                           size_t *len);
int airplay_plist_serialize(const airplay_plist *, uint8_t **out, size_t *len);
airplay_plist *airplay_plist_parse(const uint8_t *data, size_t len);

#endif
