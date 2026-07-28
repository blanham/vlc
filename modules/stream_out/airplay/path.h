/*****************************************************************************
 * path.h: local media path helpers for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_PATH_H
#define VLC_AIRPLAY_PATH_H

typedef struct vlc_object_t vlc_object_t;

char *airplay_path_from_uri(const char *uri);
char *airplay_resolve_local_path(vlc_object_t *obj);

#endif
