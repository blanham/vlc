/*****************************************************************************
 * path.c: local media path helpers for AirPlay
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

#include "path.h"

#include <stdbool.h>
#include <stdlib.h>

#ifdef AIRPLAY_PATH_URI_ONLY
char *vlc_uri2path(const char *);
#else
# include <string.h>
# include <unistd.h>

# include <vlc_common.h>
# include <vlc_input_item.h>
# include <vlc_objects.h>
# include <vlc_player.h>
# include <vlc_url.h>
#endif

static bool
airplay_is_file_uri(const char *uri)
{
    return uri != NULL
        && (uri[0] == 'f' || uri[0] == 'F')
        && (uri[1] == 'i' || uri[1] == 'I')
        && (uri[2] == 'l' || uri[2] == 'L')
        && (uri[3] == 'e' || uri[3] == 'E')
        && uri[4] == ':' && uri[5] == '/' && uri[6] == '/';
}

char *
airplay_path_from_uri(const char *uri)
{
    if (!airplay_is_file_uri(uri))
        return NULL;

    return vlc_uri2path(uri);
}

#ifndef AIRPLAY_PATH_URI_ONLY
char *
airplay_resolve_local_path(vlc_object_t *obj)
{
    if (obj == NULL)
        return NULL;

    /*
     * Renderer stream outputs are parented to the player through
     * input_resource_New(VLC_OBJECT(player)) and sout_NewInstance(p_parent).
     * Check the object type before casting: locking an arbitrary ancestor as
     * a player is not safe.
     */
    for (vlc_object_t *parent = vlc_object_parent(obj); parent != NULL;
         parent = vlc_object_parent(parent))
    {
        if (strcmp(vlc_object_typename(parent), "player") != 0)
            continue;

        vlc_player_t *player = (vlc_player_t *)parent;
        vlc_player_Lock(player);
        input_item_t *item = vlc_player_HoldCurrentMedia(player);
        vlc_player_Unlock(player);
        if (item == NULL)
            continue;

        char *uri = input_item_GetURI(item);
        input_item_Release(item);

        char *path = airplay_path_from_uri(uri);
        free(uri);
        if (path != NULL && access(path, R_OK) == 0)
            return path;

        free(path);
    }

    return NULL;
}
#endif
