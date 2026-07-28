/*****************************************************************************
 * keystore_id.h: AirPlay pairing identity keystore helper
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_KEYSTORE_ID_H
#define VLC_AIRPLAY_KEYSTORE_ID_H

#include <stddef.h>
#include <stdint.h>

typedef struct vlc_object_t vlc_object_t;

#define AIRPLAY_ID_BLOB_VERSION 2

/** HAP controller pairing id (UUID string, NUL-terminated). */
#define AIRPLAY_CONTROLLER_PAIRING_ID_LEN 37

struct airplay_identity
{
    uint8_t our_ed25519_sk[64];
    uint8_t our_ed25519_pk[32];
    uint8_t peer_ed25519_pk[32];
    uint8_t has_peer;
    char controller_pairing_id[AIRPLAY_CONTROLLER_PAIRING_ID_LEN];
};

int airplay_identity_pack(const struct airplay_identity *, uint8_t **out,
                          size_t *len);
int airplay_identity_unpack(const uint8_t *in, size_t len,
                            struct airplay_identity *out);

int airplay_identity_store(vlc_object_t *obj, const char *device_id,
                           const char *label,
                           const struct airplay_identity *id);
int airplay_identity_load(vlc_object_t *obj, const char *device_id,
                          struct airplay_identity *out);
int airplay_identity_remove(vlc_object_t *obj, const char *device_id);

#endif
