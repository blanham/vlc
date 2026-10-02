/*****************************************************************************
 * keystore_id.c: AirPlay pairing identity keystore helper
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include "keystore_id.h"

#include <stdlib.h>
#include <string.h>

#ifndef AIRPLAY_KEYSTORE_ID_PACK_ONLY
# include <vlc_common.h>
# include <vlc_configuration.h>
# include <vlc_keystore.h>
#endif

#define IDENTITY_BLOB_SIZE_V1 (4 + 64 + 32 + 32 + 1)
#define IDENTITY_BLOB_SIZE_V2 (IDENTITY_BLOB_SIZE_V1 + AIRPLAY_CONTROLLER_PAIRING_ID_LEN)

int
airplay_identity_pack(const struct airplay_identity *id, uint8_t **out,
                      size_t *len)
{
    if (id == NULL || out == NULL || len == NULL || id->has_peer > 1)
        return -1;

    uint8_t *blob = malloc(IDENTITY_BLOB_SIZE_V2);
    if (blob == NULL)
        return -1;

    blob[0] = AIRPLAY_ID_BLOB_VERSION;
    blob[1] = 0;
    blob[2] = 0;
    blob[3] = 0;
    memcpy(blob + 4, id->our_ed25519_sk, sizeof(id->our_ed25519_sk));
    memcpy(blob + 68, id->our_ed25519_pk, sizeof(id->our_ed25519_pk));
    memcpy(blob + 100, id->peer_ed25519_pk, sizeof(id->peer_ed25519_pk));
    blob[132] = id->has_peer;
    memcpy(blob + 133, id->controller_pairing_id,
           sizeof(id->controller_pairing_id));

    *out = blob;
    *len = IDENTITY_BLOB_SIZE_V2;
    return 0;
}

int
airplay_identity_unpack(const uint8_t *in, size_t len,
                        struct airplay_identity *out)
{
    if (in == NULL || out == NULL)
        return -1;
    if (in[1] != 0 || in[2] != 0 || in[3] != 0)
        return -1;

    memset(out, 0, sizeof(*out));

    if (in[0] == 1 && len == IDENTITY_BLOB_SIZE_V1)
    {
        if (in[132] > 1)
            return -1;
        memcpy(out->our_ed25519_sk, in + 4, sizeof(out->our_ed25519_sk));
        memcpy(out->our_ed25519_pk, in + 68, sizeof(out->our_ed25519_pk));
        memcpy(out->peer_ed25519_pk, in + 100, sizeof(out->peer_ed25519_pk));
        out->has_peer = in[132];
        return 0;
    }

    if (in[0] != AIRPLAY_ID_BLOB_VERSION || len != IDENTITY_BLOB_SIZE_V2 ||
        in[132] > 1)
        return -1;

    memcpy(out->our_ed25519_sk, in + 4, sizeof(out->our_ed25519_sk));
    memcpy(out->our_ed25519_pk, in + 68, sizeof(out->our_ed25519_pk));
    memcpy(out->peer_ed25519_pk, in + 100, sizeof(out->peer_ed25519_pk));
    out->has_peer = in[132];
    memcpy(out->controller_pairing_id, in + 133,
           sizeof(out->controller_pairing_id));
    out->controller_pairing_id[sizeof(out->controller_pairing_id) - 1] = '\0';
    return 0;
}

#ifndef AIRPLAY_KEYSTORE_ID_PACK_ONLY
static void
identity_values(const char *device_id, const char *values[KEY_MAX])
{
    VLC_KEYSTORE_VALUES_INIT(values);
    values[KEY_PROTOCOL] = "airplay";
    values[KEY_SERVER] = device_id;
}

/* Point this object at the plaintext file keystore before vlc_keystore_create
 * walks the config. The packaged build otherwise has no module named "any". */
static int
prepare_file_keystore(vlc_object_t *obj)
{
    char *dir = config_GetUserDir(VLC_USERDATA_DIR);
    if (dir == NULL)
        return VLC_EGENERIC;

    char path[1024];
#ifdef _WIN32
    int n = snprintf(path, sizeof path, "%s\\airplay-keystore", dir);
#else
    int n = snprintf(path, sizeof path, "%s/airplay-keystore", dir);
#endif
    free(dir);
    if (n < 0 || (size_t)n >= sizeof path)
        return VLC_EGENERIC;

    var_Create(obj, "keystore", VLC_VAR_STRING);
    var_SetString(obj, "keystore", "file_plaintext");
    var_Create(obj, "keystore-file", VLC_VAR_STRING);
    var_SetString(obj, "keystore-file", path);
    return VLC_SUCCESS;
}

static void
secret_clear(uint8_t *secret, size_t length)
{
    volatile uint8_t *cursor = secret;
    while (length-- > 0)
        *cursor++ = 0;
}

int
airplay_identity_store(vlc_object_t *obj, const char *device_id,
                       const char *label, const struct airplay_identity *id)
{
    if (obj == NULL || device_id == NULL || device_id[0] == '\0' || id == NULL)
        return VLC_EINVAL;

    uint8_t *blob;
    size_t length;
    if (airplay_identity_pack(id, &blob, &length) != 0)
        return VLC_EGENERIC;

    if (prepare_file_keystore(obj) != VLC_SUCCESS)
    {
        secret_clear(blob, length);
        free(blob);
        return VLC_EGENERIC;
    }

    vlc_keystore *keystore = vlc_keystore_create(obj);
    if (keystore == NULL)
    {
        secret_clear(blob, length);
        free(blob);
        return VLC_EGENERIC;
    }

    const char *values[KEY_MAX];
    identity_values(device_id, values);
    int result = vlc_keystore_store(keystore, values, blob, length, label);
    vlc_keystore_release(keystore);
    secret_clear(blob, length);
    free(blob);
    return result;
}

int
airplay_identity_load(vlc_object_t *obj, const char *device_id,
                      struct airplay_identity *out)
{
    if (obj == NULL || device_id == NULL || device_id[0] == '\0' || out == NULL)
        return VLC_EINVAL;

    if (prepare_file_keystore(obj) != VLC_SUCCESS)
        return VLC_EGENERIC;

    vlc_keystore *keystore = vlc_keystore_create(obj);
    if (keystore == NULL)
        return VLC_EGENERIC;

    const char *values[KEY_MAX];
    identity_values(device_id, values);
    vlc_keystore_entry *entries = NULL;
    unsigned count = vlc_keystore_find(keystore, values, &entries);
    int result = count == 0 ? VLC_EGENERIC :
                 airplay_identity_unpack(entries[0].p_secret,
                                         entries[0].i_secret_len, out);
    if (count > 0)
        vlc_keystore_release_entries(entries, count);
    vlc_keystore_release(keystore);
    return result == 0 ? VLC_SUCCESS : VLC_EGENERIC;
}

int
airplay_identity_remove(vlc_object_t *obj, const char *device_id)
{
    if (obj == NULL || device_id == NULL || device_id[0] == '\0')
        return VLC_EINVAL;

    if (prepare_file_keystore(obj) != VLC_SUCCESS)
        return VLC_EGENERIC;

    vlc_keystore *keystore = vlc_keystore_create(obj);
    if (keystore == NULL)
        return VLC_EGENERIC;

    const char *values[KEY_MAX];
    identity_values(device_id, values);
    unsigned count = vlc_keystore_remove(keystore, values);
    vlc_keystore_release(keystore);
    return count > 0 ? VLC_SUCCESS : VLC_EGENERIC;
}
#endif
