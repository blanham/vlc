/*****************************************************************************
 * pairing.h: HAP-style pairing FSM and PIN dialog for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_PAIRING_H
#define VLC_AIRPLAY_PAIRING_H

#include <stddef.h>
#include <stdint.h>

#include "keystore_id.h"

typedef struct vlc_object_t vlc_object_t;

enum airplay_pair_state {
    AIRPLAY_PAIR_IDLE,
    AIRPLAY_PAIR_NEED_PIN,
    AIRPLAY_PAIR_SETUP,
    AIRPLAY_PAIR_VERIFY,
    AIRPLAY_PAIR_READY,
    AIRPLAY_PAIR_FAILED,
};

typedef struct airplay_pairing airplay_pairing;

/**
 * Creates a pairing state machine for one accessory.
 *
 * `device_id` is the stable renderer id used as the keystore lookup key
 * (see keystore_id.h); `device_name` is the human-readable name shown in the
 * PIN dialog. Neither is a secret.
 */
airplay_pairing *airplay_pairing_new(vlc_object_t *obj, const char *ip,
                                     uint16_t port, const char *device_id,
                                     const char *device_name);
void airplay_pairing_release(airplay_pairing *);

/**
 * Supplies the accessory's advertised long-term Ed25519 public key (`pk` TXT)
 * and HAP pairing identifier (`deviceid` TXT). Required before pair-setup so
 * M6 can be checked against discovery metadata.
 */
void airplay_pairing_set_accessory_info(airplay_pairing *,
                                        const uint8_t accessory_ltpk[32],
                                        const char *accessory_pairing_id);

/**
 * Loads a previously stored identity from the keystore and runs pair-verify;
 * if no identity is stored (or verify fails against a stale one), prompts
 * for a PIN and runs pair-setup once before verifying again.
 *
 * Returns VLC_SUCCESS and leaves the state machine in AIRPLAY_PAIR_READY, or
 * a VLC error code with the state left at AIRPLAY_PAIR_NEED_PIN (no PIN
 * available yet; safe to call again once one is) or AIRPLAY_PAIR_FAILED
 * (the accessory rejected pairing outright).
 */
int airplay_pairing_ensure(airplay_pairing *);

enum airplay_pair_state airplay_pairing_state(const airplay_pairing *);

/* -- Test seams -----------------------------------------------------------
 * Production code paths (dialog, network, keystore) are only reachable when
 * the corresponding seam below has not been set; unit tests set all three
 * so the FSM can be exercised without a display, network, or live keystore
 * backend. */

/* Injects a PIN, bypassing vlc_dialog_wait_login(). */
void airplay_pairing_set_pin_for_tests(airplay_pairing *, const char *pin);

/* Injects a fake control-channel transport, bypassing the real TCP client.
 * `path` is "/pair-setup" or "/pair-verify"; `req`/`resp` are TLV8 bodies
 * (`Content-Type: application/pairing+tlv8`). Returns 0 on success, and must
 * set `*resp` to a malloc()'d buffer the caller frees. */
typedef int (*airplay_pair_transport_cb)(void *opaque, const char *path,
    const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
void airplay_pairing_set_transport_for_tests(airplay_pairing *,
    airplay_pair_transport_cb cb, void *opaque);

/* Injects fake identity persistence, bypassing airplay_identity_load/store/
 * remove() (and therefore the real VLC keystore + a live libvlc instance). */
typedef int (*airplay_pair_identity_load_cb)(void *opaque,
    struct airplay_identity *out);
typedef int (*airplay_pair_identity_store_cb)(void *opaque,
    const struct airplay_identity *id);
typedef int (*airplay_pair_identity_remove_cb)(void *opaque);
void airplay_pairing_set_identity_ops_for_tests(airplay_pairing *,
    airplay_pair_identity_load_cb load, airplay_pair_identity_store_cb store,
    airplay_pair_identity_remove_cb remove, void *opaque);

/* -- Control channel AEAD --------------------------------------------------
 * Valid only once airplay_pairing_state() == AIRPLAY_PAIR_READY. `*out` is
 * malloc()'d and must be freed by the caller. */
int airplay_pairing_encrypt(airplay_pairing *, const uint8_t *in,
                            size_t in_len, uint8_t **out, size_t *out_len);
int airplay_pairing_decrypt(airplay_pairing *, const uint8_t *in,
                            size_t in_len, uint8_t **out, size_t *out_len);

#endif
