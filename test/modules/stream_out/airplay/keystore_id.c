/*****************************************************************************
 * keystore_id.c: AirPlay keystore identity blob unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../modules/stream_out/airplay/keystore_id.h"

#define IDENTITY_BLOB_SIZE_V2 (4 + 64 + 32 + 32 + 1 + AIRPLAY_CONTROLLER_PAIRING_ID_LEN)

static int failures;

static void
expect_true(int condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static struct airplay_identity
make_identity(void)
{
    struct airplay_identity id;

    for (size_t i = 0; i < sizeof(id.our_ed25519_sk); ++i)
        id.our_ed25519_sk[i] = (uint8_t)(i + 1);
    for (size_t i = 0; i < sizeof(id.our_ed25519_pk); ++i)
        id.our_ed25519_pk[i] = (uint8_t)(0x80 + i);
    for (size_t i = 0; i < sizeof(id.peer_ed25519_pk); ++i)
        id.peer_ed25519_pk[i] = (uint8_t)(0xc0 + i);
    id.has_peer = 1;
    snprintf(id.controller_pairing_id, sizeof id.controller_pairing_id,
             "11111111-2222-3333-4444-555555555555");
    return id;
}

static void
test_pack_layout_and_round_trip(void)
{
    const struct airplay_identity expected = make_identity();
    struct airplay_identity actual;
    uint8_t *blob = NULL;
    size_t length = 0;

    expect_true(airplay_identity_pack(&expected, &blob, &length) == 0,
                "identity packs");
    expect_true(blob != NULL, "pack allocates a blob");
    expect_true(length == IDENTITY_BLOB_SIZE_V2, "blob has fixed size");
    if (blob != NULL && length == IDENTITY_BLOB_SIZE_V2)
    {
        expect_true(blob[0] == AIRPLAY_ID_BLOB_VERSION &&
                    blob[1] == 0 && blob[2] == 0 && blob[3] == 0,
                    "version is little endian");
        expect_true(memcmp(blob + 4, expected.our_ed25519_sk, 64) == 0,
                    "secret key follows version");
        expect_true(memcmp(blob + 68, expected.our_ed25519_pk, 32) == 0,
                    "public key follows secret key");
        expect_true(memcmp(blob + 100, expected.peer_ed25519_pk, 32) == 0,
                    "peer key follows public key");
        expect_true(blob[132] == 1, "peer flag precedes controller id");
        expect_true(memcmp(blob + 133, expected.controller_pairing_id,
                           sizeof(expected.controller_pairing_id)) == 0,
                    "controller pairing id is last");
        expect_true(airplay_identity_unpack(blob, length, &actual) == 0,
                    "identity unpacks");
        expect_true(memcmp(&actual, &expected, sizeof(actual)) == 0,
                    "unpacked identity matches input");
    }
    free(blob);
}

static void
test_unpack_rejects_invalid_blobs(void)
{
    struct airplay_identity id = make_identity();
    struct airplay_identity out;
    uint8_t *blob = NULL;
    size_t length = 0;

    expect_true(airplay_identity_pack(&id, &blob, &length) == 0,
                "fixture packs");
    if (blob == NULL)
        return;

    expect_true(airplay_identity_unpack(blob, length - 1, &out) != 0,
                "truncated blob is rejected");
    expect_true(airplay_identity_unpack(blob, length + 1, &out) != 0,
                "oversized blob is rejected");

    blob[0] = AIRPLAY_ID_BLOB_VERSION + 1;
    expect_true(airplay_identity_unpack(blob, length, &out) != 0,
                "unknown version is rejected");
    blob[0] = AIRPLAY_ID_BLOB_VERSION;

    blob[132] = 2;
    expect_true(airplay_identity_unpack(blob, length, &out) != 0,
                "invalid peer flag is rejected");
    free(blob);
}

static void
test_unpack_v1_backward_compat(void)
{
    struct airplay_identity expected = make_identity();
    expected.controller_pairing_id[0] = '\0';

    uint8_t blob[4 + 64 + 32 + 32 + 1];
    blob[0] = 1;
    blob[1] = blob[2] = blob[3] = 0;
    memcpy(blob + 4, expected.our_ed25519_sk, 64);
    memcpy(blob + 68, expected.our_ed25519_pk, 32);
    memcpy(blob + 100, expected.peer_ed25519_pk, 32);
    blob[132] = expected.has_peer;

    struct airplay_identity actual;
    expect_true(airplay_identity_unpack(blob, sizeof blob, &actual) == 0,
                "v1 blob unpacks");
    expect_true(actual.controller_pairing_id[0] == '\0',
                "v1 blob leaves controller pairing id empty");
    expect_true(memcmp(actual.our_ed25519_sk, expected.our_ed25519_sk, 64) == 0,
                "v1 secret key preserved");
}

static void
test_invalid_arguments(void)
{
    struct airplay_identity id = make_identity();
    uint8_t *blob = NULL;
    size_t length = 0;

    expect_true(airplay_identity_pack(NULL, &blob, &length) != 0,
                "pack rejects NULL identity");
    expect_true(airplay_identity_pack(&id, NULL, &length) != 0,
                "pack rejects NULL data output");
    expect_true(airplay_identity_pack(&id, &blob, NULL) != 0,
                "pack rejects NULL length output");
    expect_true(airplay_identity_unpack(NULL, IDENTITY_BLOB_SIZE_V2, &id) != 0,
                "unpack rejects NULL data");
    expect_true(airplay_identity_unpack((const uint8_t *)&id, sizeof(id), NULL)
                != 0, "unpack rejects NULL identity output");
}

int
main(void)
{
    test_pack_layout_and_round_trip();
    test_unpack_rejects_invalid_blobs();
    test_unpack_v1_backward_compat();
    test_invalid_arguments();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay keystore identity tests ok");
    return 0;
}
