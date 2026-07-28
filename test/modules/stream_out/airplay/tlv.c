/*****************************************************************************
 * tlv.c: AirPlay TLV8 unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../modules/stream_out/airplay/tlv.h"

static int failures;

static void
expect_true(bool condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void
test_round_trip_and_fragmentation(void)
{
    uint8_t big[400];
    for (size_t i = 0; i < sizeof big; ++i)
        big[i] = (uint8_t)i;

    hap_tlv_buf buf;
    hap_tlv_buf_init(&buf);
    expect_true(hap_tlv_buf_add(&buf, HAP_TLV_STATE, (const uint8_t[]){ 1 }, 1) == 0,
                "adds state");
    expect_true(hap_tlv_buf_add(&buf, HAP_TLV_PUBLIC_KEY, big, sizeof big) == 0,
                "adds fragmented public key");

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    expect_true(hap_tlv_buf_finish(&buf, &raw, &raw_len) == 0, "finishes buffer");

    bool ok = false;
    expect_true(hap_tlv_get_u8(raw, raw_len, HAP_TLV_STATE, &ok) == 1 && ok,
                "reads state byte");
    expect_true(!hap_tlv_has(raw, raw_len, HAP_TLV_ERROR), "no error tlv");

    uint8_t *pk = NULL;
    size_t pk_len = 0;
    expect_true(hap_tlv_get(raw, raw_len, HAP_TLV_PUBLIC_KEY, &pk, &pk_len) == 0,
                "reassembles fragmented key");
    expect_true(pk_len == sizeof big, "fragmented length preserved");
    expect_true(memcmp(pk, big, sizeof big) == 0, "fragmented payload preserved");
    free(pk);
    free(raw);
}

int
main(void)
{
    test_round_trip_and_fragmentation();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay tlv tests ok");
    return 0;
}
