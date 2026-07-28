/*****************************************************************************
 * plist.c: binary property list unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../modules/stream_out/airplay/plist.h"

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

static void
test_dictionary_round_trip(void)
{
    airplay_plist *source = airplay_plist_new();
    airplay_plist *parsed;
    uint8_t *encoded = NULL;
    uint8_t *encoded_again = NULL;
    size_t encoded_len = 0;
    size_t encoded_again_len = 0;
    char *location = NULL;
    char *name = NULL;

    expect_true(source != NULL, "create dictionary");
    expect_true(airplay_plist_set_string(source, "Content-Location",
                                        "http://10.0.0.1/x") == 0,
                "set string");
    expect_true(airplay_plist_set_real(source, "Start-Position", 0.25) == 0,
                "set real");
    expect_true(airplay_plist_set_string(source, "Name", "Caf\xc3\xa9") == 0,
                "set UTF-8 string");
    expect_true(airplay_plist_serialize(source, &encoded, &encoded_len) == 0,
                "serialize dictionary");
    expect_true(encoded_len >= 8 && memcmp(encoded, "bplist00", 8) == 0,
                "binary plist header");

    parsed = airplay_plist_parse(encoded, encoded_len);
    expect_true(parsed != NULL, "parse dictionary");
    expect_true(airplay_plist_get_string(parsed, "Content-Location",
                                        &location) == 0,
                "get parsed string");
    expect_true(location != NULL &&
                    strcmp(location, "http://10.0.0.1/x") == 0,
                "string round trip");
    expect_true(airplay_plist_get_string(parsed, "Name", &name) == 0 &&
                    strcmp(name, "Caf\xc3\xa9") == 0,
                "UTF-8 string round trip");
    expect_true(airplay_plist_serialize(parsed, &encoded_again,
                                       &encoded_again_len) == 0,
                "reserialize parsed dictionary");
    expect_true(encoded_len == encoded_again_len &&
                    memcmp(encoded, encoded_again, encoded_len) == 0,
                "real round trip");

    free(location);
    free(name);
    free(encoded_again);
    airplay_plist_release(parsed);
    free(encoded);
    airplay_plist_release(source);
}

static void
test_reject_invalid_input(void)
{
    static const uint8_t truncated[] = "bplist00";
    static const uint8_t wrong_header[] = "notplist";

    expect_true(airplay_plist_parse(truncated, sizeof(truncated) - 1) == NULL,
                "reject truncated plist");
    expect_true(airplay_plist_parse(wrong_header, sizeof(wrong_header) - 1) ==
                    NULL,
                "reject non-bplist header");
}

static void
test_data_round_trip(void)
{
    uint8_t key[32];
    airplay_plist *source = airplay_plist_new();
    airplay_plist *parsed;
    uint8_t *encoded = NULL;
    uint8_t *decoded = NULL;
    size_t encoded_len = 0;
    size_t decoded_len = 0;

    for (size_t i = 0; i < sizeof(key); ++i)
        key[i] = (uint8_t)(i * 7 + 3);

    expect_true(source != NULL, "create data dictionary");
    expect_true(airplay_plist_set_data(source, "KeyMaterial", key,
                                      sizeof(key)) == 0,
                "set data");
    expect_true(airplay_plist_serialize(source, &encoded, &encoded_len) == 0,
                "serialize data");
    parsed = airplay_plist_parse(encoded, encoded_len);
    expect_true(parsed != NULL, "parse data dictionary");
    expect_true(airplay_plist_get_data(parsed, "KeyMaterial", &decoded,
                                      &decoded_len) == 0,
                "get parsed data");
    expect_true(decoded_len == sizeof(key) &&
                    memcmp(decoded, key, sizeof(key)) == 0,
                "data round trip");

    free(decoded);
    airplay_plist_release(parsed);
    free(encoded);
    airplay_plist_release(source);
}

int
main(void)
{
    test_dictionary_round_trip();
    test_reject_invalid_input();
    test_data_round_trip();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay plist tests ok");
    return 0;
}
