/*****************************************************************************
 * session_plist.c: AirPlay session /play plist unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../modules/stream_out/airplay/session.h"
#include "../../../../modules/stream_out/airplay/plist.h"

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
test_play_body_keys(void)
{
    static const char url[] = "http://192.168.1.10:8090/airplay/abc/media.mp4";
    uint8_t *body = NULL;
    size_t body_len = 0;

    expect_true(airplay_session_build_play_body(url, 0.25, &body, &body_len) == 0,
                "build play body");
    expect_true(body != NULL && body_len >= 8, "body allocated");
    expect_true(memcmp(body, "bplist00", 8) == 0, "binary plist header");

    airplay_plist *pl = airplay_plist_parse(body, body_len);
    expect_true(pl != NULL, "parse play body");

    char *location = NULL;
    expect_true(airplay_plist_get_string(pl, "Content-Location", &location) == 0,
                "Content-Location present");
    expect_true(location != NULL && strcmp(location, url) == 0,
                "Content-Location value");

    uint8_t *start_bytes = NULL;
    size_t start_len = 0;
    expect_true(airplay_plist_get_data(pl, "Start-Position", &start_bytes,
                                      &start_len) != 0,
                "Start-Position is a real, not data");

    airplay_plist *roundtrip = airplay_plist_new();
    expect_true(roundtrip != NULL, "roundtrip dict");
    expect_true(airplay_plist_set_string(roundtrip, "Content-Location", url) == 0,
                "set location in roundtrip");
    expect_true(airplay_plist_set_real(roundtrip, "Start-Position", 0.25) == 0,
                "set start in roundtrip");
    uint8_t *expected = NULL;
    size_t expected_len = 0;
    expect_true(airplay_plist_serialize(roundtrip, &expected, &expected_len) == 0,
                "serialize roundtrip");
    expect_true(expected_len == body_len &&
                    memcmp(expected, body, body_len) == 0,
                "build_play_body matches manual plist");

    free(location);
    free(start_bytes);
    free(expected);
    airplay_plist_release(roundtrip);
    airplay_plist_release(pl);
    free(body);
}

static void
test_play_body_rejects_invalid(void)
{
    uint8_t *body = NULL;
    size_t body_len = 0;

    expect_true(airplay_session_build_play_body(NULL, 0.0, &body, &body_len) != 0,
                "rejects NULL url");
    expect_true(airplay_session_build_play_body("http://x", -0.1, &body,
                                                &body_len) != 0,
                "rejects negative start");
    expect_true(airplay_session_build_play_body("http://x", 1.1, &body,
                                                &body_len) != 0,
                "rejects start > 1");
}

int
main(void)
{
    test_play_body_keys();
    test_play_body_rejects_invalid();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay session plist tests ok");
    return 0;
}
