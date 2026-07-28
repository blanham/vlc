/*****************************************************************************
 * http_token.c: AirPlay HTTP media token unit tests
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

#include "../../../../modules/stream_out/airplay/http_media.h"

#ifdef AIRPLAY_HTTP_TOKEN_STANDALONE
void
vlc_rand_bytes(void *buffer, size_t length)
{
    static uint8_t sequence;
    uint8_t *bytes = buffer;
    for (size_t i = 0; i < length; ++i)
        bytes[i] = ++sequence;
}
#endif

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
test_token_validation(void)
{
    expect_true(airplay_http_token_valid("abcd", "abcd"), "equal ok");
    expect_true(!airplay_http_token_valid("abcd", "abce"), "mismatch");
    expect_true(!airplay_http_token_valid("abcd", NULL), "null rejected");
    expect_true(!airplay_http_token_valid("abcd", "abc"), "length mismatch");
    expect_true(!airplay_http_token_valid(NULL, "abcd"),
                "null expected rejected");
}

static void
test_token_generation(void)
{
    char *first = airplay_http_generate_token();
    char *second = airplay_http_generate_token();

    expect_true(first != NULL, "first token allocated");
    expect_true(second != NULL, "second token allocated");
    expect_true(first != NULL && strlen(first) >= 32,
                "first token has at least 128 bits encoded");
    expect_true(second != NULL && strlen(second) >= 32,
                "second token has at least 128 bits encoded");
    expect_true(first != NULL && second != NULL && strcmp(first, second) != 0,
                "independent tokens differ");

    free(second);
    free(first);
}

int
main(void)
{
    test_token_validation();
    test_token_generation();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay HTTP token tests ok");
    return 0;
}
