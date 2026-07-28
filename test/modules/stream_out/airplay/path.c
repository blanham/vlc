/*****************************************************************************
 * path.c: AirPlay local media path unit tests
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

#include "../../../../modules/stream_out/airplay/path.h"

#ifdef AIRPLAY_PATH_STANDALONE
char *
vlc_uri2path(const char *uri)
{
    if (strcmp(uri, "file:///C:/foo/bar.mp4") == 0)
        return strdup("C:\\foo\\bar.mp4");
    if (strcmp(uri, "FILE:///C:/foo/bar.mp4") == 0)
        return strdup("C:\\foo\\bar.mp4");
    if (strcmp(uri, "fd://0") == 0)
        return strdup("CON");
    return NULL;
}
#endif

static int failures;

static void
expect_null(void *value, const char *message)
{
    if (value != NULL)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
        free(value);
    }
}

static void
expect_path(const char *uri, const char *expected, const char *message)
{
    char *path = airplay_path_from_uri(uri);
    if (path == NULL || strcmp(path, expected) != 0)
    {
        fprintf(stderr, "FAIL: %s (got %s)\n", message,
                path != NULL ? path : "NULL");
        failures++;
    }
    free(path);
}

int
main(void)
{
#ifdef _WIN32
    const char *expected = "C:\\foo\\bar.mp4";
#else
    const char *expected = "/C:/foo/bar.mp4";
#endif

    expect_path("file:///C:/foo/bar.mp4", expected,
                "file URI becomes a local path");
    expect_path("FILE:///C:/foo/bar.mp4", expected,
                "file scheme is case insensitive");
    expect_null(airplay_path_from_uri("http://example.com/x"),
                "HTTP URI is rejected");
    expect_null(airplay_path_from_uri("fd://0"),
                "non-file local descriptor URI is rejected");
    expect_null(airplay_path_from_uri(NULL), "NULL URI is rejected");

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay path tests ok");
    return 0;
}
