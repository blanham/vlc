/*****************************************************************************
 * http_media.c: tokenized HTTP media server for AirPlay
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

#include "http_media.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef AIRPLAY_HTTP_TOKEN_ONLY
void vlc_rand_bytes(void *, size_t);
#else
# include <fcntl.h>
# include <sys/stat.h>
# include <unistd.h>

# include <vlc_common.h>
# include <vlc_fs.h>
# include <vlc_httpd.h>
# include <vlc_rand.h>
# include <vlc_variables.h>
#endif

#define AIRPLAY_HTTP_TOKEN_BYTES 16
#define AIRPLAY_HTTP_TOKEN_LENGTH (AIRPLAY_HTTP_TOKEN_BYTES * 2)

bool
airplay_http_token_valid(const char *expected, const char *got)
{
    if (expected == NULL || got == NULL)
        return false;

    size_t expected_length = strlen(expected);
    if (expected_length != strlen(got))
        return false;

    unsigned difference = 0;
    for (size_t i = 0; i < expected_length; ++i)
        difference |= (unsigned char)expected[i] ^ (unsigned char)got[i];
    return difference == 0;
}

char *
airplay_http_generate_token(void)
{
    static const char hexadecimal[] = "0123456789abcdef";
    uint8_t random[AIRPLAY_HTTP_TOKEN_BYTES];
    char *token = malloc(AIRPLAY_HTTP_TOKEN_LENGTH + 1);
    if (token == NULL)
        return NULL;

    vlc_rand_bytes(random, sizeof(random));
    for (size_t i = 0; i < sizeof(random); ++i)
    {
        token[i * 2] = hexadecimal[random[i] >> 4];
        token[i * 2 + 1] = hexadecimal[random[i] & 0x0f];
    }
    token[AIRPLAY_HTTP_TOKEN_LENGTH] = '\0';
    return token;
}

#ifndef AIRPLAY_HTTP_TOKEN_ONLY

struct airplay_http_media
{
    httpd_host_t *host;
    httpd_url_t *url;
    char *token;
    char *url_path;
    char *filepath;
    uint16_t port;
};

struct byte_range
{
    uint64_t start;
    uint64_t end;
    bool partial;
};

static char *
string_format(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (length < 0)
    {
        va_end(args);
        return NULL;
    }

    char *string = malloc((size_t)length + 1);
    if (string != NULL)
        vsnprintf(string, (size_t)length + 1, format, args);
    va_end(args);
    return string;
}

static void
answer_init(httpd_message_t *answer, int status)
{
    answer->i_proto = HTTPD_PROTO_HTTP;
    answer->i_version = 1;
    answer->i_type = HTTPD_MSG_ANSWER;
    answer->i_status = status;
    answer->i_body = 0;
    answer->p_body = NULL;
}

static void
answer_empty(httpd_message_t *answer, int status)
{
    answer->i_status = status;
    httpd_MsgAdd(answer, "Content-Length", "0");
}

static bool
parse_uint64(const char **cursor, uint64_t *value)
{
    const char *start = *cursor;
    uint64_t result = 0;

    if (*start < '0' || *start > '9')
        return false;

    do
    {
        unsigned digit = (unsigned)(**cursor - '0');
        if (result > (UINT64_MAX - digit) / 10)
            return false;
        result = result * 10 + digit;
        (*cursor)++;
    }
    while (**cursor >= '0' && **cursor <= '9');

    *value = result;
    return true;
}

static bool
parse_range(const char *header, uint64_t size, struct byte_range *range)
{
    range->start = 0;
    range->end = size == 0 ? 0 : size - 1;
    range->partial = false;

    if (header == NULL || *header == '\0')
        return true;
    if (strncmp(header, "bytes=", 6) != 0 || size == 0)
        return false;

    const char *cursor = header + 6;
    uint64_t first;
    uint64_t last;

    if (*cursor == '-')
    {
        cursor++;
        if (!parse_uint64(&cursor, &last) || *cursor != '\0' || last == 0)
            return false;
        if (last > size)
            last = size;
        range->start = size - last;
        range->end = size - 1;
    }
    else
    {
        if (!parse_uint64(&cursor, &first) || *cursor++ != '-')
            return false;
        if (first >= size)
            return false;

        if (*cursor == '\0')
            last = size - 1;
        else if (!parse_uint64(&cursor, &last) || *cursor != '\0' ||
                 last < first)
            return false;
        else if (last >= size)
            last = size - 1;

        range->start = first;
        range->end = last;
    }

    range->partial = true;
    return true;
}

static bool
request_token_valid(const airplay_http_media *media, const char *path)
{
    static const char prefix[] = "/airplay/";
    static const char suffix[] = "/media.mp4";

    if (path == NULL || strncmp(path, prefix, sizeof(prefix) - 1) != 0)
        return false;

    const char *token_start = path + sizeof(prefix) - 1;
    const char *suffix_start = strstr(token_start, suffix);
    if (suffix_start == NULL || suffix_start[strlen(suffix)] != '\0')
        return false;

    size_t token_length = (size_t)(suffix_start - token_start);
    if (token_length != strlen(media->token))
        return false;

    char *token = malloc(token_length + 1);
    if (token == NULL)
        return false;
    memcpy(token, token_start, token_length);
    token[token_length] = '\0';
    bool valid = airplay_http_token_valid(media->token, token);
    free(token);
    return valid;
}

static int
media_http_callback(httpd_callback_sys_t *opaque, httpd_client_t *client,
                    httpd_message_t *answer, const httpd_message_t *query)
{
    (void)client;
    airplay_http_media *media = (airplay_http_media *)opaque;
    if (answer == NULL || query == NULL)
        return VLC_SUCCESS;

    answer_init(answer, 403);
    if (!request_token_valid(media, query->psz_url))
    {
        answer_empty(answer, 403);
        return VLC_SUCCESS;
    }

    int fd = vlc_open(media->filepath, O_RDONLY);
    if (fd == -1)
    {
        answer_empty(answer, 404);
        return VLC_SUCCESS;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0 || file_stat.st_size < 0 ||
        !S_ISREG(file_stat.st_mode))
    {
        close(fd);
        answer_empty(answer, 404);
        return VLC_SUCCESS;
    }

    uint64_t file_size = (uint64_t)file_stat.st_size;
    struct byte_range range;
    if (!parse_range(httpd_MsgGet(query, "Range"), file_size, &range))
    {
        close(fd);
        answer_empty(answer, 416);
        httpd_MsgAdd(answer, "Content-Range", "bytes */%" PRIu64, file_size);
        return VLC_SUCCESS;
    }

    uint64_t response_size = file_size == 0 ? 0 : range.end - range.start + 1;
    answer->i_status = range.partial ? 206 : 200;

    if (query->i_type == HTTPD_MSG_HEAD || response_size == 0)
        close(fd);
    else
    {
        if (response_size > SIZE_MAX ||
            lseek(fd, (off_t)range.start, SEEK_SET) < 0)
        {
            close(fd);
            answer_empty(answer, 500);
            return VLC_SUCCESS;
        }

        answer->p_body = malloc((size_t)response_size);
        if (answer->p_body == NULL)
        {
            close(fd);
            answer_empty(answer, 500);
            return VLC_SUCCESS;
        }

        size_t offset = 0;
        while (offset < (size_t)response_size)
        {
            ssize_t count = read(fd, answer->p_body + offset,
                                 (size_t)response_size - offset);
            if (count > 0)
                offset += (size_t)count;
            else if (count < 0 && errno == EINTR)
                continue;
            else
                break;
        }
        close(fd);

        if (offset != (size_t)response_size)
        {
            free(answer->p_body);
            answer->p_body = NULL;
            answer_empty(answer, 500);
            return VLC_SUCCESS;
        }
        answer->i_body = offset;
    }

    httpd_MsgAdd(answer, "Accept-Ranges", "bytes");
    httpd_MsgAdd(answer, "Content-Type", "video/mp4");
    httpd_MsgAdd(answer, "Content-Length", "%" PRIu64, response_size);
    if (range.partial)
        httpd_MsgAdd(answer, "Content-Range", "bytes %" PRIu64 "-%" PRIu64
                      "/%" PRIu64, range.start, range.end, file_size);
    return VLC_SUCCESS;
}

airplay_http_media *
airplay_http_media_start(vlc_object_t *obj, uint16_t http_port,
                         const char *filepath)
{
    if (obj == NULL || http_port == 0 || filepath == NULL || *filepath == '\0')
        return NULL;

    airplay_http_media *media = calloc(1, sizeof(*media));
    if (media == NULL)
        return NULL;

    media->port = http_port;
    media->filepath = strdup(filepath);
    media->token = airplay_http_generate_token();
    if (media->token != NULL)
        media->url_path = string_format("/airplay/%s/media.mp4", media->token);
    if (media->filepath == NULL || media->token == NULL ||
        media->url_path == NULL)
        goto error;

    if (var_Create(obj, "http-port", VLC_VAR_INTEGER) != VLC_SUCCESS)
        goto error;
    var_SetInteger(obj, "http-port", http_port);

    media->host = vlc_http_HostNew(obj);
    if (media->host == NULL)
        goto error;

    media->url = httpd_UrlNew(media->host, media->url_path, NULL, NULL);
    if (media->url == NULL)
        goto error;
    if (httpd_UrlCatch(media->url, HTTPD_MSG_GET, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS ||
        httpd_UrlCatch(media->url, HTTPD_MSG_HEAD, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS)
        goto error;

    return media;

error:
    airplay_http_media_stop(media);
    return NULL;
}

void
airplay_http_media_stop(airplay_http_media *media)
{
    if (media == NULL)
        return;
    if (media->url != NULL)
        httpd_UrlDelete(media->url);
    if (media->host != NULL)
        httpd_HostDelete(media->host);
    free(media->filepath);
    free(media->url_path);
    free(media->token);
    free(media);
}

const char *
airplay_http_media_token(const airplay_http_media *media)
{
    return media == NULL ? NULL : media->token;
}

char *
airplay_http_media_url(const airplay_http_media *media, const char *lan_ip)
{
    if (media == NULL || lan_ip == NULL || *lan_ip == '\0')
        return NULL;

    return string_format("http://%s:%" PRIu16 "%s", lan_ip, media->port,
                         media->url_path);
}

#endif
