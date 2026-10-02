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

struct airplay_http_edit
{
    uint64_t offset;
    uint32_t duration;
    uint32_t media_time;
};

struct airplay_http_media
{
    vlc_object_t *obj;
    httpd_host_t *host;
    httpd_url_t *url;
    char *token;
    char *url_path;
    char *filepath;
    uint16_t port;
    struct airplay_http_edit edits[4];
    unsigned edit_count;
    httpd_url_t *urls[24];
    unsigned url_count;
    unsigned generation;
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

    if (path == NULL || strncmp(path, prefix, sizeof(prefix) - 1) != 0)
        return false;

    const char *token_start = path + sizeof(prefix) - 1;
    const char *slash = strchr(token_start, '/');
    if (slash == NULL || slash == token_start)
        return false;

    size_t token_length = (size_t)(slash - token_start);
    if (token_length != strlen(media->token))
        return false;

    const char *name = slash + 1;
    if (strncmp(name, "media", 5) != 0)
        return false;
    name += 5;
    if (*name == '-')
    {
        name++;
        if (*name < '0' || *name > '9')
            return false;
        while (*name >= '0' && *name <= '9')
            name++;
    }
    if (strcmp(name, ".mp4") != 0)
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
    if (media->obj != NULL)
        msg_Dbg(media->obj, "AirPlay HTTP %s range=%s",
                query->psz_url != NULL ? query->psz_url : "",
                httpd_MsgGet(query, "Range") != NULL ?
                    httpd_MsgGet(query, "Range") : "(none)");
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
    /* httpd sends the body only after this callback returns. A request for
     * the rest of the file is answered in pieces: the first return carries
     * the headers and Content-Length of the whole range, and a non-zero
     * i_body_offset makes httpd call us again for the next piece. */
    const uint64_t chunk = 2u * 1024u * 1024u;
    const bool resume = answer->i_body_offset > 0;
    uint64_t cursor = resume ? (uint64_t)answer->i_body_offset : range.start;

    if (cursor < range.start || (response_size > 0 && cursor > range.end))
    {
        close(fd);
        answer->i_body_offset = 0;
        answer_empty(answer, 500);
        return VLC_SUCCESS;
    }

    uint64_t remain = response_size == 0 ? 0 : range.end - cursor + 1;
    uint64_t piece = remain > chunk ? chunk : remain;

    if (!resume)
    {
        answer->i_status = range.partial ? 206 : 200;
        httpd_MsgAdd(answer, "Accept-Ranges", "bytes");
        httpd_MsgAdd(answer, "Content-Type", "video/mp4");
        httpd_MsgAdd(answer, "Content-Length", "%" PRIu64, response_size);
        if (range.partial)
            httpd_MsgAdd(answer, "Content-Range",
                          "bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64,
                          range.start, range.end, file_size);
    }

    if (query->i_type == HTTPD_MSG_HEAD || piece == 0)
    {
        close(fd);
        answer->i_body_offset = 0;
        return VLC_SUCCESS;
    }

    if (piece > SIZE_MAX || lseek(fd, (off_t)cursor, SEEK_SET) < 0)
    {
        close(fd);
        answer->i_body_offset = 0;
        if (!resume)
            answer_empty(answer, 500);
        return VLC_SUCCESS;
    }

    answer->p_body = malloc((size_t)piece);
    if (answer->p_body == NULL)
    {
        close(fd);
        answer->i_body_offset = 0;
        if (!resume)
            answer_empty(answer, 500);
        return VLC_SUCCESS;
    }

    size_t offset = 0;
    while (offset < (size_t)piece)
    {
        ssize_t count = read(fd, answer->p_body + offset,
                             (size_t)piece - offset);
        if (count > 0)
            offset += (size_t)count;
        else if (count < 0 && errno == EINTR)
            continue;
        else
            break;
    }
    close(fd);

    if (offset != (size_t)piece)
    {
        free(answer->p_body);
        answer->p_body = NULL;
        answer->i_body_offset = 0;
        if (!resume)
            answer_empty(answer, 500);
        return VLC_SUCCESS;
    }

    answer->i_body = offset;
    answer->i_body_offset = (cursor + piece <= range.end)
                            ? (int64_t)(cursor + piece) : 0;
    for (unsigned i = 0; i < media->edit_count; ++i)
    {
        const struct airplay_http_edit *edit = &media->edits[i];
        uint8_t packed[8];
        packed[0] = (uint8_t)(edit->duration >> 24);
        packed[1] = (uint8_t)(edit->duration >> 16);
        packed[2] = (uint8_t)(edit->duration >> 8);
        packed[3] = (uint8_t)edit->duration;
        packed[4] = (uint8_t)(edit->media_time >> 24);
        packed[5] = (uint8_t)(edit->media_time >> 16);
        packed[6] = (uint8_t)(edit->media_time >> 8);
        packed[7] = (uint8_t)edit->media_time;
        for (unsigned b = 0; b < sizeof packed; ++b)
        {
            uint64_t pos = edit->offset + b;
            if (pos >= cursor && pos < cursor + offset)
                answer->p_body[pos - cursor] = packed[b];
        }
    }
    return VLC_SUCCESS;
}

static uint32_t
load_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint32_t
box_timescale(const uint8_t *data, size_t length, uint64_t box, const char *type)
{
    if (box + 8 > length)
        return 0;
    uint32_t size = load_be32(data + box);
    if (size < 8 || box + size > length)
        return 0;
    uint64_t end = box + size;
    uint64_t cursor = box + 8;
    while (cursor + 8 <= end)
    {
        uint32_t child_size = load_be32(data + cursor);
        if (child_size < 8 || cursor + child_size > end)
            return 0;
        if (memcmp(data + cursor + 4, type, 4) == 0)
        {
            if (data[cursor + 8] != 0 || cursor + 24 > length)
                return 0;
            return load_be32(data + cursor + 20);
        }
        if (memcmp(data + cursor + 4, "mdia", 4) == 0)
        {
            uint32_t nested = box_timescale(data, length, cursor, type);
            if (nested != 0)
                return nested;
        }
        cursor += child_size;
    }
    return 0;
}

static uint64_t
box_elst(const uint8_t *data, size_t length, uint64_t box)
{
    if (box + 8 > length)
        return 0;
    uint32_t size = load_be32(data + box);
    if (size < 8 || box + size > length)
        return 0;
    uint64_t end = box + size;
    uint64_t cursor = box + 8;
    while (cursor + 8 <= end)
    {
        uint32_t child_size = load_be32(data + cursor);
        if (child_size < 8 || cursor + child_size > end)
            return 0;
        if (memcmp(data + cursor + 4, "elst", 4) == 0)
            return cursor;
        if (memcmp(data + cursor + 4, "edts", 4) == 0)
        {
            uint64_t nested = box_elst(data, length, cursor);
            if (nested != 0)
                return nested;
        }
        cursor += child_size;
    }
    return 0;
}

void
airplay_http_media_set_start(airplay_http_media *media, double start_seconds)
{
    if (media == NULL)
        return;
    media->edit_count = 0;
    if (start_seconds <= 0.05 || media->filepath == NULL)
        return;

    int fd = vlc_open(media->filepath, O_RDONLY);
    if (fd < 0)
        return;
    uint8_t *data = malloc(8 * 1024 * 1024);
    if (data == NULL)
    {
        close(fd);
        return;
    }
    size_t length = 0;
    while (length < 8 * 1024 * 1024)
    {
        ssize_t count = read(fd, data + length, 8 * 1024 * 1024 - length);
        if (count > 0)
            length += (size_t)count;
        else if (count < 0 && errno == EINTR)
            continue;
        else
            break;
    }
    close(fd);

    uint64_t cursor = 0;
    while (cursor + 8 <= length && media->edit_count < 4)
    {
        uint32_t size = load_be32(data + cursor);
        if (size < 8 || cursor + size > length)
            break;
        if (memcmp(data + cursor + 4, "moov", 4) == 0)
        {
            uint32_t movie_timescale = box_timescale(data, length, cursor, "mvhd");
            uint64_t track = cursor + 8;
            uint64_t end = cursor + size;
            while (track + 8 <= end && media->edit_count < 4 && movie_timescale != 0)
            {
                uint32_t track_size = load_be32(data + track);
                if (track_size < 8 || track + track_size > end)
                    break;
                if (memcmp(data + track + 4, "trak", 4) == 0)
                {
                    uint32_t media_timescale = box_timescale(data, length, track, "mdhd");
                    uint64_t elst = box_elst(data, length, track);
                    if (media_timescale != 0 && elst != 0 && elst + 28 <= length &&
                        data[elst + 8] == 0 && load_be32(data + elst + 12) == 1)
                    {
                        uint32_t duration = load_be32(data + elst + 16);
                        uint32_t media_time = load_be32(data + elst + 20);
                        uint64_t skip_movie =
                            (uint64_t)(start_seconds * movie_timescale + 0.5);
                        uint64_t skip_media =
                            (uint64_t)(start_seconds * media_timescale + 0.5);
                        if (skip_movie < duration &&
                            media_time <= UINT32_MAX - skip_media)
                        {
                            struct airplay_http_edit *edit =
                                &media->edits[media->edit_count++];
                            edit->offset = elst + 16;
                            edit->duration = (uint32_t)(duration - skip_movie);
                            edit->media_time = (uint32_t)(media_time + skip_media);
                        }
                    }
                }
                track += track_size;
            }
            break;
        }
        cursor += size;
    }
    free(data);
    if (media->obj != NULL)
        msg_Dbg(media->obj, "AirPlay HTTP: edit list start %.3f s (%u tracks)",
                start_seconds, media->edit_count);
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

    media->obj = obj;
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

    /* Exact-path registration: unknown tokens never reach the callback and
     * receive the core httpd 404. That rejection is accepted for this
     * tranche (token obscurity); callback still returns 403 if a mismatch
     * somehow reaches it. */
    media->urls[0] = httpd_UrlNew(media->host, media->url_path, NULL, NULL);
    if (media->urls[0] == NULL)
        goto error;
    media->url_count = 1;
    if (httpd_UrlCatch(media->urls[0], HTTPD_MSG_GET, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS ||
        httpd_UrlCatch(media->urls[0], HTTPD_MSG_HEAD, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS)
        goto error;

    return media;

error:
    airplay_http_media_stop(media);
    return NULL;
}

void
airplay_http_media_unpublish(airplay_http_media *media)
{
    if (media == NULL || media->host == NULL)
        return;
    for (unsigned i = 0; i < media->url_count; ++i)
    {
        if (media->urls[i] != NULL)
            httpd_UrlDelete(media->urls[i]);
        media->urls[i] = NULL;
    }
    media->url_count = 0;
    media->url = NULL;
    httpd_HostDelete(media->host);
    media->host = NULL;
}

int
airplay_http_media_republish(airplay_http_media *media)
{
    if (media == NULL || media->obj == NULL || media->url_path == NULL)
        return -1;
    if (media->host != NULL)
        return 0;

    var_Create(media->obj, "http-port", VLC_VAR_INTEGER);
    var_SetInteger(media->obj, "http-port", media->port);

    media->host = vlc_http_HostNew(media->obj);
    if (media->host == NULL)
        return -1;
    media->urls[0] = httpd_UrlNew(media->host, media->url_path, NULL, NULL);
    if (media->urls[0] == NULL)
    {
        httpd_HostDelete(media->host);
        media->host = NULL;
        return -1;
    }
    media->url_count = 1;
    if (httpd_UrlCatch(media->urls[0], HTTPD_MSG_GET, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS ||
        httpd_UrlCatch(media->urls[0], HTTPD_MSG_HEAD, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS)
    {
        httpd_UrlDelete(media->urls[0]);
        media->urls[0] = NULL;
        media->url_count = 0;
        httpd_HostDelete(media->host);
        media->host = NULL;
        return -1;
    }
    if (media->obj != NULL)
        msg_Dbg(media->obj, "AirPlay HTTP: media server listening again");
    return 0;
}

void
airplay_http_media_stop(airplay_http_media *media)
{
    if (media == NULL)
        return;
    airplay_http_media_unpublish(media);
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

    char literal[128];
    const char *host = lan_ip;
    if (strchr(lan_ip, ':') != NULL)
    {
        if (snprintf(literal, sizeof literal, "[%s]", lan_ip) < 0)
            return NULL;
        host = literal;
    }
    return string_format("http://%s:%" PRIu16 "%s", host, media->port,
                         media->url_path);
}

char *
airplay_http_media_reissue(airplay_http_media *media, const char *lan_ip,
                           double start_seconds)
{
    if (media == NULL || media->host == NULL || media->token == NULL ||
        media->url_count >= 24)
        return NULL;

    airplay_http_media_set_start(media, start_seconds);
    unsigned generation = ++media->generation;
    char *path = string_format("/airplay/%s/media-%u.mp4", media->token,
                               generation);
    if (path == NULL)
        return NULL;

    httpd_url_t *url = httpd_UrlNew(media->host, path, NULL, NULL);
    if (url == NULL)
    {
        free(path);
        return NULL;
    }
    if (httpd_UrlCatch(url, HTTPD_MSG_GET, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS ||
        httpd_UrlCatch(url, HTTPD_MSG_HEAD, media_http_callback,
                       (httpd_callback_sys_t *)media) != VLC_SUCCESS)
    {
        httpd_UrlDelete(url);
        free(path);
        return NULL;
    }
    media->urls[media->url_count++] = url;
    free(media->url_path);
    media->url_path = path;
    return airplay_http_media_url(media, lan_ip);
}

#endif
