/*****************************************************************************
 * plist.c: minimal binary property list helper for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include "plist.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum value_type { VALUE_STRING, VALUE_REAL, VALUE_DATA, VALUE_INTEGER };

struct plist_entry
{
    char *key;
    enum value_type type;
    union {
        char *string;
        double real;
        struct {
            uint8_t *bytes;
            size_t length;
        } data;
        uint64_t integer;
    } value;
};

struct airplay_plist
{
    struct plist_entry *entries;
    size_t count;
};

struct buffer
{
    uint8_t *data;
    size_t length;
    size_t capacity;
};

static char *
string_dup(const char *value)
{
    size_t length = strlen(value) + 1;
    char *copy = malloc(length);
    if (copy != NULL)
        memcpy(copy, value, length);
    return copy;
}

static void
entry_clear(struct plist_entry *entry)
{
    free(entry->key);
    if (entry->type == VALUE_STRING)
        free(entry->value.string);
    else if (entry->type == VALUE_DATA)
        free(entry->value.data.bytes);
}

airplay_plist *
airplay_plist_new(void)
{
    return calloc(1, sizeof(airplay_plist));
}

void
airplay_plist_release(airplay_plist *plist)
{
    if (plist == NULL)
        return;
    for (size_t i = 0; i < plist->count; ++i)
        entry_clear(&plist->entries[i]);
    free(plist->entries);
    free(plist);
}

static struct plist_entry *
entry_prepare(airplay_plist *plist, const char *key)
{
    if (plist == NULL || key == NULL)
        return NULL;
    for (size_t i = 0; i < plist->count; ++i)
        if (strcmp(plist->entries[i].key, key) == 0)
        {
            if (plist->entries[i].type == VALUE_STRING)
                free(plist->entries[i].value.string);
            else if (plist->entries[i].type == VALUE_DATA)
                free(plist->entries[i].value.data.bytes);
            return &plist->entries[i];
        }

    struct plist_entry *entries =
        realloc(plist->entries, (plist->count + 1) * sizeof(*entries));
    if (entries == NULL)
        return NULL;
    plist->entries = entries;
    struct plist_entry *entry = &entries[plist->count];
    memset(entry, 0, sizeof(*entry));
    entry->key = string_dup(key);
    if (entry->key == NULL)
        return NULL;
    plist->count++;
    return entry;
}

int
airplay_plist_set_string(airplay_plist *plist, const char *key, const char *value)
{
    if (value == NULL)
        return -1;
    char *copy = string_dup(value);
    if (copy == NULL)
        return -1;
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
    {
        free(copy);
        return -1;
    }
    entry->type = VALUE_STRING;
    entry->value.string = copy;
    return 0;
}

int
airplay_plist_set_real(airplay_plist *plist, const char *key, double value)
{
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
        return -1;
    entry->type = VALUE_REAL;
    entry->value.real = value;
    return 0;
}

int
airplay_plist_set_data(airplay_plist *plist, const char *key, const void *data,
                       size_t length)
{
    if (data == NULL && length != 0)
        return -1;
    uint8_t *copy = length != 0 ? malloc(length) : NULL;
    if (length != 0 && copy == NULL)
        return -1;
    if (length != 0)
        memcpy(copy, data, length);
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
    {
        free(copy);
        return -1;
    }
    entry->type = VALUE_DATA;
    entry->value.data.bytes = copy;
    entry->value.data.length = length;
    return 0;
}

static const struct plist_entry *
entry_find(const airplay_plist *plist, const char *key)
{
    if (plist != NULL && key != NULL)
        for (size_t i = 0; i < plist->count; ++i)
            if (strcmp(plist->entries[i].key, key) == 0)
                return &plist->entries[i];
    return NULL;
}

int
airplay_plist_get_string(const airplay_plist *plist, const char *key, char **out)
{
    const struct plist_entry *entry = entry_find(plist, key);
    if (out == NULL || entry == NULL || entry->type != VALUE_STRING)
        return -1;
    *out = string_dup(entry->value.string);
    return *out != NULL ? 0 : -1;
}

int
airplay_plist_get_data(const airplay_plist *plist, const char *key,
                       uint8_t **out, size_t *length)
{
    const struct plist_entry *entry = entry_find(plist, key);
    if (out == NULL || length == NULL || entry == NULL ||
        entry->type != VALUE_DATA)
        return -1;
    size_t size = entry->value.data.length;
    uint8_t *copy = size != 0 ? malloc(size) : NULL;
    if (size != 0 && copy == NULL)
        return -1;
    if (size != 0)
        memcpy(copy, entry->value.data.bytes, size);
    *out = copy;
    *length = size;
    return 0;
}

static int
buffer_append(struct buffer *buffer, const void *data, size_t length)
{
    if (length > SIZE_MAX - buffer->length)
        return -1;
    size_t needed = buffer->length + length;
    if (needed > buffer->capacity)
    {
        size_t capacity = buffer->capacity != 0 ? buffer->capacity : 128;
        while (capacity < needed)
        {
            if (capacity > SIZE_MAX / 2)
                capacity = needed;
            else
                capacity *= 2;
        }
        uint8_t *grown = realloc(buffer->data, capacity);
        if (grown == NULL)
            return -1;
        buffer->data = grown;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length = needed;
    return 0;
}

static int
append_uint(struct buffer *buffer, uint64_t value, unsigned bytes)
{
    uint8_t encoded[8];
    for (unsigned i = 0; i < bytes; ++i)
        encoded[bytes - i - 1] = (uint8_t)(value >> (i * 8));
    return buffer_append(buffer, encoded, bytes);
}

static unsigned
uint_size(uint64_t value)
{
    if (value <= UINT8_MAX)
        return 1;
    if (value <= UINT16_MAX)
        return 2;
    if (value <= UINT32_MAX)
        return 4;
    return 8;
}

static int
append_marker(struct buffer *buffer, uint8_t type, size_t length)
{
    if (length < 15)
    {
        uint8_t marker = type | (uint8_t)length;
        return buffer_append(buffer, &marker, 1);
    }
    unsigned bytes = uint_size(length);
    uint8_t marker[2] = { (uint8_t)(type | 0xf),
                         (uint8_t)(0x10 | (bytes == 1 ? 0 :
                                          bytes == 2 ? 1 :
                                          bytes == 4 ? 2 : 3)) };
    return buffer_append(buffer, marker, 2) ||
           append_uint(buffer, length, bytes);
}

static int
utf8_next(const uint8_t **cursor, const uint8_t *end, uint32_t *codepoint)
{
    if (*cursor >= end)
        return -1;
    uint8_t first = *(*cursor)++;
    if (first < 0x80)
    {
        *codepoint = first;
        return 0;
    }
    unsigned extra = first < 0xe0 ? 1 : first < 0xf0 ? 2 : 3;
    uint32_t value = first & (0x7f >> extra);
    if (first < 0xc2 || first > 0xf4 || (size_t)(end - *cursor) < extra)
        return -1;
    for (unsigned i = 0; i < extra; ++i)
    {
        uint8_t byte = *(*cursor)++;
        if ((byte & 0xc0) != 0x80)
            return -1;
        value = (value << 6) | (byte & 0x3f);
    }
    if ((extra == 2 && value < 0x800) || (extra == 3 && value < 0x10000) ||
        (value >= 0xd800 && value <= 0xdfff) || value > 0x10ffff)
        return -1;
    *codepoint = value;
    return 0;
}

static int
append_string(struct buffer *buffer, const char *string)
{
    const uint8_t *start = (const uint8_t *)string;
    const uint8_t *end = start + strlen(string);
    bool ascii = true;
    for (const uint8_t *p = start; p < end; ++p)
        ascii &= *p < 0x80;
    if (ascii)
        return append_marker(buffer, 0x50, (size_t)(end - start)) ||
               buffer_append(buffer, start, (size_t)(end - start));

    size_t units = 0;
    const uint8_t *cursor = start;
    uint32_t codepoint;
    while (cursor < end)
    {
        if (utf8_next(&cursor, end, &codepoint))
            return -1;
        units += codepoint < 0x10000 ? 1 : 2;
    }
    if (append_marker(buffer, 0x60, units))
        return -1;
    cursor = start;
    while (cursor < end)
    {
        utf8_next(&cursor, end, &codepoint);
        if (codepoint < 0x10000)
        {
            if (append_uint(buffer, codepoint, 2))
                return -1;
        }
        else
        {
            codepoint -= 0x10000;
            if (append_uint(buffer, 0xd800 | (codepoint >> 10), 2) ||
                append_uint(buffer, 0xdc00 | (codepoint & 0x3ff), 2))
                return -1;
        }
    }
    return 0;
}

static int
append_value(struct buffer *buffer, const struct plist_entry *entry)
{
    if (entry->type == VALUE_STRING)
        return append_string(buffer, entry->value.string);
    if (entry->type == VALUE_DATA)
        return append_marker(buffer, 0x40, entry->value.data.length) ||
               buffer_append(buffer, entry->value.data.bytes,
                             entry->value.data.length);
    if (entry->type == VALUE_REAL)
    {
        uint64_t bits;
        memcpy(&bits, &entry->value.real, sizeof(bits));
        uint8_t marker = 0x23;
        return buffer_append(buffer, &marker, 1) ||
               append_uint(buffer, bits, 8);
    }
    unsigned bytes = uint_size(entry->value.integer);
    uint8_t marker = (uint8_t)(0x10 | (bytes == 1 ? 0 : bytes == 2 ? 1 :
                                      bytes == 4 ? 2 : 3));
    return buffer_append(buffer, &marker, 1) ||
           append_uint(buffer, entry->value.integer, bytes);
}

int
airplay_plist_serialize(const airplay_plist *plist, uint8_t **out,
                       size_t *length)
{
    if (plist == NULL || out == NULL || length == NULL ||
        plist->count > (UINT64_MAX - 1) / 2)
        return -1;
    uint64_t object_count = plist->count * 2 + 1;
    unsigned ref_size = uint_size(object_count - 1);
    struct buffer buffer = { 0 };
    size_t *offsets = malloc((size_t)object_count * sizeof(*offsets));
    if (offsets == NULL || buffer_append(&buffer, "bplist00", 8))
        goto error;

    for (size_t i = 0; i < plist->count; ++i)
    {
        offsets[i] = buffer.length;
        if (append_string(&buffer, plist->entries[i].key))
            goto error;
    }
    for (size_t i = 0; i < plist->count; ++i)
    {
        offsets[plist->count + i] = buffer.length;
        if (append_value(&buffer, &plist->entries[i]))
            goto error;
    }
    offsets[object_count - 1] = buffer.length;
    if (append_marker(&buffer, 0xd0, plist->count))
        goto error;
    for (size_t i = 0; i < plist->count; ++i)
        if (append_uint(&buffer, i, ref_size))
            goto error;
    for (size_t i = 0; i < plist->count; ++i)
        if (append_uint(&buffer, plist->count + i, ref_size))
            goto error;

    uint64_t offset_table = buffer.length;
    unsigned offset_size = uint_size(offset_table);
    for (uint64_t i = 0; i < object_count; ++i)
        if (append_uint(&buffer, offsets[i], offset_size))
            goto error;
    uint8_t trailer[8] = { 0, 0, 0, 0, 0, 0, (uint8_t)offset_size,
                           (uint8_t)ref_size };
    if (buffer_append(&buffer, trailer, sizeof(trailer)) ||
        append_uint(&buffer, object_count, 8) ||
        append_uint(&buffer, object_count - 1, 8) ||
        append_uint(&buffer, offset_table, 8))
        goto error;

    free(offsets);
    *out = buffer.data;
    *length = buffer.length;
    return 0;

error:
    free(offsets);
    free(buffer.data);
    return -1;
}

static uint64_t
read_uint(const uint8_t *data, unsigned bytes)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < bytes; ++i)
        value = (value << 8) | data[i];
    return value;
}

static int
read_length(const uint8_t *data, size_t limit, size_t *position,
            uint8_t marker, uint64_t *length)
{
    if ((marker & 0xf) != 0xf)
    {
        *length = marker & 0xf;
        return 0;
    }
    if (*position >= limit || (data[*position] & 0xf0) != 0x10)
        return -1;
    unsigned power = data[(*position)++] & 0xf;
    if (power > 3)
        return -1;
    unsigned bytes = 1u << power;
    if (bytes > limit - *position)
        return -1;
    *length = read_uint(data + *position, bytes);
    *position += bytes;
    return 0;
}

static char *
parse_string(const uint8_t *data, size_t limit, size_t position)
{
    if (position >= limit ||
        ((data[position] & 0xf0) != 0x50 &&
         (data[position] & 0xf0) != 0x60))
        return NULL;
    uint8_t marker = data[position++];
    uint64_t length;
    bool unicode = (marker & 0xf0) == 0x60;
    if (read_length(data, limit, &position, marker, &length) ||
        length > (limit - position) / (unicode ? 2 : 1) ||
        length > (SIZE_MAX - 1) / 3)
        return NULL;
    if (!unicode)
    {
        char *string = malloc((size_t)length + 1);
        if (string != NULL)
        {
            memcpy(string, data + position, (size_t)length);
            string[length] = '\0';
        }
        return string;
    }

    char *string = malloc((size_t)length * 3 + 1);
    if (string == NULL)
        return NULL;
    size_t output = 0;
    for (uint64_t i = 0; i < length; ++i)
    {
        uint32_t codepoint = read_uint(data + position + i * 2, 2);
        if (codepoint >= 0xd800 && codepoint <= 0xdbff)
        {
            if (++i >= length)
                goto invalid;
            uint32_t low = read_uint(data + position + i * 2, 2);
            if (low < 0xdc00 || low > 0xdfff)
                goto invalid;
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
                        (low - 0xdc00);
        }
        else if (codepoint >= 0xdc00 && codepoint <= 0xdfff)
            goto invalid;
        if (codepoint < 0x80)
            string[output++] = (char)codepoint;
        else if (codepoint < 0x800)
        {
            string[output++] = (char)(0xc0 | (codepoint >> 6));
            string[output++] = (char)(0x80 | (codepoint & 0x3f));
        }
        else if (codepoint < 0x10000)
        {
            string[output++] = (char)(0xe0 | (codepoint >> 12));
            string[output++] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
            string[output++] = (char)(0x80 | (codepoint & 0x3f));
        }
        else
        {
            string[output++] = (char)(0xf0 | (codepoint >> 18));
            string[output++] = (char)(0x80 | ((codepoint >> 12) & 0x3f));
            string[output++] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
            string[output++] = (char)(0x80 | (codepoint & 0x3f));
        }
    }
    string[output] = '\0';
    return string;

invalid:
    free(string);
    return NULL;
}

airplay_plist *
airplay_plist_parse(const uint8_t *data, size_t length)
{
    if (data == NULL || length < 40 || memcmp(data, "bplist00", 8) != 0)
        return NULL;
    const uint8_t *trailer = data + length - 32;
    unsigned offset_size = trailer[6], ref_size = trailer[7];
    uint64_t object_count = read_uint(trailer + 8, 8);
    uint64_t top = read_uint(trailer + 16, 8);
    uint64_t offset_table = read_uint(trailer + 24, 8);
    if ((offset_size != 1 && offset_size != 2 && offset_size != 4 &&
         offset_size != 8) ||
        (ref_size != 1 && ref_size != 2 && ref_size != 4 && ref_size != 8) ||
        object_count == 0 || top >= object_count || offset_table < 8 ||
        offset_table > length - 32 ||
        object_count > (length - 32 - offset_table) / offset_size)
        return NULL;

#define OBJECT_OFFSET(ref) read_uint(data + offset_table + (ref) * offset_size, \
                                     offset_size)
    uint64_t dict_offset = OBJECT_OFFSET(top);
    if (dict_offset >= offset_table || (data[dict_offset] & 0xf0) != 0xd0)
        return NULL;
    size_t position = (size_t)dict_offset + 1;
    uint64_t count;
    if (read_length(data, offset_table, &position, data[dict_offset], &count) ||
        count > (offset_table - position) / (2 * ref_size))
        return NULL;

    airplay_plist *plist = airplay_plist_new();
    if (plist == NULL)
        return NULL;
    for (uint64_t i = 0; i < count; ++i)
    {
        uint64_t key_ref = read_uint(data + position + i * ref_size, ref_size);
        uint64_t value_ref =
            read_uint(data + position + (count + i) * ref_size, ref_size);
        if (key_ref >= object_count || value_ref >= object_count)
            goto error;
        uint64_t key_offset = OBJECT_OFFSET(key_ref);
        uint64_t value_offset = OBJECT_OFFSET(value_ref);
        if (key_offset >= offset_table || value_offset >= offset_table)
            goto error;
        char *key = parse_string(data, offset_table, (size_t)key_offset);
        if (key == NULL)
            goto error;
        size_t value_position = (size_t)value_offset + 1;
        uint8_t marker = data[value_offset];
        uint64_t value_length;
        int result = -1;
        if ((marker & 0xf0) == 0x50 || (marker & 0xf0) == 0x60)
        {
            char *value = parse_string(data, offset_table, value_offset);
            if (value != NULL)
            {
                result = airplay_plist_set_string(plist, key, value);
                free(value);
            }
        }
        else if ((marker & 0xf0) == 0x40 &&
                 !read_length(data, offset_table, &value_position, marker,
                              &value_length) &&
                 value_length <= offset_table - value_position)
            result = airplay_plist_set_data(plist, key, data + value_position,
                                           (size_t)value_length);
        else if (marker == 0x23 && offset_table - value_position >= 8)
        {
            uint64_t bits = read_uint(data + value_position, 8);
            double value;
            memcpy(&value, &bits, sizeof(value));
            result = airplay_plist_set_real(plist, key, value);
        }
        else if ((marker & 0xf0) == 0x10 && (marker & 0xf) <= 3)
        {
            unsigned bytes = 1u << (marker & 0xf);
            if (bytes <= offset_table - value_position)
            {
                struct plist_entry *entry = entry_prepare(plist, key);
                if (entry != NULL)
                {
                    entry->type = VALUE_INTEGER;
                    entry->value.integer =
                        read_uint(data + value_position, bytes);
                    result = 0;
                }
            }
        }
        free(key);
        if (result != 0)
            goto error;
    }
#undef OBJECT_OFFSET
    return plist;

error:
#undef OBJECT_OFFSET
    airplay_plist_release(plist);
    return NULL;
}
