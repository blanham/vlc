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

enum value_type {
    VALUE_STRING, VALUE_REAL, VALUE_DATA, VALUE_INTEGER, VALUE_BOOL,
    VALUE_DICT, VALUE_ARRAY
};

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
        struct airplay_plist *dict;
        struct {
            struct airplay_plist **items;
            size_t count;
        } array;
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

static const struct plist_entry *
entry_find(const airplay_plist *plist, const char *key);

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
entry_clear_value(struct plist_entry *entry)
{
    if (entry->type == VALUE_STRING)
        free(entry->value.string);
    else if (entry->type == VALUE_DATA)
        free(entry->value.data.bytes);
    else if (entry->type == VALUE_DICT)
        airplay_plist_release(entry->value.dict);
    else if (entry->type == VALUE_ARRAY)
    {
        for (size_t i = 0; i < entry->value.array.count; ++i)
            airplay_plist_release(entry->value.array.items[i]);
        free(entry->value.array.items);
    }
    entry->value.string = NULL;
}

static void
entry_clear(struct plist_entry *entry)
{
    free(entry->key);
    entry_clear_value(entry);
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
            entry_clear_value(&plist->entries[i]);
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
airplay_plist_set_integer(airplay_plist *plist, const char *key, uint64_t value)
{
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
        return -1;
    entry->type = VALUE_INTEGER;
    entry->value.integer = value;
    return 0;
}

int
airplay_plist_set_bool(airplay_plist *plist, const char *key, bool value)
{
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
        return -1;
    entry->type = VALUE_BOOL;
    entry->value.integer = value ? 1 : 0;
    return 0;
}

int
airplay_plist_get_integer(const airplay_plist *plist, const char *key,
                          uint64_t *out)
{
    const struct plist_entry *entry = entry_find(plist, key);
    if (out == NULL || entry == NULL || entry->type != VALUE_INTEGER)
        return -1;
    *out = entry->value.integer;
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

int
airplay_plist_set_dict(airplay_plist *plist, const char *key, airplay_plist *child)
{
    if (child == NULL)
        return -1;
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
    {
        airplay_plist_release(child);
        return -1;
    }
    entry->type = VALUE_DICT;
    entry->value.dict = child;
    return 0;
}

int
airplay_plist_set_dict_array(airplay_plist *plist, const char *key,
                            airplay_plist *item)
{
    if (item == NULL)
        return -1;
    struct airplay_plist **items = malloc(sizeof(*items));
    if (items == NULL)
    {
        airplay_plist_release(item);
        return -1;
    }
    items[0] = item;
    struct plist_entry *entry = entry_prepare(plist, key);
    if (entry == NULL)
    {
        airplay_plist_release(item);
        free(items);
        return -1;
    }
    entry->type = VALUE_ARRAY;
    entry->value.array.items = items;
    entry->value.array.count = 1;
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
    if (entry->type == VALUE_BOOL)
    {
        uint8_t marker = entry->value.integer ? 0x09 : 0x08;
        return buffer_append(buffer, &marker, 1);
    }
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

struct object_writer
{
    struct buffer buffer;
    uint64_t *offsets;
    size_t count;
    size_t capacity;
    unsigned ref_size;
};

static size_t count_dict(const airplay_plist *);

static size_t
count_value(const struct plist_entry *entry)
{
    if (entry->type == VALUE_DICT)
        return entry->value.dict != NULL ? count_dict(entry->value.dict) : 0;
    if (entry->type != VALUE_ARRAY)
        return 1;

    size_t count = 1;
    for (size_t i = 0; i < entry->value.array.count; ++i)
    {
        if (entry->value.array.items[i] == NULL)
            return 0;
        count += count_dict(entry->value.array.items[i]);
    }
    return count;
}

static size_t
count_dict(const airplay_plist *plist)
{
    size_t count = 1;
    for (size_t i = 0; i < plist->count; ++i)
    {
        size_t value = count_value(&plist->entries[i]);
        if (value == 0 || count > SIZE_MAX - 1 - value)
            return 0;
        count += 1 + value;
    }
    return count;
}

static int
writer_add(struct object_writer *writer, uint64_t *ref)
{
    if (writer->count == writer->capacity)
    {
        size_t capacity = writer->capacity != 0 ? writer->capacity * 2 : 16;
        uint64_t *grown = realloc(writer->offsets, capacity * sizeof(*grown));
        if (grown == NULL)
            return -1;
        writer->offsets = grown;
        writer->capacity = capacity;
    }
    writer->offsets[writer->count] = writer->buffer.length;
    *ref = writer->count++;
    return 0;
}

static int write_dict(struct object_writer *, const airplay_plist *, uint64_t *);

static int
write_scalar(struct object_writer *writer, const struct plist_entry *entry,
             uint64_t *ref)
{
    return writer_add(writer, ref) || append_value(&writer->buffer, entry);
}

static int
write_array(struct object_writer *writer, const struct plist_entry *entry,
            uint64_t *ref)
{
    size_t count = entry->value.array.count;
    uint64_t *items = count != 0 ? malloc(count * sizeof(*items)) : NULL;
    if (count != 0 && items == NULL)
        return -1;
    for (size_t i = 0; i < count; ++i)
        if (write_dict(writer, entry->value.array.items[i], &items[i]))
        {
            free(items);
            return -1;
        }
    int rc = writer_add(writer, ref) ||
             append_marker(&writer->buffer, 0xa0, count);
    for (size_t i = 0; rc == 0 && i < count; ++i)
        rc = append_uint(&writer->buffer, items[i], writer->ref_size);
    free(items);
    return rc;
}

static int
write_value(struct object_writer *writer, const struct plist_entry *entry,
            uint64_t *ref)
{
    if (entry->type == VALUE_DICT)
        return write_dict(writer, entry->value.dict, ref);
    if (entry->type == VALUE_ARRAY)
        return write_array(writer, entry, ref);
    return write_scalar(writer, entry, ref);
}

static int
write_dict(struct object_writer *writer, const airplay_plist *plist,
           uint64_t *ref)
{
    if (plist == NULL)
        return -1;
    uint64_t *keys = plist->count != 0 ? malloc(plist->count * sizeof(*keys)) : NULL;
    uint64_t *values = plist->count != 0 ? malloc(plist->count * sizeof(*values)) : NULL;
    if (plist->count != 0 && (keys == NULL || values == NULL))
    {
        free(keys);
        free(values);
        return -1;
    }
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < plist->count; ++i)
        rc = writer_add(writer, &keys[i]) ||
             append_string(&writer->buffer, plist->entries[i].key) ||
             write_value(writer, &plist->entries[i], &values[i]);
    if (rc == 0)
        rc = writer_add(writer, ref) ||
             append_marker(&writer->buffer, 0xd0, plist->count);
    for (size_t i = 0; rc == 0 && i < plist->count; ++i)
        rc = append_uint(&writer->buffer, keys[i], writer->ref_size);
    for (size_t i = 0; rc == 0 && i < plist->count; ++i)
        rc = append_uint(&writer->buffer, values[i], writer->ref_size);
    free(keys);
    free(values);
    return rc;
}

int
airplay_plist_serialize(const airplay_plist *plist, uint8_t **out,
                       size_t *length)
{
    if (plist == NULL || out == NULL || length == NULL)
        return -1;
    size_t objects = count_dict(plist);
    if (objects == 0)
        return -1;

    struct object_writer writer = { .ref_size = uint_size(objects - 1) };
    uint64_t top = 0;
    if (buffer_append(&writer.buffer, "bplist00", 8) ||
        write_dict(&writer, plist, &top) || writer.count != objects)
        goto error;

    uint64_t offset_table = writer.buffer.length;
    unsigned offset_size = uint_size(offset_table);
    for (size_t i = 0; i < writer.count; ++i)
        if (append_uint(&writer.buffer, writer.offsets[i], offset_size))
            goto error;
    uint8_t trailer[8] = { 0, 0, 0, 0, 0, 0, (uint8_t)offset_size,
                           writer.ref_size };
    if (buffer_append(&writer.buffer, trailer, sizeof(trailer)) ||
        append_uint(&writer.buffer, writer.count, 8) ||
        append_uint(&writer.buffer, top, 8) ||
        append_uint(&writer.buffer, offset_table, 8))
        goto error;

    free(writer.offsets);
    *out = writer.buffer.data;
    *length = writer.buffer.length;
    return 0;

error:
    free(writer.offsets);
    free(writer.buffer.data);
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

static int
integer_at(const uint8_t *data, size_t limit, size_t offset, uint64_t *out)
{
    if (offset >= limit || (data[offset] & 0xf0) != 0x10 || (data[offset] & 0xf) > 3)
        return -1;
    unsigned bytes = 1u << (data[offset] & 0xf);
    if (offset + 1 + bytes > limit)
        return -1;
    *out = read_uint(data + offset + 1, bytes);
    return 0;
}

struct plist_scan
{
    const uint8_t *data;
    size_t limit;
    const uint64_t *offsets;
    uint64_t object_count;
    unsigned ref_size;
    const char *key;
    uint64_t *out;
    uint8_t *seen;
};

static int
scan_ref(struct plist_scan *scan, uint64_t ref, int depth)
{
    if (ref >= scan->object_count || depth > 16 || scan->seen[ref])
        return -1;
    scan->seen[ref] = 1;
    uint64_t offset = scan->offsets[ref];
    if (offset >= scan->limit)
        return -1;
    uint8_t marker = scan->data[offset];
    if ((marker & 0xf0) != 0xd0 && (marker & 0xf0) != 0xa0)
        return -1;

    size_t position = (size_t)offset + 1;
    uint64_t count;
    if (read_length(scan->data, scan->limit, &position, marker, &count))
        return -1;
    bool is_dict = (marker & 0xf0) == 0xd0;
    uint64_t slots = is_dict ? count * 2 : count;
    if (scan->ref_size == 0 || slots > (scan->limit - position) / scan->ref_size)
        return -1;

    for (uint64_t i = 0; i < count; ++i)
    {
        uint64_t value_ref;
        if (is_dict)
        {
            uint64_t key_ref =
                read_uint(scan->data + position + i * scan->ref_size,
                          scan->ref_size);
            value_ref = read_uint(scan->data + position + (count + i) * scan->ref_size,
                                  scan->ref_size);
            if (key_ref >= scan->object_count || value_ref >= scan->object_count)
                continue;
            char *key = parse_string(scan->data, scan->limit,
                                    (size_t)scan->offsets[key_ref]);
            if (key != NULL && strcmp(key, scan->key) == 0 &&
                integer_at(scan->data, scan->limit,
                           (size_t)scan->offsets[value_ref], scan->out) == 0)
            {
                free(key);
                return 0;
            }
            free(key);
        }
        else
        {
            value_ref = read_uint(scan->data + position + i * scan->ref_size,
                                  scan->ref_size);
            if (value_ref >= scan->object_count)
                continue;
        }
        if (scan_ref(scan, value_ref, depth + 1) == 0)
            return 0;
    }
    return -1;
}

int
airplay_plist_find_integer(const uint8_t *data, size_t length, const char *key,
                           uint64_t *out)
{
    if (data == NULL || key == NULL || out == NULL || length < 40 ||
        memcmp(data, "bplist00", 8) != 0)
        return -1;
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
        return -1;

    uint64_t *offsets = malloc((size_t)object_count * sizeof(*offsets));
    uint8_t *seen = calloc((size_t)object_count, 1);
    if (offsets == NULL || seen == NULL)
    {
        free(offsets);
        free(seen);
        return -1;
    }
    for (uint64_t i = 0; i < object_count; ++i)
        offsets[i] = read_uint(data + offset_table + i * offset_size, offset_size);

    struct plist_scan scan = {
        .data = data,
        .limit = (size_t)offset_table,
        .offsets = offsets,
        .object_count = object_count,
        .ref_size = ref_size,
        .key = key,
        .out = out,
        .seen = seen,
    };
    int rc = scan_ref(&scan, top, 0);
    free(offsets);
    free(seen);
    return rc;
}
