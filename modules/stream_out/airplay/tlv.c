/*****************************************************************************
 * tlv.c: HAP TLV8 encode/decode for AirPlay pairing
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include "tlv.h"

#include <stdlib.h>
#include <string.h>

void
hap_tlv_buf_init(hap_tlv_buf *buf)
{
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

void
hap_tlv_buf_clear(hap_tlv_buf *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

static int
buf_grow(hap_tlv_buf *buf, size_t need)
{
    if (buf->len + need <= buf->cap)
        return 0;

    size_t cap = buf->cap != 0 ? buf->cap : 64;
    while (cap < buf->len + need)
        cap *= 2;

    uint8_t *grown = realloc(buf->data, cap);
    if (grown == NULL)
        return -1;

    buf->data = grown;
    buf->cap = cap;
    return 0;
}

int
hap_tlv_buf_add(hap_tlv_buf *buf, uint8_t type, const void *data, size_t len)
{
    const uint8_t *bytes = data;

    for (size_t offset = 0; offset < len || (len == 0 && offset == 0);)
    {
        size_t chunk = len - offset;
        if (chunk > HAP_TLV_MAX_VALUE)
            chunk = HAP_TLV_MAX_VALUE;

        if (buf_grow(buf, 2 + chunk) != 0)
            return -1;

        buf->data[buf->len++] = type;
        buf->data[buf->len++] = (uint8_t)chunk;
        if (chunk > 0)
        {
            memcpy(buf->data + buf->len, bytes + offset, chunk);
            buf->len += chunk;
        }

        offset += chunk;
        if (len == 0)
            break;
    }
    return 0;
}

int
hap_tlv_buf_finish(hap_tlv_buf *buf, uint8_t **out, size_t *out_len)
{
    if (out == NULL || out_len == NULL)
        return -1;

    *out = buf->data;
    *out_len = buf->len;
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
    return 0;
}

static size_t
tlv_value_length(const uint8_t *data, size_t len, uint8_t type)
{
    size_t total = 0;

    for (size_t i = 0; i + 2 <= len;)
    {
        uint8_t t = data[i];
        uint8_t l = data[i + 1];
        i += 2;
        if (i + l > len)
            break;
        if (t == type)
            total += l;
        i += l;
    }
    return total;
}

int
hap_tlv_get(const uint8_t *data, size_t len, uint8_t type,
            uint8_t **out, size_t *out_len)
{
    if (out == NULL || out_len == NULL)
        return -1;

    size_t total = tlv_value_length(data, len, type);
    if (total == 0)
        return -1;

    uint8_t *value = malloc(total);
    if (value == NULL)
        return -1;

    size_t written = 0;
    for (size_t i = 0; i + 2 <= len;)
    {
        uint8_t t = data[i];
        uint8_t l = data[i + 1];
        i += 2;
        if (i + l > len)
            break;
        if (t == type)
        {
            memcpy(value + written, data + i, l);
            written += l;
        }
        i += l;
    }

    *out = value;
    *out_len = written;
    return 0;
}

uint8_t
hap_tlv_get_u8(const uint8_t *data, size_t len, uint8_t type, bool *ok)
{
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (ok != NULL)
        *ok = false;
    if (hap_tlv_get(data, len, type, &value, &value_len) != 0 || value_len != 1)
    {
        free(value);
        return 0;
    }

    uint8_t byte = value[0];
    free(value);
    if (ok != NULL)
        *ok = true;
    return byte;
}

bool
hap_tlv_has(const uint8_t *data, size_t len, uint8_t type)
{
    return tlv_value_length(data, len, type) > 0;
}
