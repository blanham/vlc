/*****************************************************************************
 * airplay_discovery.c: AirPlay/RAOP DNS-SD parsing and device aggregation
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "airplay_discovery.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *
airplay_strdup_printf(const char *fmt, ...)
{
    va_list ap;
    int needed;
    char *buf;

    va_start(ap, fmt);
    needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0)
        return NULL;

    buf = malloc((size_t)needed + 1);
    if (buf == NULL)
        return NULL;

    va_start(ap, fmt);
    vsnprintf(buf, (size_t)needed + 1, fmt, ap);
    va_end(ap);
    return buf;
}

/* Selected AirPlay feature bits from public documentation / traces.
 * Kept private to discovery; not mapped wholesale into VLC flags. */
enum
{
    AIRPLAY_FEATURE_VIDEO = 1ull << 0,
    AIRPLAY_FEATURE_AUDIO = 1ull << 9,
    AIRPLAY_FEATURE_SCREEN = 1ull << 7,
};

void
airplay_endpoint_clear(struct airplay_endpoint *ep)
{
    free(ep->host);
    ep->host = NULL;
    ep->port = 0;
    ep->ipv6 = false;
    ep->valid = false;
}

int
airplay_endpoint_set(struct airplay_endpoint *ep, const char *host,
                     uint16_t port, bool ipv6)
{
    char *copy;

    if (host == NULL || host[0] == '\0' || port == 0)
        return -1;

    copy = strdup(host);
    if (copy == NULL)
        return -1;

    free(ep->host);
    ep->host = copy;
    ep->port = port;
    ep->ipv6 = ipv6;
    ep->valid = true;
    return 0;
}

void
airplay_device_init(struct airplay_discovered_device *dev)
{
    memset(dev, 0, sizeof(*dev));
}

void
airplay_device_clear(struct airplay_discovered_device *dev)
{
    free(dev->stable_id);
    free(dev->display_name);
    free(dev->model);
    free(dev->srcvers);
    free(dev->protovers);
    free(dev->deviceid);
    free(dev->raop_hwid);
    airplay_endpoint_clear(&dev->airplay);
    airplay_endpoint_clear(&dev->raop);
    memset(dev, 0, sizeof(*dev));
}

void
airplay_device_table_init(struct airplay_device_table *table)
{
    table->devices = NULL;
    table->count = 0;
}

void
airplay_device_table_clear(struct airplay_device_table *table)
{
    for (size_t i = 0; i < table->count; i++)
    {
        airplay_device_clear(table->devices[i]);
        free(table->devices[i]);
    }
    free(table->devices);
    table->devices = NULL;
    table->count = 0;
}

static int
hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

char *
airplay_normalize_device_id(const char *raw)
{
    size_t len;
    size_t out_len = 0;
    char *out;

    if (raw == NULL)
        return NULL;

    len = strlen(raw);
    out = malloc(len + 1);
    if (out == NULL)
        return NULL;

    for (size_t i = 0; i < len; i++)
    {
        int n = hex_nibble(raw[i]);
        if (n < 0)
            continue;
        out[out_len++] = (char)toupper((unsigned char)raw[i]);
    }
    out[out_len] = '\0';

    if (out_len == 0)
    {
        free(out);
        return NULL;
    }
    return out;
}

char *
airplay_raop_hwid_from_instance(const char *instance_name)
{
    const char *at;
    char *prefix;
    char *normalized;
    size_t n;

    if (instance_name == NULL)
        return NULL;

    at = strchr(instance_name, '@');
    if (at == NULL || at == instance_name)
        return NULL;

    n = (size_t)(at - instance_name);
    prefix = malloc(n + 1);
    if (prefix == NULL)
        return NULL;
    memcpy(prefix, instance_name, n);
    prefix[n] = '\0';

    normalized = airplay_normalize_device_id(prefix);
    free(prefix);
    return normalized;
}

bool
airplay_identity_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return false;
    return strcmp(a, b) == 0;
}

static int
parse_u32_token(const char *s, char **end, uint32_t *out)
{
    unsigned long long v;
    char *ep = NULL;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        v = strtoull(s, &ep, 16);
    else
        v = strtoull(s, &ep, 0);

    if (errno != 0 || ep == s || v > 0xffffffffull)
        return -1;

    *end = ep;
    *out = (uint32_t)v;
    return 0;
}

int
airplay_parse_u64(const char *value, uint64_t *out)
{
    unsigned long long v;
    char *ep = NULL;

    if (value == NULL || value[0] == '\0' || out == NULL)
        return -1;

    errno = 0;
    v = strtoull(value, &ep, 0);
    if (errno != 0 || ep == value || *ep != '\0')
        return -1;

    *out = (uint64_t)v;
    return 0;
}

int
airplay_parse_features(const char *value, uint64_t *out)
{
    const char *comma;
    uint32_t low = 0;
    uint32_t high = 0;
    char *ep = NULL;
    char *copy;
    char *second;

    if (value == NULL || value[0] == '\0' || out == NULL)
        return -1;

    comma = strchr(value, ',');
    if (comma == NULL)
        return airplay_parse_u64(value, out);

    /* Public advertisements use "low,high" 32-bit halves. */
    copy = strdup(value);
    if (copy == NULL)
        return -1;

    second = strchr(copy, ',');
    if (second == NULL)
    {
        free(copy);
        return -1;
    }
    *second++ = '\0';

    if (parse_u32_token(copy, &ep, &low) != 0 || *ep != '\0')
    {
        free(copy);
        return -1;
    }
    if (parse_u32_token(second, &ep, &high) != 0 || *ep != '\0')
    {
        free(copy);
        return -1;
    }

    free(copy);
    *out = ((uint64_t)high << 32) | (uint64_t)low;
    return 0;
}

int
airplay_parse_public_key(const char *value, uint8_t out[AIRPLAY_PK_SIZE])
{
    size_t len;

    if (value == NULL || out == NULL)
        return -1;

    len = strlen(value);
    if (len != AIRPLAY_PK_SIZE * 2)
        return -1;

    for (size_t i = 0; i < AIRPLAY_PK_SIZE; i++)
    {
        int hi = hex_nibble(value[i * 2]);
        int lo = hex_nibble(value[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int
replace_string(char **dst, const char *value)
{
    char *copy;

    if (value == NULL)
        return -1;
    copy = strdup(value);
    if (copy == NULL)
        return -1;
    free(*dst);
    *dst = copy;
    return 0;
}

static const char *
txt_value(const char *txt, const char *key, size_t key_len)
{
    if (strncmp(txt, key, key_len) != 0 || txt[key_len] != '=')
        return NULL;
    return txt + key_len + 1;
}

int
airplay_apply_txt_record(struct airplay_discovered_device *dev,
                         bool is_raop, const char *txt)
{
    const char *val;
    uint64_t u64;
    uint8_t pk[AIRPLAY_PK_SIZE];
    char *norm;

    if (dev == NULL || txt == NULL || txt[0] == '\0')
        return -1;

    if (!is_raop)
    {
        if ((val = txt_value(txt, "deviceid", 8)) != NULL
         || (val = txt_value(txt, "deviceId", 8)) != NULL)
        {
            norm = airplay_normalize_device_id(val);
            if (norm == NULL)
                return -1;
            free(dev->deviceid);
            dev->deviceid = norm;
            return 0;
        }
        if ((val = txt_value(txt, "features", 8)) != NULL)
        {
            if (airplay_parse_features(val, &u64) != 0)
                return -1;
            dev->features = u64;
            dev->has_features = true;
            return 0;
        }
        if ((val = txt_value(txt, "flags", 5)) != NULL
         || (val = txt_value(txt, "statusFlags", 11)) != NULL
         || (val = txt_value(txt, "statusflags", 11)) != NULL)
        {
            if (airplay_parse_features(val, &u64) != 0)
                return -1;
            dev->status_flags = u64;
            dev->has_status_flags = true;
            return 0;
        }
        if ((val = txt_value(txt, "model", 5)) != NULL)
            return replace_string(&dev->model, val);
        if ((val = txt_value(txt, "srcvers", 7)) != NULL)
            return replace_string(&dev->srcvers, val);
        if ((val = txt_value(txt, "protovers", 9)) != NULL)
            return replace_string(&dev->protovers, val);
        if ((val = txt_value(txt, "pk", 2)) != NULL)
        {
            if (airplay_parse_public_key(val, pk) != 0)
                return -1;
            memcpy(dev->public_key, pk, AIRPLAY_PK_SIZE);
            dev->has_public_key = true;
            return 0;
        }
        if ((val = txt_value(txt, "pw", 2)) != NULL)
        {
            if (val[0] == '1' || strcmp(val, "true") == 0)
                dev->password_required = true;
            return 0;
        }
        /* pi / gid / group fields intentionally ignored for now except that
         * presence must not crash; keep no unbounded metadata store. */
        return 0;
    }

    /* RAOP */
    if ((val = txt_value(txt, "am", 2)) != NULL)
    {
        if (dev->model == NULL)
            return replace_string(&dev->model, val);
        return 0;
    }
    if ((val = txt_value(txt, "ft", 2)) != NULL
     || (val = txt_value(txt, "features", 8)) != NULL)
    {
        if (airplay_parse_features(val, &u64) != 0)
            return -1;
        /* Prefer AirPlay features when both exist; otherwise keep RAOP. */
        if (!dev->has_features)
        {
            dev->features = u64;
            dev->has_features = true;
        }
        return 0;
    }
    if ((val = txt_value(txt, "sf", 2)) != NULL)
    {
        if (airplay_parse_features(val, &u64) != 0)
            return -1;
        if (!dev->has_status_flags)
        {
            dev->status_flags = u64;
            dev->has_status_flags = true;
        }
        return 0;
    }
    if ((val = txt_value(txt, "pk", 2)) != NULL)
    {
        if (airplay_parse_public_key(val, pk) != 0)
            return -1;
        if (!dev->has_public_key)
        {
            memcpy(dev->public_key, pk, AIRPLAY_PK_SIZE);
            dev->has_public_key = true;
        }
        return 0;
    }
    if ((val = txt_value(txt, "pw", 2)) != NULL)
    {
        if (val[0] == '1' || strcmp(val, "true") == 0)
            dev->password_required = true;
        return 0;
    }
    if ((val = txt_value(txt, "vs", 2)) != NULL)
    {
        if (dev->srcvers == NULL)
            return replace_string(&dev->srcvers, val);
        return 0;
    }
    /* ch/cn/et/md/sr/ss/tp/txtvers/vn kept out of generic store. */
    (void)txt_value;
    return 0;
}

void
airplay_refresh_capabilities(struct airplay_discovered_device *dev)
{
    /* Conservative mapping:
     *  - _raop presence is strong audio evidence
     *  - video only when AirPlay service exists and feature bits justify it
     * Do not infer support from a single stale bit without service context.
     */
    dev->supports_audio = false;
    dev->supports_video = false;

    if (dev->raop.valid)
        dev->supports_audio = true;

    if (dev->airplay.valid)
    {
        if (dev->has_features)
        {
            if (dev->features & AIRPLAY_FEATURE_AUDIO)
                dev->supports_audio = true;
            if (dev->features & (AIRPLAY_FEATURE_VIDEO | AIRPLAY_FEATURE_SCREEN))
                dev->supports_video = true;
        }
        else
        {
            /* AirPlay service without features: audio is common; do not claim
             * video until features justify it. */
            dev->supports_audio = true;
        }
    }

    if (dev->has_status_flags)
    {
        /* statusFlags bit 0x8 commonly indicates PIN required on modern
         * receivers; treat conservatively as pin_required hint only. */
        if (dev->status_flags & 0x8ull)
            dev->pin_required = true;
    }
}

static char *
pk_fingerprint(const uint8_t pk[AIRPLAY_PK_SIZE])
{
    /* Use the first 8 bytes as a stable fingerprint label (not a secret). */
    char *out = malloc(3 + 16 + 1);
    if (out == NULL)
        return NULL;
    snprintf(out, 3 + 16 + 1,
             "pk:%02X%02X%02X%02X%02X%02X%02X%02X",
             pk[0], pk[1], pk[2], pk[3], pk[4], pk[5], pk[6], pk[7]);
    return out;
}

char *
airplay_derive_stable_id(const struct airplay_discovered_device *dev,
                         const char *dns_fallback)
{
    if (dev->deviceid != NULL && dev->deviceid[0] != '\0')
        return airplay_strdup_printf("airplay:%s", dev->deviceid);
    if (dev->raop_hwid != NULL && dev->raop_hwid[0] != '\0')
        return airplay_strdup_printf("raop:%s", dev->raop_hwid);
    if (dev->has_public_key)
        return pk_fingerprint(dev->public_key);

    if (dns_fallback != NULL && dns_fallback[0] != '\0')
        return airplay_strdup_printf("dnssd:%s", dns_fallback);
    return NULL;
}

static bool
identity_overlap(const struct airplay_discovered_device *a,
                 const struct airplay_discovered_device *b)
{
    if (airplay_identity_equal(a->deviceid, b->deviceid))
        return true;
    if (airplay_identity_equal(a->raop_hwid, b->raop_hwid))
        return true;
    if (airplay_identity_equal(a->deviceid, b->raop_hwid))
        return true;
    if (airplay_identity_equal(a->raop_hwid, b->deviceid))
        return true;
    if (a->has_public_key && b->has_public_key
     && memcmp(a->public_key, b->public_key, AIRPLAY_PK_SIZE) == 0)
        return true;
    if (a->stable_id != NULL && b->stable_id != NULL
     && strcmp(a->stable_id, b->stable_id) == 0)
        return true;
    return false;
}

struct airplay_discovered_device *
airplay_device_table_find_match(struct airplay_device_table *table,
                                const struct airplay_discovered_device *probe)
{
    for (size_t i = 0; i < table->count; i++)
    {
        if (identity_overlap(table->devices[i], probe))
            return table->devices[i];
    }
    return NULL;
}

struct airplay_discovered_device *
airplay_device_table_add(struct airplay_device_table *table,
                         struct airplay_discovered_device *dev)
{
    struct airplay_discovered_device **n;

    n = realloc(table->devices, (table->count + 1) * sizeof(*n));
    if (n == NULL)
        return NULL;
    table->devices = n;
    table->devices[table->count++] = dev;
    return dev;
}

void
airplay_device_table_remove(struct airplay_device_table *table,
                             struct airplay_discovered_device *dev)
{
    for (size_t i = 0; i < table->count; i++)
    {
        if (table->devices[i] != dev)
            continue;
        airplay_device_clear(dev);
        free(dev);
        memmove(&table->devices[i], &table->devices[i + 1],
                (table->count - i - 1) * sizeof(table->devices[0]));
        table->count--;
        return;
    }
}

int
airplay_device_merge(struct airplay_discovered_device *dst,
                     const struct airplay_discovered_device *src)
{
    if (src->display_name != NULL
     && replace_string(&dst->display_name, src->display_name) != 0)
        return -1;
    if (src->model != NULL
     && replace_string(&dst->model, src->model) != 0)
        return -1;
    if (src->srcvers != NULL && dst->srcvers == NULL
     && replace_string(&dst->srcvers, src->srcvers) != 0)
        return -1;
    if (src->protovers != NULL && dst->protovers == NULL
     && replace_string(&dst->protovers, src->protovers) != 0)
        return -1;
    if (src->deviceid != NULL && dst->deviceid == NULL
     && replace_string(&dst->deviceid, src->deviceid) != 0)
        return -1;
    if (src->raop_hwid != NULL && dst->raop_hwid == NULL
     && replace_string(&dst->raop_hwid, src->raop_hwid) != 0)
        return -1;

    if (src->airplay.valid)
    {
        if (airplay_endpoint_set(&dst->airplay, src->airplay.host,
                                 src->airplay.port, src->airplay.ipv6) != 0)
            return -1;
    }
    if (src->raop.valid)
    {
        if (airplay_endpoint_set(&dst->raop, src->raop.host, src->raop.port,
                                 src->raop.ipv6) != 0)
            return -1;
    }

    if (src->has_features)
    {
        dst->features = src->features;
        dst->has_features = true;
    }
    if (src->has_status_flags)
    {
        dst->status_flags = src->status_flags;
        dst->has_status_flags = true;
    }
    if (src->has_public_key)
    {
        memcpy(dst->public_key, src->public_key, AIRPLAY_PK_SIZE);
        dst->has_public_key = true;
    }
    if (src->password_required)
        dst->password_required = true;
    if (src->pin_required)
        dst->pin_required = true;

    airplay_refresh_capabilities(dst);

    {
        char *nid = airplay_derive_stable_id(dst, dst->stable_id);
        if (nid != NULL)
        {
            free(dst->stable_id);
            dst->stable_id = nid;
        }
    }
    return 0;
}
