/*****************************************************************************
 * airplay_discovery.h: AirPlay/RAOP DNS-SD parsing and device aggregation
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

#ifndef VLC_AIRPLAY_DISCOVERY_H
#define VLC_AIRPLAY_DISCOVERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Field meanings and constants are derived from public AirPlay/RAOP
 * documentation and sanitized network traces (OwnTone, Shairport Sync, and
 * UxPlay used only as behavioral references). No third-party implementation
 * code is copied here.
 */

#define AIRPLAY_PK_SIZE 32

struct airplay_endpoint
{
    char *host;
    uint16_t port;
    bool ipv6;
    bool valid;
};

struct airplay_discovered_device
{
    char *stable_id;
    char *display_name;
    char *model;
    char *srcvers;
    char *protovers;

    struct airplay_endpoint airplay;
    struct airplay_endpoint raop;

    uint64_t features;
    uint64_t status_flags;
    bool has_features;
    bool has_status_flags;

    bool has_public_key;
    uint8_t public_key[AIRPLAY_PK_SIZE];

    bool supports_audio;
    bool supports_video;
    bool password_required;
    bool pin_required;

    char *deviceid;   /* normalized AirPlay deviceid */
    char *raop_hwid;  /* normalized RAOP hardware-id prefix */

    /* Opaque handle owned by the discovery module (renderer item). */
    void *renderer_item;
    int64_t last_seen;
    bool published;
    /* RAOP is advertised before the AirPlay service. Publishing that
     * incomplete identity replaces the Qt row a moment later. */
    bool saw_incomplete;
};

struct airplay_device_table
{
    struct airplay_discovered_device **devices;
    size_t count;
};

void airplay_device_init(struct airplay_discovered_device *dev);
void airplay_device_clear(struct airplay_discovered_device *dev);

void airplay_device_table_init(struct airplay_device_table *table);
void airplay_device_table_clear(struct airplay_device_table *table);

/**
 * Parse AirPlay/RAOP feature masks.
 *
 * Accepts:
 *  - decimal integers
 *  - hexadecimal with optional 0x prefix
 *  - comma-separated low,high 32-bit halves (public advertisement form)
 *
 * Returns 0 on success, -1 on malformed input. Does not write *out on error.
 */
int airplay_parse_features(const char *value, uint64_t *out);

/** Parse a single unsigned 64-bit integer (dec/hex). */
int airplay_parse_u64(const char *value, uint64_t *out);

/**
 * Parse a 32-byte public key encoded as 64 hexadecimal characters.
 * Rejects wrong length and non-hex input.
 */
int airplay_parse_public_key(const char *value, uint8_t out[AIRPLAY_PK_SIZE]);

/** Lowercase hex encoding of a 32-byte Ed25519 public key (64 chars + NUL). */
char *airplay_format_public_key_hex(const uint8_t pk[AIRPLAY_PK_SIZE]);

/**
 * Normalize a device identifier to uppercase hex without separators.
 * Returns a newly allocated string, or NULL on failure / empty input.
 */
char *airplay_normalize_device_id(const char *raw);

/**
 * Extract and normalize the hardware-id prefix from a RAOP service instance
 * name of the form "AABBCCDDEEFF@Name".
 */
char *airplay_raop_hwid_from_instance(const char *instance_name);

/**
 * Apply one TXT "key=value" (or key-only) record to an AirPlay or RAOP view.
 * Unknown keys are ignored. Malformed values are rejected without changing
 * prior good state for that field.
 */
int airplay_apply_txt_record(struct airplay_discovered_device *dev,
                             bool is_raop, const char *txt);

void airplay_refresh_capabilities(struct airplay_discovered_device *dev);

/**
 * Derive stable identity preference order:
 *  1. normalized AirPlay deviceid
 *  2. normalized RAOP hardware-id prefix
 *  3. fingerprint of advertised public key
 *  4. carefully prefixed DNS-SD fallback (temporary)
 *
 * Returns a newly allocated string.
 */
char *airplay_derive_stable_id(const struct airplay_discovered_device *dev,
                               const char *dns_fallback);

/**
 * Find an existing device that should merge with the identity evidence in
 * @probe, or NULL if none. Does not merge merely on host, name, or model.
 */
struct airplay_discovered_device *
airplay_device_table_find_match(struct airplay_device_table *table,
                                const struct airplay_discovered_device *probe);

struct airplay_discovered_device *
airplay_device_table_add(struct airplay_device_table *table,
                         struct airplay_discovered_device *dev);

void airplay_device_table_remove(struct airplay_device_table *table,
                                 struct airplay_discovered_device *dev);

/**
 * Merge endpoint/TXT evidence from @src into @dst. Identity fields are kept
 * when already present. Returns 0 on success.
 */
int airplay_device_merge(struct airplay_discovered_device *dst,
                         const struct airplay_discovered_device *src);

/** Copy endpoint; replaces any previous host. */
int airplay_endpoint_set(struct airplay_endpoint *ep, const char *host,
                         uint16_t port, bool ipv6);

void airplay_endpoint_clear(struct airplay_endpoint *ep);

/** True when two normalized identity strings refer to the same receiver. */
bool airplay_identity_equal(const char *a, const char *b);

#endif
