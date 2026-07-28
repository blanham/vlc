/*****************************************************************************
 * tlv.h: HAP TLV8 encode/decode for AirPlay pairing
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_TLV_H
#define VLC_AIRPLAY_TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* HAP TLV8 type tags (HomeKit Accessory Protocol). */
#define HAP_TLV_METHOD          0x00
#define HAP_TLV_IDENTIFIER      0x01
#define HAP_TLV_SALT            0x02
#define HAP_TLV_PUBLIC_KEY      0x03
#define HAP_TLV_PROOF           0x04
#define HAP_TLV_ENCRYPTED_DATA  0x05
#define HAP_TLV_STATE           0x06
#define HAP_TLV_ERROR           0x07
#define HAP_TLV_SIGNATURE       0x0A
#define HAP_TLV_FLAGS           0x13

#define HAP_TLV_MAX_VALUE 255

typedef struct hap_tlv_buf
{
    uint8_t *data;
    size_t len;
    size_t cap;
} hap_tlv_buf;

void hap_tlv_buf_init(hap_tlv_buf *);
void hap_tlv_buf_clear(hap_tlv_buf *);

/** Appends one TLV8 chunk (fragments automatically when len > 255). */
int hap_tlv_buf_add(hap_tlv_buf *, uint8_t type, const void *data, size_t len);

/** Finishes the buffer; ownership of *out transfers to the caller. */
int hap_tlv_buf_finish(hap_tlv_buf *, uint8_t **out, size_t *out_len);

/**
 * Concatenates every TLV chunk of `type` into a newly malloc()'d buffer.
 * Returns 0 on success. Missing type returns -1.
 */
int hap_tlv_get(const uint8_t *data, size_t len, uint8_t type,
                uint8_t **out, size_t *out_len);

/** Reads a single-byte TLV value; returns 0 and sets *ok=false when absent. */
uint8_t hap_tlv_get_u8(const uint8_t *data, size_t len, uint8_t type, bool *ok);

bool hap_tlv_has(const uint8_t *data, size_t len, uint8_t type);

#endif
