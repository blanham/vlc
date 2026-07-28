/*****************************************************************************
 * session_stubs.c: pairing stubs for session plist unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include "../../../../modules/stream_out/airplay/pairing.h"

enum airplay_pair_state
airplay_pairing_state(const airplay_pairing *p)
{
    (void)p;
    return AIRPLAY_PAIR_READY;
}

int
airplay_pairing_control_connect(airplay_pairing *p)
{
    (void)p;
    return -1;
}

void
airplay_pairing_control_disconnect(airplay_pairing *p)
{
    (void)p;
}

int
airplay_pairing_control_exchange(airplay_pairing *p, const uint8_t *req,
                               size_t req_len, uint8_t **resp, size_t *resp_len)
{
    (void)p; (void)req; (void)req_len; (void)resp; (void)resp_len;
    return -1;
}
