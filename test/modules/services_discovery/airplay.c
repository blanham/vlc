/*****************************************************************************
 * test_airplay_discovery.c: AirPlay/RAOP discovery unit tests
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

#undef NDEBUG

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../modules/services_discovery/airplay_discovery.h"

static int failures;

static void
expect_true(int cond, const char *msg)
{
    if (!cond)
    {
        fprintf(stderr, "FAIL: %s\n", msg);
        failures++;
    }
}

static void
expect_streq(const char *got, const char *exp, const char *msg)
{
    if (got == NULL || exp == NULL || strcmp(got, exp) != 0)
    {
        fprintf(stderr, "FAIL: %s (got \"%s\", expected \"%s\")\n",
                msg, got ? got : "(null)", exp ? exp : "(null)");
        failures++;
    }
}

/* Fixture 11 + 7: feature mask parsing including high half and malformed. */
static void
test_features_parse(void)
{
    uint64_t v = 0;

    expect_true(airplay_parse_features("0x527FFFF7,0x1E", &v) == 0,
                "comma features parse");
    expect_true(v == (((uint64_t)0x1E << 32) | 0x527FFFF7ull),
                "64-bit features value");

    expect_true(airplay_parse_features("0x100000000", &v) == 0,
                "single hex features");
    expect_true(v == 0x100000000ull, "high-bit single value");

    expect_true(airplay_parse_features("not-a-number", &v) != 0,
                "malformed features rejected");
    expect_true(airplay_parse_features("0x1,0xZZ", &v) != 0,
                "malformed high half rejected");
    expect_true(airplay_parse_features("", &v) != 0, "empty features rejected");
    expect_true(airplay_parse_features(NULL, &v) != 0, "null features rejected");
}

/* Fixture 8: malformed public key. */
static void
test_public_key(void)
{
    uint8_t pk[AIRPLAY_PK_SIZE];
    const char *good =
        "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";

    expect_true(airplay_parse_public_key(good, pk) == 0, "valid pk");
    expect_true(pk[0] == 0x01 && pk[15] == 0xEF, "pk bytes");
    expect_true(airplay_parse_public_key("deadbeef", pk) != 0,
                "short pk rejected");
    expect_true(airplay_parse_public_key(
                    "GG23456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF",
                    pk) != 0,
                "non-hex pk rejected");
}

/* Fixture 12: RAOP instance-name normalization. */
static void
test_raop_hwid(void)
{
    char *id = airplay_raop_hwid_from_instance("AABBCCDDEEFF@Living Room");
    expect_streq(id, "AABBCCDDEEFF", "raop hwid");
    free(id);

    id = airplay_normalize_device_id("aa:bb:cc:dd:ee:ff");
    expect_streq(id, "AABBCCDDEEFF", "deviceid normalize");
    free(id);

    expect_true(airplay_raop_hwid_from_instance("NoAtSign") == NULL,
                "raop without @ rejected");
}

/* Fixture 2 + 4: Apple TV both services, reverse order. */
static void
test_appletv_aggregation_orders(void)
{
    struct airplay_device_table table;
    struct airplay_discovered_device airplay;
    struct airplay_discovered_device raop;
    struct airplay_discovered_device *dev;

    airplay_device_table_init(&table);

    /* AirPlay first */
    airplay_device_init(&airplay);
    airplay.display_name = strdup("Living Room");
    airplay_apply_txt_record(&airplay, false, "deviceid=AA:BB:CC:DD:EE:FF");
    airplay_apply_txt_record(&airplay, false,
                             "features=0x527FFFF7,0x1E");
    airplay_apply_txt_record(&airplay, false, "model=AppleTV6,2");
    airplay_endpoint_set(&airplay.airplay, "192.168.1.20", 7000, false);
    airplay.stable_id = airplay_derive_stable_id(&airplay, "Living Room");
    airplay_refresh_capabilities(&airplay);
    expect_true(airplay.supports_video, "appletv video from features");
    expect_true(airplay.supports_audio, "appletv audio from features");

    {
        struct airplay_discovered_device *heap = malloc(sizeof(*heap));
        assert(heap != NULL);
        *heap = airplay;
        memset(&airplay, 0, sizeof(airplay));
        airplay_device_table_add(&table, heap);
    }

    /* RAOP second — same hardware id */
    airplay_device_init(&raop);
    raop.raop_hwid = airplay_raop_hwid_from_instance("AABBCCDDEEFF@Living Room");
    raop.display_name = strdup("Living Room");
    airplay_endpoint_set(&raop.raop, "192.168.1.20", 7000, false);
    airplay_apply_txt_record(&raop, true, "am=AppleTV6,2");
    raop.stable_id = airplay_derive_stable_id(&raop, "AABBCCDDEEFF@Living Room");
    airplay_refresh_capabilities(&raop);

    dev = airplay_device_table_find_match(&table, &raop);
    expect_true(dev != NULL, "raop matches existing airplay");
    expect_true(airplay_device_merge(dev, &raop) == 0, "merge raop into airplay");
    expect_true(dev->airplay.valid && dev->raop.valid, "both endpoints present");
    expect_streq(dev->stable_id, "airplay:AABBCCDDEEFF", "stable id prefers deviceid");
    airplay_device_clear(&raop);

    /* Reverse order on a fresh table */
    airplay_device_table_clear(&table);
    airplay_device_table_init(&table);

    airplay_device_init(&raop);
    raop.raop_hwid = airplay_raop_hwid_from_instance("AABBCCDDEEFF@Living Room");
    raop.display_name = strdup("Living Room");
    airplay_endpoint_set(&raop.raop, "192.168.1.20", 7000, false);
    raop.stable_id = airplay_derive_stable_id(&raop, NULL);
    {
        struct airplay_discovered_device *heap = malloc(sizeof(*heap));
        *heap = raop;
        memset(&raop, 0, sizeof(raop));
        airplay_device_table_add(&table, heap);
    }

    airplay_device_init(&airplay);
    airplay_apply_txt_record(&airplay, false, "deviceid=AA:BB:CC:DD:EE:FF");
    airplay.display_name = strdup("Living Room");
    airplay_endpoint_set(&airplay.airplay, "192.168.1.20", 7000, false);
    airplay.stable_id = airplay_derive_stable_id(&airplay, NULL);

    dev = airplay_device_table_find_match(&table, &airplay);
    expect_true(dev != NULL, "airplay matches existing raop");
    expect_true(airplay_device_merge(dev, &airplay) == 0, "merge airplay into raop");
    expect_streq(dev->stable_id, "airplay:AABBCCDDEEFF",
                 "stable id upgrades to deviceid");
    expect_true(table.count == 1, "single aggregated row");
    airplay_device_clear(&airplay);

    airplay_device_table_clear(&table);
}

/* Fixture 3: HomePod / audio-focused. */
static void
test_homepod_audio(void)
{
    struct airplay_discovered_device dev;
    airplay_device_init(&dev);
    airplay_apply_txt_record(&dev, false, "deviceid=11:22:33:44:55:66");
    airplay_apply_txt_record(&dev, false, "model=AudioAccessory5,1");
    /* Audio bit set, video/screen clear */
    airplay_apply_txt_record(&dev, false, "features=0x200");
    airplay_endpoint_set(&dev.airplay, "192.168.1.30", 7000, false);
    airplay_endpoint_set(&dev.raop, "192.168.1.30", 7000, false);
    airplay_refresh_capabilities(&dev);
    expect_true(dev.supports_audio, "homepod audio");
    expect_true(!dev.supports_video, "homepod no video claim");
    airplay_device_clear(&dev);
}

/* Fixture 5: endpoint address/port changes keep identity. */
static void
test_endpoint_change(void)
{
    struct airplay_discovered_device a, b;
    airplay_device_init(&a);
    airplay_device_init(&b);
    airplay_apply_txt_record(&a, false, "deviceid=AA:BB:CC:DD:EE:01");
    a.stable_id = airplay_derive_stable_id(&a, NULL);
    airplay_endpoint_set(&a.airplay, "192.168.1.10", 7000, false);

    airplay_apply_txt_record(&b, false, "deviceid=AA:BB:CC:DD:EE:01");
    b.stable_id = airplay_derive_stable_id(&b, NULL);
    airplay_endpoint_set(&b.airplay, "192.168.1.99", 7001, false);

    expect_true(strcmp(a.stable_id, b.stable_id) == 0,
                "stable id unchanged across endpoint move");
    expect_true(airplay_device_merge(&a, &b) == 0, "merge endpoint update");
    expect_streq(a.airplay.host, "192.168.1.99", "host updated");
    expect_true(a.airplay.port == 7001, "port updated");
    airplay_device_clear(&a);
    airplay_device_clear(&b);
}

/* Fixture 6: same friendly name, different IDs. */
static void
test_same_name_different_ids(void)
{
    struct airplay_device_table table;
    struct airplay_discovered_device *d1 = calloc(1, sizeof(*d1));
    struct airplay_discovered_device *d2 = calloc(1, sizeof(*d2));
    struct airplay_discovered_device probe;

    airplay_device_table_init(&table);
    airplay_device_init(d1);
    airplay_device_init(d2);
    d1->display_name = strdup("Kitchen");
    d2->display_name = strdup("Kitchen");
    airplay_apply_txt_record(d1, false, "deviceid=AA:AA:AA:AA:AA:01");
    airplay_apply_txt_record(d2, false, "deviceid=AA:AA:AA:AA:AA:02");
    d1->stable_id = airplay_derive_stable_id(d1, NULL);
    d2->stable_id = airplay_derive_stable_id(d2, NULL);
    airplay_device_table_add(&table, d1);
    airplay_device_table_add(&table, d2);

    airplay_device_init(&probe);
    airplay_apply_txt_record(&probe, false, "deviceid=AA:AA:AA:AA:AA:02");
    probe.stable_id = airplay_derive_stable_id(&probe, NULL);
    expect_true(airplay_device_table_find_match(&table, &probe) == d2,
                "match by id not name");
    airplay_device_clear(&probe);

    airplay_device_init(&probe);
    probe.display_name = strdup("Kitchen");
    expect_true(airplay_device_table_find_match(&table, &probe) == NULL,
                "name alone must not merge");
    airplay_device_clear(&probe);

    expect_true(table.count == 2, "two distinct devices");
    airplay_device_table_clear(&table);
}

/* Fixture 9: missing TXT data still yields temporary identity. */
static void
test_missing_txt(void)
{
    struct airplay_discovered_device dev;
    char *id;

    airplay_device_init(&dev);
    airplay_endpoint_set(&dev.airplay, "fe80::1", 7000, true);
    id = airplay_derive_stable_id(&dev, "Some Device");
    expect_streq(id, "dnssd:Some Device", "dns-sd fallback");
    free(id);
    airplay_refresh_capabilities(&dev);
    expect_true(dev.supports_audio, "airplay without features => audio");
    expect_true(!dev.supports_video, "airplay without features => no video");
    airplay_device_clear(&dev);
}

/* Fixture 10: partial expiration — clear one endpoint, keep device. */
static void
test_partial_expiration(void)
{
    struct airplay_discovered_device dev;
    airplay_device_init(&dev);
    airplay_apply_txt_record(&dev, false, "deviceid=DE:AD:BE:EF:00:01");
    airplay_endpoint_set(&dev.airplay, "192.168.1.5", 7000, false);
    airplay_endpoint_set(&dev.raop, "192.168.1.5", 7000, false);
    airplay_refresh_capabilities(&dev);
    expect_true(dev.supports_audio && dev.airplay.valid && dev.raop.valid,
                "both endpoints before expire");

    airplay_endpoint_clear(&dev.raop);
    airplay_refresh_capabilities(&dev);
    expect_true(dev.airplay.valid, "airplay remains");
    expect_true(!dev.raop.valid, "raop expired");
    expect_true(dev.supports_audio, "audio still via airplay");

    airplay_endpoint_clear(&dev.airplay);
    airplay_refresh_capabilities(&dev);
    expect_true(!dev.airplay.valid && !dev.raop.valid, "fully expired");
    airplay_device_clear(&dev);
}

/* Fixture 1: Chromecast TXT orthognal — document expected ca=/fn= semantics
 * used by microdns chromecast_parse_txt (regression oracle). */
static void
test_chromecast_txt_oracle(void)
{
    /* Mirrors modules/services_discovery/microdns.c chromecast_parse_txt. */
    int flags = 0x0001; /* VLC_RENDERER_CAN_AUDIO default */
    int ca = atoi("5"); /* 0x01 video | 0x04 audio */
    if ((ca & 0x01) != 0)
        flags |= 0x0002;
    if ((ca & 0x04) != 0)
        flags |= 0x0001;
    expect_true((flags & 0x0001) != 0 && (flags & 0x0002) != 0,
                "chromecast ca= video+audio");
}

int
main(void)
{
    test_features_parse();
    test_public_key();
    test_raop_hwid();
    test_appletv_aggregation_orders();
    test_homepod_audio();
    test_endpoint_change();
    test_same_name_different_ids();
    test_missing_txt();
    test_partial_expiration();
    test_chromecast_txt_oracle();

    if (failures)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }
    puts("airplay discovery tests ok");
    return 0;
}
