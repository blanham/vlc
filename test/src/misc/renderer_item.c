/*****************************************************************************
 * renderer_item.c: renderer item identity unit tests
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

#undef NDEBUG

#include <assert.h>
#include <string.h>

#include <vlc_common.h>
#include <vlc_renderer_discovery.h>

static void
test_legacy_constructor(void)
{
    vlc_renderer_item_t *item =
        vlc_renderer_item_new("chromecast", "Cast",
                              "chromecast://192.168.1.2:8009", NULL,
                              "cc_demux", NULL,
                              VLC_RENDERER_CAN_AUDIO | VLC_RENDERER_CAN_VIDEO);
    assert(item != NULL);
    assert(strcmp(vlc_renderer_item_type(item), "chromecast") == 0);
    assert(strcmp(vlc_renderer_item_name(item), "Cast") == 0);
    assert(vlc_renderer_item_id(item) == NULL);
    assert(vlc_renderer_item_flags(item)
           == (VLC_RENDERER_CAN_AUDIO | VLC_RENDERER_CAN_VIDEO));
    assert(vlc_renderer_item_capabilities(item)
           == (uint64_t)(VLC_RENDERER_CAN_AUDIO | VLC_RENDERER_CAN_VIDEO));
    assert(strstr(vlc_renderer_item_sout(item), "ip=192.168.1.2") != NULL);
    vlc_renderer_item_release(item);
}

static void
test_new_ex_with_id(void)
{
    const struct vlc_renderer_item_desc desc = {
        .type = "airplay",
        .id = "airplay:AABBCCDDEEFF",
        .name = "Living Room",
        .uri = NULL, /* not connectable yet */
        .flags = VLC_RENDERER_CAN_AUDIO | VLC_RENDERER_CAN_VIDEO,
        .capabilities = VLC_RENDERER_CAN_AUDIO | VLC_RENDERER_CAN_VIDEO,
    };
    vlc_renderer_item_t *item = vlc_renderer_item_new_ex(&desc);
    assert(item != NULL);
    assert(strcmp(vlc_renderer_item_id(item), "airplay:AABBCCDDEEFF") == 0);
    assert(strcmp(vlc_renderer_item_type(item), "airplay") == 0);
    assert(vlc_renderer_item_sout(item) != NULL);
    assert(vlc_renderer_item_sout(item)[0] == '\0');
    vlc_renderer_item_release(item);
}

static void
test_missing_optional_id(void)
{
    const struct vlc_renderer_item_desc desc = {
        .type = "chromecast",
        .id = NULL,
        .name = "TV",
        .uri = "chromecast://10.0.0.5:8009",
        .demux_filter = "cc_demux",
        .flags = VLC_RENDERER_CAN_VIDEO,
        .capabilities = VLC_RENDERER_CAN_VIDEO,
    };
    vlc_renderer_item_t *item = vlc_renderer_item_new_ex(&desc);
    assert(item != NULL);
    assert(vlc_renderer_item_id(item) == NULL);
    assert(vlc_renderer_item_flags(item) & VLC_RENDERER_CAN_VIDEO);
    vlc_renderer_item_release(item);
}

static void
test_capabilities_not_narrowed(void)
{
    const uint64_t wide = (1ull << 40) | VLC_RENDERER_CAN_AUDIO;
    const struct vlc_renderer_item_desc desc = {
        .type = "airplay",
        .id = "airplay:01",
        .name = "Wide",
        .uri = NULL,
        .flags = VLC_RENDERER_CAN_AUDIO,
        .capabilities = wide,
    };
    vlc_renderer_item_t *item = vlc_renderer_item_new_ex(&desc);
    assert(item != NULL);
    assert(vlc_renderer_item_flags(item) == VLC_RENDERER_CAN_AUDIO);
    assert(vlc_renderer_item_capabilities(item) == wide);
    vlc_renderer_item_release(item);
}

int
main(void)
{
    test_legacy_constructor();
    test_new_ex_with_id();
    test_missing_optional_id();
    test_capabilities_not_narrowed();
    return 0;
}
