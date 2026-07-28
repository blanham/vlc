/*****************************************************************************
 * microdns.c: mDNS services discovery module
 *****************************************************************************
 * Copyright © 2016 VLC authors, VideoLAN and VideoLabs
 * Copyright © 2026 VLC authors and VideoLAN
 *
 * Authors: Steve Lhomme <robux4@videolabs.io>
 *          Thomas Guillem <thomas@gllm.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdatomic.h>
#include <assert.h>

#include <vlc_common.h>
#include <vlc_arrays.h>
#include <vlc_configuration.h>
#include <vlc_plugin.h>
#include <vlc_modules.h>
#include <vlc_services_discovery.h>
#include <vlc_renderer_discovery.h>

#include <microdns/microdns.h>

#include "airplay_discovery.h"

static int OpenSD( vlc_object_t * );
static void CloseSD( vlc_object_t * );
static int OpenRD( vlc_object_t * );
static void CloseRD( vlc_object_t * );

VLC_SD_PROBE_HELPER( "microdns", N_("mDNS Network Discovery"), SD_CAT_LAN )
VLC_RD_PROBE_HELPER( "microdns_renderer", "mDNS renderer Discovery" )

#define CFG_PREFIX "sd-microdns-"

#define LISTEN_INTERVAL VLC_TICK_FROM_SEC(15) /* 15 seconds */
#define TIMEOUT (3 * LISTEN_INTERVAL + VLC_TICK_FROM_SEC(5)) /* 3 * interval + 5 seconds */

/*
 * Module descriptor
 */
vlc_module_begin()
    set_shortname( "mDNS" )
    set_description( N_( "mDNS Network Discovery" ) )
    set_subcategory( SUBCAT_PLAYLIST_SD )
    set_capability( "services_discovery", 0 )
    set_callbacks( OpenSD, CloseSD )
    add_shortcut( "mdns", "microdns" )
    VLC_SD_PROBE_SUBMODULE
    add_submodule() \
        set_description( N_( "mDNS Renderer Discovery" ) )
        set_subcategory( SUBCAT_SOUT_RENDERER )
        set_capability( "renderer_discovery", 0 )
        set_callbacks( OpenRD, CloseRD )
        add_shortcut( "mdns_renderer", "microdns_renderer" )
        VLC_RD_PROBE_SUBMODULE
vlc_module_end ()

enum mdns_renderer_kind
{
    MDNS_KIND_NONE = 0,
    MDNS_KIND_CHROMECAST,
    MDNS_KIND_AIRPLAY,
    MDNS_KIND_RAOP,
};

struct mdns_renderer_protocol
{
    const char *psz_service_name;
    const char *psz_renderer_type;
    const char *psz_sout_module;
    const char *psz_demux_filter;
    int         i_default_flags;
    enum mdns_renderer_kind kind;
};

/* Services-discovery (non-renderer) protocols */
static const struct
{
    const char *psz_protocol;
    const char *psz_service_name;
    enum input_item_type_e item_type;
} sd_protocols[] = {
    { "ftp", "_ftp._tcp.local", ITEM_TYPE_DIRECTORY },
    { "smb", "_smb._tcp.local", ITEM_TYPE_DIRECTORY },
    { "nfs", "_nfs._tcp.local", ITEM_TYPE_DIRECTORY },
    { "sftp", "_sftp-ssh._tcp.local", ITEM_TYPE_DIRECTORY },
    { "webdav", "_webdav._tcp.local", ITEM_TYPE_DIRECTORY },
    { "webdavs", "_webdavs._tcp.local", ITEM_TYPE_DIRECTORY },
    { "rtsp", "_rtsp._tcp.local", ITEM_TYPE_DIRECTORY },
    { "ndi", "_ndi._tcp.local", ITEM_TYPE_STREAM },
};

static const struct mdns_renderer_protocol renderer_protocols[] = {
    {
        "_googlecast._tcp.local",
        "chromecast",
        "chromecast",
        "cc_demux",
        VLC_RENDERER_CAN_AUDIO,
        MDNS_KIND_CHROMECAST,
    },
    {
        "_airplay._tcp.local",
        "airplay",
        "airplay",
        NULL,
        0,
        MDNS_KIND_AIRPLAY,
    },
    {
        "_raop._tcp.local",
        "airplay",
        "airplay",
        NULL,
        VLC_RENDERER_CAN_AUDIO,
        MDNS_KIND_RAOP,
    },
};


struct discovery_sys
{
    vlc_thread_t        thread;
    atomic_bool         stop;
    struct mdns_ctx *   p_microdns;
    const char *        ppsz_service_names[ARRAY_SIZE(sd_protocols)
                                          + ARRAY_SIZE(renderer_protocols)];
    unsigned int        i_nb_service_names;
    vlc_array_t         items;
    struct airplay_device_table airplay_devices;
};

struct item
{
    char *              psz_uri;
    input_item_t *      p_input_item;
    vlc_renderer_item_t*p_renderer_item;
    vlc_tick_t          i_last_seen;
};

struct srv
{
    const char *psz_protocol;
    char *      psz_device_name;
    uint16_t    i_port;
    enum input_item_type_e item_type;
    const struct mdns_renderer_protocol *renderer_proto;
    struct
    {
        char *      psz_model;
        char *      psz_icon;
        int         i_renderer_flags;
    } renderer;
};

static const char *const ppsz_options[] = {
    NULL
};

static void
print_error( vlc_object_t *p_obj, const char *psz_what, int i_status )
{
    char psz_err_str[128];

    if( mdns_strerror( i_status, psz_err_str, sizeof(psz_err_str) ) == 0)
        msg_Err( p_obj, "mDNS %s error: %s", psz_what, psz_err_str);
    else
        msg_Err( p_obj, "mDNS %s error: unknown: %d", psz_what, i_status);
}


static int
strrcmp(const char *s1, const char *s2)
{
    size_t m, n;
    m = strlen(s1);
    n = strlen(s2);
    if (n > m)
        return 1;
    return strncmp(s1 + m - n, s2, n);
}

static const struct mdns_renderer_protocol *
find_renderer_protocol( const char *psz_rr_name )
{
    for( size_t i = 0; i < ARRAY_SIZE(renderer_protocols); ++i )
    {
        if( !strrcmp( psz_rr_name, renderer_protocols[i].psz_service_name ) )
            return &renderer_protocols[i];
    }
    return NULL;
}

static int
items_add_input( struct discovery_sys *p_sys, services_discovery_t *p_sd,
                 char *psz_uri, const char *psz_name, enum input_item_type_e item_type )
{
    struct item *p_item = malloc( sizeof(struct item) );
    if( p_item == NULL )
    {
        free( psz_uri );
        return VLC_ENOMEM;
    }

    input_item_t *p_input_item = NULL;
    if( item_type == ITEM_TYPE_STREAM )
        p_input_item = input_item_NewStream( psz_uri, psz_name, INPUT_DURATION_UNSET );
    else
        p_input_item = input_item_NewDirectory( psz_uri, psz_name, ITEM_NET );
    if( p_input_item == NULL )
    {
        free( psz_uri );
        free( p_item );
        return VLC_ENOMEM;
    }

    p_item->psz_uri = psz_uri;
    p_item->p_input_item = p_input_item;
    p_item->p_renderer_item = NULL;
    p_item->i_last_seen = vlc_tick_now();
    vlc_array_append_or_abort( &p_sys->items, p_item );
    services_discovery_AddItem( p_sd, p_input_item );

    return VLC_SUCCESS;
}

static int
items_add_renderer( struct discovery_sys *p_sys, vlc_renderer_discovery_t *p_rd,
                    const char *psz_type, const char *psz_name, char *psz_uri,
                    const char *psz_demux_filter, const char *psz_icon_uri,
                    int i_flags )
{
    struct item *p_item = malloc( sizeof(struct item) );
    if( p_item == NULL )
        return VLC_ENOMEM;

    const char *psz_extra_uri = i_flags & VLC_RENDERER_CAN_VIDEO ? NULL : "no-video";

    vlc_renderer_item_t *p_renderer_item =
        vlc_renderer_item_new( psz_type, psz_name, psz_uri, psz_extra_uri,
                               psz_demux_filter, psz_icon_uri, i_flags );
    if( p_renderer_item == NULL )
    {
        free( psz_uri );
        free( p_item );
        return VLC_ENOMEM;
    }

    p_item->psz_uri = psz_uri;
    p_item->p_input_item = NULL;
    p_item->p_renderer_item = p_renderer_item;
    p_item->i_last_seen = vlc_tick_now();
    vlc_array_append_or_abort( &p_sys->items, p_item );
    vlc_rd_add_item( p_rd, p_renderer_item );

    return VLC_SUCCESS;
}

static void
items_release( struct discovery_sys *p_sys, struct item *p_item )
{
    (void) p_sys;
    if( p_item->p_input_item != NULL )
    {
        input_item_Release( p_item->p_input_item );
    }
    else
    {
        assert( p_item->p_renderer_item != NULL );
        vlc_renderer_item_release( p_item->p_renderer_item );
    }

    free( p_item->psz_uri );
    free( p_item );
}

static bool
items_exists( struct discovery_sys *p_sys, const char *psz_uri )
{
    for( size_t i = 0; i < vlc_array_count( &p_sys->items ); ++i )
    {
        struct item *p_item = vlc_array_item_at_index( &p_sys->items, i );
        if( strcmp( p_item->psz_uri, psz_uri ) == 0 )
        {
            p_item->i_last_seen = vlc_tick_now();
            return true;
        }
    }
    return false;
}

static void
items_timeout( struct discovery_sys *p_sys, services_discovery_t *p_sd,
               vlc_renderer_discovery_t *p_rd )
{
    assert( p_rd != NULL || p_sd != NULL );
    vlc_tick_t i_now = vlc_tick_now();

    /* Remove items that are not seen since TIMEOUT */
    for( size_t i = 0; i < vlc_array_count( &p_sys->items ); ++i )
    {
        struct item *p_item = vlc_array_item_at_index( &p_sys->items, i );
        if( i_now - p_item->i_last_seen > TIMEOUT )
        {
            if( p_sd != NULL )
                services_discovery_RemoveItem( p_sd, p_item->p_input_item );
            else
                vlc_rd_remove_item( p_rd, p_item->p_renderer_item );
            items_release( p_sys, p_item );
            vlc_array_remove( &p_sys->items, i-- );
        }
    }

    if( p_rd == NULL )
        return;

    /* Expire aggregated AirPlay devices when both endpoints are gone. */
    for( size_t i = 0; i < p_sys->airplay_devices.count; )
    {
        struct airplay_discovered_device *dev = p_sys->airplay_devices.devices[i];
        if( i_now - (vlc_tick_t)dev->last_seen <= TIMEOUT
         && (dev->airplay.valid || dev->raop.valid) )
        {
            i++;
            continue;
        }

        if( dev->renderer_item != NULL )
        {
            vlc_rd_remove_item( p_rd, dev->renderer_item );
            vlc_renderer_item_release( dev->renderer_item );
            dev->renderer_item = NULL;
        }
        airplay_device_table_remove( &p_sys->airplay_devices, dev );
    }
}

static void
items_clear( struct discovery_sys *p_sys )
{
    for( size_t i = 0; i < vlc_array_count( &p_sys->items ); ++i )
    {
        struct item *p_item = vlc_array_item_at_index( &p_sys->items, i );
        items_release( p_sys, p_item );
    }
    vlc_array_clear( &p_sys->items );

    for( size_t i = 0; i < p_sys->airplay_devices.count; ++i )
    {
        struct airplay_discovered_device *dev = p_sys->airplay_devices.devices[i];
        if( dev->renderer_item != NULL )
        {
            vlc_renderer_item_release( dev->renderer_item );
            dev->renderer_item = NULL;
        }
    }
    airplay_device_table_clear( &p_sys->airplay_devices );
}

static void clear_srvs( struct srv *p_srvs, unsigned int i_nb_srv )
{
    for( unsigned int i = 0; i < i_nb_srv; ++i )
    {
        free( p_srvs[i].psz_device_name );
        free( p_srvs[i].renderer.psz_model);
        free( p_srvs[i].renderer.psz_icon );
    }
    free( p_srvs );
}

static void
chromecast_parse_txt( struct srv *p_srv, const char *psz_txt )
{
    if ( !strncmp( "fn=", psz_txt, 3 ) )
    {
        free( p_srv->psz_device_name );
        p_srv->psz_device_name = strdup( psz_txt + 3 );
    }
    else if( !strncmp( "ca=", psz_txt, 3 ) )
    {
        int ca = atoi( psz_txt + 3);
        /*
         * For chromecast, the `ca=` is composed from (at least)
         * 0x01 to indicate video support
         * 0x04 to indicate audio support
         */
        if ( ( ca & 0x01 ) != 0 )
            p_srv->renderer.i_renderer_flags |= VLC_RENDERER_CAN_VIDEO;
        if ( ( ca & 0x04 ) != 0 )
            p_srv->renderer.i_renderer_flags |= VLC_RENDERER_CAN_AUDIO;
    }
    else if( !strncmp("md=", psz_txt, 3) )
    {
        free( p_srv->renderer.psz_model );
        p_srv->renderer.psz_model = strdup( psz_txt + 3 );
    }
    else if( !strncmp("ic=", psz_txt, 3) )
    {
        free( p_srv->renderer.psz_icon );
        p_srv->renderer.psz_icon = strdup( psz_txt + 3 );
    }
}

static int
parse_entries_sd( const struct rr_entry *p_entries,
                  struct srv **pp_srvs, unsigned int *p_nb_srv,
                  const char **ppsz_ip, bool *p_ipv6 )
{
    unsigned int i_nb_srv = 0;
    for( const struct rr_entry *p_entry = p_entries;
         p_entry != NULL; p_entry = p_entry->next )
    {
        if( p_entry->type == RR_SRV )
            i_nb_srv++;
    }
    if( i_nb_srv == 0 )
        return VLC_EGENERIC;

    struct srv *p_srvs = calloc(i_nb_srv, sizeof(struct srv));
    if( p_srvs == NULL )
        return VLC_EGENERIC;

    const char *psz_ip = NULL;
    i_nb_srv = 0;
    for( const struct rr_entry *p_entry = p_entries;
         p_entry != NULL; p_entry = p_entry->next )
    {
        if( p_entry->type == RR_SRV )
        {
            for (size_t i = 0; i < ARRAY_SIZE(sd_protocols); ++i)
            {
                if( !strrcmp( p_entry->name, sd_protocols[i].psz_service_name ) )
                {
                    struct srv *p_srv = &p_srvs[i_nb_srv];

                    p_srv->psz_device_name =
                        strndup( p_entry->name, strlen( p_entry->name )
                                 - strlen( sd_protocols[i].psz_service_name ) - 1);
                    if( p_srv->psz_device_name == NULL )
                        break;
                    p_srv->psz_protocol = sd_protocols[i].psz_protocol;
                    p_srv->i_port = p_entry->data.SRV.port;
                    p_srv->item_type = sd_protocols[i].item_type;
                    p_srv->renderer_proto = NULL;
                    ++i_nb_srv;
                    break;
                }
            }
        }
        else if( p_entry->type == RR_A && psz_ip == NULL )
            psz_ip = p_entry->data.A.addr_str;
        else if( p_entry->type == RR_AAAA && psz_ip == NULL )
        {
            psz_ip = p_entry->data.AAAA.addr_str;
            *p_ipv6 = true;
        }
    }
    if( psz_ip == NULL || i_nb_srv == 0 )
    {
        clear_srvs( p_srvs, i_nb_srv );
        return VLC_EGENERIC;
    }

    *pp_srvs = p_srvs;
    *p_nb_srv = i_nb_srv;
    *ppsz_ip = psz_ip;
    return VLC_SUCCESS;
}

static int
parse_entries_rd( const struct rr_entry *p_entries,
                  struct srv **pp_srvs, unsigned int *p_nb_srv,
                  const char **ppsz_ip, bool *p_ipv6 )
{
    unsigned int i_nb_srv = 0;
    for( const struct rr_entry *p_entry = p_entries;
         p_entry != NULL; p_entry = p_entry->next )
    {
        if( p_entry->type == RR_SRV )
            i_nb_srv++;
    }
    if( i_nb_srv == 0 )
        return VLC_EGENERIC;

    struct srv *p_srvs = calloc(i_nb_srv, sizeof(struct srv));
    if( p_srvs == NULL )
        return VLC_EGENERIC;

    const char *psz_ip = NULL;
    struct srv *p_srv = NULL;
    i_nb_srv = 0;
    for( const struct rr_entry *p_entry = p_entries;
         p_entry != NULL; p_entry = p_entry->next )
    {
        if( p_entry->type == RR_SRV )
        {
            const struct mdns_renderer_protocol *proto =
                find_renderer_protocol( p_entry->name );
            if( proto == NULL )
                continue;

            p_srv = &p_srvs[i_nb_srv];
            p_srv->psz_device_name =
                strndup( p_entry->name, strlen( p_entry->name )
                         - strlen( proto->psz_service_name ) - 1);
            if( p_srv->psz_device_name == NULL )
                break;
            p_srv->psz_protocol = proto->psz_sout_module != NULL
                                ? proto->psz_sout_module
                                : proto->psz_renderer_type;
            p_srv->i_port = p_entry->data.SRV.port;
            p_srv->renderer_proto = proto;
            p_srv->renderer.i_renderer_flags = proto->i_default_flags;
            ++i_nb_srv;
        }
        else if( p_entry->type == RR_A && psz_ip == NULL )
            psz_ip = p_entry->data.A.addr_str;
        else if( p_entry->type == RR_AAAA && psz_ip == NULL )
        {
            psz_ip = p_entry->data.AAAA.addr_str;
            *p_ipv6 = true;
        }
        else if( p_entry->type == RR_TXT && p_srv != NULL
              && p_srv->renderer_proto != NULL
              && p_srv->renderer_proto->kind == MDNS_KIND_CHROMECAST )
        {
            for ( struct rr_data_txt *p_txt = p_entry->data.TXT;
                  p_txt != NULL ; p_txt = p_txt->next )
                chromecast_parse_txt( p_srv, p_txt->txt );
        }
    }
    if( psz_ip == NULL || i_nb_srv == 0 )
    {
        clear_srvs( p_srvs, i_nb_srv );
        return VLC_EGENERIC;
    }

    *pp_srvs = p_srvs;
    *p_nb_srv = i_nb_srv;
    *ppsz_ip = psz_ip;
    return VLC_SUCCESS;
}

static char *
create_uri( const char *psz_protocol, const char *psz_ip, bool b_ipv6,
            uint16_t i_port )
{
    char *psz_uri;

    return asprintf( &psz_uri, "%s://%s%s%s:%u", psz_protocol,
                     b_ipv6 ? "[" : "", psz_ip, b_ipv6 ? "]" : "",
                     i_port ) < 0 ? NULL : psz_uri;
}

static void
airplay_collect_txt( struct airplay_discovered_device *dev, bool is_raop,
                     const struct rr_entry *p_entries )
{
    for( const struct rr_entry *p_entry = p_entries;
         p_entry != NULL; p_entry = p_entry->next )
    {
        if( p_entry->type != RR_TXT )
            continue;
        for ( struct rr_data_txt *p_txt = p_entry->data.TXT;
              p_txt != NULL ; p_txt = p_txt->next )
            airplay_apply_txt_record( dev, is_raop, p_txt->txt );
    }
}

static int
airplay_publish( vlc_renderer_discovery_t *p_rd,
                 struct airplay_discovered_device *dev )
{
    char *psz_name = NULL;
    char *psz_uri = NULL;
    char *psz_extra_sout = NULL;
    int flags = 0;
    struct vlc_renderer_item_desc desc;
    vlc_renderer_item_t *item;

    airplay_refresh_capabilities( dev );

    if( !dev->airplay.valid && !dev->raop.valid )
        return VLC_EGENERIC;

    if( dev->stable_id == NULL )
    {
        dev->stable_id = airplay_derive_stable_id( dev, dev->display_name );
        if( dev->stable_id == NULL )
            return VLC_ENOMEM;
    }

    if( dev->display_name != NULL && dev->model != NULL )
    {
        if( asprintf( &psz_name, "%s (%s)", dev->display_name, dev->model ) < 0 )
            return VLC_ENOMEM;
    }
    else if( dev->display_name != NULL )
    {
        psz_name = strdup( dev->display_name );
        if( psz_name == NULL )
            return VLC_ENOMEM;
    }
    else
    {
        psz_name = strdup( "AirPlay" );
        if( psz_name == NULL )
            return VLC_ENOMEM;
    }

    if( dev->supports_audio )
        flags |= VLC_RENDERER_CAN_AUDIO;
    if( dev->supports_video )
        flags |= VLC_RENDERER_CAN_VIDEO;

    if( dev->airplay.valid )
    {
        const struct airplay_endpoint *ep = &dev->airplay;

        if( asprintf( &psz_uri, "airplay://%s%s%s:%u",
                      ep->ipv6 ? "[" : "", ep->host,
                      ep->ipv6 ? "]" : "", ep->port ) < 0 )
            goto error;
        if( asprintf( &psz_extra_sout, "device-id=%s",
                      dev->stable_id ) < 0 )
            goto error;
    }

    memset( &desc, 0, sizeof(desc) );
    desc.type = "airplay";
    desc.id = dev->stable_id;
    desc.name = psz_name;
    desc.uri = psz_uri;
    desc.extra_sout = psz_extra_sout;
    desc.flags = flags;
    desc.capabilities = (uint64_t)flags;

    item = vlc_renderer_item_new_ex( &desc );
    free( psz_extra_sout );
    free( psz_uri );
    free( psz_name );
    if( item == NULL )
        return VLC_ENOMEM;

    if( dev->renderer_item != NULL )
    {
        vlc_rd_remove_item( p_rd, dev->renderer_item );
        vlc_renderer_item_release( dev->renderer_item );
        dev->renderer_item = NULL;
    }

    vlc_rd_add_item( p_rd, item );
    dev->renderer_item = item;
    dev->published = true;
    return VLC_SUCCESS;

error:
    free( psz_extra_sout );
    free( psz_uri );
    free( psz_name );
    return VLC_ENOMEM;
}

static void
airplay_handle_service( vlc_renderer_discovery_t *p_rd,
                        struct discovery_sys *p_sys,
                        const struct srv *p_srv,
                        const char *psz_ip, bool b_ipv6,
                        const struct rr_entry *p_entries )
{
    struct airplay_discovered_device probe;
    struct airplay_discovered_device *dev;
    bool is_raop = p_srv->renderer_proto->kind == MDNS_KIND_RAOP;
    const char *dns_fallback = p_srv->psz_device_name;

    airplay_device_init( &probe );

    if( p_srv->psz_device_name != NULL )
    {
        if( is_raop )
        {
            probe.raop_hwid =
                airplay_raop_hwid_from_instance( p_srv->psz_device_name );
            /* Friendly name after '@' when present. */
            const char *at = strchr( p_srv->psz_device_name, '@' );
            probe.display_name = strdup( at != NULL ? at + 1
                                                    : p_srv->psz_device_name );
        }
        else
            probe.display_name = strdup( p_srv->psz_device_name );
    }

    if( is_raop )
        airplay_endpoint_set( &probe.raop, psz_ip, p_srv->i_port, b_ipv6 );
    else
        airplay_endpoint_set( &probe.airplay, psz_ip, p_srv->i_port, b_ipv6 );

    airplay_collect_txt( &probe, is_raop, p_entries );
    airplay_refresh_capabilities( &probe );
    probe.stable_id = airplay_derive_stable_id( &probe, dns_fallback );
    probe.last_seen = vlc_tick_now();

    dev = airplay_device_table_find_match( &p_sys->airplay_devices, &probe );
    if( dev == NULL )
    {
        dev = calloc( 1, sizeof(*dev) );
        if( dev == NULL )
        {
            airplay_device_clear( &probe );
            return;
        }
        airplay_device_init( dev );
        if( airplay_device_merge( dev, &probe ) != 0
         || airplay_device_table_add( &p_sys->airplay_devices, dev ) == NULL )
        {
            airplay_device_clear( &probe );
            airplay_device_clear( dev );
            free( dev );
            return;
        }
        dev->last_seen = vlc_tick_now();
    }
    else
    {
        if( airplay_device_merge( dev, &probe ) != 0 )
        {
            airplay_device_clear( &probe );
            return;
        }
        dev->last_seen = vlc_tick_now();
    }

    airplay_device_clear( &probe );
    airplay_publish( p_rd, dev );
}

static void
new_entries_sd_cb( void *p_this, int i_status, const struct rr_entry *p_entries )
{
    services_discovery_t *p_sd = (services_discovery_t *)p_this;
    struct discovery_sys *p_sys = p_sd->p_sys;
    if( i_status < 0 )
    {
        print_error( VLC_OBJECT( p_sd ), "entry callback", i_status );
        return;
    }

    struct srv *p_srvs;
    unsigned i_nb_srv;
    const char *psz_ip;
    bool b_ipv6 = false;
    if( parse_entries_sd( p_entries, &p_srvs, &i_nb_srv,
                          &psz_ip, &b_ipv6 ) != VLC_SUCCESS )
        return;

    for( unsigned int i = 0; i < i_nb_srv; ++i )
    {
        struct srv *p_srv = &p_srvs[i];
        char *psz_uri = create_uri( p_srv->psz_protocol, psz_ip, b_ipv6,
                                    p_srv->i_port );

        if( psz_uri == NULL )
            break;

        if( items_exists( p_sys, psz_uri ) )
        {
            free( psz_uri );
            continue;
        }
        items_add_input( p_sys, p_sd, psz_uri, p_srv->psz_device_name, p_srv->item_type );
    }

    clear_srvs( p_srvs, i_nb_srv );
}


static bool
stop_sd_cb( void *p_this )
{
    services_discovery_t *p_sd = ( services_discovery_t* )p_this;
    struct discovery_sys *p_sys = p_sd->p_sys;

    if( atomic_load( &p_sys->stop ) )
        return true;
    else
    {
        items_timeout( p_sys, p_sd, NULL );
        return false;
    }
}

static void *
RunSD( void *p_this )
{
    vlc_thread_set_name("vlc-mdns-servis");

    services_discovery_t *p_sd = ( services_discovery_t* )p_this;
    struct discovery_sys *p_sys = p_sd->p_sys;

    int i_status = mdns_listen( p_sys->p_microdns,
                                p_sys->ppsz_service_names,
                                p_sys->i_nb_service_names,
                                RR_PTR, SEC_FROM_VLC_TICK(LISTEN_INTERVAL),
                                stop_sd_cb, new_entries_sd_cb, p_sd );

    if( i_status < 0 )
        print_error( VLC_OBJECT( p_sd ), "listen", i_status );

    return NULL;
}

static void
new_entries_rd_cb( void *p_this, int i_status, const struct rr_entry *p_entries )
{
    vlc_renderer_discovery_t *p_rd = (vlc_renderer_discovery_t *)p_this;
    struct discovery_sys *p_sys = p_rd->p_sys;
    if( i_status < 0 )
    {
        print_error( VLC_OBJECT( p_rd ), "entry callback", i_status );
        return;
    }

    struct srv *p_srvs;
    unsigned i_nb_srv;
    const char *psz_ip;
    bool b_ipv6 = false;
    if( parse_entries_rd( p_entries, &p_srvs, &i_nb_srv,
                          &psz_ip, &b_ipv6 ) != VLC_SUCCESS )
        return;

    for( unsigned int i = 0; i < i_nb_srv; ++i )
    {
        struct srv *p_srv = &p_srvs[i];
        const struct mdns_renderer_protocol *proto = p_srv->renderer_proto;

        if( proto == NULL )
            continue;

        if( proto->kind == MDNS_KIND_AIRPLAY || proto->kind == MDNS_KIND_RAOP )
        {
            airplay_handle_service( p_rd, p_sys, p_srv, psz_ip, b_ipv6,
                                    p_entries );
            continue;
        }

        /* Chromecast path — preserve prior URI/sout/demux behavior. */
        char *psz_icon_uri = NULL;
        char *psz_uri = create_uri( p_srv->psz_protocol, psz_ip, b_ipv6,
                                    p_srv->i_port );
        const char *psz_demux_filter = proto->psz_demux_filter;

        if( psz_uri == NULL )
            break;

        if( items_exists( p_sys, psz_uri ) )
        {
            free( psz_uri );
            continue;
        }

        if( p_srv->renderer.psz_icon != NULL
         && asprintf( &psz_icon_uri, "http://%s:8008%s", psz_ip,
                      p_srv->renderer.psz_icon ) == -1 )
        {
            free( psz_uri );
            break;
        }
        if( p_srv->renderer.psz_model != NULL )
        {
            char* psz_name;
            if ( asprintf( &psz_name, "%s (%s)", p_srv->psz_device_name,
                           p_srv->renderer.psz_model ) > 0 )
            {
                free( p_srv->psz_device_name );
                p_srv->psz_device_name = psz_name;
            }
        }

        items_add_renderer( p_sys, p_rd, proto->psz_renderer_type,
                            p_srv->psz_device_name, psz_uri,
                            psz_demux_filter, psz_icon_uri,
                            p_srv->renderer.i_renderer_flags );
        free(psz_icon_uri);
    }

    clear_srvs( p_srvs, i_nb_srv );
}

static bool
stop_rd_cb( void *p_this )
{
    vlc_renderer_discovery_t *p_rd = p_this;
    struct discovery_sys *p_sys = p_rd->p_sys;

    if( atomic_load( &p_sys->stop ) )
        return true;
    else
    {
        items_timeout( p_sys, NULL, p_rd );
        return false;
    }
}

static void *
RunRD( void *p_this )
{
    vlc_thread_set_name("vlc-mdns-render");

    vlc_renderer_discovery_t *p_rd = p_this;
    struct discovery_sys *p_sys = p_rd->p_sys;

    int i_status = mdns_listen( p_sys->p_microdns,
                                p_sys->ppsz_service_names,
                                p_sys->i_nb_service_names,
                                RR_PTR, SEC_FROM_VLC_TICK(LISTEN_INTERVAL),
                                stop_rd_cb, new_entries_rd_cb, p_rd );

    if( i_status < 0 )
        print_error( VLC_OBJECT( p_rd ), "listen", i_status );

    return NULL;
}

static int
OpenCommon( vlc_object_t *p_obj, struct discovery_sys *p_sys, bool b_renderer )
{
    int i_ret = VLC_EGENERIC;
    atomic_init( &p_sys->stop, false );
    vlc_array_init( &p_sys->items );
    airplay_device_table_init( &p_sys->airplay_devices );

    if( b_renderer )
    {
        for( size_t i = 0; i < ARRAY_SIZE(renderer_protocols); ++i )
            p_sys->ppsz_service_names[p_sys->i_nb_service_names++] =
                renderer_protocols[i].psz_service_name;
    }
    else
    {
        for( size_t i = 0; i < ARRAY_SIZE(sd_protocols); ++i )
            p_sys->ppsz_service_names[p_sys->i_nb_service_names++] =
                sd_protocols[i].psz_service_name;
    }

    if( p_sys->i_nb_service_names == 0 )
    {
        msg_Err( p_obj, "no services found" );
        goto error;
    }
    for( unsigned int i = 0; i < p_sys->i_nb_service_names; ++i )
        msg_Dbg( p_obj, "mDNS: listening to %s %s", p_sys->ppsz_service_names[i],
                 b_renderer ? "renderer" : "service" );

    int i_status;
    if( ( i_status = mdns_init( &p_sys->p_microdns, MDNS_ADDR_IPV4,
                                MDNS_PORT ) ) < 0 )
    {
        print_error( p_obj, "init", i_status );
        goto error;
    }

    if( vlc_clone( &p_sys->thread, b_renderer ? RunRD : RunSD, p_obj) )
    {
        msg_Err( p_obj, "Can't run the lookup thread" );
        goto error;
    }

    return VLC_SUCCESS;
error:
    if( p_sys->p_microdns != NULL )
        mdns_destroy( p_sys->p_microdns );
    free( p_sys );
    return i_ret;
}

static void
CleanCommon( struct discovery_sys *p_sys )
{
    atomic_store( &p_sys->stop, true );
    vlc_join( p_sys->thread, NULL );

    items_clear( p_sys );
    mdns_destroy( p_sys->p_microdns );
    free( p_sys );
}

static int
OpenSD( vlc_object_t *p_obj )
{
    services_discovery_t *p_sd = (services_discovery_t *)p_obj;

    struct discovery_sys *p_sys = calloc( 1, sizeof(struct discovery_sys) );
    if( !p_sys )
        return VLC_ENOMEM;
    p_sd->p_sys = p_sys;

    p_sd->description = _("mDNS Network Discovery");
    config_ChainParse( p_sd, CFG_PREFIX, ppsz_options, p_sd->p_cfg );

    return OpenCommon( p_obj, p_sys, false );
}

static void
CloseSD( vlc_object_t *p_this )
{
    services_discovery_t *p_sd = (services_discovery_t *) p_this;
    struct discovery_sys *p_sys = p_sd->p_sys;

    CleanCommon( p_sys );
}

static int
OpenRD( vlc_object_t *p_obj )
{
    vlc_renderer_discovery_t *p_rd = (vlc_renderer_discovery_t *)p_obj;

    struct discovery_sys *p_sys = calloc( 1, sizeof(struct discovery_sys) );
    if( !p_sys )
        return VLC_ENOMEM;
    p_rd->p_sys = p_sys;

    config_ChainParse( p_rd, CFG_PREFIX, ppsz_options, p_rd->p_cfg );

    return OpenCommon( p_obj, p_sys, true );
}

static void
CloseRD( vlc_object_t *p_this )
{
    vlc_renderer_discovery_t *p_rd = (vlc_renderer_discovery_t *) p_this;
    struct discovery_sys *p_sys = p_rd->p_sys;

    CleanCommon( p_sys );
}
