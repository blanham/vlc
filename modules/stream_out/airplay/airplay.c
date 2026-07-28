/*****************************************************************************
 * airplay.c: AirPlay stream output module
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

#include <string.h>
#include <stdlib.h>

#include <vlc_common.h>
#include <vlc_configuration.h>
#include <vlc_dialog.h>
#include <vlc_network.h>
#include <vlc_objects.h>
#include <vlc_plugin.h>
#include <vlc_player.h>
#include <vlc_block.h>
#include <vlc_sout.h>
#include <vlc_threads.h>

#include "airplay.h"
#include "http_media.h"
#include "pairing.h"
#include "path.h"
#include "session.h"

static char *
airplay_lan_ip_for_peer(sout_stream_t *p_stream, const char *ip, uint16_t port)
{
    int fd = net_Connect(VLC_OBJECT(p_stream), ip, port, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
        return NULL;

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    char host[NI_MAXHOST];
    char *result = NULL;

    if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == 0 &&
        vlc_getnameinfo((const struct sockaddr *)&addr, addrlen,
                        host, sizeof(host), NULL, NI_NUMERICHOST) == 0 &&
        strcmp(host, "127.0.0.1") != 0 && strcmp(host, "::1") != 0)
        result = strdup(host);

    net_Close(fd);
    return result;
}

static vlc_player_t *
airplay_find_player(vlc_object_t *obj)
{
    for( vlc_object_t *parent = vlc_object_parent(obj); parent != NULL;
         parent = vlc_object_parent(parent) )
    {
        if( strcmp(vlc_object_typename(parent), "player") == 0 )
            return (vlc_player_t *) parent;
    }
    return NULL;
}

static void
airplay_queue_rate(struct airplay_sys *sys, double rate)
{
    vlc_mutex_lock(&sys->lock);
    sys->requested_rate = rate;
    sys->pending_rate = true;
    vlc_cond_signal(&sys->wait);
    vlc_mutex_unlock(&sys->lock);
}

static void
airplay_queue_scrub(struct airplay_sys *sys, double position)
{
    vlc_mutex_lock(&sys->lock);
    sys->requested_scrub = position;
    sys->pending_scrub = true;
    vlc_cond_signal(&sys->wait);
    vlc_mutex_unlock(&sys->lock);
}

static void
airplay_queue_stop(struct airplay_sys *sys)
{
    vlc_mutex_lock(&sys->lock);
    sys->pending_stop = true;
    vlc_cond_signal(&sys->wait);
    vlc_mutex_unlock(&sys->lock);
}

static void
player_on_state_changed(vlc_player_t *player, enum vlc_player_state state,
                        void *data)
{
    VLC_UNUSED(player);
    struct airplay_sys *sys = data;

    switch( state )
    {
        case VLC_PLAYER_STATE_PLAYING:
            airplay_queue_rate(sys, 1.0);
            break;
        case VLC_PLAYER_STATE_PAUSED:
            airplay_queue_rate(sys, 0.0);
            break;
        case VLC_PLAYER_STATE_STOPPING:
        case VLC_PLAYER_STATE_STOPPED:
            airplay_queue_stop(sys);
            break;
        default:
            break;
    }
}

static void
player_timer_on_seek(const struct vlc_player_timer_point *value, void *data)
{
    if( value == NULL )
        return;

    struct airplay_sys *sys = data;
    if( value->position >= 0.0 && value->position <= 1.0 )
        airplay_queue_scrub(sys, value->position);
}

static const struct vlc_player_cbs player_cbs = {
    .on_state_changed = player_on_state_changed,
};

static const struct vlc_player_timer_cbs player_timer_cbs = {
    .on_seek = player_timer_on_seek,
};

static void *
AirPlayControlThread(void *data)
{
    struct airplay_sys *sys = data;
    vlc_thread_set_name("vlc-airplay-ctl");

    for (;;)
    {
        bool stop = false, do_rate = false, do_scrub = false;
        double rate = 0.0, scrub = 0.0;

        vlc_mutex_lock(&sys->lock);
        while( !sys->closing && !sys->pending_stop && !sys->pending_rate &&
               !sys->pending_scrub )
            vlc_cond_wait(&sys->wait, &sys->lock);

        if( sys->closing )
        {
            vlc_mutex_unlock(&sys->lock);
            break;
        }

        stop = sys->pending_stop;
        do_rate = sys->pending_rate;
        do_scrub = sys->pending_scrub;
        rate = sys->requested_rate;
        scrub = sys->requested_scrub;
        sys->pending_stop = false;
        sys->pending_rate = false;
        sys->pending_scrub = false;
        vlc_mutex_unlock(&sys->lock);

        if( stop )
        {
            airplay_session_stop(sys->session);
            continue;
        }
        if( do_scrub )
            airplay_session_scrub(sys->session, scrub);
        if( do_rate )
            airplay_session_rate(sys->session, rate);
    }

    return NULL;
}

static void *Add( sout_stream_t *p_stream, const es_format_t *p_fmt, const char *es_id )
{
    VLC_UNUSED(p_stream); VLC_UNUSED(p_fmt); VLC_UNUSED(es_id);
    return malloc( 1 );
}

static void Del( sout_stream_t *p_stream, void *id )
{
    VLC_UNUSED(p_stream);
    free( id );
}

static int Send( sout_stream_t *p_stream, void *id, block_t *p_buffer )
{
    VLC_UNUSED(p_stream); VLC_UNUSED(id);
    block_ChainRelease( p_buffer );
    return VLC_SUCCESS;
}

static void Close( sout_stream_t *p_stream )
{
    struct airplay_sys *p_sys = p_stream->p_sys;
    if( p_sys == NULL )
        return;

    if( p_sys->player != NULL && p_sys->player_timer != NULL )
        vlc_player_RemoveTimer(p_sys->player, p_sys->player_timer);
    if( p_sys->player != NULL && p_sys->player_listener != NULL )
    {
        vlc_player_Lock(p_sys->player);
        vlc_player_RemoveListener(p_sys->player, p_sys->player_listener);
        vlc_player_Unlock(p_sys->player);
    }

    if( p_sys->control_thread_started )
    {
        vlc_mutex_lock(&p_sys->lock);
        p_sys->closing = true;
        vlc_cond_signal(&p_sys->wait);
        vlc_mutex_unlock(&p_sys->lock);
        vlc_join(p_sys->control_thread, NULL);
    }

    if( p_sys->session != NULL )
        airplay_session_release( p_sys->session );
    if( p_sys->pairing != NULL )
        airplay_pairing_release( p_sys->pairing );
    if( p_sys->media != NULL )
        airplay_http_media_stop( p_sys->media );

    free( p_sys->media_url );
    free( p_sys->lan_ip );
    free( p_sys->filepath );
    free( p_sys->ip );
    free( p_sys->device_id );
    free( p_sys->device_name );
    free( p_sys );
    p_stream->p_sys = NULL;
}

static const struct sout_stream_operations ops = {
    .add = Add,
    .del = Del,
    .send = Send,
    .close = Close,
};

static const char *const ppsz_sout_options[] = {
    "ip", "port", "http-port", "device-id", "device-name", NULL
};

static int Open( vlc_object_t *p_this )
{
    sout_stream_t *p_stream = (sout_stream_t *)p_this;
    struct airplay_sys *p_sys;

    p_sys = calloc( 1, sizeof( *p_sys ) );
    if( unlikely( p_sys == NULL ) )
        return VLC_ENOMEM;
    p_stream->p_sys = p_sys;
    vlc_mutex_init(&p_sys->lock);
    vlc_cond_init(&p_sys->wait);

    config_ChainParse( p_stream, SOUT_CFG_PREFIX, ppsz_sout_options,
                       p_stream->p_cfg );

    p_sys->ip = var_GetNonEmptyString( p_stream, SOUT_CFG_PREFIX "ip" );
    p_sys->port = var_GetInteger( p_stream, SOUT_CFG_PREFIX "port" );
    p_sys->http_port = var_GetInteger( p_stream, SOUT_CFG_PREFIX "http-port" );
    p_sys->device_id = var_GetNonEmptyString( p_stream, SOUT_CFG_PREFIX "device-id" );
    p_sys->device_name = var_GetNonEmptyString( p_stream, SOUT_CFG_PREFIX "device-name" );

    if( p_sys->ip == NULL || p_sys->device_id == NULL || p_sys->port == 0 ||
        p_sys->http_port == 0 )
    {
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Missing AirPlay target settings." );
        goto error;
    }

    p_sys->filepath = airplay_resolve_local_path( VLC_OBJECT( p_stream ) );
    if( p_sys->filepath == NULL )
    {
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Current media is not a readable local file." );
        goto error;
    }

    p_sys->pairing = airplay_pairing_new( VLC_OBJECT( p_stream ), p_sys->ip,
                                          p_sys->port, p_sys->device_id,
                                          p_sys->device_name );
    if( p_sys->pairing == NULL || airplay_pairing_ensure( p_sys->pairing ) != VLC_SUCCESS )
    {
        vlc_dialog_display_error( p_stream, "AirPlay pairing failed",
                                  "Could not pair with %s.",
                                  p_sys->device_name != NULL ? p_sys->device_name
                                                             : p_sys->device_id );
        goto error;
    }

    p_sys->media = airplay_http_media_start( VLC_OBJECT( p_stream ),
                                             p_sys->http_port, p_sys->filepath );
    if( p_sys->media == NULL )
    {
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Could not start the local AirPlay media server." );
        goto error;
    }

    p_sys->lan_ip = airplay_lan_ip_for_peer( p_stream, p_sys->ip, p_sys->port );
    if( p_sys->lan_ip == NULL )
    {
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Could not determine a LAN IP address reachable by the receiver." );
        goto error;
    }

    p_sys->media_url = airplay_http_media_url( p_sys->media, p_sys->lan_ip );
    if( p_sys->media_url == NULL )
        goto error;

    p_sys->session = airplay_session_new( VLC_OBJECT( p_stream ), p_sys->pairing,
                                          p_sys->ip, p_sys->port );
    if( p_sys->session == NULL )
        goto error;

    p_sys->player = airplay_find_player(VLC_OBJECT(p_stream));
    if( p_sys->player != NULL )
    {
        vlc_player_Lock(p_sys->player);
        p_sys->player_listener = vlc_player_AddListener(p_sys->player,
                                                        &player_cbs, p_sys);
        vlc_player_Unlock(p_sys->player);
        if( p_sys->player_listener == NULL )
            goto error;

        p_sys->player_timer = vlc_player_AddTimer(p_sys->player,
                                                  VLC_TICK_INVALID,
                                                  &player_timer_cbs, p_sys);
        if( p_sys->player_timer == NULL )
            goto error;
    }

    if( p_sys->player != NULL )
    {
        if( vlc_clone(&p_sys->control_thread, AirPlayControlThread, p_sys) != 0 )
            goto error;
        p_sys->control_thread_started = true;
    }

    if( airplay_session_play( p_sys->session, p_sys->media_url, 0.0 ) != 0 )
    {
        vlc_dialog_display_error( p_stream, "AirPlay playback failed",
                                  "Could not start playback on %s.",
                                  p_sys->device_name != NULL ? p_sys->device_name
                                                             : p_sys->device_id );
        goto error;
    }

    p_stream->ops = &ops;
    return VLC_SUCCESS;

error:
    Close( p_stream );
    return VLC_EGENERIC;
}

#define IP_TEXT N_("Target IP address")
#define IP_LONGTEXT N_("IP address of the AirPlay receiver.")

#define PORT_TEXT N_("RAOP port")
#define PORT_LONGTEXT N_("Port for the RAOP control connection.")

#define HTTP_PORT_TEXT N_("HTTP port")
#define HTTP_PORT_LONGTEXT N_("Port for the AirPlay HTTP control server.")

#define ID_TEXT N_("Device identifier")
#define ID_LONGTEXT N_("Stable renderer identifier (not a secret).")

#define NAME_TEXT N_("Device name")
#define NAME_LONGTEXT N_("Human-readable name of the AirPlay receiver.")

vlc_module_begin()
    set_shortname(N_("AirPlay"))
    set_description(N_("AirPlay stream output"))
    set_capability("sout output", 0)
    add_shortcut("airplay")
    add_string(SOUT_CFG_PREFIX "ip", NULL, IP_TEXT, IP_LONGTEXT)
        change_private()
    add_integer(SOUT_CFG_PREFIX "port", 7000, PORT_TEXT, PORT_LONGTEXT)
        change_private()
    add_integer(SOUT_CFG_PREFIX "http-port", AIRPLAY_DEFAULT_HTTP_PORT,
                HTTP_PORT_TEXT, HTTP_PORT_LONGTEXT)
    add_string(SOUT_CFG_PREFIX "device-id", NULL, ID_TEXT, ID_LONGTEXT)
        change_private()
    add_string(SOUT_CFG_PREFIX "device-name", NULL, NAME_TEXT, NAME_LONGTEXT)
        change_private()
    set_callback(Open)
vlc_module_end()
