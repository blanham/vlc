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
#include <vlc_interrupt.h>

#include "airplay.h"
#include "http_media.h"
#include "pairing.h"
#include "path.h"
#include "session.h"

static int
parse_hex_byte(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int
parse_accessory_pk(const char *hex, uint8_t out[32])
{
    if (hex == NULL || strlen(hex) != 64)
        return -1;

    for (size_t i = 0; i < 32; ++i)
    {
        int hi = parse_hex_byte(hex[i * 2]);
        int lo = parse_hex_byte(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void
airplay_apply_accessory_info(airplay_pairing *pairing, sout_stream_t *stream)
{
    char *pk_hex = var_GetNonEmptyString(stream, SOUT_CFG_PREFIX "accessory-pk");
    char *pairing_id = var_GetNonEmptyString(stream,
                                             SOUT_CFG_PREFIX "accessory-pairing-id");
    uint8_t pk[32];

    if (pk_hex != NULL && parse_accessory_pk(pk_hex, pk) == 0)
        airplay_pairing_set_accessory_info(pairing, pk, pairing_id);

    free(pk_hex);
    free(pairing_id);
}

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
    {
        /* Drop a numeric zone id; it is not meaningful to the receiver. */
        char *zone = strchr(host, '%');
        if (zone != NULL)
            *zone = '\0';
        result = strdup(host);
    }

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
    if( sys->cast_left )
    {
        vlc_mutex_unlock(&sys->lock);
        return;
    }
    sys->requested_rate = rate;
    sys->pending_rate = true;
    vlc_cond_signal(&sys->wait);
    vlc_mutex_unlock(&sys->lock);
}

static void
airplay_queue_scrub(struct airplay_sys *sys, double position)
{
    vlc_mutex_lock(&sys->lock);
    if( sys->cast_left )
    {
        vlc_mutex_unlock(&sys->lock);
        return;
    }
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
airplay_pace_interrupt(void *data)
{
    struct airplay_sys *sys = data;

    vlc_mutex_lock(&sys->lock);
    sys->closing = true;
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
            vlc_mutex_lock(&sys->lock);
            if( sys->paused )
            {
                if( sys->pace_started )
                    sys->pace_origin_wall += vlc_tick_now() - sys->pause_since;
                sys->paused = false;
            }
            vlc_cond_signal(&sys->wait);
            vlc_mutex_unlock(&sys->lock);
            airplay_queue_rate(sys, 1.0);
            break;
        case VLC_PLAYER_STATE_PAUSED:
            vlc_mutex_lock(&sys->lock);
            if( !sys->paused )
            {
                sys->paused = true;
                sys->pause_since = vlc_tick_now();
            }
            vlc_cond_signal(&sys->wait);
            vlc_mutex_unlock(&sys->lock);
            airplay_queue_rate(sys, 0.0);
            break;
        case VLC_PLAYER_STATE_STOPPING:
            vlc_mutex_lock(&sys->lock);
            sys->closing = true;
            vlc_cond_signal(&sys->wait);
            vlc_mutex_unlock(&sys->lock);
            airplay_queue_stop(sys);
            break;
        default:
            break;
    }
}

static void
player_timer_on_update(const struct vlc_player_timer_point *value, void *data)
{
    VLC_UNUSED(value);
    VLC_UNUSED(data);
}

static void
player_timer_on_seek(const struct vlc_player_timer_point *value, void *data)
{
    if( value == NULL )
        return;

    struct airplay_sys *sys = data;
    vlc_mutex_lock(&sys->lock);
    sys->pace_reset = true;
    vlc_cond_signal(&sys->wait);
    vlc_mutex_unlock(&sys->lock);

    double seconds = -1.0;
    if( value->ts >= VLC_TICK_0 )
        seconds = secf_from_vlc_tick(value->ts - VLC_TICK_0);
    else if( value->length > VLC_TICK_0 &&
             value->position >= 0.0 && value->position <= 1.0 )
        seconds = value->position * secf_from_vlc_tick(value->length);
    if( seconds >= 0.0 )
        airplay_queue_scrub(sys, seconds);
}

static void
player_on_renderer_changed(vlc_player_t *player, vlc_renderer_item_t *new_item,
                           void *data)
{
    VLC_UNUSED(player);
    struct airplay_sys *sys = data;

    vlc_mutex_lock(&sys->lock);
    if( new_item != NULL )
    {
        vlc_mutex_unlock(&sys->lock);
        return;
    }

    /* SetRenderer queues work for this thread, which is blocked in Send.
     * Wake it so the input can tear the output down and stop the Apple TV. */
    sys->cast_left = true;
    sys->pending_stop = true;
    sys->pending_scrub = false;
    sys->pending_rate = false;
    sys->release_send = true;
    vlc_cond_broadcast(&sys->wait);
    vlc_mutex_unlock(&sys->lock);
}

static const struct vlc_player_cbs player_cbs = {
    .on_state_changed = player_on_state_changed,
    .on_renderer_changed = player_on_renderer_changed,
};

static const struct vlc_player_timer_cbs player_timer_cbs = {
    .on_update = player_timer_on_update,
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

        double deferred = -1.0;
        vlc_mutex_lock(&sys->lock);
        while( !sys->closing && !sys->pending_stop &&
               !sys->pending_rate && !sys->pending_scrub )
        {
            if( airplay_session_take_start_scrub(sys->session, &deferred) )
                break;
            vlc_cond_timedwait(&sys->wait, &sys->lock,
                               vlc_tick_now() + VLC_TICK_FROM_MS(250));
        }

        if( sys->closing && !sys->pending_stop )
        {
            vlc_mutex_unlock(&sys->lock);
            break;
        }

        bool closing = sys->closing;
        stop = sys->pending_stop;
        do_rate = sys->pending_rate && !sys->closing;
        do_scrub = sys->pending_scrub && !stop && !sys->closing;
        rate = sys->requested_rate;
        scrub = sys->requested_scrub;
        sys->pending_stop = false;
        sys->pending_rate = false;
        sys->pending_scrub = false;
        if( do_scrub && !stop )
        {
            vlc_tick_t quiet = vlc_tick_now() + VLC_TICK_FROM_MS(250);
            while( !sys->closing && vlc_tick_now() < quiet )
            {
                vlc_cond_timedwait(&sys->wait, &sys->lock, quiet);
                if( sys->pending_scrub )
                {
                    scrub = sys->requested_scrub;
                    sys->pending_scrub = false;
                    quiet = vlc_tick_now() + VLC_TICK_FROM_MS(250);
                }
            }
            do_scrub = !sys->closing;
        }
        vlc_mutex_unlock(&sys->lock);

        if( stop )
        {
            airplay_session_stop(sys->session);
            airplay_session_quiesce(sys->session);
            /* Stop serving the file before Close() tears the HTTP host down. */
            airplay_http_media_unpublish(sys->media);
        }
        if( stop || closing )
        {
            if( closing )
                break;
            continue;
        }
        if( deferred >= 0.0 )
            airplay_session_scrub(sys->session, deferred);
        if( do_scrub )
        {
            char *url = airplay_http_media_reissue(sys->media, sys->lan_ip, scrub);
            if( url != NULL )
            {
                airplay_session_requeue(sys->session, url, scrub);
                free(url);
            }
        }
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
    VLC_UNUSED(id);
    struct airplay_sys *sys = p_stream->p_sys;
    vlc_tick_t pts = VLC_TICK_INVALID;

    for( block_t *b = p_buffer; b != NULL; b = b->p_next )
    {
        if( b->i_pts != VLC_TICK_INVALID )
            pts = b->i_pts;
        else if( pts == VLC_TICK_INVALID && b->i_dts != VLC_TICK_INVALID )
            pts = b->i_dts;
    }
    block_ChainRelease( p_buffer );

    if( sys == NULL || pts == VLC_TICK_INVALID )
        return VLC_SUCCESS;

    /* Stop and close are posted to this same thread. A plain cond wait never
     * sees that, so quitting leaves the window hidden and the process alive. */
    vlc_interrupt_register(airplay_pace_interrupt, sys);
    vlc_mutex_lock(&sys->lock);
    if( !sys->pace_started || sys->pace_reset )
    {
        sys->pace_origin_pts = pts;
        sys->pace_origin_wall = vlc_tick_now();
        sys->pace_started = true;
        sys->pace_reset = false;
        msg_Dbg(p_stream, "AirPlay: pacing local input to the media timeline");
    }

    for( ;; )
    {
        if( sys->closing || sys->cast_left )
            break;
        if( sys->pace_reset )
        {
            sys->pace_origin_pts = pts;
            sys->pace_origin_wall = vlc_tick_now();
            sys->pace_reset = false;
            break;
        }
        if( sys->paused )
        {
            vlc_cond_wait(&sys->wait, &sys->lock);
            continue;
        }

        vlc_tick_t target = sys->pace_origin_wall + (pts - sys->pace_origin_pts);
        vlc_tick_t now = vlc_tick_now();
        if( now >= target )
            break;

        vlc_tick_t slice = target - now;
        if( slice > VLC_TICK_FROM_MS(200) )
            slice = VLC_TICK_FROM_MS(200);
        /* Interruptible: a seek or pause must wake the input thread immediately,
         * otherwise the timeline jumps back while this wait is still outstanding. */
        vlc_cond_timedwait(&sys->wait, &sys->lock, now + slice);
    }
    vlc_mutex_unlock(&sys->lock);
    vlc_interrupt_unregister();
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
    "ip", "port", "http-port", "device-id", "device-name",
    "accessory-pk", "accessory-pairing-id", NULL
};

static int Open( vlc_object_t *p_this )
{
    sout_stream_t *p_stream = (sout_stream_t *)p_this;
    struct airplay_sys *p_sys;
    int open_err = VLC_EGENERIC;

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
        msg_Err( p_stream, "AirPlay: no readable local file path for current media" );
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Current media is not a readable local file." );
        goto error;
    }

    msg_Dbg( p_stream, "AirPlay: casting %s to %s:%u",
             p_sys->filepath, p_sys->ip, (unsigned)p_sys->port );

    p_sys->pairing = airplay_pairing_new( VLC_OBJECT( p_stream ), p_sys->ip,
                                          p_sys->port, p_sys->device_id,
                                          p_sys->device_name );
    if( p_sys->pairing == NULL )
        goto error;

    airplay_apply_accessory_info( p_sys->pairing, p_stream );

    if( airplay_pairing_ensure( p_sys->pairing ) != VLC_SUCCESS )
    {
        const char *perr = p_sys->pairing != NULL ?
            airplay_pairing_error( p_sys->pairing ) : NULL;
        const char *dname = p_sys->device_name != NULL ? p_sys->device_name
                                                         : p_sys->device_id;
        msg_Err( p_stream, "AirPlay pairing failed with %s", dname );
        if( perr != NULL )
            vlc_dialog_display_error( p_stream, "AirPlay pairing failed",
                                      "%s", perr );
        else
            vlc_dialog_display_error( p_stream, "AirPlay pairing failed",
                                      _("Could not pair with %s."), dname );
        /* Stop module probing — a second Open would re-trigger pairing backoff. */
        open_err = VLC_ETIMEOUT;
        goto error;
    }

    /* Pairing succeeded — don't let VLC retry on later failures. */
    open_err = VLC_ETIMEOUT;

    msg_Dbg( p_stream, "AirPlay: starting HTTP media server on port %u",
             (unsigned)p_sys->http_port );
    p_sys->media = airplay_http_media_start( VLC_OBJECT( p_stream ),
                                             p_sys->http_port, p_sys->filepath );
    if( p_sys->media == NULL )
    {
        msg_Err( p_stream, "AirPlay: HTTP media server failed to start" );
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Could not start the local AirPlay media server." );
        goto error;
    }

    p_sys->lan_ip = airplay_lan_ip_for_peer( p_stream, p_sys->ip, p_sys->port );
    if( p_sys->lan_ip == NULL )
    {
        msg_Err( p_stream, "AirPlay: could not determine LAN IP" );
        vlc_dialog_display_error( p_stream, "AirPlay error",
                                  "%s", "Could not determine a LAN IP address reachable by the receiver." );
        goto error;
    }

    p_sys->media_url = airplay_http_media_url( p_sys->media, p_sys->lan_ip );
    if( p_sys->media_url == NULL )
    {
        msg_Err( p_stream, "AirPlay: could not build media URL" );
        goto error;
    }

    msg_Dbg( p_stream, "AirPlay: media URL = %s", p_sys->media_url );

    double start_seconds = 0.0;
    double duration_seconds = 0.0;
    p_sys->player = airplay_find_player(VLC_OBJECT(p_stream));
    if( p_sys->player != NULL )
    {
        vlc_player_Lock(p_sys->player);
        vlc_tick_t media_time = vlc_player_GetTime(p_sys->player);
        vlc_tick_t media_length = vlc_player_GetLength(p_sys->player);
        vlc_player_Unlock(p_sys->player);
        if( media_time > VLC_TICK_0 )
            start_seconds = secf_from_vlc_tick(media_time);
        if( media_length > VLC_TICK_0 )
            duration_seconds = secf_from_vlc_tick(media_length);
    }
    msg_Dbg( p_stream, "AirPlay: start position %.3f s of %.3f s",
             start_seconds, duration_seconds );
    airplay_http_media_set_start(p_sys->media, start_seconds);

    p_sys->session = airplay_session_new( VLC_OBJECT( p_stream ), p_sys->pairing,
                                          p_sys->ip, p_sys->port );
    if( p_sys->session == NULL )
    {
        msg_Err( p_stream, "AirPlay: session creation failed" );
        goto error;
    }

    msg_Dbg( p_stream, "AirPlay: sending /play to %s:%u",
             p_sys->ip, (unsigned)p_sys->port );
    if( airplay_session_play( p_sys->session, p_sys->media_url, start_seconds,
                              duration_seconds ) != 0 )
    {
        msg_Err( p_stream, "AirPlay: /play failed" );
        vlc_dialog_display_error( p_stream, "AirPlay playback failed",
                                  "Could not start playback on %s.",
                                  p_sys->device_name != NULL ? p_sys->device_name
                                                             : p_sys->device_id );
        goto error;
    }

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

    p_stream->ops = &ops;
    return VLC_SUCCESS;

error:
    Close( p_stream );
    return open_err;
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

#define ACCESSORY_PK_TEXT N_("Accessory public key")
#define ACCESSORY_PK_LONGTEXT N_("Ed25519 public key from mDNS (pk TXT), hex.")

#define ACCESSORY_PAIRING_ID_TEXT N_("Accessory pairing identifier")
#define ACCESSORY_PAIRING_ID_LONGTEXT N_("HAP pairing id from mDNS (deviceid TXT).")

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
    add_string(SOUT_CFG_PREFIX "accessory-pk", NULL,
               ACCESSORY_PK_TEXT, ACCESSORY_PK_LONGTEXT)
        change_private()
    add_string(SOUT_CFG_PREFIX "accessory-pairing-id", NULL,
               ACCESSORY_PAIRING_ID_TEXT, ACCESSORY_PAIRING_ID_LONGTEXT)
        change_private()
    set_callback(Open)
vlc_module_end()
