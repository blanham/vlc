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

#include <stdlib.h>

#include <vlc_common.h>
#include <vlc_configuration.h>
#include <vlc_plugin.h>
#include <vlc_block.h>
#include <vlc_sout.h>

#include "airplay.h"

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

    free( p_sys->ip );
    free( p_sys->device_id );
    free( p_sys->device_name );
    free( p_sys );
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

    config_ChainParse( p_stream, SOUT_CFG_PREFIX, ppsz_sout_options,
                       p_stream->p_cfg );

    p_sys->ip = var_GetNonEmptyString( p_stream, SOUT_CFG_PREFIX "ip" );
    p_sys->port = var_GetInteger( p_stream, SOUT_CFG_PREFIX "port" );
    p_sys->http_port = var_GetInteger( p_stream, SOUT_CFG_PREFIX "http-port" );
    p_sys->device_id = var_GetNonEmptyString( p_stream, SOUT_CFG_PREFIX "device-id" );
    p_sys->device_name = var_GetNonEmptyString( p_stream, SOUT_CFG_PREFIX "device-name" );

    p_stream->p_sys = p_sys;
    p_stream->ops = &ops;
    return VLC_SUCCESS;
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
