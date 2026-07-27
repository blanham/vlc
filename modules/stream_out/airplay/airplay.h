#ifndef VLC_AIRPLAY_SOUT_H
#define VLC_AIRPLAY_SOUT_H

#include <vlc_common.h>
#include <vlc_sout.h>

#define SOUT_CFG_PREFIX "sout-airplay-"
#define AIRPLAY_DEFAULT_HTTP_PORT 8090  /* avoid Chromecast 8010 */

struct airplay_sys
{
    char *ip;
    uint16_t port;
    uint16_t http_port;
    char *device_id;   /* stable renderer id; not a secret */
    char *device_name;
};

#endif
