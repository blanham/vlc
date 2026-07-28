#ifndef VLC_AIRPLAY_SOUT_H
#define VLC_AIRPLAY_SOUT_H

#include <vlc_common.h>
#include <vlc_player.h>
#include <vlc_sout.h>
#include <vlc_threads.h>

#define SOUT_CFG_PREFIX "sout-airplay-"
#define AIRPLAY_DEFAULT_HTTP_PORT 8090  /* avoid Chromecast 8010 */

typedef struct airplay_http_media airplay_http_media;
typedef struct airplay_pairing airplay_pairing;
typedef struct airplay_session airplay_session;

struct airplay_sys
{
    char *ip;
    uint16_t port;
    uint16_t http_port;
    char *device_id;   /* stable renderer id; not a secret */
    char *device_name;
    char *filepath;
    char *lan_ip;
    char *media_url;
    airplay_http_media *media;
    airplay_pairing *pairing;
    airplay_session *session;
    vlc_player_t *player;
    vlc_player_listener_id *player_listener;
    vlc_player_timer_id *player_timer;
    vlc_mutex_t lock;
    vlc_cond_t wait;
    vlc_thread_t control_thread;
    bool control_thread_started;
    bool closing;
    bool pending_stop;
    bool pending_rate;
    double requested_rate;
    bool pending_scrub;
    double requested_scrub;
};

#endif
