vlc_modules += {
    'name' : 'stream_out_airplay',
    'sources' : files('airplay.c', 'plist.c'),
    'dependencies' : [socket_libs, gcrypt_dep],
    'enabled' : get_option('stream_outputs') and gcrypt_dep.found(),
    'shortname' : 's_o_airp',
}
