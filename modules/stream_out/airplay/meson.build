# crypto.c needs libgcrypt's gcry_kdf_open()/HKDF support (>= 1.10.0) and
# the gcry_ecc_mul_point() Curve25519 API (>= 1.9.0); the top-level
# `gcrypt_dep` only guarantees >= 1.6.0, which is too old for this module.
# Re-resolve libgcrypt with the higher floor locally so the module (and its
# unit test) are simply disabled on older gcrypt instead of failing to
# compile, without raising the tree-wide gcrypt requirement.
airplay_gcrypt_dep = dependency('libgcrypt',
                                 version: '>= 1.10.0',
                                 required: false)

vlc_modules += {
    'name' : 'stream_out_airplay',
    'sources' : files(
        'airplay.c',
        'crypto.c',
        'http_media.c',
        'keystore_id.c',
        'path.c',
        'plist.c'),
    'dependencies' : [socket_libs, airplay_gcrypt_dep],
    'enabled' : get_option('stream_outputs') and airplay_gcrypt_dep.found(),
    'shortname' : 's_o_airp',
}
