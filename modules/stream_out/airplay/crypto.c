/*****************************************************************************
 * crypto.c: gcrypt-backed pairing crypto helpers for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "crypto.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#ifndef AIRPLAY_CRYPTO_STANDALONE
# include <vlc_common.h>
# include <vlc_gcrypt.h>
#endif

void
airplay_crypto_init(void)
{
#ifdef AIRPLAY_CRYPTO_STANDALONE
    gcry_check_version(NULL);
#else
    vlc_gcrypt_init();
#endif
}

/* -- shared helpers ------------------------------------------------------ */

static void
secure_clear(void *buf, size_t len)
{
    volatile uint8_t *cursor = buf;
    while (len-- > 0)
        *cursor++ = 0;
}

static int
consttime_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

/* Extracts the raw octets of a named sub-value anywhere in `sexp`
 * (e.g. "q", "d", "r", "s"), left-padding with zero bytes up to out_len
 * if the underlying value was shorter (libgcrypt may strip leading
 * zero bytes from values it treats as ordinary big-endian integers). */
static int
sexp_token_bytes(gcry_sexp_t sexp, const char *name, uint8_t *out,
                  size_t out_len)
{
    gcry_sexp_t node = gcry_sexp_find_token(sexp, name, 0);
    if (node == NULL)
        return -1;

    size_t len;
    const char *data = gcry_sexp_nth_data(node, 1, &len);
    int ret = -1;
    if (data != NULL && len <= out_len)
    {
        memset(out, 0, out_len - len);
        memcpy(out + (out_len - len), data, len);
        ret = 0;
    }
    gcry_sexp_release(node);
    return ret;
}

/* -- Ed25519 (RFC 8032) --------------------------------------------------- */

int
airplay_ed25519_keypair(uint8_t sk[64], uint8_t pk[32])
{
    gcry_sexp_t parms = NULL, pair = NULL;
    int ret = -1;

    if (gcry_sexp_build(&parms, NULL,
            "(genkey (ecc (curve \"Ed25519\") (flags eddsa)))") != 0)
        return -1;

    if (gcry_pk_genkey(&pair, parms) == 0)
    {
        if (sexp_token_bytes(pair, "q", pk, 32) == 0 &&
            sexp_token_bytes(pair, "d", sk, 32) == 0)
        {
            memcpy(sk + 32, pk, 32);
            ret = 0;
        }
    }

    gcry_sexp_release(pair);
    gcry_sexp_release(parms);
    return ret;
}

int
airplay_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t len,
                      const uint8_t sk[64])
{
    static const uint8_t empty = 0;
    const uint8_t *safe_msg = (len == 0) ? &empty : msg;
    gcry_sexp_t key = NULL, data = NULL, result = NULL;
    int ret = -1;

    if (msg == NULL && len != 0)
        return -1;

    if (gcry_sexp_build(&key, NULL,
            "(private-key (ecc (curve \"Ed25519\") (flags eddsa)"
            " (q %b) (d %b)))",
            32, sk + 32, 32, sk) != 0)
        return -1;

    if (gcry_sexp_build(&data, NULL,
            "(data (flags eddsa) (hash-algo sha512) (value %b))",
            (int)len, safe_msg) != 0)
        goto out;

    if (gcry_pk_sign(&result, data, key) != 0)
        goto out;

    if (sexp_token_bytes(result, "r", sig, 32) == 0 &&
        sexp_token_bytes(result, "s", sig + 32, 32) == 0)
        ret = 0;

out:
    gcry_sexp_release(result);
    gcry_sexp_release(data);
    gcry_sexp_release(key);
    return ret;
}

int
airplay_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t len,
                        const uint8_t pk[32])
{
    static const uint8_t empty = 0;
    const uint8_t *safe_msg = (len == 0) ? &empty : msg;
    gcry_sexp_t key = NULL, data = NULL, sigsexp = NULL;
    int ret = -1;

    if (msg == NULL && len != 0)
        return -1;

    if (gcry_sexp_build(&key, NULL,
            "(public-key (ecc (curve \"Ed25519\") (flags eddsa) (q %b)))",
            32, pk) != 0)
        return -1;

    if (gcry_sexp_build(&data, NULL,
            "(data (flags eddsa) (hash-algo sha512) (value %b))",
            (int)len, safe_msg) != 0)
        goto out;

    if (gcry_sexp_build(&sigsexp, NULL,
            "(sig-val (eddsa (r %b) (s %b)))",
            32, sig, 32, sig + 32) != 0)
        goto out;

    ret = (gcry_pk_verify(sigsexp, data, key) == 0) ? 0 : -1;

out:
    gcry_sexp_release(sigsexp);
    gcry_sexp_release(data);
    gcry_sexp_release(key);
    return ret;
}

/* -- X25519 (RFC 7748) ---------------------------------------------------- */

int
airplay_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32])
{
    return gcry_ecc_mul_point(GCRY_ECC_CURVE25519, shared, sk, pk) == 0
               ? 0 : -1;
}

int
airplay_x25519_keypair(uint8_t sk[32], uint8_t pk[32])
{
    gcry_randomize(sk, 32, GCRY_STRONG_RANDOM);
    return gcry_ecc_mul_point(GCRY_ECC_CURVE25519, pk, sk, NULL) == 0
               ? 0 : -1;
}

/* -- ChaCha20-Poly1305 AEAD (RFC 8439) ------------------------------------ */

#define AIRPLAY_POLY1305_TAG_LEN 16

static int
chacha_crypt(int encrypt, uint8_t *out, size_t *out_len,
             const uint8_t *in, size_t in_len,
             const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t *ad, size_t ad_len)
{
    gcry_cipher_hd_t hd;
    int ret = -1;

    if (out == NULL || out_len == NULL || in == NULL || key == NULL ||
        nonce == NULL || (ad == NULL && ad_len != 0))
        return -1;

    if (gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                          GCRY_CIPHER_MODE_POLY1305, 0) != 0)
        return -1;

    if (gcry_cipher_setkey(hd, key, 32) != 0)
        goto out;
    if (gcry_cipher_setiv(hd, nonce, 12) != 0)
        goto out;
    if (ad_len > 0 && gcry_cipher_authenticate(hd, ad, ad_len) != 0)
        goto out;

    if (encrypt)
    {
        if (in_len > 0 &&
            gcry_cipher_encrypt(hd, out, in_len, in, in_len) != 0)
            goto out;
        if (gcry_cipher_gettag(hd, out + in_len, AIRPLAY_POLY1305_TAG_LEN)
                != 0)
            goto out;
        *out_len = in_len + AIRPLAY_POLY1305_TAG_LEN;
    }
    else
    {
        if (in_len < AIRPLAY_POLY1305_TAG_LEN)
            goto out;

        size_t ct_len = in_len - AIRPLAY_POLY1305_TAG_LEN;
        if (ct_len > 0 &&
            gcry_cipher_decrypt(hd, out, ct_len, in, ct_len) != 0)
            goto out;
        if (gcry_cipher_checktag(hd, in + ct_len, AIRPLAY_POLY1305_TAG_LEN)
                != 0)
            goto out;
        *out_len = ct_len;
    }
    ret = 0;

out:
    gcry_cipher_close(hd);
    return ret;
}

int
airplay_chacha_encrypt(uint8_t *out, size_t *out_len,
                        const uint8_t *in, size_t in_len,
                        const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *ad, size_t ad_len)
{
    return chacha_crypt(1, out, out_len, in, in_len, key, nonce, ad, ad_len);
}

int
airplay_chacha_decrypt(uint8_t *out, size_t *out_len,
                        const uint8_t *in, size_t in_len,
                        const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *ad, size_t ad_len)
{
    return chacha_crypt(0, out, out_len, in, in_len, key, nonce, ad, ad_len);
}

/* -- HKDF-SHA512 (RFC 5869) ------------------------------------------------
 * libgcrypt's HKDF context ignores the outer "salt" argument and instead
 * reuses the "key" slot as the HKDF salt and the "ad" slot as the HKDF
 * "info"; see cipher/kdf.c _gcry_kdf_open()'s GCRY_KDF_HKDF case. */

int
airplay_hkdf_sha512(uint8_t *out, size_t out_len,
                     const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len)
{
    gcry_kdf_hd_t hd;
    unsigned long param[1] = { (unsigned long)out_len };
    int ret = -1;

    if (out == NULL || out_len == 0 || ikm == NULL || ikm_len == 0)
        return -1;

    if (gcry_kdf_open(&hd, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA512,
                       param, 1,
                       ikm, ikm_len,
                       NULL, 0,
                       salt, salt_len,
                       info, info_len) != 0)
        return -1;

    if (gcry_kdf_compute(hd, NULL) == 0 &&
        gcry_kdf_final(hd, out_len, out) == 0)
        ret = 0;

    gcry_kdf_close(hd);
    return ret;
}

/* -- SRP-6a, HAP 3072-bit group, SHA-512, username "Pair-Setup" ----------- */

#define SRP_N_BYTES 384
#define SRP_USERNAME "Pair-Setup"

/* RFC 5054 Appendix A, 3072-bit group. */
static const char srp_hap_n_hex[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

#define SRP_GENERATOR 5

struct airplay_srp_ctx
{
    char *pin;
    gcry_mpi_t a;
    gcry_mpi_t A;
    uint8_t A_bytes[SRP_N_BYTES];
    uint8_t K[64];
    uint8_t M1[64];
    bool have_secret;
    bool have_m1;
};

static int
srp_load_group(gcry_mpi_t *out_n, gcry_mpi_t *out_g)
{
    if (gcry_mpi_scan(out_n, GCRYMPI_FMT_HEX, srp_hap_n_hex, 0, NULL) != 0)
        return -1;

    *out_g = gcry_mpi_set_ui(NULL, SRP_GENERATOR);
    if (*out_g == NULL)
    {
        gcry_mpi_release(*out_n);
        return -1;
    }
    return 0;
}

static int
mpi_to_padded(gcry_mpi_t v, uint8_t *out, size_t out_len)
{
    size_t nbytes = 0;
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nbytes, v);
    if (nbytes > out_len)
        return -1;

    memset(out, 0, out_len - nbytes);
    if (nbytes == 0)
        return 0;

    size_t written = 0;
    if (gcry_mpi_print(GCRYMPI_FMT_USG, out + (out_len - nbytes), nbytes,
                        &written, v) != 0)
        return -1;
    return 0;
}

static gcry_mpi_t
mpi_from_bytes(const uint8_t *buf, size_t len)
{
    gcry_mpi_t v = NULL;
    if (gcry_mpi_scan(&v, GCRYMPI_FMT_USG, buf, len, NULL) != 0)
        return NULL;
    return v;
}

static void
sha512_parts(uint8_t out[64], ...)
{
    gcry_md_hd_t md;
    if (gcry_md_open(&md, GCRY_MD_SHA512, 0) != 0)
    {
        memset(out, 0, 64);
        return;
    }

    va_list ap;
    va_start(ap, out);
    for (;;)
    {
        const uint8_t *part = va_arg(ap, const uint8_t *);
        if (part == NULL)
            break;
        size_t part_len = va_arg(ap, size_t);
        gcry_md_write(md, part, part_len);
    }
    va_end(ap);

    memcpy(out, gcry_md_read(md, 0), 64);
    gcry_md_close(md);
}

/* k = H(N | PAD(g)) */
static int
srp_compute_k(gcry_mpi_t n, gcry_mpi_t g, gcry_mpi_t *out_k)
{
    uint8_t n_buf[SRP_N_BYTES], g_buf[SRP_N_BYTES], k_hash[64];

    if (mpi_to_padded(n, n_buf, sizeof n_buf) != 0 ||
        mpi_to_padded(g, g_buf, sizeof g_buf) != 0)
        return -1;

    sha512_parts(k_hash, n_buf, sizeof n_buf, g_buf, sizeof g_buf,
                 (const uint8_t *)NULL);

    *out_k = mpi_from_bytes(k_hash, sizeof k_hash);
    return (*out_k != NULL) ? 0 : -1;
}

airplay_srp_ctx *
airplay_srp_client_new(const char *pin)
{
    if (pin == NULL)
        return NULL;

    airplay_srp_ctx *ctx = calloc(1, sizeof (*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->pin = strdup(pin);
    if (ctx->pin == NULL)
    {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void
airplay_srp_client_release(airplay_srp_ctx *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->pin != NULL)
    {
        secure_clear(ctx->pin, strlen(ctx->pin));
        free(ctx->pin);
    }
    if (ctx->a != NULL)
        gcry_mpi_release(ctx->a);
    if (ctx->A != NULL)
        gcry_mpi_release(ctx->A);
    secure_clear(ctx->K, sizeof ctx->K);
    secure_clear(ctx, sizeof (*ctx));
    free(ctx);
}

int
airplay_srp_client_start(airplay_srp_ctx *ctx, uint8_t **A, size_t *A_len)
{
    if (ctx == NULL || A == NULL || A_len == NULL || ctx->a != NULL)
        return -1;

    gcry_mpi_t n = NULL, g = NULL;
    int ret = -1;

    if (srp_load_group(&n, &g) != 0)
        return -1;

    uint8_t a_random[32];
    gcry_randomize(a_random, sizeof a_random, GCRY_STRONG_RANDOM);
    gcry_mpi_t a = mpi_from_bytes(a_random, sizeof a_random);
    secure_clear(a_random, sizeof a_random);
    if (a == NULL)
        goto out;

    gcry_mpi_t big_a = gcry_mpi_new(0);
    if (big_a == NULL)
    {
        gcry_mpi_release(a);
        goto out;
    }
    gcry_mpi_powm(big_a, g, a, n);

    uint8_t *buf = malloc(SRP_N_BYTES);
    if (buf == NULL || mpi_to_padded(big_a, buf, SRP_N_BYTES) != 0)
    {
        free(buf);
        gcry_mpi_release(a);
        gcry_mpi_release(big_a);
        goto out;
    }

    ctx->a = a;
    ctx->A = big_a;
    memcpy(ctx->A_bytes, buf, SRP_N_BYTES);
    *A = buf;
    *A_len = SRP_N_BYTES;
    ret = 0;

out:
    gcry_mpi_release(n);
    gcry_mpi_release(g);
    return ret;
}

int
airplay_srp_client_finish(airplay_srp_ctx *ctx,
                           const uint8_t *salt, size_t salt_len,
                           const uint8_t *B, size_t B_len,
                           uint8_t **M1, size_t *M1_len,
                           uint8_t shared_key[32])
{
    if (ctx == NULL || ctx->a == NULL || ctx->A == NULL || salt == NULL ||
        salt_len == 0 || B == NULL || B_len == 0 || M1 == NULL ||
        M1_len == NULL || shared_key == NULL)
        return -1;

    gcry_mpi_t n = NULL, g = NULL, k = NULL, big_b = NULL, u = NULL,
               x = NULL, gx = NULL, t1 = NULL, base = NULL, ux = NULL,
               exponent = NULL, s = NULL;
    int ret = -1;

    if (srp_load_group(&n, &g) != 0)
        return -1;
    if (srp_compute_k(n, g, &k) != 0)
        goto out;

    big_b = mpi_from_bytes(B, B_len);
    if (big_b == NULL)
        goto out;

    /* Reject the degenerate server value B == 0 (mod N), which would let
     * an attacker force a known session key (RFC 5054 s. 2.5.4). */
    gcry_mpi_t b_mod_n = gcry_mpi_new(0);
    if (b_mod_n == NULL)
        goto out;
    gcry_mpi_mod(b_mod_n, big_b, n);
    bool b_is_zero = gcry_mpi_cmp_ui(b_mod_n, 0) == 0;
    gcry_mpi_release(b_mod_n);
    if (b_is_zero)
        goto out;

    uint8_t b_buf[SRP_N_BYTES];
    if (mpi_to_padded(big_b, b_buf, sizeof b_buf) != 0)
        goto out;

    uint8_t u_hash[64];
    sha512_parts(u_hash, ctx->A_bytes, (size_t)SRP_N_BYTES,
                 b_buf, (size_t)sizeof b_buf, (const uint8_t *)NULL);
    u = mpi_from_bytes(u_hash, sizeof u_hash);
    if (u == NULL || gcry_mpi_cmp_ui(u, 0) == 0)
        goto out;

    uint8_t inner_hash[64];
    sha512_parts(inner_hash,
                 (const uint8_t *)SRP_USERNAME, (size_t)strlen(SRP_USERNAME),
                 (const uint8_t *)":", (size_t)1,
                 (const uint8_t *)ctx->pin, strlen(ctx->pin),
                 (const uint8_t *)NULL);
    uint8_t x_hash[64];
    sha512_parts(x_hash, salt, salt_len, inner_hash, (size_t)sizeof inner_hash,
                 (const uint8_t *)NULL);
    x = mpi_from_bytes(x_hash, sizeof x_hash);
    if (x == NULL)
        goto out;

    gx = gcry_mpi_new(0);
    t1 = gcry_mpi_new(0);
    base = gcry_mpi_new(0);
    ux = gcry_mpi_new(0);
    exponent = gcry_mpi_new(0);
    s = gcry_mpi_new(0);
    if (gx == NULL || t1 == NULL || base == NULL || ux == NULL ||
        exponent == NULL || s == NULL)
        goto out;

    gcry_mpi_powm(gx, g, x, n);
    gcry_mpi_mulm(t1, k, gx, n);
    gcry_mpi_subm(base, big_b, t1, n);

    gcry_mpi_mul(ux, u, x);
    gcry_mpi_add(exponent, ctx->a, ux);
    gcry_mpi_powm(s, base, exponent, n);

    uint8_t s_buf[SRP_N_BYTES];
    if (mpi_to_padded(s, s_buf, sizeof s_buf) != 0)
        goto out;

    uint8_t k_session[64];
    sha512_parts(k_session, s_buf, sizeof s_buf, (const uint8_t *)NULL);
    memcpy(ctx->K, k_session, sizeof k_session);
    ctx->have_secret = true;
    memcpy(shared_key, k_session, 32);

    uint8_t hn[64], hg[64], hn_xor_hg[64], hi[64];
    uint8_t n_buf[SRP_N_BYTES], g_buf[SRP_N_BYTES];
    if (mpi_to_padded(n, n_buf, sizeof n_buf) != 0 ||
        mpi_to_padded(g, g_buf, sizeof g_buf) != 0)
        goto out;
    sha512_parts(hn, n_buf, sizeof n_buf, (const uint8_t *)NULL);
    sha512_parts(hg, g_buf, sizeof g_buf, (const uint8_t *)NULL);
    for (size_t i = 0; i < sizeof hn_xor_hg; i++)
        hn_xor_hg[i] = hn[i] ^ hg[i];
    sha512_parts(hi, (const uint8_t *)SRP_USERNAME,
                 (size_t)strlen(SRP_USERNAME), (const uint8_t *)NULL);

    uint8_t m1_hash[64];
    sha512_parts(m1_hash,
                 hn_xor_hg, (size_t)sizeof hn_xor_hg,
                 hi, (size_t)sizeof hi,
                 salt, salt_len,
                 ctx->A_bytes, (size_t)SRP_N_BYTES,
                 b_buf, (size_t)sizeof b_buf,
                 ctx->K, (size_t)sizeof ctx->K,
                 (const uint8_t *)NULL);

    uint8_t *m1_copy = malloc(sizeof m1_hash);
    if (m1_copy == NULL)
        goto out;
    memcpy(m1_copy, m1_hash, sizeof m1_hash);
    memcpy(ctx->M1, m1_hash, sizeof m1_hash);
    ctx->have_m1 = true;

    *M1 = m1_copy;
    *M1_len = sizeof m1_hash;
    ret = 0;

out:
    gcry_mpi_release(n);
    gcry_mpi_release(g);
    gcry_mpi_release(k);
    gcry_mpi_release(big_b);
    gcry_mpi_release(u);
    gcry_mpi_release(x);
    gcry_mpi_release(gx);
    gcry_mpi_release(t1);
    gcry_mpi_release(base);
    gcry_mpi_release(ux);
    gcry_mpi_release(exponent);
    gcry_mpi_release(s);
    return ret;
}

int
airplay_srp_client_verify_proof(airplay_srp_ctx *ctx,
                                 const uint8_t *M2, size_t M2_len)
{
    if (ctx == NULL || !ctx->have_m1 || !ctx->have_secret || M2 == NULL ||
        M2_len != 64)
        return -1;

    uint8_t expected[64];
    sha512_parts(expected,
                 ctx->A_bytes, (size_t)SRP_N_BYTES,
                 ctx->M1, (size_t)sizeof ctx->M1,
                 ctx->K, (size_t)sizeof ctx->K,
                 (const uint8_t *)NULL);

    return consttime_eq(expected, M2, sizeof expected) ? 0 : -1;
}
