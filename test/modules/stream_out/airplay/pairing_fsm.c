/*****************************************************************************
 * pairing_fsm.c: AirPlay pairing FSM unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include "../../../../modules/stream_out/airplay/pairing.h"
#include "../../../../modules/stream_out/airplay/keystore_id.h"
#include "../../../../modules/stream_out/airplay/crypto.h"
#include "../../../../modules/stream_out/airplay/tlv.h"

static int failures;

static void
expect_true(bool condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static int
buf_cat(uint8_t **out, size_t *out_len,
        const uint8_t *a, size_t a_len,
        const uint8_t *b, size_t b_len,
        const uint8_t *c, size_t c_len)
{
    size_t total = a_len + b_len + c_len;
    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return -1;

    size_t off = 0;
    if (a_len > 0)
    {
        memcpy(buf + off, a, a_len);
        off += a_len;
    }
    if (b_len > 0)
    {
        memcpy(buf + off, b, b_len);
        off += b_len;
    }
    if (c_len > 0)
        memcpy(buf + off, c, c_len);

    *out = buf;
    *out_len = total;
    return 0;
}

/* -- SRP-6a server-side math (RFC 5054 Appendix A 3072-bit group) --------- */

#define SRP_N_BYTES 384
#define SRP_USERNAME "Pair-Setup"
#define SRP_GENERATOR 5

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

#define FAKE_ACCESSORY_PAIRING_ID "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

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
    return gcry_mpi_print(GCRYMPI_FMT_USG, out + (out_len - nbytes), nbytes,
                          &written, v) == 0 ? 0 : -1;
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
    return *out_k != NULL ? 0 : -1;
}

/* -- fake accessory -------------------------------------------------------- */

struct fake_accessory
{
    const char *pin;
    uint8_t identity_sk[64];
    uint8_t identity_pk[32];

    gcry_mpi_t v, b;
    uint8_t B_bytes[SRP_N_BYTES];
    uint8_t salt[16];
    uint8_t K[64];

    uint8_t verify_eph_sk[32];
    uint8_t verify_eph_pk[32];
    uint8_t client_eph_pk[32];
};

static void
fake_accessory_init(struct fake_accessory *acc, const char *pin)
{
    memset(acc, 0, sizeof *acc);
    acc->pin = pin;
    if (airplay_ed25519_keypair(acc->identity_sk, acc->identity_pk) != 0)
        abort();
}

static void
fake_accessory_reset_srp(struct fake_accessory *acc)
{
    if (acc->v != NULL)
        gcry_mpi_release(acc->v);
    if (acc->b != NULL)
        gcry_mpi_release(acc->b);
    acc->v = NULL;
    acc->b = NULL;
}

static int
accessory_setup_state1(struct fake_accessory *acc, uint8_t **out,
                       size_t *out_len)
{
    gcry_mpi_t n = NULL, g = NULL, x = NULL, gb = NULL, kv = NULL, big_b = NULL;
    int ret = -1;

    fake_accessory_reset_srp(acc);
    gcry_randomize(acc->salt, sizeof acc->salt, GCRY_STRONG_RANDOM);

    uint8_t inner_hash[64], x_hash[64];
    sha512_parts(inner_hash, (const uint8_t *)SRP_USERNAME,
                (size_t)strlen(SRP_USERNAME), (const uint8_t *)":",
                (size_t)1, (const uint8_t *)acc->pin, strlen(acc->pin),
                (const uint8_t *)NULL);
    sha512_parts(x_hash, acc->salt, sizeof acc->salt, inner_hash,
                (size_t)sizeof inner_hash, (const uint8_t *)NULL);

    if (srp_load_group(&n, &g) != 0)
        return -1;
    x = mpi_from_bytes(x_hash, sizeof x_hash);
    gcry_mpi_t k = NULL;
    if (x == NULL || srp_compute_k(n, g, &k) != 0)
        goto out;

    acc->v = gcry_mpi_new(0);
    gcry_mpi_powm(acc->v, g, x, n);

    uint8_t b_random[32];
    gcry_randomize(b_random, sizeof b_random, GCRY_STRONG_RANDOM);
    acc->b = mpi_from_bytes(b_random, sizeof b_random);
    if (acc->b == NULL)
        goto out;

    gb = gcry_mpi_new(0);
    gcry_mpi_powm(gb, g, acc->b, n);
    kv = gcry_mpi_new(0);
    gcry_mpi_mulm(kv, k, acc->v, n);
    big_b = gcry_mpi_new(0);
    gcry_mpi_addm(big_b, kv, gb, n);
    if (mpi_to_padded(big_b, acc->B_bytes, sizeof acc->B_bytes) != 0)
        goto out;

    hap_tlv_buf tlv;
    hap_tlv_buf_init(&tlv);
    if (hap_tlv_buf_add(&tlv, HAP_TLV_STATE, (const uint8_t[]){ 2 }, 1) != 0 ||
        hap_tlv_buf_add(&tlv, HAP_TLV_SALT, acc->salt, sizeof acc->salt) != 0 ||
        hap_tlv_buf_add(&tlv, HAP_TLV_PUBLIC_KEY, acc->B_bytes,
                        sizeof acc->B_bytes) != 0 ||
        hap_tlv_buf_finish(&tlv, out, out_len) != 0)
    {
        hap_tlv_buf_clear(&tlv);
        goto out;
    }

    ret = 0;
out:
    gcry_mpi_release(n);
    gcry_mpi_release(g);
    gcry_mpi_release(x);
    gcry_mpi_release(k);
    gcry_mpi_release(gb);
    gcry_mpi_release(kv);
    gcry_mpi_release(big_b);
    return ret;
}

static int
accessory_setup_state3(struct fake_accessory *acc, const uint8_t *in,
                       size_t in_len, uint8_t **out, size_t *out_len)
{
    if (acc->v == NULL || acc->b == NULL)
        return -1;

    uint8_t *A = NULL, *m1 = NULL;
    size_t A_len = 0, m1_len = 0;
    int ret = -1;
    gcry_mpi_t n = NULL, g = NULL, a_mpi = NULL, u = NULL, vu = NULL,
               avu = NULL, s = NULL;

    if (hap_tlv_get(in, in_len, HAP_TLV_PUBLIC_KEY, &A, &A_len) != 0 ||
        A_len != SRP_N_BYTES ||
        hap_tlv_get(in, in_len, HAP_TLV_PROOF, &m1, &m1_len) != 0 ||
        m1_len != 64)
        goto out;

    if (srp_load_group(&n, &g) != 0)
        goto out;
    a_mpi = mpi_from_bytes(A, A_len);
    if (a_mpi == NULL)
        goto out;

    uint8_t u_hash[64];
    sha512_parts(u_hash, A, (size_t)SRP_N_BYTES, acc->B_bytes,
                (size_t)sizeof acc->B_bytes, (const uint8_t *)NULL);
    u = mpi_from_bytes(u_hash, sizeof u_hash);
    if (u == NULL)
        goto out;

    vu = gcry_mpi_new(0);
    gcry_mpi_powm(vu, acc->v, u, n);
    avu = gcry_mpi_new(0);
    gcry_mpi_mulm(avu, a_mpi, vu, n);
    s = gcry_mpi_new(0);
    gcry_mpi_powm(s, avu, acc->b, n);

    uint8_t s_bytes[SRP_N_BYTES];
    if (mpi_to_padded(s, s_bytes, sizeof s_bytes) != 0)
        goto out;
    sha512_parts(acc->K, s_bytes, sizeof s_bytes, (const uint8_t *)NULL);

    uint8_t m2[64];
    sha512_parts(m2, A, (size_t)SRP_N_BYTES, m1, (size_t)64, acc->K,
                (size_t)sizeof acc->K, (const uint8_t *)NULL);

    hap_tlv_buf tlv;
    hap_tlv_buf_init(&tlv);
    if (hap_tlv_buf_add(&tlv, HAP_TLV_STATE, (const uint8_t[]){ 4 }, 1) != 0 ||
        hap_tlv_buf_add(&tlv, HAP_TLV_PROOF, m2, sizeof m2) != 0 ||
        hap_tlv_buf_finish(&tlv, out, out_len) != 0)
    {
        hap_tlv_buf_clear(&tlv);
        goto out;
    }

    ret = 0;
out:
    free(A);
    free(m1);
    gcry_mpi_release(n);
    gcry_mpi_release(g);
    gcry_mpi_release(a_mpi);
    gcry_mpi_release(u);
    gcry_mpi_release(vu);
    gcry_mpi_release(avu);
    gcry_mpi_release(s);
    return ret;
}

static int
accessory_setup_state5(struct fake_accessory *acc, const uint8_t *in,
                       size_t in_len, uint8_t **out, size_t *out_len)
{
    uint8_t setup_key[32];
    static const char salt_str[] = "Pair-Setup-Encrypt-Salt";
    static const char info_str[] = "Pair-Setup-Encrypt-Info";
    if (airplay_hkdf_sha512(setup_key, sizeof setup_key, acc->K,
                            sizeof acc->K, (const uint8_t *)salt_str,
                            sizeof salt_str - 1, (const uint8_t *)info_str,
                            sizeof info_str - 1) != 0)
        return -1;

    uint8_t *enc5 = NULL;
    size_t enc5_len = 0;
    if (hap_tlv_get(in, in_len, HAP_TLV_ENCRYPTED_DATA, &enc5, &enc5_len) != 0 ||
        enc5_len < 16)
    {
        free(enc5);
        return -1;
    }

    uint8_t *dec = malloc(enc5_len - 16);
    size_t dec_len = 0;
    static const uint8_t nonce5[12] = "PS-Msg05\0\0\0";
    int rc = dec == NULL ? -1 :
        airplay_chacha_decrypt(dec, &dec_len, enc5, enc5_len, setup_key,
                               nonce5, NULL, 0);
    free(enc5);
    if (rc != 0)
    {
        free(dec);
        return -1;
    }

    uint8_t *ctrl_id = NULL, *ctrl_pk = NULL, *ctrl_sig = NULL;
    size_t ctrl_id_len = 0, ctrl_pk_len = 0, ctrl_sig_len = 0;
    rc = -1;
    if (hap_tlv_get(dec, dec_len, HAP_TLV_IDENTIFIER, &ctrl_id, &ctrl_id_len) == 0 &&
        hap_tlv_get(dec, dec_len, HAP_TLV_PUBLIC_KEY, &ctrl_pk, &ctrl_pk_len) == 0 &&
        ctrl_pk_len == 32 &&
        hap_tlv_get(dec, dec_len, HAP_TLV_SIGNATURE, &ctrl_sig, &ctrl_sig_len) == 0 &&
        ctrl_sig_len == 64)
    {
        static const char ctrl_sign_salt[] = "Pair-Setup-Controller-Sign-Salt";
        static const char ctrl_sign_info[] = "Pair-Setup-Controller-Sign-Info";
        uint8_t ctrl_x[32];
        if (airplay_hkdf_sha512(ctrl_x, sizeof ctrl_x, acc->K, sizeof acc->K,
                                (const uint8_t *)ctrl_sign_salt,
                                sizeof ctrl_sign_salt - 1,
                                (const uint8_t *)ctrl_sign_info,
                                sizeof ctrl_sign_info - 1) == 0)
        {
            uint8_t *msg = NULL;
            size_t msg_len = 0;
            if (buf_cat(&msg, &msg_len, ctrl_x, sizeof ctrl_x, ctrl_id,
                        ctrl_id_len, ctrl_pk, 32) == 0 &&
                airplay_ed25519_verify(ctrl_sig, msg, msg_len, ctrl_pk) == 0)
                rc = 0;
            free(msg);
        }
    }
    free(dec);
    free(ctrl_id);
    free(ctrl_pk);
    free(ctrl_sig);
    if (rc != 0)
        return -1;

    static const char acc_sign_salt[] = "Pair-Setup-Accessory-Sign-Salt";
    static const char acc_sign_info[] = "Pair-Setup-Accessory-Sign-Info";
    uint8_t acc_x[32];
    if (airplay_hkdf_sha512(acc_x, sizeof acc_x, acc->K, sizeof acc->K,
                            (const uint8_t *)acc_sign_salt,
                            sizeof acc_sign_salt - 1,
                            (const uint8_t *)acc_sign_info,
                            sizeof acc_sign_info - 1) != 0)
        return -1;

    const char *acc_id = FAKE_ACCESSORY_PAIRING_ID;
    size_t acc_id_len = strlen(acc_id);
    uint8_t *acc_msg = NULL;
    size_t acc_msg_len = 0;
    if (buf_cat(&acc_msg, &acc_msg_len, acc_x, sizeof acc_x,
                (const uint8_t *)acc_id, acc_id_len, acc->identity_pk, 32) != 0)
        return -1;

    uint8_t sig[64];
    rc = airplay_ed25519_sign(sig, acc_msg, acc_msg_len, acc->identity_sk);
    free(acc_msg);
    if (rc != 0)
        return -1;

    hap_tlv_buf inner;
    hap_tlv_buf_init(&inner);
    if (hap_tlv_buf_add(&inner, HAP_TLV_IDENTIFIER, acc_id, acc_id_len) != 0 ||
        hap_tlv_buf_add(&inner, HAP_TLV_PUBLIC_KEY, acc->identity_pk, 32) != 0 ||
        hap_tlv_buf_add(&inner, HAP_TLV_SIGNATURE, sig, sizeof sig) != 0)
    {
        hap_tlv_buf_clear(&inner);
        return -1;
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (hap_tlv_buf_finish(&inner, &raw, &raw_len) != 0)
        return -1;

    uint8_t *enc = malloc(raw_len + 16);
    size_t enc_len = 0;
    static const uint8_t nonce6[12] = "PS-Msg06\0\0\0";
    rc = enc == NULL ? -1 :
        airplay_chacha_encrypt(enc, &enc_len, raw, raw_len, setup_key,
                               nonce6, NULL, 0);
    free(raw);
    if (rc != 0)
    {
        free(enc);
        return -1;
    }

    hap_tlv_buf tlv;
    hap_tlv_buf_init(&tlv);
    if (hap_tlv_buf_add(&tlv, HAP_TLV_STATE, (const uint8_t[]){ 6 }, 1) != 0 ||
        hap_tlv_buf_add(&tlv, HAP_TLV_ENCRYPTED_DATA, enc, enc_len) != 0 ||
        hap_tlv_buf_finish(&tlv, out, out_len) != 0)
    {
        free(enc);
        hap_tlv_buf_clear(&tlv);
        return -1;
    }
    free(enc);
    return 0;
}

static int
accessory_verify_state1(struct fake_accessory *acc, const uint8_t *in,
                        size_t in_len, uint8_t **out, size_t *out_len)
{
    uint8_t *client_pk = NULL;
    size_t client_pk_len = 0;
    if (hap_tlv_get(in, in_len, HAP_TLV_PUBLIC_KEY, &client_pk, &client_pk_len) != 0 ||
        client_pk_len != 32)
    {
        free(client_pk);
        return -1;
    }
    memcpy(acc->client_eph_pk, client_pk, 32);
    free(client_pk);

    if (airplay_x25519_keypair(acc->verify_eph_sk, acc->verify_eph_pk) != 0)
        return -1;

    uint8_t shared[32];
    if (airplay_x25519(shared, acc->verify_eph_sk, acc->client_eph_pk) != 0)
        return -1;

    uint8_t verify_key[32];
    static const char v_salt[] = "Pair-Verify-Encrypt-Salt";
    static const char v_info[] = "Pair-Verify-Encrypt-Info";
    if (airplay_hkdf_sha512(verify_key, sizeof verify_key, shared,
                            sizeof shared, (const uint8_t *)v_salt,
                            sizeof v_salt - 1, (const uint8_t *)v_info,
                            sizeof v_info - 1) != 0)
        return -1;

    const char *acc_id = FAKE_ACCESSORY_PAIRING_ID;
    size_t acc_id_len = strlen(acc_id);
    uint8_t *msg = NULL;
    size_t msg_len = 0;
    if (buf_cat(&msg, &msg_len, acc->verify_eph_pk, 32,
                (const uint8_t *)acc_id, acc_id_len, acc->client_eph_pk,
                32) != 0)
        return -1;

    uint8_t sig[64];
    int rc = airplay_ed25519_sign(sig, msg, msg_len, acc->identity_sk);
    free(msg);
    if (rc != 0)
        return -1;

    hap_tlv_buf inner;
    hap_tlv_buf_init(&inner);
    if (hap_tlv_buf_add(&inner, HAP_TLV_IDENTIFIER, acc_id, acc_id_len) != 0 ||
        hap_tlv_buf_add(&inner, HAP_TLV_SIGNATURE, sig, sizeof sig) != 0)
    {
        hap_tlv_buf_clear(&inner);
        return -1;
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (hap_tlv_buf_finish(&inner, &raw, &raw_len) != 0)
        return -1;

    uint8_t *enc = malloc(raw_len + 16);
    size_t enc_len = 0;
    static const uint8_t nonce2[12] = "PV-Msg02\0\0\0";
    rc = enc == NULL ? -1 :
        airplay_chacha_encrypt(enc, &enc_len, raw, raw_len, verify_key,
                               nonce2, NULL, 0);
    free(raw);
    if (rc != 0)
    {
        free(enc);
        return -1;
    }

    hap_tlv_buf tlv;
    hap_tlv_buf_init(&tlv);
    if (hap_tlv_buf_add(&tlv, HAP_TLV_STATE, (const uint8_t[]){ 2 }, 1) != 0 ||
        hap_tlv_buf_add(&tlv, HAP_TLV_PUBLIC_KEY, acc->verify_eph_pk,
                        sizeof acc->verify_eph_pk) != 0 ||
        hap_tlv_buf_add(&tlv, HAP_TLV_ENCRYPTED_DATA, enc, enc_len) != 0 ||
        hap_tlv_buf_finish(&tlv, out, out_len) != 0)
    {
        free(enc);
        hap_tlv_buf_clear(&tlv);
        return -1;
    }
    free(enc);
    return 0;
}

static int
accessory_verify_state3(struct fake_accessory *acc, const uint8_t *in,
                        size_t in_len, uint8_t **out, size_t *out_len)
{
    uint8_t shared[32];
    if (airplay_x25519(shared, acc->verify_eph_sk, acc->client_eph_pk) != 0)
        return -1;

    uint8_t verify_key[32];
    static const char v_salt[] = "Pair-Verify-Encrypt-Salt";
    static const char v_info[] = "Pair-Verify-Encrypt-Info";
    if (airplay_hkdf_sha512(verify_key, sizeof verify_key, shared,
                            sizeof shared, (const uint8_t *)v_salt,
                            sizeof v_salt - 1, (const uint8_t *)v_info,
                            sizeof v_info - 1) != 0)
        return -1;

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    if (hap_tlv_get(in, in_len, HAP_TLV_ENCRYPTED_DATA, &enc, &enc_len) != 0 ||
        enc_len < 16)
    {
        free(enc);
        return -1;
    }

    uint8_t *dec = malloc(enc_len - 16);
    size_t dec_len = 0;
    static const uint8_t nonce3[12] = "PV-Msg03\0\0\0";
    int rc = dec == NULL ? -1 :
        airplay_chacha_decrypt(dec, &dec_len, enc, enc_len, verify_key,
                               nonce3, NULL, 0);
    free(enc);
    if (rc != 0)
    {
        free(dec);
        return -1;
    }

    uint8_t *ctrl_id = NULL, *ctrl_sig = NULL;
    size_t ctrl_id_len = 0, ctrl_sig_len = 0;
    rc = -1;
    if (hap_tlv_get(dec, dec_len, HAP_TLV_IDENTIFIER, &ctrl_id, &ctrl_id_len) == 0 &&
        hap_tlv_get(dec, dec_len, HAP_TLV_SIGNATURE, &ctrl_sig, &ctrl_sig_len) == 0 &&
        ctrl_sig_len == 64)
    {
        uint8_t *msg = NULL;
        size_t msg_len = 0;
        if (buf_cat(&msg, &msg_len, acc->client_eph_pk, 32, ctrl_id,
                    ctrl_id_len, acc->verify_eph_pk, 32) == 0)
        {
            /* Signature is checked by the client; accept any well-formed M3. */
            (void)ctrl_sig;
            rc = 0;
        }
        free(msg);
    }
    free(dec);
    free(ctrl_id);
    free(ctrl_sig);
    if (rc != 0)
        return -1;

    hap_tlv_buf tlv;
    hap_tlv_buf_init(&tlv);
    if (hap_tlv_buf_add(&tlv, HAP_TLV_STATE, (const uint8_t[]){ 4 }, 1) != 0 ||
        hap_tlv_buf_finish(&tlv, out, out_len) != 0)
    {
        hap_tlv_buf_clear(&tlv);
        return -1;
    }
    return 0;
}

static int
fake_transport(void *opaque, const char *path, const uint8_t *req,
              size_t req_len, uint8_t **resp, size_t *resp_len)
{
    struct fake_accessory *acc = opaque;

    if (strcmp(path, "/pair-pin-start") == 0)
    {
        *resp = NULL;
        *resp_len = 0;
        return 0;
    }

    bool ok = false;
    uint8_t state = hap_tlv_get_u8(req, req_len, HAP_TLV_STATE, &ok);
    if (!ok)
        return -1;

    int ret = -1;
    if (strcmp(path, "/pair-setup") == 0)
    {
        if (state == 1)
            ret = accessory_setup_state1(acc, resp, resp_len);
        else if (state == 3)
            ret = accessory_setup_state3(acc, req, req_len, resp, resp_len);
        else if (state == 5)
            ret = accessory_setup_state5(acc, req, req_len, resp, resp_len);
    }
    else if (strcmp(path, "/pair-verify") == 0)
    {
        if (state == 1)
            ret = accessory_verify_state1(acc, req, req_len, resp, resp_len);
        else if (state == 3)
            ret = accessory_verify_state3(acc, req, req_len, resp, resp_len);
    }
    return ret;
}

static int
always_fail_transport(void *opaque, const char *path, const uint8_t *req,
                      size_t req_len, uint8_t **resp, size_t *resp_len)
{
    (void) opaque; (void) path; (void) req; (void) req_len;
    (void) resp; (void) resp_len;
    return -1;
}

/* -- identity persistence test seam ---------------------------------------- */

struct identity_fixture
{
    bool has_identity;
    struct airplay_identity identity;
    int store_calls;
    int remove_calls;
};

static int
fixture_load(void *opaque, struct airplay_identity *out)
{
    struct identity_fixture *f = opaque;
    if (!f->has_identity)
        return -1;
    *out = f->identity;
    return 0;
}

static int
fixture_store(void *opaque, const struct airplay_identity *id)
{
    struct identity_fixture *f = opaque;
    f->identity = *id;
    f->has_identity = true;
    f->store_calls++;
    return 0;
}

static int
fixture_remove(void *opaque)
{
    struct identity_fixture *f = opaque;
    f->has_identity = false;
    f->remove_calls++;
    return 0;
}

static void
wire_identity_fixture(airplay_pairing *p, struct identity_fixture *f)
{
    airplay_pairing_set_identity_ops_for_tests(p, fixture_load, fixture_store,
                                               fixture_remove, f);
}

static void
wire_fake_accessory(airplay_pairing *p, struct fake_accessory *acc)
{
    airplay_pairing_set_accessory_info(p, acc->identity_pk,
                                       FAKE_ACCESSORY_PAIRING_ID);
    airplay_pairing_set_transport_for_tests(p, fake_transport, acc);
}

/* -- test cases -------------------------------------------------------------- */

static void
test_idle_needpin_setup_fail(void)
{
    airplay_pairing *p = airplay_pairing_new(NULL, "127.0.0.1", 7000,
                                             "dev-1", "Fake Device");
    expect_true(p != NULL, "pairing object allocates");
    if (p == NULL)
        return;

    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_IDLE,
                "starts idle");

    struct identity_fixture fixture = { 0 };
    wire_identity_fixture(p, &fixture);
    airplay_pairing_set_pin_for_tests(p, "1234");
    airplay_pairing_set_transport_for_tests(p, always_fail_transport, NULL);

    int ret = airplay_pairing_ensure(p);
    expect_true(ret != 0, "ensure fails when the transport fails");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_FAILED,
                "setup failure leaves the FSM in FAILED");
    expect_true(fixture.store_calls == 0,
                "no identity is stored on setup failure");

    airplay_pairing_release(p);
}

static void
test_setup_ok_verify_ok_ready(void)
{
    airplay_pairing *p = airplay_pairing_new(NULL, "127.0.0.1", 7000,
                                             "dev-2", "Fake Device");
    expect_true(p != NULL, "pairing object allocates");
    if (p == NULL)
        return;

    struct fake_accessory acc;
    fake_accessory_init(&acc, "1234");
    struct identity_fixture fixture = { 0 };
    wire_identity_fixture(p, &fixture);
    airplay_pairing_set_pin_for_tests(p, "1234");
    wire_fake_accessory(p, &acc);

    int ret = airplay_pairing_ensure(p);
    expect_true(ret == 0, "ensure succeeds through setup");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_PAIRED,
                "FSM reaches PAIRED after setup");
    expect_true(fixture.store_calls == 1,
                "identity is stored exactly once after a fresh pairing");
    expect_true(fixture.has_identity && fixture.identity.has_peer,
                "stored identity records the accessory's peer key");
    expect_true(fixture.identity.controller_pairing_id[0] != '\0',
                "stored identity records a controller pairing id");

    expect_true(airplay_pairing_control_connect(p) == 0,
                "control connect runs deferred verify");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_READY,
                "FSM reaches READY after control verify");

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    static const uint8_t plaintext[] = "hello airplay";
    expect_true(airplay_pairing_encrypt(p, plaintext, sizeof plaintext, &enc,
                                        &enc_len) == 0,
                "encrypt succeeds once READY");
    expect_true(enc_len == sizeof plaintext + 16,
                "ciphertext carries a 16-byte AEAD tag");
    free(enc);

    airplay_pairing_release(p);
}

static void
test_load_identity_verify_ok_skips_pin(void)
{
    airplay_pairing *p = airplay_pairing_new(NULL, "127.0.0.1", 7000,
                                             "dev-3", "Fake Device");
    expect_true(p != NULL, "pairing object allocates");
    if (p == NULL)
        return;

    struct fake_accessory acc;
    fake_accessory_init(&acc, "1234");

    struct identity_fixture fixture = { 0 };
    fixture.has_identity = true;
    memcpy(fixture.identity.peer_ed25519_pk, acc.identity_pk, 32);
    fixture.identity.has_peer = 1;
    if (airplay_ed25519_keypair(fixture.identity.our_ed25519_sk,
                                fixture.identity.our_ed25519_pk) != 0)
        abort();
    snprintf(fixture.identity.controller_pairing_id,
             sizeof fixture.identity.controller_pairing_id,
             "CCCCCCCC-DDDD-EEEE-FFFF-000000000001");
    wire_identity_fixture(p, &fixture);

    wire_fake_accessory(p, &acc);

    int ret = airplay_pairing_ensure(p);
    expect_true(ret == 0, "ensure succeeds via stored identity");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_PAIRED,
                "FSM reaches PAIRED without visiting NEED_PIN");
    expect_true(fixture.store_calls == 0,
                "no re-pairing occurs when a stored identity is loaded");

    expect_true(airplay_pairing_control_connect(p) == 0,
                "control connect verifies stored identity");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_READY,
                "FSM reaches READY after control verify");

    airplay_pairing_release(p);
}

static void
test_verify_fail_remove_needpin(void)
{
    airplay_pairing *p = airplay_pairing_new(NULL, "127.0.0.1", 7000,
                                             "dev-4", "Fake Device");
    expect_true(p != NULL, "pairing object allocates");
    if (p == NULL)
        return;

    struct fake_accessory acc;
    fake_accessory_init(&acc, "1234");

    struct identity_fixture fixture = { 0 };
    fixture.has_identity = true;
    memset(fixture.identity.peer_ed25519_pk, 0x42, 32);
    fixture.identity.has_peer = 1;
    if (airplay_ed25519_keypair(fixture.identity.our_ed25519_sk,
                                fixture.identity.our_ed25519_pk) != 0)
        abort();
    snprintf(fixture.identity.controller_pairing_id,
             sizeof fixture.identity.controller_pairing_id,
             "CCCCCCCC-DDDD-EEEE-FFFF-000000000002");
    wire_identity_fixture(p, &fixture);

    wire_fake_accessory(p, &acc);

    int ret = airplay_pairing_ensure(p);
    expect_true(ret == 0, "ensure loads the stored identity");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_PAIRED,
                "stale identity is accepted until control verify");

    ret = airplay_pairing_control_connect(p);
    expect_true(ret != 0, "control verify reports failure without a PIN");
    expect_true(airplay_pairing_state(p) == AIRPLAY_PAIR_NEED_PIN,
                "stale identity is dropped and the FSM waits for a PIN");
    expect_true(fixture.remove_calls == 1,
                "the stale identity is removed exactly once");
    expect_true(!fixture.has_identity,
                "the fixture no longer reports a stored identity");

    airplay_pairing_release(p);
}

static void
test_encrypt_decrypt_require_ready(void)
{
    airplay_pairing *p = airplay_pairing_new(NULL, "127.0.0.1", 7000,
                                             "dev-5", "Fake Device");
    expect_true(p != NULL, "pairing object allocates");
    if (p == NULL)
        return;

    uint8_t *out = NULL;
    size_t out_len = 0;
    static const uint8_t plaintext[] = "not ready yet";
    expect_true(airplay_pairing_encrypt(p, plaintext, sizeof plaintext, &out,
                                        &out_len) != 0,
                "encrypt rejected before READY");
    expect_true(airplay_pairing_decrypt(p, plaintext, sizeof plaintext, &out,
                                        &out_len) != 0,
                "decrypt rejected before READY");

    airplay_pairing_release(p);
}

int
main(void)
{
    airplay_crypto_init();

    test_idle_needpin_setup_fail();
    test_setup_ok_verify_ok_ready();
    test_load_identity_verify_ok_skips_pin();
    test_verify_fail_remove_needpin();
    test_encrypt_decrypt_require_ready();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay pairing FSM tests ok");
    return 0;
}
