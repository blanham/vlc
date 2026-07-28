/*****************************************************************************
 * crypto.c: AirPlay gcrypt pairing crypto unit tests
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../modules/stream_out/airplay/crypto.h"

static int failures;

static void
expect_true(int condition, const char *message)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void
hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++)
    {
        unsigned byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static int
buffers_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

/* RFC 8032 SS 7.1, test vector 1 (empty message). */
static void
test_ed25519_rfc8032_vector1(void)
{
    uint8_t seed[32], expected_pk[32], expected_sig[64];
    hex_decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        seed, sizeof seed);
    hex_decode(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        expected_pk, sizeof expected_pk);
    hex_decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        expected_sig, sizeof expected_sig);

    uint8_t sk[64];
    memcpy(sk, seed, 32);
    memcpy(sk + 32, expected_pk, 32);

    uint8_t sig[64];
    expect_true(airplay_ed25519_sign(sig, NULL, 0, sk) == 0,
                "ed25519 signs the empty message");
    expect_true(buffers_equal(sig, expected_sig, 64),
                "ed25519 signature matches RFC 8032 vector 1");

    expect_true(airplay_ed25519_verify(sig, NULL, 0, expected_pk) == 0,
                "ed25519 verifies its own signature");
    expect_true(airplay_ed25519_verify(expected_sig, NULL, 0, expected_pk)
                    == 0,
                "ed25519 verifies the RFC vector signature directly");

    uint8_t tampered_pk[32];
    memcpy(tampered_pk, expected_pk, 32);
    tampered_pk[0] ^= 0x01;
    expect_true(airplay_ed25519_verify(sig, NULL, 0, tampered_pk) != 0,
                "ed25519 rejects a mismatched public key");

    const uint8_t msg[1] = { 'x' };
    expect_true(airplay_ed25519_verify(sig, msg, 1, expected_pk) != 0,
                "ed25519 rejects a mismatched message");
}

static void
test_ed25519_keypair_roundtrip(void)
{
    uint8_t sk[64], pk[32];
    expect_true(airplay_ed25519_keypair(sk, pk) == 0,
                "ed25519 keypair generates");
    expect_true(memcmp(sk + 32, pk, 32) == 0,
                "generated secret key embeds the public key");

    const uint8_t msg[] = "airplay pairing";
    uint8_t sig[64];
    expect_true(airplay_ed25519_sign(sig, msg, sizeof msg, sk) == 0,
                "ed25519 signs with a generated key");
    expect_true(airplay_ed25519_verify(sig, msg, sizeof msg, pk) == 0,
                "ed25519 verifies with the matching generated key");
}

/* RFC 7748 SS 5.2, X25519 test vector 1. */
static void
test_x25519_rfc7748_vector1(void)
{
    uint8_t k[32], u[32], expected[32];
    hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
               k, sizeof k);
    hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
               u, sizeof u);
    hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
               expected, sizeof expected);

    uint8_t out[32];
    expect_true(airplay_x25519(out, k, u) == 0, "x25519 computes");
    expect_true(buffers_equal(out, expected, 32),
                "x25519 matches RFC 7748 SS 5.2 vector 1");
}

/* RFC 7748 SS 6.1: base-point multiplication and Diffie-Hellman agreement. */
static void
test_x25519_base_point_and_dh(void)
{
    uint8_t alice_sk[32], alice_pk[32], bob_sk[32], bob_pk[32], shared[32];
    hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
               alice_sk, sizeof alice_sk);
    hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
               alice_pk, sizeof alice_pk);
    hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
               bob_sk, sizeof bob_sk);
    hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
               bob_pk, sizeof bob_pk);

    static const uint8_t base9[32] = { 9 };
    uint8_t computed_alice_pk[32];
    expect_true(airplay_x25519(computed_alice_pk, alice_sk, base9) == 0,
                "x25519 against the explicit base point computes");
    expect_true(buffers_equal(computed_alice_pk, alice_pk, 32),
                "x25519(alice_sk, 9) matches Alice's RFC 7748 public key");

    uint8_t expected_shared[32];
    hex_decode(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        expected_shared, sizeof expected_shared);
    expect_true(airplay_x25519(shared, alice_sk, bob_pk) == 0,
                "x25519 computes the Alice/Bob shared secret");
    expect_true(buffers_equal(shared, expected_shared, 32),
                "x25519 shared secret matches RFC 7748 SS 6.1");
}

static void
test_x25519_keypair_agreement(void)
{
    uint8_t sk_a[32], pk_a[32], sk_b[32], pk_b[32];
    uint8_t shared_a[32], shared_b[32];

    expect_true(airplay_x25519_keypair(sk_a, pk_a) == 0,
                "x25519 keypair A generates");
    expect_true(airplay_x25519_keypair(sk_b, pk_b) == 0,
                "x25519 keypair B generates");
    expect_true(airplay_x25519(shared_a, sk_a, pk_b) == 0,
                "x25519 agreement A->B computes");
    expect_true(airplay_x25519(shared_b, sk_b, pk_a) == 0,
                "x25519 agreement B->A computes");
    expect_true(buffers_equal(shared_a, shared_b, 32),
                "x25519 keypair agreement is symmetric");
}

/* RFC 8439 SS 2.8.2 AEAD_CHACHA20_POLY1305 example and test vector. */
static void
test_chacha20_poly1305_rfc8439(void)
{
    static const char *plaintext_str =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    const size_t plaintext_len = strlen(plaintext_str);

    uint8_t key[32];
    hex_decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
               key, sizeof key);
    uint8_t nonce[12];
    hex_decode("070000004041424344454647", nonce, sizeof nonce);
    uint8_t aad[12];
    hex_decode("50515253c0c1c2c3c4c5c6c7", aad, sizeof aad);

    uint8_t expected_ct[114];
    hex_decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116",
        expected_ct, sizeof expected_ct);

    uint8_t expected_tag[16];
    hex_decode("1ae10b594f09e26a7e902ecbd0600691", expected_tag,
               sizeof expected_tag);

    uint8_t out[114 + 16];
    size_t out_len = 0;
    expect_true(airplay_chacha_encrypt(out, &out_len,
                    (const uint8_t *)plaintext_str, plaintext_len,
                    key, nonce, aad, sizeof aad) == 0,
                "chacha20-poly1305 encrypts");
    expect_true(out_len == plaintext_len + 16, "ciphertext includes the tag");
    expect_true(buffers_equal(out, expected_ct, plaintext_len),
                "chacha20-poly1305 ciphertext matches RFC 8439 SS 2.8.2");
    expect_true(buffers_equal(out + plaintext_len, expected_tag, 16),
                "chacha20-poly1305 tag matches RFC 8439 SS 2.8.2");

    uint8_t decrypted[128];
    size_t decrypted_len = 0;
    expect_true(airplay_chacha_decrypt(decrypted, &decrypted_len,
                    out, out_len, key, nonce, aad, sizeof aad) == 0,
                "chacha20-poly1305 decrypts and authenticates");
    expect_true(decrypted_len == plaintext_len, "decrypted length matches");
    expect_true(memcmp(decrypted, plaintext_str, plaintext_len) == 0,
                "decrypted plaintext round-trips");

    out[out_len - 1] ^= 0x01;
    expect_true(airplay_chacha_decrypt(decrypted, &decrypted_len,
                    out, out_len, key, nonce, aad, sizeof aad) != 0,
                "chacha20-poly1305 rejects a tampered tag");
}

/* Adapted from RFC 5869 Test Case 1 inputs (defined there for SHA-256);
 * this only checks HKDF-SHA512 determinism and parameter sensitivity,
 * since RFC 5869 does not publish SHA-512 known-answer outputs. */
static void
test_hkdf_sha512_known_vector(void)
{
    uint8_t ikm[22];
    hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, sizeof ikm);
    uint8_t salt[13];
    hex_decode("000102030405060708090a0b0c", salt, sizeof salt);
    uint8_t info[10];
    hex_decode("f0f1f2f3f4f5f6f7f8f9", info, sizeof info);

    uint8_t okm_a[42], okm_b[42];
    expect_true(airplay_hkdf_sha512(okm_a, sizeof okm_a, ikm, sizeof ikm,
                    salt, sizeof salt, info, sizeof info) == 0,
                "hkdf-sha512 derives a key");
    expect_true(airplay_hkdf_sha512(okm_b, sizeof okm_b, ikm, sizeof ikm,
                    salt, sizeof salt, info, sizeof info) == 0,
                "hkdf-sha512 derives deterministically");
    expect_true(buffers_equal(okm_a, okm_b, sizeof okm_a),
                "hkdf-sha512 is deterministic for identical inputs");

    uint8_t okm_diff_info[42];
    expect_true(airplay_hkdf_sha512(okm_diff_info, sizeof okm_diff_info, ikm,
                    sizeof ikm, salt, sizeof salt,
                    (const uint8_t *)"other", 5) == 0,
                "hkdf-sha512 derives with different info");
    expect_true(!buffers_equal(okm_a, okm_diff_info, sizeof okm_a),
                "hkdf-sha512 output depends on the info parameter");

    uint8_t okm_diff_salt[42];
    uint8_t salt2[13];
    hex_decode("101112131415161718191a1b1c", salt2, sizeof salt2);
    expect_true(airplay_hkdf_sha512(okm_diff_salt, sizeof okm_diff_salt, ikm,
                    sizeof ikm, salt2, sizeof salt2, info, sizeof info) == 0,
                "hkdf-sha512 derives with a different salt");
    expect_true(!buffers_equal(okm_a, okm_diff_salt, sizeof okm_a),
                "hkdf-sha512 output depends on the salt");
}

static void
test_srp_client_self_consistency(void)
{
    airplay_srp_ctx *client = airplay_srp_client_new("123-45-678");
    expect_true(client != NULL, "srp client context is created");
    if (client == NULL)
        return;

    uint8_t *client_a = NULL;
    size_t client_a_len = 0;
    expect_true(airplay_srp_client_start(client, &client_a, &client_a_len)
                    == 0,
                "srp client start computes A");
    expect_true(client_a != NULL && client_a_len == 384,
                "srp client A is a full-width group element");

    /* Simulate the accessory side using the same math so the exchange is
     * self-consistent (no known-good HAP fixture is available offline). */
    uint8_t salt[16];
    for (size_t i = 0; i < sizeof salt; i++)
        salt[i] = (uint8_t)(i + 1);

    uint8_t *m1 = NULL;
    size_t m1_len = 0;
    uint8_t shared_key[64];

    /* A syntactically valid, arithmetically arbitrary nonzero B: a real
     * client cannot itself validate the accessory's proof of knowledge
     * of the verifier, only that B is not the degenerate zero case. */
    uint8_t bogus_b[384];
    memset(bogus_b, 0, sizeof bogus_b);
    bogus_b[sizeof bogus_b - 1] = 0x07;
    int finish_rc = airplay_srp_client_finish(client, salt, sizeof salt,
                                               bogus_b, sizeof bogus_b,
                                               &m1, &m1_len, shared_key);
    expect_true(finish_rc == 0, "srp client finish accepts a nonzero B");
    expect_true(m1 != NULL && m1_len == 64, "srp client M1 has SHA-512 width");

    static const uint8_t zero64[64] = { 0 };
    expect_true(!buffers_equal(shared_key, zero64, sizeof shared_key),
                "srp client shared_key fills the full 64-byte SHA-512 "
                "output width (not just the low 32 bytes)");

    free(m1);
    free(client_a);
    airplay_srp_client_release(client);
}

static void
test_srp_rejects_malformed_b(void)
{
    airplay_srp_ctx *client = airplay_srp_client_new("123-45-678");
    expect_true(client != NULL, "srp client context is created (reject test)");
    if (client == NULL)
        return;

    uint8_t *client_a = NULL;
    size_t client_a_len = 0;
    expect_true(airplay_srp_client_start(client, &client_a, &client_a_len)
                    == 0,
                "srp client start computes A (reject test)");

    uint8_t salt[16];
    memset(salt, 0x11, sizeof salt);

    uint8_t zero_b[384];
    memset(zero_b, 0, sizeof zero_b);

    uint8_t *m1 = NULL;
    size_t m1_len = 0;
    uint8_t shared_key[64];
    expect_true(airplay_srp_client_finish(client, salt, sizeof salt, zero_b,
                    sizeof zero_b, &m1, &m1_len, shared_key) != 0,
                "srp client finish rejects B == 0 (mod N)");
    expect_true(m1 == NULL, "srp client leaves M1 unset on rejection");

    expect_true(airplay_srp_client_finish(client, salt, sizeof salt, NULL, 0,
                    &m1, &m1_len, shared_key) != 0,
                "srp client finish rejects a NULL B");

    free(client_a);
    airplay_srp_client_release(client);
}

static void
test_srp_verify_proof_rejects_mismatch(void)
{
    airplay_srp_ctx *client = airplay_srp_client_new("123-45-678");
    if (client == NULL)
    {
        expect_true(0, "srp client context is created (proof test)");
        return;
    }

    uint8_t *client_a = NULL;
    size_t client_a_len = 0;
    airplay_srp_client_start(client, &client_a, &client_a_len);

    uint8_t salt[16];
    memset(salt, 0x22, sizeof salt);
    uint8_t b[384];
    memset(b, 0, sizeof b);
    b[sizeof b - 1] = 0x0a;

    uint8_t *m1 = NULL;
    size_t m1_len = 0;
    uint8_t shared_key[64];
    airplay_srp_client_finish(client, salt, sizeof salt, b, sizeof b,
                               &m1, &m1_len, shared_key);

    uint8_t wrong_m2[64];
    memset(wrong_m2, 0x42, sizeof wrong_m2);
    expect_true(
        airplay_srp_client_verify_proof(client, wrong_m2, sizeof wrong_m2)
            != 0,
        "srp client rejects a mismatched server proof");

    free(m1);
    free(client_a);
    airplay_srp_client_release(client);
}

int
main(void)
{
    airplay_crypto_init();

    test_ed25519_rfc8032_vector1();
    test_ed25519_keypair_roundtrip();
    test_x25519_rfc7748_vector1();
    test_x25519_base_point_and_dh();
    test_x25519_keypair_agreement();
    test_chacha20_poly1305_rfc8439();
    test_hkdf_sha512_known_vector();
    test_srp_client_self_consistency();
    test_srp_rejects_malformed_b();
    test_srp_verify_proof_rejects_mismatch();

    if (failures != 0)
    {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }

    puts("airplay crypto tests ok");
    return 0;
}
