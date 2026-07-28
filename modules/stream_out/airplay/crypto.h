/*****************************************************************************
 * crypto.h: gcrypt-backed pairing crypto helpers for AirPlay
 *****************************************************************************
 * Copyright (C) 2026 VLC authors and VideoLAN
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *****************************************************************************/

#ifndef VLC_AIRPLAY_CRYPTO_H
#define VLC_AIRPLAY_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/**
 * Ensures the process-wide gcrypt thread setup has run exactly once.
 * Must be called before any other function in this file.
 */
void airplay_crypto_init(void);

/* -- Ed25519 (RFC 8032) -----------------------------------------------
 * The secret key layout matches the common "seed || public key" 64-byte
 * convention: sk[0..31] is the 32-byte seed, sk[32..63] is the 32-byte
 * public key. This mirrors struct airplay_identity in keystore_id.h.
 */
int airplay_ed25519_keypair(uint8_t sk[64], uint8_t pk[32]);
int airplay_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t len,
                          const uint8_t sk[64]);
int airplay_ed25519_verify(const uint8_t sig[64], const uint8_t *msg,
                            size_t len, const uint8_t pk[32]);

/* -- X25519 (RFC 7748) -------------------------------------------------- */
int airplay_x25519(uint8_t shared[32], const uint8_t sk[32],
                    const uint8_t pk[32]);
int airplay_x25519_keypair(uint8_t sk[32], uint8_t pk[32]);

/* -- ChaCha20-Poly1305 AEAD (RFC 8439) -----------------------------------
 * "Combined" mode: airplay_chacha_encrypt() appends the 16-byte Poly1305
 * tag to the ciphertext (*out_len == in_len + 16); airplay_chacha_decrypt()
 * expects the tag as the last 16 bytes of `in` and outputs only the
 * plaintext (*out_len == in_len - 16). `out` may not alias `in`.
 */
int airplay_chacha_encrypt(uint8_t *out, size_t *out_len,
                            const uint8_t *in, size_t in_len,
                            const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *ad, size_t ad_len);
int airplay_chacha_decrypt(uint8_t *out, size_t *out_len,
                            const uint8_t *in, size_t in_len,
                            const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *ad, size_t ad_len);

/* -- HKDF-SHA512 (RFC 5869) ----------------------------------------------- */
int airplay_hkdf_sha512(uint8_t *out, size_t out_len,
                         const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len);

/* -- SRP-6a, HAP 3072-bit group, SHA-512, username "Pair-Setup" ----------
 * Client-side only, as needed to build a Pair-Setup request:
 *
 *   ctx = airplay_srp_client_new(pin);
 *   airplay_srp_client_start(ctx, &A, &A_len);           -> send A
 *   /' receive salt + B from the accessory '/
 *   airplay_srp_client_finish(ctx, salt, salt_len, B, B_len,
 *                              &M1, &M1_len, shared_key); -> send M1
 *   /' receive M2 from the accessory '/
 *   airplay_srp_client_verify_proof(ctx, M2, M2_len);
 *   airplay_srp_client_release(ctx);
 *
 * `shared_key` receives the full 64-byte K = SHA-512(S). HAP Pair-Setup
 * uses the complete, untruncated SRP session key as the HKDF-SHA512 IKM
 * (input keying material) for deriving subsequent pairing keys; truncating
 * K to 32 bytes would silently discard entropy the HAP spec requires and
 * break interop with real accessories.
 */
typedef struct airplay_srp_ctx airplay_srp_ctx;

airplay_srp_ctx *airplay_srp_client_new(const char *pin);
void airplay_srp_client_release(airplay_srp_ctx *);

int airplay_srp_client_start(airplay_srp_ctx *, uint8_t **A, size_t *A_len);

int airplay_srp_client_finish(airplay_srp_ctx *,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *B, size_t B_len,
                               uint8_t **M1, size_t *M1_len,
                               uint8_t shared_key[64]);

int airplay_srp_client_verify_proof(airplay_srp_ctx *,
                                     const uint8_t *M2, size_t M2_len);

#endif
