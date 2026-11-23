// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR's cryptography (docs/spec/otar.md 5, 7): AES-256 decryption (FIPS-197 5.3), AES key wrap (RFC 3394, NIST SP
// 800-38F KW), AES-256-CMAC (NIST SP 800-38B), and the UKEK and MAC key a member and a net control derive from their
// X25519 key pairs. Pure: no RTOS, no allocation. Built on the AES-256 encryption of dmr/dmrAes.c
#ifndef RFOUNDRY_OTAR_CRYPTO_H
#define RFOUNDRY_OTAR_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dmr/dmrAes.h"
#include "support/x25519.h"

#define OTAR_KEY_LEN		32u
#define OTAR_KW_OVERHEAD	8u	// a wrapped key is 8 octets longer (the integrity check)
#define OTAR_CMAC_LEN		16u

// One block decrypted with a key schedule from aes256Init (the encryption one: the inverse cipher runs it backwards)
void otar_aes256_decrypt(const aes256_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);

// RFC 3394: wrap n octets (a multiple of 8, 16 to 64) under kek into out (n + 8 octets). False for a bad length
bool otar_kw_wrap(const uint8_t kek[OTAR_KEY_LEN], const uint8_t *in, size_t n, uint8_t *out);
// Unwrap n octets (a multiple of 8, 24 to 72) into out (n - 8 octets). False for a bad length or a failed integrity
// check (then out is zeroed)
bool otar_kw_unwrap(const uint8_t kek[OTAR_KEY_LEN], const uint8_t *in, size_t n, uint8_t *out);

// AES-256-CMAC of n octets under key
void otar_cmac(const uint8_t key[OTAR_KEY_LEN], const uint8_t *msg, size_t n, uint8_t tag[OTAR_CMAC_LEN]);

// The UKEK and MAC key of two radios (otar.md 5): X25519 of one's private key and the other's public key, through
// HKDF-SHA-256 with the net ID and both DMR IDs. The same on both sides. False when the shared secret is all zeros
// (RFC 7748 6.1); then both outputs are zeroed. ws: X25519's work space
bool otar_pair_keys(const uint8_t own_priv[X25519_LEN], const uint8_t peer_pub[X25519_LEN], uint16_t net_id,
		    uint32_t own_id, uint32_t peer_id, uint8_t ukek[OTAR_KEY_LEN], uint8_t k_mac[OTAR_KEY_LEN],
		    x25519_ws_t *ws);

// A public key's fingerprint, the 3 octets two users read out to each other (shown as 6 hex digits like a check value)
void otar_fingerprint(const uint8_t pub[X25519_LEN], uint8_t out[3]);

#endif
