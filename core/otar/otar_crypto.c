// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR's cryptography: see otar_crypto.h. Written from FIPS-197, RFC 3394, NIST SP 800-38B and RFC 5869
#include <string.h>
#include "otar/otar_crypto.h"
#include "support/hkdf.h"
#include "support/sha256.h"

#define AES256_ROUNDS	14

// The inverse of the AES S-box (FIPS-197 5.3.2), generated from the S-box
static const uint8_t INV_SBOX[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static uint8_t xt(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1Bu : 0u));
}

// Multiplication in GF(2^8) by the small constants InvMixColumns uses
static uint8_t mul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	while (b != 0) {
		if (b & 1u)
			p ^= a;
		a = xt(a);
		b >>= 1;
	}
	return p;
}

void otar_aes256_decrypt(const aes256_ctx_t *ctx, const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16], t[16];
	for (int i = 0; i < 16; i++)
		s[i] = (uint8_t)(in[i] ^ ctx->rk[16 * AES256_ROUNDS + i]);
	for (int r = AES256_ROUNDS - 1; r >= 0; r--) {
		// InvShiftRows and InvSubBytes (column-major state: byte 4c + row), then AddRoundKey
		for (int c = 0; c < 4; c++)
			for (int row = 0; row < 4; row++)
				t[4 * c + row] = INV_SBOX[s[4 * ((c - row) & 3) + row]];
		for (int i = 0; i < 16; i++)
			s[i] = (uint8_t)(t[i] ^ ctx->rk[16 * r + i]);
		if (r == 0)
			break;
		// InvMixColumns
		for (int c = 0; c < 4; c++) {
			uint8_t *col = &s[4 * c];
			uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
			col[0] = (uint8_t)(mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9));
			col[1] = (uint8_t)(mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13));
			col[2] = (uint8_t)(mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11));
			col[3] = (uint8_t)(mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14));
		}
	}
	memcpy(out, s, 16);
	crypto_wipe(s, sizeof s);
	crypto_wipe(t, sizeof t);
}

static const uint8_t KW_IV[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

bool otar_kw_wrap(const uint8_t kek[OTAR_KEY_LEN], const uint8_t *in, size_t n, uint8_t *out)
{
	if (n < 16u || n > 64u || (n % 8u) != 0)
		return false;
	aes256_ctx_t ctx;
	uint8_t a[8], b[16];
	size_t blocks = n / 8u;
	aes256Init(&ctx, kek);
	memcpy(a, KW_IV, 8);
	memmove(out + 8, in, n);
	for (unsigned j = 0; j <= 5u; j++) {
		for (size_t i = 1; i <= blocks; i++) {
			memcpy(b, a, 8);
			memcpy(b + 8, out + 8 * i, 8);
			aes256Encrypt(&ctx, b, b);
			uint32_t t = (uint32_t)(blocks * j + i);
			memcpy(a, b, 8);
			a[4] ^= (uint8_t)(t >> 24);
			a[5] ^= (uint8_t)(t >> 16);
			a[6] ^= (uint8_t)(t >> 8);
			a[7] ^= (uint8_t)t;
			memcpy(out + 8 * i, b + 8, 8);
		}
	}
	memcpy(out, a, 8);
	crypto_wipe(&ctx, sizeof ctx);
	crypto_wipe(b, sizeof b);
	return true;
}

bool otar_kw_unwrap(const uint8_t kek[OTAR_KEY_LEN], const uint8_t *in, size_t n, uint8_t *out)
{
	if (n < 24u || n > 72u || (n % 8u) != 0)
		return false;
	aes256_ctx_t ctx;
	uint8_t a[8], b[16];
	size_t blocks = n / 8u - 1u;
	aes256Init(&ctx, kek);
	memcpy(a, in, 8);
	memmove(out, in + 8, n - 8u);
	for (int j = 5; j >= 0; j--) {
		for (size_t i = blocks; i >= 1; i--) {
			uint32_t t = (uint32_t)(blocks * (size_t)j + i);
			memcpy(b, a, 8);
			b[4] ^= (uint8_t)(t >> 24);
			b[5] ^= (uint8_t)(t >> 16);
			b[6] ^= (uint8_t)(t >> 8);
			b[7] ^= (uint8_t)t;
			memcpy(b + 8, out + 8 * (i - 1u), 8);
			otar_aes256_decrypt(&ctx, b, b);
			memcpy(a, b, 8);
			memcpy(out + 8 * (i - 1u), b + 8, 8);
		}
	}
	bool ok = crypto_equal(a, KW_IV, 8);
	if (!ok)
		crypto_wipe(out, n - 8u);
	crypto_wipe(&ctx, sizeof ctx);
	crypto_wipe(b, sizeof b);
	return ok;
}

// K << 1 in GF(2^128), with the reduction constant 0x87 (SP 800-38B 6.1)
static void dbl(uint8_t k[16])
{
	uint8_t carry = (uint8_t)(k[0] >> 7);
	for (int i = 0; i < 15; i++)
		k[i] = (uint8_t)((k[i] << 1) | (k[i + 1] >> 7));
	k[15] = (uint8_t)((k[15] << 1) ^ (carry ? 0x87u : 0u));
}

void otar_cmac(const uint8_t key[OTAR_KEY_LEN], const uint8_t *msg, size_t n, uint8_t tag[OTAR_CMAC_LEN])
{
	aes256_ctx_t ctx;
	uint8_t k1[16] = { 0 }, x[16] = { 0 }, last[16];
	aes256Init(&ctx, key);
	aes256Encrypt(&ctx, k1, k1);	// L
	dbl(k1);			// K1
	size_t full = n == 0 ? 0 : (n - 1u) / 16u;	// blocks before the last
	for (size_t i = 0; i < full; i++) {
		for (int k = 0; k < 16; k++)
			x[k] ^= msg[16 * i + k];
		aes256Encrypt(&ctx, x, x);
	}
	size_t rem = n - 16u * full;
	memset(last, 0, sizeof last);
	if (rem > 0)
		memcpy(last, msg + 16 * full, rem);
	if (rem != 16u) {
		last[rem] = 0x80;	// padded: K2
		dbl(k1);
	}
	for (int k = 0; k < 16; k++)
		x[k] ^= (uint8_t)(last[k] ^ k1[k]);
	aes256Encrypt(&ctx, x, tag);
	crypto_wipe(&ctx, sizeof ctx);
	crypto_wipe(k1, sizeof k1);
	crypto_wipe(x, sizeof x);
	crypto_wipe(last, sizeof last);
}

static void put24(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 16);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)v;
}

bool otar_pair_keys(const uint8_t own_priv[X25519_LEN], const uint8_t peer_pub[X25519_LEN], uint16_t net_id,
		    uint32_t own_id, uint32_t peer_id, uint8_t ukek[OTAR_KEY_LEN], uint8_t k_mac[OTAR_KEY_LEN],
		    x25519_ws_t *ws)
{
	uint8_t shared[X25519_LEN], prk[SHA256_LEN];
	// salt = "RFOTAR1" | net ID | the lower DMR ID | the higher one: the same on both sides
	uint8_t salt[7 + 2 + 3 + 3] = { 'R', 'F', 'O', 'T', 'A', 'R', '1' };
	uint32_t lo = own_id < peer_id ? own_id : peer_id, hi = own_id < peer_id ? peer_id : own_id;
	salt[7] = (uint8_t)(net_id >> 8);
	salt[8] = (uint8_t)net_id;
	put24(&salt[9], lo);
	put24(&salt[12], hi);
	bool ok = x25519(shared, own_priv, peer_pub, ws);
	if (ok) {
		hkdf_extract(salt, sizeof salt, shared, sizeof shared, prk);
		ok = hkdf_expand(prk, "RFOTAR1 ukek", 12, ukek, OTAR_KEY_LEN) &&
		     hkdf_expand(prk, "RFOTAR1 mac", 11, k_mac, OTAR_KEY_LEN);
	}
	if (!ok) {
		crypto_wipe(ukek, OTAR_KEY_LEN);
		crypto_wipe(k_mac, OTAR_KEY_LEN);
	}
	crypto_wipe(shared, sizeof shared);
	crypto_wipe(prk, sizeof prk);
	return ok;
}

void otar_fingerprint(const uint8_t pub[X25519_LEN], uint8_t out[3])
{
	sha256_t s;
	uint8_t h[SHA256_LEN];
	sha256_init(&s);
	sha256_update(&s, "RFOTAR1 fp", 10);
	sha256_update(&s, pub, X25519_LEN);
	sha256_final(&s, h);
	memcpy(out, h, 3);
}
