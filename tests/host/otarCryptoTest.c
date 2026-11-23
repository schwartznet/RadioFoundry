// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR's cryptography (core/otar/otar_crypto.c, docs/spec/otar.md 5, 7) against the published vectors: AES-256
// decryption (FIPS-197 C.3), AES key wrap (RFC 3394 4.6: 256 bits under a 256-bit KEK), AES-256-CMAC (NIST SP
// 800-38B, the four AES-256 examples); then wrap and unwrap round trips at every length, every altered octet refused,
// the pair keys the same on both sides and different for any other pair, a low-order public key refused.
#include <stdio.h>
#include <string.h>
#include "otar/otar_crypto.h"
#include "otar/otar_msg.h"

static int failures;

#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static size_t hex(const char *s, uint8_t *out)
{
	size_t n = 0;
	while (s[0] && s[1]) {
		unsigned v;
		sscanf(s, "%2x", &v);
		out[n++] = (uint8_t)v;
		s += 2;
	}
	return n;
}

static void test_aes_decrypt(void)
{
	uint8_t key[32], pt[16], ct[16], back[16];
	hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
	hex("00112233445566778899aabbccddeeff", pt);
	aes256_ctx_t ctx;
	aes256Init(&ctx, key);
	aes256Encrypt(&ctx, pt, ct);
	uint8_t want[16];
	hex("8ea2b7ca516745bfeafc49904b496089", want);
	CHECK(memcmp(ct, want, 16) == 0);
	otar_aes256_decrypt(&ctx, ct, back);
	CHECK(memcmp(back, pt, 16) == 0);
	// Many blocks round trip
	uint8_t b[16];
	for (int i = 0; i < 64; i++) {
		for (int k = 0; k < 16; k++)
			b[k] = (uint8_t)(i * 31 + k * 7);
		aes256Encrypt(&ctx, b, ct);
		otar_aes256_decrypt(&ctx, ct, back);
		CHECK(memcmp(back, b, 16) == 0);
	}
}

static void test_kw(void)
{
	uint8_t kek[32], data[32], out[40], want[40], back[32];
	hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", kek);
	hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", data);
	hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21", want);
	CHECK(otar_kw_wrap(kek, data, 32, out) && memcmp(out, want, 40) == 0);
	CHECK(otar_kw_unwrap(kek, out, 40, back) && memcmp(back, data, 32) == 0);
	// Every octet altered is refused, and nothing comes out
	for (int i = 0; i < 40; i++) {
		uint8_t bad[40];
		memcpy(bad, out, 40);
		bad[i] ^= 0x01;
		memset(back, 0x5A, sizeof back);
		CHECK(!otar_kw_unwrap(kek, bad, 40, back));
		uint8_t zero[32] = { 0 };
		CHECK(memcmp(back, zero, 32) == 0);
	}
	// Another KEK is refused
	uint8_t kek2[32];
	memcpy(kek2, kek, 32);
	kek2[31] ^= 0x80;
	CHECK(!otar_kw_unwrap(kek2, out, 40, back));
	// Lengths: 16 to 64 octets in 8s round trip; others are refused
	uint8_t big[64], w[72], u[64];
	for (int i = 0; i < 64; i++)
		big[i] = (uint8_t)(i * 13 + 5);
	for (size_t n = 16; n <= 64; n += 8) {
		CHECK(otar_kw_wrap(kek, big, n, w) && otar_kw_unwrap(kek, w, n + 8, u) && memcmp(u, big, n) == 0);
	}
	CHECK(!otar_kw_wrap(kek, big, 8, w) && !otar_kw_wrap(kek, big, 20, w) && !otar_kw_wrap(kek, big, 72, w));
	CHECK(!otar_kw_unwrap(kek, w, 16, u) && !otar_kw_unwrap(kek, w, 30, u) && !otar_kw_unwrap(kek, w, 80, u));
}

static void test_cmac(void)
{
	static const struct { const char *m, *tag; } v[] = {
		{ "", "028962f61b7bf89efc6b551f4667d983" },
		{ "6bc1bee22e409f96e93d7e117393172a", "28a7023f452e8f82bd4bf28d8c37c35c" },
		{ "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
		  "aaf3d8f1de5640c232f5b169b9c911e6" },
		{ "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		  "e1992190549f6ed5696a2c056c315410" },
	};
	uint8_t key[32], m[64], want[16], tag[16];
	hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
	for (unsigned i = 0; i < sizeof v / sizeof v[0]; i++) {
		size_t n = hex(v[i].m, m);
		hex(v[i].tag, want);
		otar_cmac(key, m, n, tag);
		CHECK(memcmp(tag, want, 16) == 0);
	}
}

static void test_pair_keys(void)
{
	uint8_t a[32], b[32], c[32], pa[32], pb[32], pc[32];
	x25519_ws_t ws;
	for (int i = 0; i < 32; i++) {
		a[i] = (uint8_t)(i * 7 + 1);
		b[i] = (uint8_t)(i * 11 + 3);
		c[i] = (uint8_t)(i * 13 + 9);
	}
	x25519_public(pa, a, &ws);
	x25519_public(pb, b, &ws);
	x25519_public(pc, c, &ws);
	uint8_t u1[32], m1[32], u2[32], m2[32], u3[32], m3[32];
	// Member A (4675810) and net control B (4678512), net 0x1A2B: the same keys on both sides
	CHECK(otar_pair_keys(a, pb, 0x1A2B, 4675810, 4678512, u1, m1, &ws));
	CHECK(otar_pair_keys(b, pa, 0x1A2B, 4678512, 4675810, u2, m2, &ws));
	CHECK(memcmp(u1, u2, 32) == 0 && memcmp(m1, m2, 32) == 0 && memcmp(u1, m1, 32) != 0);
	// Another member, another net, other IDs: other keys
	CHECK(otar_pair_keys(c, pb, 0x1A2B, 4674131, 4678512, u3, m3, &ws) && memcmp(u3, u1, 32) != 0);
	CHECK(otar_pair_keys(a, pb, 0x1A2C, 4675810, 4678512, u3, m3, &ws) && memcmp(u3, u1, 32) != 0);
	CHECK(otar_pair_keys(a, pb, 0x1A2B, 4675811, 4678512, u3, m3, &ws) && memcmp(u3, u1, 32) != 0);
	// A low-order public key (all zeros) is refused and leaves zeros
	uint8_t zero[32] = { 0 };
	memset(u3, 0x55, 32);
	CHECK(!otar_pair_keys(a, zero, 0x1A2B, 1, 2, u3, m3, &ws) && memcmp(u3, zero, 32) == 0);
	// Fingerprints: the same key the same, another key another
	uint8_t f1[3], f2[3], f3[3];
	otar_fingerprint(pa, f1);
	otar_fingerprint(pa, f2);
	otar_fingerprint(pb, f3);
	CHECK(memcmp(f1, f2, 3) == 0 && memcmp(f1, f3, 3) != 0);
}

// The key management messages (otar_msg.c, otar.md 7): each type round trips; every octet altered, another MAC key,
// other addresses and another UKEK are refused; the lengths and the header checks
static void test_msgs(void)
{
	uint8_t ukek[32], kmac[32], kmac2[32], tek[32], buf[OTAR_MSG_MAX];
	for (int i = 0; i < 32; i++) {
		ukek[i] = (uint8_t)(i + 1);
		kmac[i] = (uint8_t)(0x80 + i);
		kmac2[i] = (uint8_t)(0x81 + i);
		tek[i] = (uint8_t)(0xC0 ^ i);
	}
	otar_addr_t a = { 4674131, 4675810 }, swapped = { 4675810, 4674131 };
	otar_msg_t m, got;
	memset(&m, 0, sizeof m);
	m.net_id = 0xE721;
	m.msgnum = 77;
	m.rank = 1;
	m.keyset = 3;
	m.ckr = 1;
	m.kid = 34;
	m.changeover = 476000;
	m.flags = 1;
	memcpy(m.tek, tek, 32);
	int n = otar_rekey_build(buf, &a, ukek, kmac, &m);
	CHECK(n == (int)OTAR_REKEY_LEN && n <= (int)OTAR_MSG_MAX);
	CHECK(otar_peek(buf, n, &got) && got.type == OTAR_REKEY && got.net_id == 0xE721 && got.msgnum == 77 && got.rank == 1);
	CHECK(otar_open(buf, n, &a, ukek, kmac, &got));
	CHECK(got.keyset == 3 && got.ckr == 1 && got.kid == 34 && got.changeover == 476000 && got.flags == 1 &&
	      memcmp(got.tek, tek, 32) == 0);
	// The TEK isn't in the message in the clear
	int found = 0;
	for (int i = 0; i + 4 <= n; i++)
		found += memcmp(&buf[i], tek, 4) == 0;
	CHECK(found == 0);
	for (int i = 0; i < n; i++) {
		uint8_t bad[OTAR_MSG_MAX];
		memcpy(bad, buf, (size_t)n);
		bad[i] ^= 0x10;
		CHECK(!otar_open(bad, n, &a, ukek, kmac, &got));
	}
	CHECK(!otar_open(buf, n, &a, ukek, kmac2, &got));
	CHECK(!otar_open(buf, n, &swapped, ukek, kmac, &got));
	uint8_t ukek2[32];
	memcpy(ukek2, ukek, 32);
	ukek2[0] ^= 1;
	CHECK(!otar_open(buf, n, &a, ukek2, kmac, &got));
	CHECK(!otar_open(buf, n, &a, NULL, kmac, &got));
	CHECK(!otar_open(buf, n - 1, &a, ukek, kmac, &got) && !otar_peek(buf, n + 1, &got));

	// ACK
	memset(&m, 0, sizeof m);
	m.net_id = 0xE721;
	m.msgnum = 5;
	m.keyset = 3;
	m.ckr = 1;
	m.result = OTAR_ACK_STORED;
	m.kcv[0] = 0x4B;
	m.kcv[1] = 0x02;
	m.kcv[2] = 0x69;
	n = otar_ack_build(buf, &swapped, kmac, &m);
	CHECK(n == (int)OTAR_ACK_LEN && otar_open(buf, n, &swapped, NULL, kmac, &got));
	CHECK(got.type == OTAR_ACK && got.keyset == 3 && got.result == OTAR_ACK_STORED && got.kcv[2] == 0x69 && got.rank == 0);
	CHECK(!otar_open(buf, n, &a, NULL, kmac, &got));

	// HELLO
	memset(&m, 0, sizeof m);
	m.net_id = 0xE721;
	m.msgnum = 6;
	m.active_kid = 32;
	m.next_kid = 34;
	m.flags = 1;
	n = otar_hello_build(buf, &swapped, kmac, &m);
	CHECK(n == (int)OTAR_HELLO_LEN && otar_open(buf, n, &swapped, NULL, kmac, &got));
	CHECK(got.type == OTAR_HELLO && got.active_kid == 32 && got.next_kid == 34 && got.flags == 1);

	// CHANGEOVER: to the talkgroup, under the key from the TEK it makes active
	uint8_t gk[32], gk2[32];
	otar_group_mac_key(tek, gk);
	tek[5] ^= 1;
	otar_group_mac_key(tek, gk2);
	CHECK(memcmp(gk, gk2, 32) != 0 && memcmp(gk, tek, 32) != 0);
	otar_addr_t tg = { 4674131, 42001 };
	memset(&m, 0, sizeof m);
	m.net_id = 0xE721;
	m.msgnum = 78;
	m.rank = 1;
	m.keyset = 3;
	m.kid = 34;
	n = otar_changeover_build(buf, &tg, gk, &m);
	CHECK(n == (int)OTAR_CHANGEOVER_LEN && otar_open(buf, n, &tg, NULL, gk, &got) && got.kid == 34 && got.keyset == 3);
	CHECK(!otar_open(buf, n, &tg, NULL, gk2, &got));	// a radio without the next TEK can't make or check one

	// Headers: another version, magic, net 0, a rank past 4, an unknown type
	uint8_t h[OTAR_MSG_MAX];
	memcpy(h, buf, (size_t)n);
	h[1] = 2;
	CHECK(!otar_peek(h, n, &got));
	memcpy(h, buf, (size_t)n);
	h[0] = 'P';
	CHECK(!otar_peek(h, n, &got));
	memcpy(h, buf, (size_t)n);
	h[3] = h[4] = 0;
	CHECK(!otar_peek(h, n, &got));
	memcpy(h, buf, (size_t)n);
	h[9] = 5;
	CHECK(!otar_peek(h, n, &got));
	memcpy(h, buf, (size_t)n);
	h[2] = 9;
	CHECK(!otar_peek(h, n, &got));
}

int main(void)
{
	test_aes_decrypt();
	test_kw();
	test_cmac();
	test_pair_keys();
	test_msgs();
	if (failures == 0)
		printf("# otarCryptoTest PASSED\n");
	else
		printf("# otarCryptoTest FAILED (%d)\n", failures);
	return failures != 0;
}
