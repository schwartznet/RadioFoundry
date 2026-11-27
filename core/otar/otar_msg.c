// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR key management messages: see otar_msg.h
#include <string.h>
#include "otar/otar_msg.h"
#include "support/hkdf.h"

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void header(uint8_t *out, uint8_t type, const otar_msg_t *m)
{
	out[0] = 'O';
	out[1] = OTAR_VERSION;
	out[2] = type;
	out[3] = (uint8_t)(m->net_id >> 8);
	out[4] = (uint8_t)m->net_id;
	put32(&out[5], m->msgnum);
	out[9] = m->rank;
}

// CMAC over src (3) | dst (3) | msg[0 .. n-1], truncated
static void mac(const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const uint8_t *msg, int n, uint8_t out[OTAR_MAC])
{
	uint8_t buf[6 + OTAR_MSG_MAX], tag[OTAR_CMAC_LEN];
	buf[0] = (uint8_t)(a->src >> 16);
	buf[1] = (uint8_t)(a->src >> 8);
	buf[2] = (uint8_t)a->src;
	buf[3] = (uint8_t)(a->dst >> 16);
	buf[4] = (uint8_t)(a->dst >> 8);
	buf[5] = (uint8_t)a->dst;
	memcpy(&buf[6], msg, (size_t)n);
	otar_cmac(k_mac, buf, (size_t)(6 + n), tag);
	memcpy(out, tag, OTAR_MAC);
	crypto_wipe(buf, sizeof buf);
	crypto_wipe(tag, sizeof tag);
}

// The body's encryption key: HKDF-Expand with the message's MAC key as the PRK (RFC 5869 2.3; it is 32 uniform octets)
static __attribute__((noinline)) void enc_key(const uint8_t k_mac[OTAR_KEY_LEN], uint8_t k_enc[OTAR_KEY_LEN])
{
	(void)hkdf_expand(k_mac, OTAR_ENC_LABEL, sizeof OTAR_ENC_LABEL - 1u, k_enc, OTAR_KEY_LEN);
}

// AES-256-CTR (NIST SP 800-38A 6.5) over n octets of body, in place (otar.md 7): the counter block is the sender's and
// receiver's DMR IDs (3 + 3), the type, the message number (4) and the rank from the header hdr, then a 32-bit block
// counter from 0. A sender's message numbers never repeat (otar.md 7.6), so no counter block does under one key
static __attribute__((noinline)) void crypt_body(const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN],
						 const uint8_t *hdr, uint8_t *body, int n)
{
	static aes256_ctx_t ctx;	// off the stack (one caller at a time: the UI task's OTAR engine, docs/spec/otar.md 4)
	uint8_t k[OTAR_KEY_LEN], ctr[16], ks[16];
	enc_key(k_mac, k);
	aes256Init(&ctx, k);
	crypto_wipe(k, sizeof k);
	ctr[0] = (uint8_t)(a->src >> 16);
	ctr[1] = (uint8_t)(a->src >> 8);
	ctr[2] = (uint8_t)a->src;
	ctr[3] = (uint8_t)(a->dst >> 16);
	ctr[4] = (uint8_t)(a->dst >> 8);
	ctr[5] = (uint8_t)a->dst;
	ctr[6] = hdr[2];
	memcpy(&ctr[7], &hdr[5], 5);	// message number, rank
	for (int i = 0; i < n; i += 16) {
		put32(&ctr[12], (uint32_t)(i / 16));
		aes256Encrypt(&ctx, ctr, ks);
		for (int j = 0; j < 16 && i + j < n; j++)
			body[i + j] ^= ks[j];
	}
	crypto_wipe(&ctx, sizeof ctx);
	crypto_wipe(ks, sizeof ks);
}

// Encrypt then MAC: the body encrypted, then the MAC over the header and the encrypted body
static int seal(uint8_t *out, int n, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN])
{
	crypt_body(a, k_mac, out, &out[OTAR_HDR], n - (int)OTAR_HDR);
	mac(a, k_mac, out, n, &out[n]);
	return n + (int)OTAR_MAC;
}

int otar_rekey_build(uint8_t *out, const otar_addr_t *a, const uint8_t ukek[OTAR_KEY_LEN],
		     const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_REKEY, m);
	uint8_t *p = &out[OTAR_HDR];
	put32(p, m->keyset);
	p[4] = m->ckr;
	p[5] = m->kid;
	put32(&p[6], m->changeover);
	p[10] = m->flags;
	if (!otar_kw_wrap(ukek, m->tek, OTAR_KEY_LEN, &p[11]))
		return 0;
	return seal(out, (int)(OTAR_REKEY_LEN - OTAR_MAC), a, k_mac);
}

int otar_ack_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_ACK, m);
	uint8_t *p = &out[OTAR_HDR];
	put32(p, m->keyset);
	p[4] = m->ckr;
	p[5] = m->result;
	memcpy(&p[6], m->kcv, 3);
	put32(&p[9], m->echo);
	return seal(out, (int)(OTAR_ACK_LEN - OTAR_MAC), a, k_mac);
}

int otar_hello_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_HELLO, m);
	uint8_t *p = &out[OTAR_HDR];
	put32(p, m->keyset);
	put32(&p[4], m->next_keyset);
	p[8] = m->flags;
	return seal(out, (int)(OTAR_HELLO_LEN - OTAR_MAC), a, k_mac);
}

int otar_changeover_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_CHANGEOVER, m);
	uint8_t *p = &out[OTAR_HDR];
	put32(p, m->keyset);
	p[4] = m->kid;
	return seal(out, (int)(OTAR_CHANGEOVER_LEN - OTAR_MAC), a, k_mac);
}

int otar_roster_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_ROSTER, m);
	memcpy(&out[OTAR_HDR], m->rec, OTAR_ROSTER_REC);
	return seal(out, (int)(OTAR_ROSTER_LEN - OTAR_MAC), a, k_mac);
}

int otar_zeroize_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_ZEROIZE, m);
	out[OTAR_HDR] = (uint8_t)(m->target >> 16);
	out[OTAR_HDR + 1] = (uint8_t)(m->target >> 8);
	out[OTAR_HDR + 2] = (uint8_t)m->target;
	return seal(out, (int)(OTAR_ZEROIZE_LEN - OTAR_MAC), a, k_mac);
}

int otar_inventory_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_INVENTORY, m);
	return seal(out, (int)OTAR_HDR, a, k_mac);
}

int otar_time_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_TIME, m);
	put32(&out[OTAR_HDR], m->time_s);
	return seal(out, (int)(OTAR_TIME_LEN - OTAR_MAC), a, k_mac);
}

int otar_locate_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_LOCATE, m);
	return seal(out, (int)OTAR_HDR, a, k_mac);
}

int otar_position_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_POSITION, m);
	uint8_t *p = &out[OTAR_HDR];
	put32(p, m->echo);
	p[4] = m->result;
	put32(&p[5], (uint32_t)m->lat);
	put32(&p[9], (uint32_t)m->lon);
	p[13] = (uint8_t)((uint16_t)m->alt_m >> 8);
	p[14] = (uint8_t)m->alt_m;
	p[15] = (uint8_t)(m->age_s >> 8);
	p[16] = (uint8_t)m->age_s;
	return seal(out, (int)(OTAR_POSITION_LEN - OTAR_MAC), a, k_mac);
}

static int len_of(uint8_t type)
{
	switch (type) {
	case OTAR_REKEY: return (int)OTAR_REKEY_LEN;
	case OTAR_ACK: return (int)OTAR_ACK_LEN;
	case OTAR_HELLO: return (int)OTAR_HELLO_LEN;
	case OTAR_CHANGEOVER: return (int)OTAR_CHANGEOVER_LEN;
	case OTAR_ROSTER: return (int)OTAR_ROSTER_LEN;
	case OTAR_ZEROIZE: return (int)OTAR_ZEROIZE_LEN;
	case OTAR_INVENTORY: return (int)OTAR_INVENTORY_LEN;
	case OTAR_TIME: return (int)OTAR_TIME_LEN;
	case OTAR_LOCATE: return (int)OTAR_LOCATE_LEN;
	case OTAR_POSITION: return (int)OTAR_POSITION_LEN;
	default: return -1;
	}
}

bool otar_peek(const uint8_t *msg, int len, otar_msg_t *m)
{
	memset(m, 0, sizeof *m);
	if (msg == NULL || len < (int)OTAR_HDR || msg[0] != 'O' || msg[1] != OTAR_VERSION || len != len_of(msg[2]))
		return false;
	m->type = msg[2];
	m->net_id = (uint16_t)((msg[3] << 8) | msg[4]);
	m->msgnum = get32(&msg[5]);
	m->rank = msg[9];
	return m->net_id != 0 && m->rank <= 4u;
}

static bool parse(otar_msg_t *m, const uint8_t *p, const uint8_t *ukek);

bool otar_open(const uint8_t *msg, int len, const otar_addr_t *a, const uint8_t *ukek,
	       const uint8_t k_mac[OTAR_KEY_LEN], otar_msg_t *m)
{
	if (!otar_peek(msg, len, m))
		return false;
	uint8_t want[OTAR_MAC];
	mac(a, k_mac, msg, len - (int)OTAR_MAC, want);
	bool ok = crypto_equal(want, &msg[len - (int)OTAR_MAC], OTAR_MAC);
	crypto_wipe(want, sizeof want);
	if (!ok)
		return false;
	// The MAC checked: the body decrypted into a copy (msg stays as it came)
	uint8_t p[OTAR_MSG_MAX - OTAR_HDR - OTAR_MAC];
	int bn = len - (int)OTAR_HDR - (int)OTAR_MAC;
	memcpy(p, &msg[OTAR_HDR], (size_t)bn);
	crypt_body(a, k_mac, msg, p, bn);
	ok = parse(m, p, ukek);
	crypto_wipe(p, sizeof p);
	if (!ok)
		crypto_wipe(m->tek, sizeof m->tek);
	return ok;
}

static bool parse(otar_msg_t *m, const uint8_t *p, const uint8_t *ukek)
{
	switch (m->type) {
	case OTAR_REKEY:
		m->keyset = get32(p);
		m->ckr = p[4];
		m->kid = p[5];
		m->changeover = get32(&p[6]);
		m->flags = p[10];
		return ukek != NULL && otar_kw_unwrap(ukek, &p[11], 40, m->tek) && m->ckr >= 1 && m->ckr <= 4;
	case OTAR_ACK:
		m->keyset = get32(p);
		m->ckr = p[4];
		m->result = p[5];
		memcpy(m->kcv, &p[6], 3);
		m->echo = get32(&p[9]);
		return true;
	case OTAR_HELLO:
		m->keyset = get32(p);
		m->next_keyset = get32(&p[4]);
		m->flags = p[8];
		return true;
	case OTAR_CHANGEOVER:
		m->keyset = get32(p);
		m->kid = p[4];
		return true;
	case OTAR_ROSTER:
		memcpy(m->rec, p, OTAR_ROSTER_REC);
		return true;
	case OTAR_ZEROIZE:
		m->target = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
		return true;
	case OTAR_INVENTORY:
		return true;
	case OTAR_TIME:
		m->time_s = get32(p);
		return true;
	case OTAR_LOCATE:
		return true;
	case OTAR_POSITION:
		m->echo = get32(p);
		m->result = p[4];
		m->lat = (int32_t)get32(&p[5]);
		m->lon = (int32_t)get32(&p[9]);
		m->alt_m = (int16_t)(uint16_t)((p[13] << 8) | p[14]);
		m->age_s = (uint16_t)((p[15] << 8) | p[16]);
		// A known result, and a position on the globe (another result carries none)
		if (m->result > OTAR_POS_REFUSED)
			return false;
		return m->result != OTAR_POS_OK ||
		       (m->lat >= -900000000 && m->lat <= 900000000 && m->lon >= -1800000000 && m->lon <= 1800000000);
	default:
		return false;
	}
}

void otar_group_mac_key(const uint8_t tek[OTAR_KEY_LEN], const char *label, uint8_t k_mac[OTAR_KEY_LEN])
{
	uint8_t prk[SHA256_LEN];
	hkdf_extract((const uint8_t *)"RFOTAR1 group", 13, tek, OTAR_KEY_LEN, prk);
	(void)hkdf_expand(prk, label, strlen(label), k_mac, OTAR_KEY_LEN);
	crypto_wipe(prk, sizeof prk);
}
