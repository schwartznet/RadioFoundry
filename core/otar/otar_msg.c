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

static int seal(uint8_t *out, int n, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN])
{
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
	return seal(out, (int)(OTAR_ACK_LEN - OTAR_MAC), a, k_mac);
}

int otar_hello_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m)
{
	header(out, OTAR_HELLO, m);
	uint8_t *p = &out[OTAR_HDR];
	p[0] = m->active_kid;
	p[1] = m->next_kid;
	p[2] = m->flags;
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

static int len_of(uint8_t type)
{
	switch (type) {
	case OTAR_REKEY: return (int)OTAR_REKEY_LEN;
	case OTAR_ACK: return (int)OTAR_ACK_LEN;
	case OTAR_HELLO: return (int)OTAR_HELLO_LEN;
	case OTAR_CHANGEOVER: return (int)OTAR_CHANGEOVER_LEN;
	case OTAR_ROSTER: return (int)OTAR_ROSTER_LEN;
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
	const uint8_t *p = &msg[OTAR_HDR];
	switch (m->type) {
	case OTAR_REKEY:
		m->keyset = get32(p);
		m->ckr = p[4];
		m->kid = p[5];
		m->changeover = get32(&p[6]);
		m->flags = p[10];
		if (ukek == NULL || !otar_kw_unwrap(ukek, &p[11], 40, m->tek) || m->ckr < 1 || m->ckr > 4) {
			crypto_wipe(m->tek, sizeof m->tek);
			return false;
		}
		return true;
	case OTAR_ACK:
		m->keyset = get32(p);
		m->ckr = p[4];
		m->result = p[5];
		memcpy(m->kcv, &p[6], 3);
		return true;
	case OTAR_HELLO:
		m->active_kid = p[0];
		m->next_kid = p[1];
		m->flags = p[2];
		return true;
	case OTAR_CHANGEOVER:
		m->keyset = get32(p);
		m->kid = p[4];
		return true;
	case OTAR_ROSTER:
		memcpy(m->rec, p, OTAR_ROSTER_REC);
		return true;
	default:
		return false;
	}
}

void otar_group_mac_key(const uint8_t tek[OTAR_KEY_LEN], uint8_t k_mac[OTAR_KEY_LEN])
{
	uint8_t prk[SHA256_LEN];
	hkdf_extract((const uint8_t *)"RFOTAR1 group", 13, tek, OTAR_KEY_LEN, prk);
	(void)hkdf_expand(prk, "co", 2, k_mac, OTAR_KEY_LEN);
	crypto_wipe(prk, sizeof prk);
}
