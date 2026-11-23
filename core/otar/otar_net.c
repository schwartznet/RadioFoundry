// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// An OTAR net's roster and joining: see otar_net.h
#include "config.h"
#if CONFIG_OTAR
#include <string.h>
#include "otar/otar_net.h"
#include "codeplug/codeplug.h"
#include "codeplug/codeplug_kv.h"

#define ROSTER_LO	CODEPLUG_KEY_OTAR_ROSTER
#define ROSTER_HI	((uint16_t)(CODEPLUG_KEY_OTAR_ROSTER + OTAR_ROSTER_MAX - 1u))

void otar_member_pack(const otar_member_t *m, uint8_t rec[OTAR_REC_LEN])
{
	rec[0] = (uint8_t)(m->id >> 16);
	rec[1] = (uint8_t)(m->id >> 8);
	rec[2] = (uint8_t)m->id;
	rec[3] = m->rank;
	rec[4] = m->flags;
	memcpy(&rec[5], m->pub, X25519_LEN);
}

bool otar_member_unpack(const uint8_t *rec, int len, otar_member_t *m)
{
	if (len != (int)OTAR_REC_LEN)
		return false;
	m->id = ((uint32_t)rec[0] << 16) | ((uint32_t)rec[1] << 8) | rec[2];
	m->rank = rec[3];
	m->flags = rec[4];
	memcpy(m->pub, &rec[5], X25519_LEN);
	return m->id != 0 && m->id <= CODEPLUG_DMR_ID_MAX && m->rank <= OTAR_RANK_MAX;
}

uint16_t otar_roster_window(uint16_t first, otar_member_t *out, uint16_t max, uint16_t *total)
{
	uint8_t rec[OTAR_REC_LEN];
	codeplug_kv_cursor_t c;
	uint16_t k, at = 0, filled = 0;
	int len;
	codeplug_kv_begin(&c, ROSTER_LO, ROSTER_HI);
	while ((len = codeplug_kv_next(&c, &k, rec, sizeof rec)) >= 0) {
		otar_member_t m;
		if (!otar_member_unpack(rec, len, &m))
			continue;
		uint16_t n = at++;
		if (n >= first && filled < max)
			out[filled++] = m;
	}
	*total = at;
	return filled;
}

// The record key of this DMR ID, else 0; *free_key the first key without a record (0: none)
static uint16_t key_of(uint32_t id, uint16_t *free_key, otar_member_t *found)
{
	uint8_t rec[OTAR_REC_LEN];
	bool used[OTAR_ROSTER_MAX];
	codeplug_kv_cursor_t c;
	uint16_t k, hit = 0;
	int len;
	memset(used, 0, sizeof used);
	codeplug_kv_begin(&c, ROSTER_LO, ROSTER_HI);
	while ((len = codeplug_kv_next(&c, &k, rec, sizeof rec)) >= 0) {
		used[k - ROSTER_LO] = true;
		otar_member_t m;
		if (hit == 0 && otar_member_unpack(rec, len, &m) && m.id == id) {
			hit = k;
			if (found != NULL)
				*found = m;
		}
	}
	if (free_key != NULL) {
		*free_key = 0;
		for (uint16_t i = 0; i < OTAR_ROSTER_MAX && *free_key == 0; i++)
			if (!used[i])
				*free_key = (uint16_t)(ROSTER_LO + i);
	}
	return hit;
}

bool otar_roster_find(uint32_t id, otar_member_t *m)
{
	return key_of(id, NULL, m) != 0;
}

bool otar_roster_put(const otar_member_t *m)
{
	uint16_t free_key, k = key_of(m->id, &free_key, NULL);
	if (k == 0)
		k = free_key;
	if (k == 0)
		return false;
	uint8_t rec[OTAR_REC_LEN];
	otar_member_pack(m, rec);
	return codeplug_kv_set(k, rec, sizeof rec);
}

bool otar_roster_clear(void)
{
	static const uint16_t range[] = { ROSTER_LO, ROSTER_HI };
	codeplug_kv_cursor_t c;
	uint16_t k;
	bool ok = true;
	// One record at a time: a roster is at most 64 small records
	for (;;) {
		codeplug_kv_begin(&c, range[0], range[1]);
		if (codeplug_kv_next(&c, &k, NULL, 0) < 0)
			break;
		if (!codeplug_kv_remove(k)) {
			ok = false;
			break;
		}
	}
	return ok;
}

int otar_join_build(uint16_t net_id, uint8_t rank, uint8_t *out, int cap)
{
	if (cap < (int)OTAR_JOIN_LEN || net_id == 0 || rank == 0 || rank > OTAR_RANK_MAX)
		return 0;
	out[0] = KF_CLASS_NET;
	out[1] = (uint8_t)(net_id >> 8);
	out[2] = (uint8_t)net_id;
	out[3] = rank;
	out[4] = 0;
	return (int)OTAR_JOIN_LEN;
}

bool otar_join_parse(const uint8_t *p, int len, uint16_t *net_id, uint8_t *rank)
{
	if (p == NULL || len != (int)OTAR_JOIN_LEN || p[0] != KF_CLASS_NET || p[4] != 0)
		return false;
	*net_id = (uint16_t)((p[1] << 8) | p[2]);
	*rank = p[3];
	return *net_id != 0 && *rank >= 1 && *rank <= OTAR_RANK_MAX;
}
#endif
