// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR keysets (docs/spec/otar.md 8): see otar_keys.h
#include <string.h>
#include "otar/otar_keys.h"

static bool ckr_ok(uint8_t ckr) { return ckr >= 1u && ckr <= OTAR_CKRS; }

bool otar_kid(const otar_keys_t *k, uint8_t which, uint8_t ckr, uint8_t *kid)
{
	if (!otar_on(k) || !ckr_ok(ckr))
		return false;
	uint8_t bit = (uint8_t)(1u << (ckr - 1u));
	switch (which) {
	case OTAR_ACTIVE:
		if (!(k->mask & bit))
			return false;
		*kid = k->kid_active[ckr - 1u];
		return true;
	case OTAR_NEXT:
		if (!(k->flags & OTAR_F_NEXT) || !(k->mask & (bit << 4)))
			return false;
		*kid = k->kid_next[ckr - 1u];
		return true;
	case OTAR_PREV:
		if (!(k->flags & OTAR_F_PREV) || !(k->prev_mask & bit))
			return false;
		*kid = k->kid_prev[ckr - 1u];
		return true;
	default:
		return false;
	}
}

uint8_t otar_ckr(uint16_t aes_ref)
{
	return aes_ref >= 1u && aes_ref <= OTAR_CKRS ? (uint8_t)aes_ref : 1u;
}

void otar_start(otar_keys_t *k, uint8_t system, uint8_t kid)
{
	memset(k, 0, sizeof *k);
	k->system = (uint8_t)(system + 1u);
	k->ks_active = 1;
	k->mask = 0x01;
	k->kid_active[0] = kid;
}

void otar_stop(otar_keys_t *k)
{
	memset(k, 0, sizeof *k);
}

bool otar_set_next(otar_keys_t *k, uint8_t ckr, uint8_t kid, uint32_t changeover, bool own_clock)
{
	if (!otar_on(k) || !ckr_ok(ckr))
		return false;
	if (!(k->flags & OTAR_F_NEXT)) {
		k->flags |= OTAR_F_NEXT;
		k->ks_next = (uint16_t)(k->ks_active + 1u);
		k->mask &= 0x0Fu;
		memset(k->kid_next, 0, sizeof k->kid_next);
	}
	k->kid_next[ckr - 1u] = kid;
	k->mask |= (uint8_t)(0x10u << (ckr - 1u));
	k->changeover = changeover;
	k->flags = (uint8_t)((k->flags & (uint8_t)~OTAR_F_OWN_CLOCK) | (own_clock && changeover != 0 ? OTAR_F_OWN_CLOCK : 0));
	return true;
}

void otar_clear_next(otar_keys_t *k)
{
	k->flags &= (uint8_t)~(OTAR_F_NEXT | OTAR_F_OWN_CLOCK);
	k->mask &= 0x0Fu;
	k->ks_next = 0;
	k->changeover = 0;
	memset(k->kid_next, 0, sizeof k->kid_next);
}

bool otar_due(const otar_keys_t *k, bool clock_ok, uint32_t now_min)
{
	return otar_on(k) && (k->flags & OTAR_F_NEXT) && (k->flags & OTAR_F_OWN_CLOCK) && k->changeover != 0 && clock_ok &&
	       now_min >= k->changeover;
}

bool otar_change_over(otar_keys_t *k)
{
	if (!otar_on(k) || !(k->flags & OTAR_F_NEXT))
		return false;
	memcpy(k->kid_prev, k->kid_active, sizeof k->kid_prev);
	k->prev_mask = (uint8_t)(k->mask & 0x0Fu);
	k->flags |= OTAR_F_PREV;
	// A CKR the next keyset doesn't name keeps its active key
	for (uint8_t i = 0; i < OTAR_CKRS; i++)
		if (k->mask & (0x10u << i))
			k->kid_active[i] = k->kid_next[i];
	k->mask = (uint8_t)((k->mask & 0x0Fu) | (k->mask >> 4));
	k->ks_active = k->ks_next;
	otar_clear_next(k);
	return true;
}

static bool in_use(const otar_keys_t *k, uint8_t kid)
{
	uint8_t x;
	for (uint8_t ckr = 1; ckr <= OTAR_CKRS; ckr++)
		if ((otar_kid(k, OTAR_ACTIVE, ckr, &x) && x == kid) || (otar_kid(k, OTAR_NEXT, ckr, &x) && x == kid))
			return true;
	return false;
}

uint8_t otar_drop_prev(otar_keys_t *k, uint8_t out[OTAR_CKRS])
{
	uint8_t n = 0;
	if (k->flags & OTAR_F_PREV) {
		for (uint8_t i = 0; i < OTAR_CKRS; i++) {
			uint8_t kid = k->kid_prev[i];
			if (!(k->prev_mask & (1u << i)) || in_use(k, kid))
				continue;
			bool dup = false;
			for (uint8_t j = 0; j < n; j++)
				dup = dup || out[j] == kid;
			if (!dup)
				out[n++] = kid;
		}
	}
	k->flags &= (uint8_t)~OTAR_F_PREV;
	k->prev_mask = 0;
	memset(k->kid_prev, 0, sizeof k->kid_prev);
	return n;
}

// Days since 1970-01-01 of a date, and back (the proleptic Gregorian calendar)
static int32_t days_from_civil(int32_t y, uint32_t m, uint32_t d)
{
	y -= m <= 2;
	int32_t era = (y >= 0 ? y : y - 399) / 400;
	uint32_t yoe = (uint32_t)(y - era * 400);
	uint32_t doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
	uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + (int32_t)doe - 719468;
}

void otar_civil(uint32_t min, uint16_t *year, uint8_t *month, uint8_t *day, uint8_t *hour, uint8_t *minute)
{
	int32_t z = (int32_t)(OTAR_EPOCH_UNIX / 86400) + (int32_t)(min / 1440u) + 719468;
	int32_t era = z / 146097;
	uint32_t doe = (uint32_t)(z - era * 146097);
	uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	uint32_t mp = (5 * doy + 2) / 153;
	uint32_t d = doy - (153 * mp + 2) / 5 + 1;
	uint32_t m = mp < 10 ? mp + 3 : mp - 9;
	*year = (uint16_t)((int32_t)yoe + era * 400 + (m <= 2));
	*month = (uint8_t)m;
	*day = (uint8_t)d;
	*hour = (uint8_t)((min % 1440u) / 60u);
	*minute = (uint8_t)(min % 60u);
}

uint32_t otar_from_civil(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute)
{
	static const uint8_t mdays[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	if (year < 2026 || year > 2099 || month < 1 || month > 12 || day < 1 || day > mdays[month - 1] || hour > 23 ||
	    minute > 59)
		return 0;
	if (month == 2 && day == 29 && (year % 4) != 0)
		return 0;
	int32_t days = days_from_civil(year, month, day) - (int32_t)(OTAR_EPOCH_UNIX / 86400);
	return (uint32_t)days * 1440u + hour * 60u + minute;
}

uint32_t otar_minutes(int64_t unix_s)
{
	if (unix_s < OTAR_EPOCH_UNIX)
		return 0;
	return (uint32_t)((unix_s - OTAR_EPOCH_UNIX) / 60);
}
