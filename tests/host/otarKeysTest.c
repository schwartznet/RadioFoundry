// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR keysets (core/otar/otar_keys.c, docs/spec/otar.md 8): start, the next keyset, the changeover by clock and by
// hand, the previous keyset and which of its keys may be erased, CKRs, keyset numbers, and the UTC minutes and
// calendar conversions.
#include <stdio.h>
#include <string.h>
#include "otar/otar_keys.h"

static int failures;

#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static void test_start_and_next(void)
{
	otar_keys_t k;
	uint8_t kid;
	memset(&k, 0xA5, sizeof k);
	otar_stop(&k);
	CHECK(!otar_on(&k) && !otar_kid(&k, OTAR_ACTIVE, 1, &kid));
	CHECK(!otar_set_next(&k, 1, 9, 0, false));	// nothing managed

	otar_start(&k, 2, 77);
	CHECK(otar_on(&k) && otar_system(&k) == 2 && k.ks_active == 1);
	CHECK(otar_kid(&k, OTAR_ACTIVE, 1, &kid) && kid == 77);
	CHECK(!otar_kid(&k, OTAR_ACTIVE, 2, &kid));	// only CKR 1
	CHECK(!otar_kid(&k, OTAR_NEXT, 1, &kid) && !otar_kid(&k, OTAR_PREV, 1, &kid));
	CHECK(!otar_kid(&k, OTAR_ACTIVE, 0, &kid) && !otar_kid(&k, OTAR_ACTIVE, 5, &kid));

	// CKRs from a channel's reference: 1-4 as they are, anything else 1
	CHECK(otar_ckr(1) == 1 && otar_ckr(4) == 4 && otar_ckr(0) == 1 && otar_ckr(78) == 1);

	// The next keyset: opened as active + 1, by hand (0) or at a minute by the radio's clock
	CHECK(otar_set_next(&k, 1, 78, 0, true));
	CHECK(otar_kid(&k, OTAR_NEXT, 1, &kid) && kid == 78 && k.ks_next == 2);
	CHECK(!(k.flags & OTAR_F_OWN_CLOCK));	// by hand: never by the clock
	CHECK(!otar_due(&k, true, 999999));
	CHECK(otar_set_next(&k, 1, 7, 5000, true));	// replaced, same keyset number
	CHECK(otar_kid(&k, OTAR_NEXT, 1, &kid) && kid == 7 && k.ks_next == 2 && (k.flags & OTAR_F_OWN_CLOCK));
	CHECK(!otar_due(&k, true, 4999) && otar_due(&k, true, 5000) && otar_due(&k, true, 6000));
	CHECK(!otar_due(&k, false, 6000));	// no clock: waits
	CHECK(!otar_set_next(&k, 0, 1, 0, false) && !otar_set_next(&k, 5, 1, 0, false));

	otar_clear_next(&k);
	CHECK(!otar_kid(&k, OTAR_NEXT, 1, &kid) && k.ks_next == 0 && k.changeover == 0 && !otar_due(&k, true, 6000));
	CHECK(otar_kid(&k, OTAR_ACTIVE, 1, &kid) && kid == 77);
	CHECK(!otar_change_over(&k));	// nothing next
}

static void test_changeover(void)
{
	otar_keys_t k;
	uint8_t kid, out[OTAR_CKRS];
	otar_start(&k, 0, 10);
	CHECK(otar_set_next(&k, 1, 11, 100, true));
	CHECK(otar_change_over(&k));
	CHECK(otar_kid(&k, OTAR_ACTIVE, 1, &kid) && kid == 11 && k.ks_active == 2);
	CHECK(otar_kid(&k, OTAR_PREV, 1, &kid) && kid == 10);
	CHECK(!otar_kid(&k, OTAR_NEXT, 1, &kid) && k.changeover == 0 && !(k.flags & OTAR_F_OWN_CLOCK));
	CHECK(!otar_due(&k, true, 200));

	// The overlap ends: key 10 may be erased
	CHECK(otar_drop_prev(&k, out) == 1 && out[0] == 10);
	CHECK(!otar_kid(&k, OTAR_PREV, 1, &kid) && otar_drop_prev(&k, out) == 0);

	// A previous key that a keyset still names isn't erased: 11 -> 12 -> back to 11 next
	CHECK(otar_set_next(&k, 1, 12, 0, false) && otar_change_over(&k));	// active 12, previous 11
	CHECK(otar_set_next(&k, 1, 11, 0, false));				// 11 comes back next
	CHECK(otar_drop_prev(&k, out) == 0);
	CHECK(otar_kid(&k, OTAR_ACTIVE, 1, &kid) && kid == 12 && k.ks_active == 3);

	// A second changeover before the overlap ends: the newest previous replaces the older one
	CHECK(otar_change_over(&k));	// active 11, previous 12
	CHECK(otar_kid(&k, OTAR_PREV, 1, &kid) && kid == 12 && k.ks_active == 4);

	// Several CKRs: one the next keyset doesn't name keeps its key
	otar_start(&k, 1, 20);
	CHECK(otar_set_next(&k, 2, 30, 0, false) && otar_change_over(&k));
	CHECK(otar_kid(&k, OTAR_ACTIVE, 1, &kid) && kid == 20);
	CHECK(otar_kid(&k, OTAR_ACTIVE, 2, &kid) && kid == 30);
	CHECK(otar_set_next(&k, 1, 21, 0, false) && otar_set_next(&k, 2, 31, 0, false) && otar_change_over(&k));
	uint8_t n = otar_drop_prev(&k, out);
	CHECK(n == 2 && out[0] == 20 && out[1] == 30);

	// Keyset numbers only go up
	CHECK(k.ks_active == 3);
}

static void test_time(void)
{
	CHECK(otar_minutes(0) == 0 && otar_minutes(OTAR_EPOCH_UNIX - 1) == 0);
	CHECK(otar_minutes(OTAR_EPOCH_UNIX + 60) == 1);
	// 2026-11-23 14:05 UTC = 1795442700 s
	uint32_t m = otar_minutes(1795442700LL);
	uint16_t y;
	uint8_t mo, d, h, mi;
	otar_civil(m, &y, &mo, &d, &h, &mi);
	CHECK(y == 2026 && mo == 11 && d == 23 && h == 14 && mi == 5);
	CHECK(otar_from_civil(2026, 11, 23, 14, 5) == m);
	// Leap days and month ends round trip
	static const struct { uint16_t y; uint8_t mo, d; } dates[] = {
		{ 2026, 1, 2 }, { 2026, 2, 28 }, { 2026, 12, 31 }, { 2028, 2, 29 }, { 2028, 3, 1 }, { 2099, 12, 31 },
	};
	for (unsigned i = 0; i < sizeof dates / sizeof dates[0]; i++) {
		uint32_t x = otar_from_civil(dates[i].y, dates[i].mo, dates[i].d, 23, 59);
		CHECK(x != 0);
		otar_civil(x, &y, &mo, &d, &h, &mi);
		CHECK(y == dates[i].y && mo == dates[i].mo && d == dates[i].d && h == 23 && mi == 59);
	}
	// Not dates
	CHECK(otar_from_civil(2025, 12, 31, 0, 0) == 0 && otar_from_civil(2027, 2, 29, 0, 0) == 0);
	CHECK(otar_from_civil(2026, 13, 1, 0, 0) == 0 && otar_from_civil(2026, 4, 31, 0, 0) == 0);
	CHECK(otar_from_civil(2026, 4, 30, 24, 0) == 0 && otar_from_civil(2026, 4, 30, 0, 60) == 0);
	CHECK(otar_from_civil(2100, 1, 1, 0, 0) == 0);
	// Minutes and unix seconds agree
	CHECK(otar_minutes(OTAR_EPOCH_UNIX + (int64_t)otar_from_civil(2027, 6, 15, 8, 30) * 60) ==
	      otar_from_civil(2027, 6, 15, 8, 30));
}

int main(void)
{
	test_start_and_next();
	test_changeover();
	test_time();
	if (failures == 0)
		printf("# otarKeysTest PASSED\n");
	else
		printf("# otarKeysTest FAILED (%d)\n", failures);
	return failures != 0;
}
