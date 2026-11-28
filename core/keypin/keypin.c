// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The key PIN (keypin.h, docs/spec/key-pin.md)
#include "keypin/keypin.h"
#if CONFIG_KEY_PIN
#include <string.h>
#include "board.h"
#include "hal_time.h"
#include "settings/settings.h"
#include "support/sha256.h"

// The last wrong try's uptime, in RAM only. Until one is made since start-up the wait counts from start-up (uptime 0),
// so a restart neither resets the back-off nor makes it longer than it was
static uint32_t last_wrong_ms;

// Zeroes n octets so the compiler can't drop it as a dead store (a secret going out of scope)
static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;
	while (n-- > 0) {
		*v++ = 0;
	}
}

void keypin_hash(uint32_t salt, const char *pin, uint8_t len, uint8_t out[KEYPIN_HASH_LEN])
{
	static const char label[5] = { 'R', 'F', 'K', 'P', '1' };
	uint8_t uid[12] = { 0 }, s[4];
	hal_chip_t c;
	if (board.system != NULL && board.system->chip != NULL && board.system->chip(&c)) {
		for (unsigned i = 0; i < 12u; i++) {
			uid[i] = (uint8_t)(c.uid[i / 4u] >> (8u * (i % 4u)));
		}
	}
	for (unsigned i = 0; i < 4u; i++) {
		s[i] = (uint8_t)(salt >> (8u * i));
	}
	sha256_t h;
	uint8_t d[SHA256_LEN];
	sha256_init(&h);
	sha256_update(&h, label, sizeof(label));
	sha256_update(&h, uid, sizeof(uid));
	sha256_update(&h, s, sizeof(s));
	sha256_update(&h, &len, 1);		// "1234" and "12340000" can't share a hash
	sha256_update(&h, pin, len);
	sha256_final(&h, d);
	memcpy(out, d, KEYPIN_HASH_LEN);
	wipe(&h, sizeof(h));	// the PIN was in its block
	wipe(d, sizeof(d));
}

static uint8_t wrong_of(const settings_t *st)
{
	return (uint8_t)(st->kp_flags >> SETTINGS_KP_WRONG_SHIFT);
}

static void set_wrong(settings_t *st, uint8_t n)
{
	n = n > KEYPIN_WRONG_MAX ? KEYPIN_WRONG_MAX : n;
	st->kp_flags = (uint8_t)((st->kp_flags & ~(0x0Fu << SETTINGS_KP_WRONG_SHIFT)) | (n << SETTINGS_KP_WRONG_SHIFT));
}

bool keypin_set(const char *pin, uint8_t len)
{
	if (!keypin_valid(pin, len)) {
		return false;
	}
	uint8_t h[KEYPIN_HASH_LEN];
	settings_t *st = settings_begin();
	// Not random (the HAL has none): the uptime mixed into the last salt, so each setting differs (spec 2)
	uint32_t salt = (st->kp_salt ^ hal_millis()) * 2654435761u + 0x7F4A7C15u;
	keypin_hash(salt, pin, len, h);
	st->kp_salt = salt;
	memcpy(st->kp_hash, h, sizeof(h));
	st->kp_flags = SETTINGS_KP_SET;		// the wrong count 0
	settings_end(hal_millis());
	wipe(h, sizeof(h));
	keypin_note(true);
	return true;
}

void keypin_clear(void)
{
	settings_t *st = settings_begin();
	st->kp_flags = 0;
	st->kp_salt = 0;
	memset(st->kp_hash, 0, sizeof(st->kp_hash));
	settings_end(hal_millis());
	keypin_note(false);
}

void keypin_init(void)
{
	keypin_lock();
	keypin_note(keypin_is_set());
}

// A read, not a change: the UI asks every frame (its status) and at every push into the key screens
bool keypin_is_set(void)
{
	return (SETTINGS_FIELD(kp_flags) & SETTINGS_KP_SET) != 0;
}

uint8_t keypin_wrong(void)
{
	return (uint8_t)(SETTINGS_FIELD(kp_flags) >> SETTINGS_KP_WRONG_SHIFT);
}

uint32_t keypin_wait_ms(uint32_t now_ms)
{
	return keypin_wait_left(keypin_wrong(), last_wrong_ms, now_ms);
}

keypin_result_t keypin_try(const char *pin, uint8_t len, uint32_t now_ms)
{
	uint8_t want[KEYPIN_HASH_LEN], got[KEYPIN_HASH_LEN];
	settings_t *st = settings_begin();
	bool set = (st->kp_flags & SETTINGS_KP_SET) != 0;
	uint8_t wrong = wrong_of(st);
	uint32_t salt = st->kp_salt;
	memcpy(want, st->kp_hash, sizeof(want));
	settings_end(hal_millis());
	if (!set) {
		wipe(want, sizeof(want));
		return KEYPIN_NOT_SET;
	}
	if (keypin_wait_left(wrong, last_wrong_ms, now_ms) != 0) {
		wipe(want, sizeof(want));
		return KEYPIN_WAIT;	// not even hashed: the back-off is what limits the tries
	}
	uint8_t diff = 1;
	if (keypin_valid(pin, len)) {
		keypin_hash(salt, pin, len, got);
		diff = 0;
		for (unsigned i = 0; i < KEYPIN_HASH_LEN; i++) {
			diff |= (uint8_t)(want[i] ^ got[i]);	// constant time: a timing gives nothing away
		}
		wipe(got, sizeof(got));
	}
	wipe(want, sizeof(want));
	if (diff == 0) {
		if (wrong != 0) {	// a write only when there is something to reset
			st = settings_begin();
			set_wrong(st, 0);
			settings_end(hal_millis());
		}
		return KEYPIN_RIGHT;
	}
	last_wrong_ms = now_ms;
	st = settings_begin();
	set_wrong(st, (uint8_t)(wrong_of(st) + 1u));
	// Saved at the next settings poll, not once changes rest: switching off right after a wrong try keeps it counted
	settings_end_soon(hal_millis());
	return KEYPIN_WRONG;
}
#endif
