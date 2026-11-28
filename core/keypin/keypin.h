// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The key PIN (docs/spec/key-pin.md, CONFIG_KEY_PIN): 4 to 8 digits typed before Settings > Privacy or Tools > Key
// fill opens, kept as a salted hash in the settings store, with a back-off after wrong tries that a restart doesn't
// reset. The back-off's times are header only, so the UI's host simulator follows the same rule
#ifndef RFOUNDRY_KEYPIN_H
#define RFOUNDRY_KEYPIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"

#define KEYPIN_MIN		4u	// digits
#define KEYPIN_MAX		8u
#define KEYPIN_HASH_LEN		16u
#define KEYPIN_WRONG_MAX	15u	// settings_t.kp_flags bits 4-7 (saturates)
#define KEYPIN_FREE_TRIES	3u	// wrong tries before the back-off starts (spec 4)
#define KEYPIN_WAIT_FIRST_MS	30000u	// the first wait, doubled at each wrong try after it
#define KEYPIN_WAIT_MAX_MS	(15u * 60u * 1000u)

// How long the next try waits after `wrong` consecutive wrong tries: none for the first KEYPIN_FREE_TRIES, then 30 s,
// 1, 2, 4, 8 min, then 15 min for every one after (spec 4)
static inline uint32_t keypin_delay_ms(uint8_t wrong)
{
	if (wrong < KEYPIN_FREE_TRIES) {
		return 0;
	}
	uint32_t ms = KEYPIN_WAIT_FIRST_MS;
	for (uint8_t n = KEYPIN_FREE_TRIES; n < wrong && ms < KEYPIN_WAIT_MAX_MS; n++) {
		ms *= 2u;
	}
	return ms < KEYPIN_WAIT_MAX_MS ? ms : KEYPIN_WAIT_MAX_MS;
}

// The wait still left at now_ms after `wrong` wrong tries, the last of them at last_ms (0 none left)
static inline uint32_t keypin_wait_left(uint8_t wrong, uint32_t last_ms, uint32_t now_ms)
{
	uint32_t d = keypin_delay_ms(wrong), gone = now_ms - last_ms;
	return gone >= d ? 0 : d - gone;
}

// Digits only, KEYPIN_MIN to KEYPIN_MAX of them
static inline bool keypin_valid(const char *pin, uint8_t len)
{
	if (pin == NULL || len < KEYPIN_MIN || len > KEYPIN_MAX) {
		return false;
	}
	for (uint8_t i = 0; i < len; i++) {
		if (pin[i] < '0' || pin[i] > '9') {
			return false;
		}
	}
	return true;
}

#if CONFIG_KEY_PIN
typedef enum {
	KEYPIN_RIGHT,		// the PIN: the wrong count is 0 again
	KEYPIN_WRONG,		// not the PIN (or not 4 to 8 digits): counted
	KEYPIN_WAIT,		// not tried: the back-off's wait isn't over
	KEYPIN_NOT_SET,		// no PIN set
} keypin_result_t;

// The hash of pin under salt: the first KEYPIN_HASH_LEN octets of SHA-256("RFKP1" | UID | salt | len | pin), len one
// octet (spec 2)
void keypin_hash(uint32_t salt, const char *pin, uint8_t len, uint8_t out[KEYPIN_HASH_LEN]);
// Set (a new salt, its hash, the wrong count 0) or clear the PIN in the settings store; false when pin isn't 4 to 8
// digits
bool keypin_set(const char *pin, uint8_t len);
void keypin_clear(void);
bool keypin_is_set(void);
// Consecutive wrong tries, saturating at KEYPIN_WRONG_MAX (kept over a restart)
uint8_t keypin_wrong(void);
// The back-off's wait left at now_ms (0: a try may be made). After a restart the wait counts from start-up
uint32_t keypin_wait_ms(uint32_t now_ms);
// Try a PIN typed at now_ms (constant-time compare). A wrong one is counted and saved soon (settings_end_soon)
keypin_result_t keypin_try(const char *pin, uint8_t len, uint32_t now_ms);
// At start-up, after settings_init: the RAM copy of "a PIN is set" (keypin_note) taken from the settings store
void keypin_init(void);

// --- The RAM state (keypin_state.c: no dependencies, safe from any task; spec 3, 10) ---
// Unlocked: the right PIN typed on the radio, not locked again since (Home, key lock, 5 minutes, restart). The UI sets
// it; the host paths read it. Locked at start-up
bool keypin_open(void);
void keypin_unlock(void);
void keypin_lock(void);
// A PIN is set (kept by keypin_set / keypin_clear / keypin_init)
void keypin_note(bool set);
// A PIN is set and the radio is locked: the cable sees no key material (codeplug_kv_redact, codeplug_kv_commit's
// merge, the refused raw reads)
bool keypin_guard(void);
#define KEYPIN_GUARD()	keypin_guard()
#else
#define KEYPIN_GUARD()	false	// no key PIN in this build: the cable sees what it always did
#endif

#endif
