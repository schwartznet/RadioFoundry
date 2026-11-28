// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The key PIN (core/keypin, docs/spec/key-pin.md) on a simulated NOR flash with the real storage and settings store:
// the hash and its construction, set / check / clear, 4 to 8 digits only, the back-off's times, the wrong count kept
// over a restart, a factory reset clearing it, and the PIN never stored as typed
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "keypin/keypin.h"
#include "settings/settings.h"
#include "storage/storage.h"
#include "support/sha256.h"
#include "hal_time.h"
#include "board.h"
#include "sim/sim_flash.h"

static int failures, checks;

#define CHECK(cond) do { checks++; if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

void storage_lock(void) {}
void storage_unlock(void) {}
void storage_quick_lock(void) {}
void storage_quick_unlock(void) {}

static uint32_t now_ms = 1000;
uint32_t hal_millis(void) { return now_ms; }
void hal_delay_ms(uint32_t ms) { now_ms += ms; }

#define FLASH_SIZE	0x400000u
static const hal_flash_map_t map = {
	.settings_addr = 0x011000u, .settings_size = 0x008000u, .journal_addr = 0x019000u,
	.openfw_eeprom = 0, .openfw_flash = 0x020000u, .openfw_end = 0x300000u,
	.calibration_addr = 0x010000u, .calibration_size = 0x200u,
	.native_addr = 0x300000u, .native_size = 0x040000u, .staging_addr = 0x340000u, .staging_size = 0x040000u,
};

static uint32_t uid[3] = { 0x11223344u, 0x55667788u, 0x99AABBCCu };
static bool chip(hal_chip_t *c)
{
	memset(c, 0, sizeof(*c));
	memcpy(c->uid, uid, sizeof(uid));
	return true;
}
static const hal_system_t sys = { .chip = chip };
static band_t bands[] = { { 136000000, 174000000, true }, { 400000000, 480000000, true } };
const board_t board = { .name = "test", .bands = bands, .band_count = 2, .power_count = 9, .flash = &sim_flash,
			.system = &sys };

static void fresh(void)
{
	sim_flash_create(FLASH_SIZE, &map);
	CHECK(storage_init());
	settings_init();
	now_ms = 1000;
}

static bool in_flash(const void *pat, size_t n)
{
	for (uint32_t a = 0; a + n <= FLASH_SIZE; a++) {
		if (sim_flash_data[a] == ((const uint8_t *)pat)[0] && memcmp(&sim_flash_data[a], pat, n) == 0)
			return true;
	}
	return false;
}

// The spec's construction, built here on its own: SHA-256("RFKP1" | UID (12 octets, little endian words) | salt
// (little endian) | length | PIN), its first 16 octets
static void spec_hash(uint32_t salt, const char *pin, uint8_t len, uint8_t out[16])
{
	uint8_t m[5 + 12 + 4 + 1 + 8];
	size_t n = 0;
	memcpy(m, "RFKP1", 5);
	n = 5;
	for (unsigned i = 0; i < 12; i++)
		m[n++] = (uint8_t)(uid[i / 4] >> (8 * (i % 4)));
	for (unsigned i = 0; i < 4; i++)
		m[n++] = (uint8_t)(salt >> (8 * i));
	m[n++] = len;
	memcpy(&m[n], pin, len);
	n += len;
	uint8_t d[SHA256_LEN];
	sha256_t h;
	sha256_init(&h);
	sha256_update(&h, m, n);
	sha256_final(&h, d);
	memcpy(out, d, 16);
}

static void test_hash(void)
{
	uint8_t a[16], b[16];
	keypin_hash(0x12345678u, "1234", 4, a);
	spec_hash(0x12345678u, "1234", 4, b);
	CHECK(memcmp(a, b, 16) == 0);
	keypin_hash(0x12345679u, "1234", 4, b);
	CHECK(memcmp(a, b, 16) != 0);			// the salt counts
	keypin_hash(0x12345678u, "12340", 5, b);
	CHECK(memcmp(a, b, 16) != 0);			// so does the length
	uid[0] ^= 1u;
	keypin_hash(0x12345678u, "1234", 4, b);
	uid[0] ^= 1u;
	CHECK(memcmp(a, b, 16) != 0);			// and the radio's UID
}

static void test_set_check_clear(void)
{
	fresh();
	CHECK(!keypin_is_set());
	CHECK(keypin_try("1234", 4, now_ms) == KEYPIN_NOT_SET);
	CHECK(!keypin_set("123", 3));			// 4 to 8 digits only
	CHECK(!keypin_set("123456789", 9));
	CHECK(!keypin_set("12a4", 4));
	CHECK(!keypin_is_set());
	CHECK(keypin_set("73914", 5));
	CHECK(keypin_is_set() && keypin_wrong() == 0);
	CHECK(keypin_try("73914", 5, now_ms) == KEYPIN_RIGHT);
	CHECK(keypin_try("7391", 4, now_ms) == KEYPIN_WRONG);	// a prefix is wrong
	CHECK(keypin_try("739140", 6, now_ms) == KEYPIN_WRONG);
	CHECK(keypin_try("739", 3, now_ms) == KEYPIN_WRONG);	// too short: counted as a try too
	CHECK(keypin_wrong() == 3);
	settings_t s;
	settings_read(&s);
	CHECK((s.kp_flags & SETTINGS_KP_SET) && s.kp_salt != 0 && s.kp_reserved[0] == 0);
	uint8_t want[16];
	spec_hash(s.kp_salt, "73914", 5, want);
	CHECK(memcmp(s.kp_hash, want, 16) == 0);
	// The PIN is never stored as typed (the hash and salt are): not in any record in the flash
	CHECK(settings_flush());
	CHECK(!in_flash("73914", 5));
	// A new salt each time it is set
	uint32_t salt1 = s.kp_salt;
	now_ms += 17;
	CHECK(keypin_set("73914", 5));
	settings_read(&s);
	CHECK(s.kp_salt != salt1 && keypin_wrong() == 0);	// and setting it starts the count again
	keypin_clear();
	settings_read(&s);
	CHECK(!keypin_is_set() && s.kp_flags == 0 && s.kp_salt == 0);
	for (unsigned i = 0; i < 16; i++)
		CHECK(s.kp_hash[i] == 0);
	CHECK(keypin_try("73914", 5, now_ms) == KEYPIN_NOT_SET);
}

static void test_delays(void)
{
	CHECK(keypin_delay_ms(0) == 0 && keypin_delay_ms(1) == 0 && keypin_delay_ms(2) == 0);
	CHECK(keypin_delay_ms(3) == 30000u);
	CHECK(keypin_delay_ms(4) == 60000u);
	CHECK(keypin_delay_ms(5) == 120000u);
	CHECK(keypin_delay_ms(6) == 240000u);
	CHECK(keypin_delay_ms(7) == 480000u);
	CHECK(keypin_delay_ms(8) == 900000u);		// 960 s capped at 15 min
	CHECK(keypin_delay_ms(15) == 900000u);
	CHECK(keypin_delay_ms(255) == 900000u);
	CHECK(keypin_wait_left(3, 1000, 1000) == 30000u);
	CHECK(keypin_wait_left(3, 1000, 31000) == 0);
	CHECK(keypin_wait_left(3, 1000, 30999) == 1);
	CHECK(keypin_wait_left(2, 1000, 1000) == 0);
	CHECK(keypin_wait_left(3, 0xFFFFF000u, 0x1000u) == 30000u - 0x2000u);	// over the uptime's wrap
}

static void test_backoff(void)
{
	fresh();
	CHECK(keypin_set("2580", 4));
	// Three wrong tries are free
	for (int i = 0; i < 3; i++) {
		CHECK(keypin_wait_ms(now_ms) == 0);
		CHECK(keypin_try("0000", 4, now_ms) == KEYPIN_WRONG);
		now_ms += 100;
	}
	CHECK(keypin_wrong() == 3);
	CHECK(keypin_wait_ms(now_ms) == 30000u - 100u);
	// Meanwhile not even the right PIN is tried, and the count stays
	CHECK(keypin_try("2580", 4, now_ms) == KEYPIN_WAIT);
	CHECK(keypin_try("0000", 4, now_ms) == KEYPIN_WAIT);
	CHECK(keypin_wrong() == 3);
	now_ms += 30000u;
	CHECK(keypin_wait_ms(now_ms) == 0);
	CHECK(keypin_try("0000", 4, now_ms) == KEYPIN_WRONG);	// the 4th: 60 s
	CHECK(keypin_wrong() == 4 && keypin_wait_ms(now_ms) == 60000u);
	now_ms += 60000u;
	CHECK(keypin_try("0000", 4, now_ms) == KEYPIN_WRONG);	// the 5th: 120 s
	CHECK(keypin_wait_ms(now_ms) == 120000u);
	// The count survives a restart (saved soon, not when changes rest)
	settings_poll(now_ms);
	settings_init();
	CHECK(keypin_wrong() == 5 && keypin_is_set());
	// The right PIN after the wait opens and starts the count again
	now_ms += 120000u;
	CHECK(keypin_try("2580", 4, now_ms) == KEYPIN_RIGHT);
	CHECK(keypin_wrong() == 0 && keypin_wait_ms(now_ms) == 0);
	// The count saturates at 15
	for (int i = 0; i < 20; i++) {
		now_ms += KEYPIN_WAIT_MAX_MS;
		(void)keypin_try("1111", 4, now_ms);
	}
	CHECK(keypin_wrong() == KEYPIN_WRONG_MAX && keypin_wait_ms(now_ms) == KEYPIN_WAIT_MAX_MS);
	CHECK(keypin_is_set());				// the bit 0 the count shares an octet with stays
}

static void test_reset(void)
{
	fresh();
	CHECK(keypin_set("1234", 4));
	settings_t *st = settings_begin();
	settings_defaults(st);				// a factory reset (and the emergency wipe of keys and codeplug)
	settings_end(now_ms);
	CHECK(!keypin_is_set() && keypin_wrong() == 0);
	// A record from before the key PIN reads no PIN: its fields are past the end of the old record, read as 0
	settings_t d;
	settings_defaults(&d);
	CHECK(d.kp_flags == 0 && d.kp_salt == 0);
}

int main(void)
{
	test_hash();
	test_set_check_clear();
	test_delays();
	test_backoff();
	test_reset();
	if (failures) {
		printf("# FAILED keypinTest: %d of %d checks\n", failures, checks);
		return 1;
	}
	printf("# PASSED keypinTest: %d checks\n", checks);
	return 0;
}
