// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The receiver's noise as randomness (support/noise.h, docs/spec/key-fill.md 6.1)
#include "config.h"
#if CONFIG_KEY_FILL	// the whole file
#include <string.h>
#include "support/noise.h"
#include "support/hkdf.h"

static const char L_NOISE[] = "RFNOISE1";

uint8_t noise_health(const int16_t *x, unsigned n)
{
	if (x == NULL || n != NOISE_SAMPLES)
		return NOISE_SHORT;
	const unsigned mask = (1u << NOISE_SYMBOL_BITS) - 1u;
	// Repetition count (4.4.1)
	unsigned run = 1;
	for (unsigned i = 1; i < n; i++) {
		run = ((unsigned)x[i] & mask) == ((unsigned)x[i - 1] & mask) ? run + 1u : 1u;
		if (run >= NOISE_RCT_CUTOFF)
			return NOISE_RCT;
	}
	// Adaptive proportion over the one window (4.4.2)
	unsigned first = (unsigned)x[0] & mask, count = 0;
	int lo = x[0], hi = x[0];
	for (unsigned i = 0; i < n; i++) {
		count += ((unsigned)x[i] & mask) == first;
		lo = x[i] < lo ? x[i] : lo;
		hi = x[i] > hi ? x[i] : hi;
	}
	if (count >= NOISE_APT_CUTOFF)
		return NOISE_APT;
	return hi - lo >= NOISE_MIN_SPREAD ? NOISE_OK : NOISE_FLAT;
}

void noise_digest(const int16_t *x, unsigned n, uint8_t out[SHA256_LEN])
{
	sha256_t h;
	sha256_init(&h);
	sha256_update(&h, L_NOISE, sizeof L_NOISE - 1u);
	for (unsigned i = 0; i < n; i++) {
		uint8_t b[2] = { (uint8_t)x[i], (uint8_t)((uint16_t)x[i] >> 8) };
		sha256_update(&h, b, 2);
	}
	sha256_final(&h, out);
	crypto_wipe(&h, sizeof h);
}

// The mailbox from the radio task to the UI task: a sequence number, odd while it is being written
static volatile uint32_t seq;
static uint8_t box[SHA256_LEN];
static uint16_t box_credit;
static uint32_t taken_seq;
static noise_stats_t stats;

bool noise_quiet(int16_t rssi, int16_t floor)
{
	if (floor == 0)
		return rssi <= NOISE_QUIET_DBM;
	int limit = floor + NOISE_FLOOR_MARGIN_DB;
	if (limit > NOISE_QUIET_MAX_DBM)
		limit = NOISE_QUIET_MAX_DBM;
	return rssi <= limit;
}

void noise_post(const int16_t *x, unsigned n, int16_t rssi, int16_t floor)
{
	bool quiet = noise_quiet(rssi, floor);
	stats.last_rssi = rssi;
	stats.last_floor = floor;
	uint8_t why = noise_health(x, n);
	if (why == NOISE_OK && !quiet)
		why = NOISE_LOUD;	// mixed in, credited nothing: a signal may have shaped it
	stats.grabs++;
	if (why == NOISE_OK)
		stats.passed++;
	else
		stats.failed[why]++;
	uint8_t d[SHA256_LEN];
	noise_digest(x, n, d);
	seq++;
	__asm__ volatile("" ::: "memory");
	memcpy(box, d, sizeof box);
	box_credit = why == NOISE_OK ? (uint16_t)(n / NOISE_CREDIT_PER) : 0u;	// a failed grab is still mixed in
	__asm__ volatile("" ::: "memory");
	seq++;
	crypto_wipe(d, sizeof d);
}

bool noise_take(uint8_t out[SHA256_LEN], unsigned *credit)
{
	uint32_t s = seq;
	if ((s & 1u) || s == taken_seq)
		return false;
	__asm__ volatile("" ::: "memory");
	memcpy(out, box, SHA256_LEN);
	*credit = box_credit;
	__asm__ volatile("" ::: "memory");
	if (seq != s)
		return false;	// written meanwhile: the next call takes the new one
	taken_seq = s;
	stats.taken++;
	return true;
}

void noise_get_stats(noise_stats_t *s)
{
	*s = stats;
}
#endif
