// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The receiver's noise as randomness (core/support/noise.c, docs/spec/key-fill.md 6.1): the SP 800-90B 4.4 health
// tests on a grab, and the mailbox from the radio task to the UI task
#include <stdio.h>
#include <string.h>
#include "support/noise.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static int16_t x[NOISE_SAMPLES];

// Noise-like: a wide spread, the low bits from a generator (stands in for the receiver's measured noise)
static void noisy(uint32_t seed)
{
	for (unsigned i = 0; i < NOISE_SAMPLES; i++) {
		seed = seed * 1664525u + 1013904223u;
		x[i] = (int16_t)((int32_t)(seed >> 16) - 32768) / 4;
	}
}

int main(void)
{
	noisy(1);
	CHECK(noise_health(x, NOISE_SAMPLES) == NOISE_OK);
	CHECK(noise_health(x, NOISE_SAMPLES - 1) == NOISE_SHORT);	// a short read (the tap gave less)
	CHECK(noise_health(NULL, NOISE_SAMPLES) == NOISE_SHORT);

	// Stuck: the same low bits NOISE_RCT_CUTOFF times in a row (the rest noisy): the repetition count fails
	noisy(2);
	for (unsigned i = 100; i < 100 + NOISE_RCT_CUTOFF; i++)
		x[i] = (int16_t)((x[i] & ~0xF) | 0x5);
	CHECK(noise_health(x, NOISE_SAMPLES) == NOISE_RCT);
	// One fewer: passes
	noisy(2);
	for (unsigned i = 100; i < 100 + NOISE_RCT_CUTOFF - 1u; i++)
		x[i] = (int16_t)((x[i] & ~0xF) | 0x5);
	CHECK(noise_health(x, NOISE_SAMPLES) == NOISE_OK);

	// Biased: two low-bit values taking turns (no long run), the first in half the window: the proportion test fails
	noisy(3);
	for (unsigned i = 0; i < NOISE_SAMPLES; i++)
		x[i] = (int16_t)((x[i] & ~0xF) | (i & 1 ? 0x3 : 0xC));
	CHECK(noise_health(x, NOISE_SAMPLES) == NOISE_APT);

	// A receiver not running: tiny values that still look random in the low bits
	noisy(4);
	for (unsigned i = 0; i < NOISE_SAMPLES; i++)
		x[i] = (int16_t)(x[i] & 0x1F);
	CHECK(noise_health(x, NOISE_SAMPLES) == NOISE_FLAT);

	// The mailbox: a good grab comes out once, credited a bit per NOISE_CREDIT_PER samples; a failed one credited 0
	uint8_t d1[32], d2[32], want[32];
	unsigned credit = 99;
	CHECK(!noise_take(d1, &credit));
	noisy(5);
	noise_digest(x, NOISE_SAMPLES, want);
	noise_post(x, NOISE_SAMPLES, true);
	CHECK(noise_take(d1, &credit) && credit == NOISE_SAMPLES / NOISE_CREDIT_PER && memcmp(d1, want, 32) == 0);
	CHECK(!noise_take(d2, &credit));		// taken once
	noise_post(x, 10, true);			// short: failed, still mixed in
	CHECK(noise_take(d2, &credit) && credit == 0 && memcmp(d1, d2, 32) != 0);
	noisy(6);
	uint8_t other[32];
	noise_digest(x, NOISE_SAMPLES, other);
	CHECK(memcmp(other, want, 32) != 0);	// another grab, another digest
	// A good grab with a signal on the channel: mixed in, credited nothing (a carrier could have shaped it)
	noise_post(x, NOISE_SAMPLES, false);
	CHECK(noise_take(d2, &credit) && credit == 0);
	noise_stats_t st;
	noise_get_stats(&st);
	CHECK(st.grabs == 3 && st.passed == 1 && st.failed[NOISE_SHORT] == 1 && st.failed[NOISE_LOUD] == 1 && st.taken == 3);

	printf("noiseTest: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
