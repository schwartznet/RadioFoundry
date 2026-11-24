// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The receiver's noise as randomness for key fill and OTAR (docs/spec/key-fill.md 6.1): a short grab of the FM receive
// copy (hal_baseband_t) checked by the SP 800-90B 4.4 health tests, hashed, and posted to the UI task, which stirs the
// digest into the pool (support/entropy.h: the pool is the UI task's alone).
//
// Run time: the radio task grabs (radio_task.c, RREQ_NOISE) and calls noise_post; the UI task calls noise_take.
// noise_health and noise_digest are pure (host-tested in noiseTest).
#ifndef RFOUNDRY_NOISE_H
#define RFOUNDRY_NOISE_H

#include <stdbool.h>
#include <stdint.h>
#include "support/sha256.h"

#define NOISE_SAMPLES		512u	// one grab: 64 ms at 8000 Hz
#define NOISE_SYMBOL_BITS	4u	// the health tests and the credit look at each sample's low 4 bits
// The health tests' cutoffs for a claimed 2 bits of min-entropy per 4-bit symbol (measured 3.7, the worst case under
// an unmodulated carrier) and a false alarm rate of 2^-20 (SP 800-90B 4.4.1, 4.4.2, window 512)
#define NOISE_RCT_CUTOFF	11u	// the same symbol this many times in a row: failed
#define NOISE_APT_CUTOFF	177u	// the window's first symbol this many times in the window: failed
#define NOISE_MIN_SPREAD	64	// counts between the lowest and highest sample: a receiver that isn't running fails
#define NOISE_CREDIT_PER	4u	// one bit credited per this many samples (a quarter of the worst case measured)
// Credited only when the channel is quiet (6.1): the signal strength at or below this, read before and after the grab.
// A carrier strong enough to quiet the discriminator, which a sender could modulate to pass the health tests with
// little entropy, is well above it; the radio's own floor is about -106 dBm
#define NOISE_QUIET_DBM		(-100)

enum { NOISE_OK, NOISE_SHORT, NOISE_RCT, NOISE_APT, NOISE_FLAT, NOISE_LOUD };

typedef struct {
	uint32_t grabs;		// noise_post calls
	uint32_t passed;
	uint32_t failed[6];	// by NOISE_* reason (failed[NOISE_OK] unused; NOISE_LOUD: a signal on the channel)
	uint32_t taken;		// digests the UI task stirred in
} noise_stats_t;

// NOISE_OK when n samples pass: n is NOISE_SAMPLES, no run of NOISE_RCT_CUTOFF equal symbols, the first symbol
// fewer than NOISE_APT_CUTOFF times, a spread of NOISE_MIN_SPREAD counts or more
uint8_t noise_health(const int16_t *x, unsigned n);
// SHA-256 over a label and the samples, as little-endian octets
void noise_digest(const int16_t *x, unsigned n, uint8_t out[SHA256_LEN]);
// The radio task: checks and hashes a grab, and posts the digest with its credit (0 when it failed, or when the channel
// wasn't quiet: quiet false)
void noise_post(const int16_t *x, unsigned n, bool quiet);
// The UI task: true when a digest was posted since the last call: it is in out, and *credit the bits to credit it
// (0 for a grab that failed its health tests: stirred in all the same, counted for nothing)
bool noise_take(uint8_t out[SHA256_LEN], unsigned *credit);
void noise_get_stats(noise_stats_t *s);

#endif
