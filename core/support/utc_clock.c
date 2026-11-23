// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The radio's UTC clock: see utc_clock.h
#include "support/utc_clock.h"
#include "hal_rtc.h"

// A board without a backed real-time clock (board.toml clock rtc) holds nothing: its own hal_rtc_* replace these
__attribute__((weak)) bool hal_rtc_get(int64_t *unix_s)
{
	(void)unix_s;
	return false;
}

__attribute__((weak)) bool hal_rtc_set(int64_t unix_s)
{
	(void)unix_s;
	return false;
}

// Written by one task. A reader may see a half-written pair across a set; the set moves the time by little (a GPS
// fix every minute), and the sequence count makes a reader that raced it try once more
static volatile uint32_t seq;
static volatile int64_t base_s;
static volatile uint32_t base_ms;
static volatile uint8_t source;

void utc_clock_set(int64_t unix_s, uint32_t now_ms, uint8_t src)
{
	seq++;
	base_s = unix_s;
	base_ms = now_ms;
	source = src;
	seq++;
}

bool utc_clock_now(uint32_t now_ms, int64_t *unix_s, uint8_t *src)
{
	for (int tries = 0; tries < 3; tries++) {
		uint32_t s0 = seq;
		uint8_t from = source;
		int64_t b = base_s;
		uint32_t ms = base_ms;
		if (s0 != seq || (s0 & 1u))
			continue;
		if (from == UTC_SRC_NONE)
			return false;
		*unix_s = b + (int64_t)((uint32_t)(now_ms - ms) / 1000u);
		if (src != 0)
			*src = from;
		return true;
	}
	return false;
}

void utc_clock_clear(void)
{
	seq++;
	source = UTC_SRC_NONE;
	seq++;
}
