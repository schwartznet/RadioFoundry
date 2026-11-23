// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The radio's UTC clock (docs/spec/otar.md 7.4): a time from a source, carried forward on the millisecond clock. RAM
// only: after a restart it waits for its next source. One writer (the radio task); readers on any task take a copy
#ifndef RFOUNDRY_UTC_CLOCK_H
#define RFOUNDRY_UTC_CLOCK_H

#include <stdbool.h>
#include <stdint.h>

enum { UTC_SRC_NONE, UTC_SRC_GPS, UTC_SRC_HAND };

// The time is unix_s at millisecond now_ms, from src
void utc_clock_set(int64_t unix_s, uint32_t now_ms, uint8_t src);
// UTC seconds now; false (and *unix_s untouched) when no source set it since the start. *src may be NULL
bool utc_clock_now(uint32_t now_ms, int64_t *unix_s, uint8_t *src);
// Forget the time (a test, or the emergency wipe's restart)
void utc_clock_clear(void);

#endif
