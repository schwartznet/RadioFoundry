// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The board's real-time clock (docs/spec/otar.md 7.4): UTC kept through power-off on a board whose board.toml says
// clock rtc = "backed". Radio task only. A board without one links the defaults (support/utc_clock.c), which hold
// nothing
#ifndef HAL_RTC_H
#define HAL_RTC_H

#include <stdbool.h>
#include <stdint.h>

// UTC seconds now: false when the board has no clock, it holds no valid time, or it can't be read
bool hal_rtc_get(int64_t *unix_s);
// Set it: false when the board has none or the write failed
bool hal_rtc_set(int64_t unix_s);

#endif
