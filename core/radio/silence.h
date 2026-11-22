// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * Radio silence (docs/spec/radio-silence.md): while it is on the radio transmits only what its user starts (PTT, a
 * message, a key fill, an emergency), never by itself: no replies, registrations, beacons, probes, repeating or
 * host traffic. The radio core sets it from the saved setting; every automatic source asks radio_silent() before it
 * transmits. One flag, read from any task (a single byte: no lock)
 */
#ifndef RFOUNDRY_RADIO_SILENCE_H
#define RFOUNDRY_RADIO_SILENCE_H

#include <stdbool.h>
#include "config.h"

#if CONFIG_RADIO_SILENCE
extern volatile bool radio_silence_flag;
static inline bool radio_silent(void) { return radio_silence_flag; }
static inline void radio_silence_set(bool on) { radio_silence_flag = on; }
#else
static inline bool radio_silent(void) { return false; }
static inline void radio_silence_set(bool on) { (void)on; }
#endif

#endif
