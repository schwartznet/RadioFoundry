// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The key PIN's RAM state (keypin.h, docs/spec/key-pin.md 3, 10): unlocked or not, and a copy of "a PIN is set" for
// the host paths (CPS, TFTP, debug link), which run on other tasks than the UI. No dependencies, so every build and test
// that links the codeplug settings area links this too
#include "keypin/keypin.h"
#if CONFIG_KEY_PIN

// One byte each, written whole: a byte store is atomic on every MCU we build for, so a reader on another task sees the
// old value or the new one, never a mix, and needs no lock. volatile: read again at every call
static volatile uint8_t pin_set;	// keypin_note: a PIN is set (the settings store's kp_flags bit 0)
static volatile uint8_t pin_open;	// the right PIN was typed and it hasn't locked again

bool keypin_open(void) { return pin_open != 0; }
void keypin_unlock(void) { pin_open = 1; }
void keypin_lock(void) { pin_open = 0; }
void keypin_note(bool set) { pin_set = set ? 1 : 0; }
bool keypin_guard(void) { return pin_set != 0 && pin_open == 0; }
#endif
