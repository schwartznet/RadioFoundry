// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The key PIN for the UI (ui_svc.h, docs/spec/key-pin.md): core/keypin on the UI task's clock
#include "config.h"
#if CONFIG_KEY_PIN
#include "ui/ui_svc.h"
#include "hal_time.h"
#include "keypin/keypin.h"

bool ui_svc_keypin_is_set(void)
{
	return keypin_is_set();
}

bool ui_svc_keypin_set(const char *pin, uint8_t len)
{
	return keypin_set(pin, len);
}

void ui_svc_keypin_clear(void)
{
	keypin_clear();
}

uint8_t ui_svc_keypin_try(const char *pin, uint8_t len, uint32_t *wait_ms)
{
	uint32_t now = hal_millis();
	keypin_result_t r = keypin_try(pin, len, now);
	*wait_ms = keypin_wait_ms(now);
	return r == KEYPIN_RIGHT ? UI_KP_RIGHT : r == KEYPIN_WAIT ? UI_KP_WAIT : UI_KP_WRONG;
}

uint32_t ui_svc_keypin_wait_ms(void)
{
	return keypin_wait_ms(hal_millis());
}

uint8_t ui_svc_keypin_wrong(void)
{
	return keypin_wrong();
}
#endif
