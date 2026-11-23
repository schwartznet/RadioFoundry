// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The ui_svc.h calls for Net keys (docs/spec/otar.md 8): what the screen checks in the codeplug before it asks the
// radio task for a change
#include "config.h"

#if CONFIG_OTAR
#include "ui_svc.h"
#include "codeplug/codeplug.h"
#include "codeplug/codeplug_records.h"
#include "dmr/dmrAes.h"

bool ui_svc_aes_key_there(uint8_t system, uint8_t kid)
{
	uint8_t k[DMR_AES_KEY_BYTES];
	bool there = codeplug_traffic_key(system, DMR_AES_ALG_AES256, kid, k, sizeof k) == (int)sizeof k;
	dmrAesWipe(k, sizeof k);
	return there;
}
#endif
