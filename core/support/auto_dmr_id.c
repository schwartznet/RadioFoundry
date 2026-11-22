// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// Auto DMR ID (auto_dmr_id.h, docs/spec/auto-dmr-id.md)
#include "config.h"
#if CONFIG_AUTO_DMR_ID
#include <string.h>
#include "support/auto_dmr_id.h"
#include "support/sha256.h"
#include "board.h"

uint32_t auto_dmr_id(const uint8_t uid[AUTO_DMR_ID_UID_LEN], uint8_t k, uint32_t base, uint32_t span)
{
	if (span == 0) {
		return 0;
	}
	sha256_t s;
	uint8_t h[SHA256_LEN];
	sha256_init(&s);
	sha256_update(&s, uid, AUTO_DMR_ID_UID_LEN);
	if (k != 0) {
		sha256_update(&s, &k, 1);
	}
	sha256_final(&s, h);
	uint32_t v = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
	return base + v % span;
}

#ifndef AUTO_DMR_ID_NO_BOARD
bool auto_dmr_id_uid(uint8_t uid[AUTO_DMR_ID_UID_LEN])
{
	hal_chip_t c;
	memset(&c, 0, sizeof c);
	if (board.system == NULL || board.system->chip == NULL || !board.system->chip(&c)) {
		return false;
	}
	if (c.uid[0] == 0 && c.uid[1] == 0 && c.uid[2] == 0) {
		return false;	// no ID read
	}
	for (int w = 0; w < 3; w++) {
		uint32_t x = c.uid[2 - w];	// the high word first, as INFO_CHIP prints it
		uid[4 * w] = (uint8_t)(x >> 24);
		uid[4 * w + 1] = (uint8_t)(x >> 16);
		uid[4 * w + 2] = (uint8_t)(x >> 8);
		uid[4 * w + 3] = (uint8_t)x;
	}
	return true;
}
#endif
#endif
