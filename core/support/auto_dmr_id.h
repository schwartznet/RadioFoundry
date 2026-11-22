// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * Auto DMR ID (docs/spec/auto-dmr-id.md): a DMR ID made from the radio's chip unique ID, so a fleet of radios can each
 * set its own ID without a PC, the same one every time. tools/dmrid_from_uid.py computes the same IDs on a PC
 */
#ifndef RFOUNDRY_AUTO_DMR_ID_H
#define RFOUNDRY_AUTO_DMR_ID_H

#include <stdbool.h>
#include <stdint.h>

#define AUTO_DMR_ID_UID_LEN	12u	// the 96-bit UID as the debug link's INFO_CHIP prints it: uid[2], uid[1], uid[0], each big endian

// The ID of candidate k (0..255) for this UID: base + (the first 4 octets of SHA-256(uid) as a big-endian number)
// % span for k 0, and of SHA-256(uid || k) for k 1 and up. 0 when span is 0
uint32_t auto_dmr_id(const uint8_t uid[AUTO_DMR_ID_UID_LEN], uint8_t k, uint32_t base, uint32_t span);

// This radio's UID in that octet order: false where the board can't read one (no board.system or chip hook)
bool auto_dmr_id_uid(uint8_t uid[AUTO_DMR_ID_UID_LEN]);

#endif
