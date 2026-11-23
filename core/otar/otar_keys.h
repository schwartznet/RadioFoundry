// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR keysets (docs/spec/otar.md 8): which key IDs a managed system's channels use, the next keyset waiting for its
// changeover and the previous one kept through the overlap. Pure: no RTOS, no flash, no radio mode. The keys
// themselves stay traffic key records of the system; a keyset names them by key ID, one per common key reference
// (CKR 1..OTAR_CKRS). Held in the settings record (settings_t.otar), so it is the radio's own, not the shared codeplug's
#ifndef RFOUNDRY_OTAR_KEYS_H
#define RFOUNDRY_OTAR_KEYS_H

#include <stdbool.h>
#include <stdint.h>

#define OTAR_CKRS		4u
#define OTAR_GRACE_MS		(30u * 60u * 1000u)	// the previous keyset kept after a changeover (8)
// UTC minutes count from 2026-01-01 00:00 UTC (otar.md 7.1); 0 = "by hand only"
#define OTAR_EPOCH_UNIX		1767225600LL

// flags
#define OTAR_F_NEXT		0x01u	// a next keyset is held
#define OTAR_F_PREV		0x02u	// the previous keyset is held (until the overlap ends, or the next start)
#define OTAR_F_OWN_CLOCK	0x04u	// the next keyset may become active by this radio's clock at changeover

enum { OTAR_ACTIVE, OTAR_NEXT, OTAR_PREV };

typedef struct {
	uint32_t changeover;		// UTC minutes the next keyset becomes active; 0: by hand (or net control) only
	uint16_t ks_active;		// keyset numbers: only go up; 0 = none
	uint16_t ks_next;
	uint8_t system;			// the managed system + 1; 0 = OTAR off
	uint8_t flags;			// OTAR_F_*
	uint8_t mask;			// CKRs held: bits 0-3 the active keyset's, bits 4-7 the next one's
	uint8_t prev_mask;		// bits 0-3 the previous keyset's
	uint8_t kid_active[OTAR_CKRS];
	uint8_t kid_next[OTAR_CKRS];
	uint8_t kid_prev[OTAR_CKRS];
} otar_keys_t;

// This radio's place in a net (otar.md 5, 6; phase 2): the net, its rank (0 member, 1-4 net control) and its X25519
// private key. In the settings record, never the codeplug (which is shared) or a file; the emergency wipe clears it
#define OTAR_NET_IN		0x01u	// flags: in a net
typedef struct {
	uint16_t net_id;
	uint8_t rank;
	uint8_t flags;
	uint8_t priv[32];		// all zeros: no key pair yet
} otar_net_t;

static inline bool otar_on(const otar_keys_t *k) { return k->system != 0; }
static inline uint8_t otar_system(const otar_keys_t *k) { return (uint8_t)(k->system - 1u); }

// The key ID for CKR ckr (1..OTAR_CKRS) in keyset which (OTAR_*): false when that keyset doesn't hold it
bool otar_kid(const otar_keys_t *k, uint8_t which, uint8_t ckr, uint8_t *kid);
// A channel's CKR from its key reference (aes_ref): 1..OTAR_CKRS as it is, anything else CKR 1
uint8_t otar_ckr(uint16_t aes_ref);
// Manage system (0..254) with kid as CKR 1's active key: keyset 1, nothing next or previous
void otar_start(otar_keys_t *k, uint8_t system, uint8_t kid);
void otar_stop(otar_keys_t *k);
// Hold kid as CKR ckr's key in the next keyset (opened as active + 1 if none is held), changing over at UTC minute
// changeover (0: by hand), by this radio's clock when own_clock. False: OTAR off or a bad CKR
bool otar_set_next(otar_keys_t *k, uint8_t ckr, uint8_t kid, uint32_t changeover, bool own_clock);
// Drop the next keyset
void otar_clear_next(otar_keys_t *k);
// Whether the next keyset is due now by this radio's clock (clock_ok: now_min is a real UTC minute)
bool otar_due(const otar_keys_t *k, bool clock_ok, uint32_t now_min);
// The next keyset becomes the active one; the active one becomes the previous one (replacing an older previous).
// False when there is no next keyset
bool otar_change_over(otar_keys_t *k);
// The previous keyset dropped. Its key IDs that neither the active nor the next keyset uses go into out (one per CKR,
// in CKR order): their count. Those keys can be erased
uint8_t otar_drop_prev(otar_keys_t *k, uint8_t out[OTAR_CKRS]);
// UTC seconds since 1970 as OTAR minutes (0 before 2026, or when the clock isn't set)
uint32_t otar_minutes(int64_t unix_s);
// OTAR minutes as a UTC date and time (year 2026..), and back: 0 when the date isn't a real one from 2026 to 2099
void otar_civil(uint32_t min, uint16_t *year, uint8_t *month, uint8_t *day, uint8_t *hour, uint8_t *minute);
uint32_t otar_from_civil(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute);

#endif
