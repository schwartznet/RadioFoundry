// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// An OTAR net's roster and joining (docs/spec/otar.md 5, 6; phase 2). The roster is the codeplug's (public keys only:
// CODEPLUG_KEY_OTAR_ROSTER + n); this radio's key pair and net are its settings (settings_t.otar_net). Joining is a
// key fill session where both radios use their X25519 key pairs instead of fresh ones and the sender's payload is
// class 3: the net ID and the sender's rank. The roster writes are the housekeeping task's (storage jobs)
#ifndef RFOUNDRY_OTAR_NET_H
#define RFOUNDRY_OTAR_NET_H

#include <stdbool.h>
#include <stdint.h>
#include "support/x25519.h"

#define OTAR_ROSTER_MAX		64u
#define OTAR_REC_LEN		37u	// DMR ID (3), rank (1), flags (1), public key (32)
#define OTAR_RANK_MAX		4u
#define OTAR_M_REVOKED		0x01u	// member flags

#define KF_CLASS_NET		3u	// key fill payload class 3 (key-fill.md 4.3): joining a net
#define OTAR_JOIN_LEN		5u	// class, net ID (2), the sender's rank, flags (0)

typedef struct {
	uint32_t id;
	uint8_t rank;		// 0 member, 1-4 net control
	uint8_t flags;		// OTAR_M_*
	uint8_t pub[X25519_LEN];
} otar_member_t;

// The record of m, and back (false for a record of another length or an ID or rank out of range)
void otar_member_pack(const otar_member_t *m, uint8_t rec[OTAR_REC_LEN]);
bool otar_member_unpack(const uint8_t *rec, int len, otar_member_t *m);

// The roster, in record order: members first .. first + max - 1 into out (max may be 0) and the count into *total,
// from one walk of the codeplug area. Its count
uint16_t otar_roster_window(uint16_t first, otar_member_t *out, uint16_t max, uint16_t *total);
// The member with this DMR ID: true and *m
bool otar_roster_find(uint32_t id, otar_member_t *m);
// Store m: over the record of its DMR ID, else in the first free one. False when the roster is full or the write
// fails. Housekeeping task (a storage job)
bool otar_roster_put(const otar_member_t *m);
// Every member removed (leaving a net). Housekeeping task
bool otar_roster_clear(void);

// The join payload (class 3), and back: false for a payload that isn't one
int otar_join_build(uint16_t net_id, uint8_t rank, uint8_t *out, int cap);
bool otar_join_parse(const uint8_t *p, int len, uint16_t *net_id, uint8_t *rank);

#endif
