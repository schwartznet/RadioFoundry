// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR key management messages (docs/spec/otar.md 7): REKEY, ACK, HELLO, CHANGEOVER, INVENTORY, ROSTER, TIME and
// ZEROIZE, built and checked.
// Pure: no RTOS, no allocation. Every message: a 10-octet header, a body, and the first 8 octets of an AES-256-CMAC
// over the sender's and receiver's DMR IDs (3 + 3) and every octet before it. REKEY, ACK and HELLO go between two
// radios under their pair's MAC key; CHANGEOVER and TIME go to the talkgroup under a key from a TEK (7.3)
#ifndef RFOUNDRY_OTAR_MSG_H
#define RFOUNDRY_OTAR_MSG_H

#include <stdbool.h>
#include <stdint.h>
#include "otar/otar_crypto.h"

#define OTAR_PORT		4103u	// UDP source and destination port
#define OTAR_VERSION		1u
#define OTAR_HDR		10u
#define OTAR_MAC		8u
#define OTAR_MSG_MAX		72u

enum { OTAR_REKEY = 1, OTAR_ACK = 2, OTAR_CHANGEOVER = 3, OTAR_HELLO = 4, OTAR_INVENTORY = 5, OTAR_ROSTER = 6,
       OTAR_TIME = 7, OTAR_ZEROIZE = 8 };

// ACK results (7.2)
enum { OTAR_ACK_STORED = 0, OTAR_ACK_HELD = 1, OTAR_ACK_OLD = 2, OTAR_ACK_STORE_FAILED = 3, OTAR_ACK_WRAP = 4,
       OTAR_ACK_NOT_MANAGED = 5, OTAR_ACK_REFUSED = 6, OTAR_ACK_ASKED = 7 };

#define OTAR_REKEY_LEN		(OTAR_HDR + 4u + 1u + 1u + 4u + 1u + 40u + OTAR_MAC)	// 69
#define OTAR_ACK_LEN		(OTAR_HDR + 4u + 1u + 1u + 3u + OTAR_MAC)		// 27
#define OTAR_HELLO_LEN		(OTAR_HDR + 1u + 1u + 1u + OTAR_MAC)			// 21
#define OTAR_CHANGEOVER_LEN	(OTAR_HDR + 4u + 1u + OTAR_MAC)				// 23
#define OTAR_ROSTER_REC		37u	// a roster record (otar_net.h OTAR_REC_LEN): DMR ID, rank, flags, public key
#define OTAR_ROSTER_LEN		(OTAR_HDR + OTAR_ROSTER_REC + OTAR_MAC)			// 55
#define OTAR_ZEROIZE_LEN	(OTAR_HDR + 3u + OTAR_MAC)				// 21
#define OTAR_INVENTORY_LEN	(OTAR_HDR + OTAR_MAC)					// 18
#define OTAR_TIME_LEN		(OTAR_HDR + 4u + OTAR_MAC)				// 22

typedef struct {
	uint8_t type;
	uint16_t net_id;
	uint32_t msgnum;
	uint8_t rank;		// the sender's: 0 member, 1-4 net control
	// REKEY, ACK, CHANGEOVER
	uint32_t keyset;
	uint8_t ckr;
	uint8_t kid;
	uint32_t changeover;	// REKEY: UTC minutes since 2026-01-01, 0 by hand
	uint8_t flags;		// REKEY: bit 0 change over by the member's clock; HELLO: bit 0 a next key is held
	union {
		uint8_t tek[OTAR_KEY_LEN];	// REKEY: unwrapped (wipe it)
		uint8_t rec[OTAR_ROSTER_REC];	// ROSTER: the entry, as the roster stores it
	};
	// ACK (of a ROSTER: CKR 0, keyset 0, the check value the entry's fingerprint)
	uint8_t result;
	uint8_t kcv[3];
	// HELLO
	uint8_t active_kid, next_kid;
	// ZEROIZE: the DMR ID of the radio told to wipe its keys
	uint32_t target;
	// TIME: UTC seconds since 2026-01-01
	uint32_t time_s;
} otar_msg_t;

// The addresses a MAC covers: the sender's DMR ID and the receiver's (a radio's, or the talkgroup's)
typedef struct {
	uint32_t src, dst;
} otar_addr_t;

int otar_rekey_build(uint8_t *out, const otar_addr_t *a, const uint8_t ukek[OTAR_KEY_LEN],
		     const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
int otar_ack_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
int otar_hello_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
int otar_changeover_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// ROSTER (otar.md 7.5): a net control to a member, one roster entry under the pair's MAC key
int otar_roster_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// ZEROIZE (otar.md 7.5): a net control tells one member to wipe its keys, under the pair's MAC key
int otar_zeroize_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// INVENTORY (otar.md 7, 9): a net control asks a member what it holds; no body. The member answers an ACK per keyset
int otar_inventory_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// TIME (otar.md 7.4): a net control's UTC to the talkgroup, under the active TEK's group key "time"
int otar_time_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);

// The header of a message (no MAC checked yet): its type, net, message number and rank. False for one that isn't an
// OTAR message of this version, or has another length for its type
bool otar_peek(const uint8_t *msg, int len, otar_msg_t *m);
// Check the MAC under k_mac and parse the body into *m; a REKEY's TEK is unwrapped under ukek (NULL for other
// types). False for a bad MAC, a failed unwrap or a malformed body (then *m holds nothing secret)
bool otar_open(const uint8_t *msg, int len, const otar_addr_t *a, const uint8_t *ukek,
	       const uint8_t k_mac[OTAR_KEY_LEN], otar_msg_t *m);

// A group message's MAC key from a TEK (otar.md 7.3): label OTAR_GK_CO for CHANGEOVER (the TEK it makes active),
// OTAR_GK_TIME for TIME (the active TEK)
#define OTAR_GK_CO	"co"
#define OTAR_GK_TIME	"time"
void otar_group_mac_key(const uint8_t tek[OTAR_KEY_LEN], const char *label, uint8_t k_mac[OTAR_KEY_LEN]);

#endif
