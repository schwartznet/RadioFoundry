// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR key management messages (docs/spec/otar.md 7, phase 3): REKEY, ACK, HELLO and CHANGEOVER, built and checked.
// Pure: no RTOS, no allocation. Every message: a 10-octet header, a body, and the first 8 octets of an AES-256-CMAC
// over the sender's and receiver's DMR IDs (3 + 3) and every octet before it. REKEY, ACK and HELLO go between two
// radios under their pair's MAC key; CHANGEOVER goes to the talkgroup under a key from the next TEK
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

enum { OTAR_REKEY = 1, OTAR_ACK = 2, OTAR_CHANGEOVER = 3, OTAR_HELLO = 4 };

// ACK results (7.2)
enum { OTAR_ACK_STORED = 0, OTAR_ACK_HELD = 1, OTAR_ACK_OLD = 2, OTAR_ACK_STORE_FAILED = 3, OTAR_ACK_WRAP = 4,
       OTAR_ACK_NOT_MANAGED = 5 };

#define OTAR_REKEY_LEN		(OTAR_HDR + 4u + 1u + 1u + 4u + 1u + 40u + OTAR_MAC)	// 69
#define OTAR_ACK_LEN		(OTAR_HDR + 4u + 1u + 1u + 3u + OTAR_MAC)		// 27
#define OTAR_HELLO_LEN		(OTAR_HDR + 1u + 1u + 1u + OTAR_MAC)			// 21
#define OTAR_CHANGEOVER_LEN	(OTAR_HDR + 4u + 1u + OTAR_MAC)				// 23

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
	uint8_t tek[OTAR_KEY_LEN];	// REKEY: unwrapped (wipe it)
	// ACK
	uint8_t result;
	uint8_t kcv[3];
	// HELLO
	uint8_t active_kid, next_kid;
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

// The header of a message (no MAC checked yet): its type, net, message number and rank. False for one that isn't an
// OTAR message of this version, or has another length for its type
bool otar_peek(const uint8_t *msg, int len, otar_msg_t *m);
// Check the MAC under k_mac and parse the body into *m; a REKEY's TEK is unwrapped under ukek (NULL for other
// types). False for a bad MAC, a failed unwrap or a malformed body (then *m holds nothing secret)
bool otar_open(const uint8_t *msg, int len, const otar_addr_t *a, const uint8_t *ukek,
	       const uint8_t k_mac[OTAR_KEY_LEN], otar_msg_t *m);

// The MAC key a CHANGEOVER uses: from the TEK it makes active (otar.md 7.3)
void otar_group_mac_key(const uint8_t tek[OTAR_KEY_LEN], uint8_t k_mac[OTAR_KEY_LEN]);

#endif
