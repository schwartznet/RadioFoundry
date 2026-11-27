// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR key management messages (docs/spec/otar.md 7): REKEY, ACK, HELLO, CHANGEOVER, INVENTORY, ROSTER, TIME,
// ZEROIZE, LOCATE and POSITION, built and checked.
// Pure: no RTOS, no allocation. Every message: a 10-octet header in the clear, a body encrypted with AES-256-CTR under
// a key from the MAC key, and the first 8 octets of an AES-256-CMAC over the sender's and receiver's DMR IDs (3 + 3)
// and every octet before it (encrypt then MAC, otar.md 7). REKEY, ACK and HELLO go between two radios under their
// pair's MAC key, TIME too; CHANGEOVER goes to the talkgroup under a key from a TEK (7.3). The messages protect
// themselves: they go in the clear at the data layer (dmr-data.md 13.5)
#ifndef RFOUNDRY_OTAR_MSG_H
#define RFOUNDRY_OTAR_MSG_H

#include <stdbool.h>
#include <stdint.h>
#include "otar/otar_crypto.h"
#include "otar/otar_keys.h"

#define OTAR_PORT		4103u	// UDP source and destination port
// 4: ACK echoes its request's number; 3: HELLO keysets, TIME per member; 2: body encrypted. ACK results 8-10 came
// later without a new version: a version 4 radio ignores an ACK it doesn't wait for, and counts one it waits for with
// CKR 0 and another result as a roster entry not stored, so a net part-way through an update keeps working (otar.md 7.2).
// LOCATE and POSITION (types 10, 11) came the same way: a version 4 radio from before drops a type it doesn't know
// (otar_peek), so a net control asking one sees "no answer" (otar.md 7.7). NETCHAN (12) the same (7.8)
#define OTAR_VERSION		4u
#define OTAR_ENC_LABEL		"RFOTAR2 enc"	// HKDF info of the body's key
#define OTAR_HDR		10u
#define OTAR_MAC		8u
#define OTAR_MSG_MAX		72u

enum { OTAR_REKEY = 1, OTAR_ACK = 2, OTAR_CHANGEOVER = 3, OTAR_HELLO = 4, OTAR_INVENTORY = 5, OTAR_ROSTER = 6,
       OTAR_TIME = 7, OTAR_ZEROIZE = 8, OTAR_LOCATE = 10, OTAR_POSITION = 11, OTAR_NETCHAN = 12 };	// 9: TAKEOVER, reserved (otar.md 22)

// POSITION results (7.7)
enum { OTAR_POS_OK = 0, OTAR_POS_NO_FIX = 1, OTAR_POS_REFUSED = 2 };
#define OTAR_ALT_NONE	INT16_MIN	// POSITION: altitude not known (0x8000)

// REKEY flags (7.1)
#define OTAR_RK_CLOCK	0x01u	// change over at the changeover time by the member's clock
#define OTAR_RK_NOW	0x02u	// the net's active key: change over to it once stored (a member that missed it, 9)

// ACK results (7.2). WIPED: a ZEROIZE taken, the keys wiped once this ACK has gone (7.5). CURRENT: a net control's
// answer to a HELLO when it has nothing to send the member, keyset its own active one (9; NOT_MANAGED when it manages
// no keys). MSGNUM: a message whose MAC checked but whose number isn't above the last one taken from its sender, which
// keyset carries (7.6); sent at most once per few minutes per sender. All three with CKR 0
enum { OTAR_ACK_STORED = 0, OTAR_ACK_HELD = 1, OTAR_ACK_OLD = 2, OTAR_ACK_STORE_FAILED = 3, OTAR_ACK_WRAP = 4,
       OTAR_ACK_NOT_MANAGED = 5, OTAR_ACK_REFUSED = 6, OTAR_ACK_ASKED = 7, OTAR_ACK_WIPED = 8, OTAR_ACK_CURRENT = 9,
       OTAR_ACK_MSGNUM = 10 };

#define OTAR_REKEY_LEN		(OTAR_HDR + 4u + 1u + 1u + 4u + 1u + 40u + OTAR_MAC)	// 69
#define OTAR_ACK_LEN		(OTAR_HDR + 4u + 1u + 1u + 3u + 4u + OTAR_MAC)		// 31
#define OTAR_HELLO_LEN		(OTAR_HDR + 4u + 4u + 1u + OTAR_MAC)			// 27
#define OTAR_CHANGEOVER_LEN	(OTAR_HDR + 4u + 1u + OTAR_MAC)				// 23
#define OTAR_ROSTER_REC		37u	// a roster record (otar_net.h OTAR_REC_LEN): DMR ID, rank, flags, public key
#define OTAR_ROSTER_LEN		(OTAR_HDR + OTAR_ROSTER_REC + OTAR_MAC)			// 55
#define OTAR_ZEROIZE_LEN	(OTAR_HDR + 3u + OTAR_MAC)				// 21
#define OTAR_INVENTORY_LEN	(OTAR_HDR + OTAR_MAC)					// 18
#define OTAR_TIME_LEN		(OTAR_HDR + 4u + OTAR_MAC)				// 22
#define OTAR_LOCATE_LEN		(OTAR_HDR + OTAR_MAC)					// 18
#define OTAR_POSITION_LEN	(OTAR_HDR + 4u + 1u + 4u + 4u + 2u + 2u + OTAR_MAC)	// 35
#define OTAR_NETCHAN_LEN	(OTAR_HDR + 4u + 4u + 1u + OTAR_CHAN_NAME + OTAR_MAC)	// 43

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
	uint8_t flags;		// REKEY: OTAR_RK_*; HELLO: bit 0 a next key is held
	union {
		uint8_t tek[OTAR_KEY_LEN];	// REKEY: unwrapped (wipe it)
		uint8_t rec[OTAR_ROSTER_REC];	// ROSTER: the entry, as the roster stores it
		otar_chan_t chan;		// NETCHAN: the net's channel (rx_hz 0: none)
	};
	// ACK (of a ROSTER: CKR 0, keyset 0, the check value the entry's fingerprint)
	uint8_t result;
	uint8_t kcv[3];
	uint32_t echo;		// the message number of the message it answers (7.2)
	// HELLO: the active keyset's number in keyset, the next one's here (0 none)
	uint32_t next_keyset;
	// ZEROIZE: the DMR ID of the radio told to wipe its keys
	uint32_t target;
	// TIME: UTC seconds since 2026-01-01
	uint32_t time_s;
	// POSITION (result OTAR_POS_* in result, the LOCATE's number in echo): 1e-7 degree, meters (OTAR_ALT_NONE), and
	// the fix's age in seconds (at most 65535)
	int32_t lat, lon;
	int16_t alt_m;
	uint16_t age_s;
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
// TIME (otar.md 7.4): a net control's UTC to one member, under the pair's MAC key (a group key would let any radio
// holding the traffic key forge it)
int otar_time_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// LOCATE (otar.md 7.7): a net control asks one member where it is, under the pair's MAC key; no body
int otar_locate_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// POSITION (otar.md 7.7): the member's answer to that net control, under the pair's keys, its body encrypted
int otar_position_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);
// NETCHAN (otar.md 7.8): a net control tells a member the net's channel, under the pair's keys, its body encrypted
int otar_netchan_build(uint8_t *out, const otar_addr_t *a, const uint8_t k_mac[OTAR_KEY_LEN], const otar_msg_t *m);

// The header of a message (no MAC checked yet): its type, net, message number and rank. False for one that isn't an
// OTAR message of this version, or has another length for its type
bool otar_peek(const uint8_t *msg, int len, otar_msg_t *m);
// Check the MAC under k_mac and parse the body into *m; a REKEY's TEK is unwrapped under ukek (NULL for other
// types). False for a bad MAC, a failed unwrap or a malformed body (then *m holds nothing secret)
bool otar_open(const uint8_t *msg, int len, const otar_addr_t *a, const uint8_t *ukek,
	       const uint8_t k_mac[OTAR_KEY_LEN], otar_msg_t *m);

// A group message's MAC key from a TEK (otar.md 7.3): label OTAR_GK_CO for CHANGEOVER (the TEK it makes active)
#define OTAR_GK_CO	"co"
void otar_group_mac_key(const uint8_t tek[OTAR_KEY_LEN], const char *label, uint8_t k_mac[OTAR_KEY_LEN]);

#endif
