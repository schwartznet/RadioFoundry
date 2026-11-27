// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR's transport (docs/spec/otar.md 7): key management messages as UDP datagrams on port 4103 over the DMR data
// service, through the air queue. Individual messages (REKEY, ACK, HELLO) go confirmed, CHANGEOVER to the talkgroup.
// Received ones are held (a few) for the UI task while a net is open. otar/otar_svc.c
#ifndef RFOUNDRY_OTAR_API_H
#define RFOUNDRY_OTAR_API_H

#include <stdbool.h>
#include <stdint.h>
#include "otar/otar_msg.h"

#define OTAR_SEND_WAIT_MS	10000	// a message the data service doesn't take by then fails
#define OTAR_HELD		4	// messages held for the UI task

typedef enum { OTAR_SEND_IDLE, OTAR_SEND_SENDING, OTAR_SEND_SENT, OTAR_SEND_FAILED } otar_send_state_t;

// A net control's ACKs from members (on_member), by what came of them: the debug link's otar.ack_* (otar.md 12)
typedef enum { OTAR_AN_IN, OTAR_AN_UNWANTED, OTAR_AN_NO_PAIR, OTAR_AN_BAD_MAC, OTAR_AN_NO_MATCH, OTAR_AN_COUNTED,
	       OTAR_AN_COUNT } otar_ack_note_t;

typedef struct {
	uint32_t rx, rx_closed, rx_full, sent, send_failed;
	uint16_t ack[OTAR_AN_COUNT];
	uint8_t ack_last_result;	// the last counted ACK's result (0xFF: none yet)
} otar_svc_stats_t;

// The UI task notes an ACK (otar_ack_note_t); result is the ACK's own, for OTAR_AN_COUNTED
void otar_note_ack(otar_ack_note_t what, uint8_t result);

void otar_svc_init(void);
// While open, received messages are held for the UI task; closed, every one is dropped and the queue cleared
void otar_svc_open(bool open);
// The oldest message held: its length (0: none), its source, its destination and whether that is a talkgroup
int otar_take(uint8_t out[OTAR_MSG_MAX], uint32_t *src, uint32_t *dst, bool *group);
// Send one message to dst (a radio's ID, confirmed; or a talkgroup, unconfirmed). False when one is still sending
bool otar_send(uint32_t dst, bool group, const uint8_t *msg, int len);
otar_send_state_t otar_send_state(void);
void otar_get_stats(otar_svc_stats_t *out);

#endif
