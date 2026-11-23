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

typedef struct {
	uint32_t rx, rx_closed, rx_full, sent, send_failed;
} otar_svc_stats_t;

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
