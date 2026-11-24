// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// OTAR on the data service: the UDP port, the air queue, the messages held for the UI task (otar/otar_api.h)
#include "config.h"
#if CONFIG_OTAR	// the whole file
#include <string.h>
#include "otar/otar_api.h"
#include "dmr/dmrAirQueue.h"
#include "dmr/dmrDataService.h"
#include "dmr/dmrData.h"

// OTAR goes in the clear on an AES channel (dmrDataUdpClear): its messages are encrypted and MACed themselves
_Static_assert(OTAR_PORT == DMR_UDP_PORT_OTAR, "OTAR's port is the data layer's clear one");

#define UDP_HEADER	8

// Written by the radio task (the data service's receive path), read by the UI task, both under the data service's lock
static struct {
	uint8_t len;		// 0: free
	bool group;
	uint32_t src, dst;
	uint8_t msg[OTAR_MSG_MAX];
} held[OTAR_HELD];
static volatile bool open_rx;
static volatile uint8_t send_state = OTAR_SEND_IDLE;
static otar_svc_stats_t stats;

static void send_done(const airqItem_t *item, airqResult_t result)
{
	(void)item;
	if (result == AIRQ_SENT) {
		stats.sent++;
		send_state = OTAR_SEND_SENT;
	} else {
		stats.send_failed++;
		send_state = OTAR_SEND_FAILED;
	}
}

void otar_svc_init(void)
{
	memset(held, 0, sizeof held);
	memset(&stats, 0, sizeof stats);
	open_rx = false;
	send_state = OTAR_SEND_IDLE;
	airqSetDone(AIRQ_OWNER_OTAR, send_done);
}

void otar_svc_open(bool open)
{
	if (open == open_rx)
		return;
	dmrDataServiceLock();
	open_rx = open;
	memset(held, 0, sizeof held);
	dmrDataServiceUnlock();
	if (!open)
		airqCancel(AIRQ_OWNER_OTAR, 0);
}

// The radio task. Not inlined: the frame stays off handlePacket's deepest path (docs/dev/stack-check.md)
__attribute__((noinline)) void dmrDataServiceOtarRx(uint32_t src, uint32_t dst, bool group, const uint8_t *payload,
						    int length)
{
	stats.rx++;
	if (!open_rx) {
		stats.rx_closed++;
		return;
	}
	if (length < (int)OTAR_HDR || length > (int)OTAR_MSG_MAX)
		return;
	dmrDataServiceLock();
	int slot = -1;
	for (int i = 0; i < OTAR_HELD && slot < 0; i++)
		if (held[i].len == 0)
			slot = i;
	if (slot >= 0) {
		memcpy(held[slot].msg, payload, (size_t)length);
		held[slot].src = src;
		held[slot].dst = dst;
		held[slot].group = group;
		held[slot].len = (uint8_t)length;
	}
	dmrDataServiceUnlock();
	if (slot < 0)
		stats.rx_full++;
}

int otar_take(uint8_t out[OTAR_MSG_MAX], uint32_t *src, uint32_t *dst, bool *group)
{
	dmrDataServiceLock();
	int n = 0;
	for (int i = 0; i < OTAR_HELD && n == 0; i++) {
		if (held[i].len != 0) {
			n = held[i].len;
			memcpy(out, held[i].msg, (size_t)n);
			*src = held[i].src;
			*dst = held[i].dst;
			*group = held[i].group;
			memset(&held[i], 0, sizeof held[i]);
		}
	}
	dmrDataServiceUnlock();
	return n;
}

bool otar_send(uint32_t dst, bool group, const uint8_t *msg, int len)
{
	if (dst == 0 || dst > 0xFFFFFFu || len < 1 || len > (int)OTAR_MSG_MAX || send_state == OTAR_SEND_SENDING)
		return false;
	uint8_t udp[UDP_HEADER];
	int n = UDP_HEADER + len;
	udp[0] = (uint8_t)(OTAR_PORT >> 8);
	udp[1] = (uint8_t)OTAR_PORT;
	udp[2] = (uint8_t)(OTAR_PORT >> 8);
	udp[3] = (uint8_t)OTAR_PORT;
	udp[4] = (uint8_t)(n >> 8);
	udp[5] = (uint8_t)n;
	udp[6] = 0;
	udp[7] = 0;
	airqItem_t it = { .kind = AIRQ_IP, .owner = AIRQ_OWNER_OTAR, .protocol = DMR_IP_PROTO_UDP,
			  .delivery = group ? DMR_IPS_UNCONFIRMED : DMR_IPS_CONFIRMED, .dst = dst, .group = group,
			  .waitMs = OTAR_SEND_WAIT_MS, .data = udp, .length = UDP_HEADER, .tail = msg,
			  .tailLength = (uint16_t)len };
	send_state = OTAR_SEND_SENDING;
	if (!airqPut(&it)) {
		send_state = OTAR_SEND_FAILED;
		return false;
	}
	return true;
}

otar_send_state_t otar_send_state(void)
{
	return (otar_send_state_t)send_state;
}

void otar_get_stats(otar_svc_stats_t *out)
{
	*out = stats;
}

#endif	// CONFIG_OTAR
