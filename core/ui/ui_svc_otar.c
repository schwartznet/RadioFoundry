// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The ui_svc.h calls for Net keys (docs/spec/otar.md 8): what the screen checks in the codeplug before it asks the
// radio task for a change
#include "config.h"

#if CONFIG_OTAR
#include <string.h>
#include "ui_svc.h"
#include "codeplug/codeplug.h"
#include "codeplug/codeplug_kv.h"
#include "codeplug/codeplug_records.h"
#include "dmr/dmrAes.h"
#include "otar/otar_crypto.h"
#include "otar/otar_net.h"
#include "settings/settings.h"
#include "storage/storage.h"
#include "support/entropy.h"
#include "support/hkdf.h"
#include "hal_time.h"
#include "FreeRTOS.h"

bool ui_svc_aes_key_there(uint8_t system, uint8_t kid)
{
	uint8_t k[DMR_AES_KEY_BYTES];
	bool there = codeplug_traffic_key(system, DMR_AES_ALG_AES256, kid, k, sizeof k) == (int)sizeof k;
	dmrAesWipe(k, sizeof k);
	return there;
}

// ---- The Net screen (otar.md 5, 6) ----
static struct {
	bool fp_ok;
	uint8_t fp[3];
	uint8_t fp_of[8];		// the first octets of the private key the fingerprint is of
	bool starting;
	uint32_t own;
	// The roster's writes waiting for the housekeeping task (net_job: 1 put member, 2 clear)
	bool want_clear, want_put;
	uint8_t job;
	volatile bool job_running;
	otar_member_t member;
	// A page of the roster for the Members screen, kept until the codeplug changes or a second passes
	bool page_ok;
	uint8_t page_serial;
	uint32_t page_at;
	uint16_t page_first, page_n, page_total;
	otar_member_t page[6];
} net;

static void net_read(otar_net_t *n)
{
	settings_t *st = settings_begin();
	*n = st->otar_net;
	settings_end(0);
}

static bool has_key(const otar_net_t *n)
{
	static const uint8_t zero[X25519_LEN];
	return !crypto_equal(n->priv, zero, X25519_LEN);
}

// The fingerprint of this radio's public key, worked out once per key (X25519 takes a moment)
static void fingerprint(const otar_net_t *n)
{
	if (net.fp_ok && memcmp(net.fp_of, n->priv, sizeof net.fp_of) == 0)
		return;
	x25519_ws_t *ws = pvPortMalloc(sizeof *ws);
	if (ws == NULL)
		return;
	uint8_t pub[X25519_LEN];
	x25519_public(pub, n->priv, ws);
	vPortFree(ws);
	otar_fingerprint(pub, net.fp);
	memcpy(net.fp_of, n->priv, sizeof net.fp_of);
	net.fp_ok = true;
}

void ui_svc_net_view(ui_net_view_t *v)
{
	otar_net_t n;
	memset(v, 0, sizeof *v);
	net_read(&n);
	v->in_net = (n.flags & OTAR_NET_IN) != 0;
	v->net_id = n.net_id;
	v->rank = n.rank;
	v->has_key = has_key(&n);
	if (v->has_key) {
		fingerprint(&n);
		memcpy(v->fp, net.fp, 3);
	}
	v->starting = net.starting;
	unsigned bits = entropy_bits();
	v->presses = net.starting && bits < ENTROPY_FULL ?
		(uint8_t)((ENTROPY_FULL - bits + ENTROPY_KEY_BITS - 1u) / ENTROPY_KEY_BITS) : 0;
	crypto_wipe(&n, sizeof n);
}

void ui_svc_net_start(uint32_t own)
{
	if (own == 0 || own > CODEPLUG_DMR_ID_MAX)
		return;
	net.starting = true;
	net.own = own;
}

void ui_svc_net_cancel_start(void)
{
	net.starting = false;
}

void ui_svc_net_leave(void)
{
	settings_t *st = settings_begin();
	st->otar_net.net_id = 0;
	st->otar_net.rank = 0;
	st->otar_net.flags = 0;
	settings_end(hal_millis());
	net.want_clear = true;
	net.page_ok = false;
}

static void net_job(void *ctx)
{
	(void)ctx;
	if (net.job == 1)
		(void)otar_roster_put(&net.member);
	else if (net.job == 2)
		(void)otar_roster_clear();
	net.job = 0;
	net.job_running = false;
}

// The pool full: the key pair (when there is none), a net ID, rank 1, and this radio first in the roster
static void start_now(uint32_t now)
{
	uint8_t rnd[X25519_LEN + 2];
	entropy_take(rnd, sizeof rnd);
	settings_t *st = settings_begin();
	if (!has_key(&st->otar_net))
		memcpy(st->otar_net.priv, rnd, X25519_LEN);
	uint16_t id = (uint16_t)((rnd[X25519_LEN] << 8) | rnd[X25519_LEN + 1]);
	st->otar_net.net_id = id != 0 ? id : 1u;
	st->otar_net.rank = 1;
	st->otar_net.flags = OTAR_NET_IN;
	otar_net_t n = st->otar_net;
	settings_end(now);
	crypto_wipe(rnd, sizeof rnd);
	x25519_ws_t *ws = pvPortMalloc(sizeof *ws);
	if (ws != NULL) {
		memset(&net.member, 0, sizeof net.member);
		net.member.id = net.own;
		net.member.rank = 1;
		x25519_public(net.member.pub, n.priv, ws);
		vPortFree(ws);
		net.want_clear = true;	// a roster from an earlier net goes first
		net.want_put = true;
	}
	crypto_wipe(&n, sizeof n);
	net.starting = false;
	net.page_ok = false;
}

bool ui_svc_net_tick(uint32_t now)
{
	bool changed = false;
	if (net.starting && entropy_bits() >= ENTROPY_FULL) {
		start_now(now);
		changed = true;
	}
	// The roster's writes, one storage job at a time: a clear first, then a put
	if (!net.job_running) {
		uint8_t next = net.want_clear ? 2u : net.want_put ? 1u : 0u;
		if (next != 0) {
			net.job = next;
			net.job_running = true;
			if (!storage_job_post(net_job, NULL)) {
				net.job_running = false;	// another job runs: the next tick tries again
			} else if (next == 2u) {
				net.want_clear = false;
			} else {
				net.want_put = false;
			}
		}
	}
	return changed;
}

static bool page_fresh(void)
{
	return net.page_ok && net.page_serial == codeplug_kv_serial() && (uint32_t)(hal_millis() - net.page_at) < 1000u;
}

static void page_fill(uint16_t first)
{
	net.page_first = first;
	net.page_n = otar_roster_window(first, net.page, sizeof net.page / sizeof net.page[0], &net.page_total);
	net.page_serial = codeplug_kv_serial();
	net.page_at = hal_millis();
	net.page_ok = true;
}

uint16_t ui_svc_net_members(void)
{
	if (!page_fresh())
		page_fill(net.page_ok ? net.page_first : 0);
	return net.page_total;
}

bool ui_svc_net_member(uint16_t i, uint32_t *id, uint8_t *rank, uint8_t fp[3])
{
	const uint16_t size = sizeof net.page / sizeof net.page[0];
	if (!page_fresh() || i < net.page_first || i >= net.page_first + net.page_n)
		page_fill(i >= size / 2u ? (uint16_t)(i - size / 2u) : 0);
	if (i < net.page_first || i >= net.page_first + net.page_n)
		return false;
	const otar_member_t *m = &net.page[i - net.page_first];
	*id = m->id;
	*rank = m->rank;
	otar_fingerprint(m->pub, fp);
	return true;
}
#endif
