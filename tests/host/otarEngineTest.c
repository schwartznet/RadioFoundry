// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The OTAR engine (core/ui/ui_svc_otar.c, docs/spec/otar.md 7-10, 23) on the host: the real engine, messages and
// crypto, with the radio core, codeplug, settings, storage jobs and transport faked here. The test plays the other
// radio with its own key pair, building and opening real messages (otar_msg.c): first the engine is a member and the
// test its net control, then the engine is net control 1 and the test a member.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "ui_svc.h"
#include "codeplug/codeplug.h"
#include "codeplug/codeplug_kv.h"
#include "codeplug/codeplug_records.h"
#include "otar/otar_api.h"
#include "otar/otar_crypto.h"
#include "otar/otar_keys.h"
#include "otar/otar_msg.h"
#include "otar/otar_net.h"
#include "radio/radio.h"
#include "settings/settings.h"
#include "storage/storage.h"
#include "support/entropy.h"
#include "support/hkdf.h"
#include "support/kcv.h"
#include "support/utc_clock.h"
#include "FreeRTOS.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

#define ENGINE_ID	4675810u	// the radio under test
#define PEER_ID		4678512u	// the test's radio
#define OTHER_NC	4674131u	// a second net control on the roster
#define NET_ID		0x8B16u

// --- the clock
static uint32_t now_ms = 1000;
uint32_t hal_millis(void) { return now_ms; }
uint32_t hal_micros(void) { return now_ms * 1000u; }
bool utc_clock_now(uint32_t ms, int64_t *s, uint8_t *src)
{
	*s = OTAR_EPOCH_UNIX + 30LL * 86400 + ms / 1000u;
	if (src)
		*src = UTC_SRC_GPS;
	return true;
}
void utc_clock_set(int64_t s, uint32_t ms, uint8_t src) { (void)s; (void)ms; (void)src; }

// --- the heap
void *pvPortMalloc(size_t n) { return malloc(n); }
void vPortFree(void *p) { free(p); }

// --- settings: the live copy, and what a save has written. auto_save off: nothing reaches the "flash"
static settings_t live, saved;
static bool auto_save = true;
settings_t *settings_begin(void) { return &live; }
void settings_end(uint32_t ms) { (void)ms; if (auto_save) saved = live; }
void settings_end_soon(uint32_t ms) { settings_end(ms); }
bool settings_u32_is_saved(size_t off, uint32_t v)
{
	uint32_t a, b;
	memcpy(&a, (uint8_t *)&live + off, 4);
	memcpy(&b, (uint8_t *)&saved + off, 4);
	return a == v && b == v;
}
uint32_t settings_read_field(size_t off, size_t size)
{
	uint32_t v = 0;
	memcpy(&v, (uint8_t *)&live + off, size <= 4 ? size : 4);
	return v;
}

// --- storage jobs: run at once
bool storage_job_post(void (*fn)(void *), void *ctx) { fn(ctx); return true; }

// --- the codeplug: a key-value area in RAM (the roster lives here, otar_net.c) and the traffic keys
#define KV_MAX 128
static struct { uint16_t key; uint16_t len; uint8_t v[64]; } kv[KV_MAX];
static int kv_n;
static uint8_t kv_ser;
uint8_t codeplug_kv_serial(void) { return kv_ser; }
void codeplug_kv_begin(codeplug_kv_cursor_t *c, uint16_t lo, uint16_t hi)
{
	memset(c, 0, sizeof *c);
	c->lo = lo;
	c->hi = hi;
}
int codeplug_kv_next(codeplug_kv_cursor_t *c, uint16_t *key, void *buf, uint16_t max)
{
	while (c->at < kv_n) {
		int i = c->at++;
		if (kv[i].key < c->lo || kv[i].key > c->hi)
			continue;
		*key = kv[i].key;
		if (buf != NULL)
			memcpy(buf, kv[i].v, kv[i].len < max ? kv[i].len : max);
		return kv[i].len;
	}
	return -1;
}
bool codeplug_kv_set(uint16_t key, const void *value, uint16_t len)
{
	kv_ser++;
	for (int i = 0; i < kv_n; i++)
		if (kv[i].key == key) {
			kv[i].len = len;
			memcpy(kv[i].v, value, len);
			return true;
		}
	if (kv_n >= KV_MAX || len > 64)
		return false;
	kv[kv_n].key = key;
	kv[kv_n].len = len;
	memcpy(kv[kv_n].v, value, len);
	kv_n++;
	return true;
}
bool codeplug_kv_remove(uint16_t key)
{
	kv_ser++;
	for (int i = 0; i < kv_n; i++)
		if (kv[i].key == key) {
			kv[i] = kv[--kv_n];
			return true;
		}
	return false;
}
static struct { bool used; uint8_t k[32]; } tek[256];
int codeplug_traffic_key(uint8_t system, uint8_t alg, uint16_t id, uint8_t *key, uint16_t cap)
{
	(void)system; (void)alg;
	if (id > 255 || !tek[id].used || cap < 32)
		return 0;
	memcpy(key, tek[id].k, 32);
	return 32;
}
bool codeplug_traffic_key_set(uint8_t system, uint8_t alg, uint16_t id, const uint8_t *key, uint8_t len)
{
	(void)system; (void)alg;
	if (id > 255 || len != 32)
		return false;
	tek[id].used = true;
	memcpy(tek[id].k, key, 32);
	return true;
}
bool ui_svc_clear_keys_start(void) { return true; }
void ui_svc_noise_want(uint32_t ms) { (void)ms; }

// --- randomness: deterministic, always full (the engine's own key presses aren't what is tested here)
static uint8_t rnd_ctr;
unsigned entropy_bits(void) { return ENTROPY_FULL; }
void entropy_take(uint8_t *out, size_t n) { for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(0xA5 ^ (rnd_ctr++ * 31u)); }
void entropy_stir(const void *d, size_t n, unsigned bits) { (void)d; (void)n; (void)bits; }

// --- the radio core: the engine's requests applied to a keyset state, as radio_aes.c does
static otar_keys_t keys;
static int req_time, req_now;
void radio_req_otar(uint8_t op, uint32_t value)
{
	switch (op) {
	case RADIO_OTAR_START: otar_start(&keys, 0, (uint8_t)value); break;
	case RADIO_OTAR_NEXT_AT: (void)otar_set_next(&keys, 1, (uint8_t)value, value >> 8, (value >> 8) != 0); break;
	case RADIO_OTAR_NEXT_KS:
		if ((keys.flags & OTAR_F_NEXT) && value > keys.ks_active)
			keys.ks_next = (uint16_t)value;
		break;
	case RADIO_OTAR_NOW: (void)otar_change_over(&keys); req_now++; break;
	case RADIO_OTAR_TIME: req_time++; break;
	default: break;
	}
}
static radio_view_t view;
static const radio_view_t *v_now(void)
{
	memset(&view.otar, 0, sizeof view.otar);
	view.dmr.own_id = ENGINE_ID;
	view.otar.on = otar_on(&keys);
	view.otar.system = 0;
	view.otar.keyset = keys.ks_active;
	view.otar.has_kid = otar_kid(&keys, OTAR_ACTIVE, 1, &view.otar.kid);
	view.otar.has_next = otar_kid(&keys, OTAR_NEXT, 1, &view.otar.next_kid);
	view.otar.next_keyset = keys.ks_next;
	view.otar.clock_ok = true;
	view.otar.now_min = 30u * 1440u + now_ms / 60000u;
	view.otar.clock_src = UTC_SRC_GPS;
	return &view;
}

// --- the transport
typedef struct { uint32_t src, dst; bool group; int len; uint8_t m[OTAR_MSG_MAX]; } pkt_t;
static pkt_t inbox[8], outbox[16];
static int in_n, out_n;
void otar_svc_open(bool open) { (void)open; }
bool otar_send(uint32_t dst, bool group, const uint8_t *msg, int len)
{
	if (out_n < 16) {
		outbox[out_n] = (pkt_t){ ENGINE_ID, dst, group, len, { 0 } };
		memcpy(outbox[out_n].m, msg, (size_t)len);
		out_n++;
	}
	return true;
}
otar_send_state_t otar_send_state(void) { return OTAR_SEND_SENT; }
int otar_take(uint8_t out[OTAR_MSG_MAX], uint32_t *src, uint32_t *dst, bool *group)
{
	if (in_n == 0)
		return 0;
	pkt_t p = inbox[0];
	memmove(&inbox[0], &inbox[1], sizeof inbox[0] * (size_t)(--in_n));
	memcpy(out, p.m, (size_t)p.len);
	*src = p.src;
	*dst = p.dst;
	*group = p.group;
	return p.len;
}
static void deliver(uint32_t src, uint32_t dst, bool group, const uint8_t *m, int len)
{
	inbox[in_n] = (pkt_t){ src, dst, group, len, { 0 } };
	memcpy(inbox[in_n].m, m, (size_t)len);
	in_n++;
}

// Run the engine for ms, a tick every 100 ms
static void run(uint32_t ms)
{
	for (uint32_t t = 0; t < ms; t += 100) {
		now_ms += 100;
		(void)ui_svc_net_tick(v_now(), now_ms);
	}
}

// --- the test's radio
static uint8_t peer_priv[32], peer_pub[32], eng_pub[32];
static uint8_t ukek[32], kmac[32];	// the pair's, worked out by the test
static uint32_t peer_msgnum = 100;

static void roster_add(uint32_t id, uint8_t rank, const uint8_t pub[32])
{
	otar_member_t m;
	memset(&m, 0, sizeof m);
	m.id = id;
	m.rank = rank;
	memcpy(m.pub, pub, 32);
	CHECK(otar_roster_put(&m));
}

// The engine's settings: in net NET_ID with rank, its key pair from priv
static void setup(uint8_t rank)
{
	x25519_ws_t ws;
	live.otar_net.flags = 0;	// out of the net first: the engine starts again when it is back in
	run(200);
	uint32_t msgnum = live.otar_msgnum;
	memset(&live, 0, sizeof live);
	live.otar_msgnum = msgnum;
	for (int i = 0; i < 32; i++) {
		live.otar_net.priv[i] = (uint8_t)(i * 7 + 1);
		peer_priv[i] = (uint8_t)(i * 13 + 5);
	}
	x25519_public(eng_pub, live.otar_net.priv, &ws);
	x25519_public(peer_pub, peer_priv, &ws);
	live.otar_net.net_id = NET_ID;
	live.otar_net.rank = rank;
	live.otar_net.flags = OTAR_NET_IN;
	saved = live;
	kv_n = 0;
	CHECK(otar_pair_keys(peer_priv, eng_pub, NET_ID, PEER_ID, ENGINE_ID, ukek, kmac, &ws));
}

// A message from the test's radio to the engine, built under the pair's keys
static int build(uint8_t type, otar_msg_t *m, uint8_t *out)
{
	otar_addr_t a = { PEER_ID, ENGINE_ID };
	m->net_id = NET_ID;
	if (m->msgnum == 0)
		m->msgnum = ++peer_msgnum;
	switch (type) {
	case OTAR_REKEY: return otar_rekey_build(out, &a, ukek, kmac, m);
	case OTAR_ACK: return otar_ack_build(out, &a, kmac, m);
	case OTAR_HELLO: return otar_hello_build(out, &a, kmac, m);
	case OTAR_ROSTER: return otar_roster_build(out, &a, kmac, m);
	case OTAR_TIME: return otar_time_build(out, &a, kmac, m);
	default: return 0;
	}
}

// The engine's last message to the test's radio, opened; false when there is none
static bool last_out(otar_msg_t *m)
{
	if (out_n == 0)
		return false;
	pkt_t *p = &outbox[out_n - 1];
	otar_addr_t a = { ENGINE_ID, p->dst };
	return p->dst == PEER_ID && otar_open(p->m, p->len, &a, ukek, kmac, m);
}

static void rekey_msg(otar_msg_t *m, uint32_t keyset, uint8_t kid, uint8_t fill, uint8_t flags)
{
	memset(m, 0, sizeof *m);
	m->rank = 1;
	m->keyset = keyset;
	m->ckr = 1;
	m->kid = kid;
	m->flags = flags;
	memset(m->tek, fill, 32);
}

static void kcv_of(uint8_t fill, uint8_t out[3])
{
	uint8_t k[32];
	memset(k, fill, 32);
	CHECK(kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, k, 32, out));
}

// ===================== the engine as a member, the test as its net control (rank 1)
static void test_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;		// the net is on keyset 4
	out_n = 0;
	run(25000);			// HELLO after 20 s
	otar_msg_t r;
	CHECK(out_n == 1 && outbox[0].dst == PEER_ID && last_out(&r) && r.type == OTAR_HELLO && r.keyset == 4);

	// A REKEY to keyset 5: stored under the net's number 5, ACKed with its check value
	uint8_t buf[OTAR_MSG_MAX], kcv5[3];
	otar_msg_t m;
	rekey_msg(&m, 5, 78, 0x55, 0);
	int n = build(OTAR_REKEY, &m, buf);
	uint8_t replay[OTAR_MSG_MAX];
	memcpy(replay, buf, (size_t)n);
	int replay_n = n;
	deliver(PEER_ID, ENGINE_ID, false, buf, n);
	out_n = 0;
	run(1000);
	kcv_of(0x55, kcv5);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_STORED && memcmp(r.kcv, kcv5, 3) == 0);
	CHECK(keys.ks_next == 5 && keys.kid_next[0] == 78);

	// The same message again, recorded and played back: no answer at all (otar.md 23.1)
	out_n = 0;
	deliver(PEER_ID, ENGINE_ID, false, replay, replay_n);
	run(1000);
	CHECK(out_n == 0);

	// A net control's retry (a new message number): HELD; the same keyset and key ID with another key: refused
	rekey_msg(&m, 5, 78, 0x55, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_HELD);
	rekey_msg(&m, 5, 78, 0x66, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && keys.kid_next[0] == 78);

	// Back to an older keyset: refused as old, nothing changed (7.1)
	rekey_msg(&m, 4, 79, 0x44, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_OLD && keys.ks_active == 4 && keys.kid_active[0] == 77);

	// The net's active key flagged now (a member behind): stored, made next under keyset 6, changed over at once
	int now_before = req_now;
	rekey_msg(&m, 6, 80, 0x60, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && req_now == now_before + 1);
	CHECK(keys.ks_active == 6 && keys.kid_active[0] == 80);

	// TIME under the pair's keys: taken. TIME under a key from the traffic key (any holder of it): ignored (7.4)
	int t0 = req_time;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.time_s = 30u * 86400u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_TIME, &m, buf));
	run(500);
	CHECK(req_time == t0 + 1);
	uint8_t gk[32];
	otar_group_mac_key(tek[80].k, "time", gk);
	otar_addr_t ga = { PEER_ID, 42001 };
	memset(&m, 0, sizeof m);
	m.net_id = NET_ID;
	m.rank = 1;
	m.msgnum = 0xFFFFFFF0u;	// the attack: the highest numbers, to lock the net control out
	m.time_s = 1;
	n = otar_time_build(buf, &ga, gk, &m);
	deliver(PEER_ID, 42001, true, buf, n);
	run(500);
	CHECK(req_time == t0 + 1);
	// ... and the net control's next REKEY still goes through
	rekey_msg(&m, 7, 81, 0x71, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED);
}

// ===================== ranks in ROSTER (otar.md 10): the test is net control 2
static void test_ranks(void)
{
	setup(0);
	x25519_ws_t ws;
	uint8_t nc1_pub[32], nc1_priv[32];
	memset(nc1_priv, 0x21, 32);
	x25519_public(nc1_pub, nc1_priv, &ws);
	roster_add(OTHER_NC, 1, nc1_pub);
	roster_add(PEER_ID, 2, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	out_n = 0;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	otar_member_t e;
	// HELLO went to the best-ranked net control (NC 1), not the first on the roster
	CHECK(out_n >= 1 && outbox[0].dst == OTHER_NC);

	// NC 2 making itself NC 1: refused
	memset(&e, 0, sizeof e);
	e.id = PEER_ID;
	e.rank = 1;
	memcpy(e.pub, peer_pub, 32);
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	out_n = 0;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_REFUSED);
	CHECK(otar_roster_find(PEER_ID, &e) && e.rank == 2);

	// NC 2 adding a new NC 1: refused
	memset(&e, 0, sizeof e);
	e.id = 4699999u;
	e.rank = 1;
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && !otar_roster_find(4699999u, &e));

	// Each rule on its own (the cases above trip two at once). NC 2 changing its own entry, rank kept (a new public
	// key): refused. ("Not above its sender" is never alone: anything it refuses, the other two refuse too)
	memset(&e, 0, sizeof e);
	e.id = PEER_ID;
	e.rank = 2;
	memset(e.pub, 0x77, 32);
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && otar_roster_find(PEER_ID, &e) && e.pub[0] == peer_pub[0]);
	// NC 2 giving a member rank 3 (not above its own): refused, only NC 1 gives ranks
	memset(&e, 0, sizeof e);
	e.id = ENGINE_ID;
	e.rank = 3;
	memcpy(e.pub, eng_pub, 32);
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && otar_roster_find(ENGINE_ID, &e) && e.rank == 0);

	// NC 2 adding a plain member: taken
	memset(&e, 0, sizeof e);
	e.id = 4688888u;
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && otar_roster_find(4688888u, &e));

	// Counters per sender: NC 1's high numbers don't lock NC 2 out. The engine takes NC 2's low ones still
	peer_msgnum = 10;
	memset(&e, 0, sizeof e);
	e.id = 4688889u;
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED);
}

// ===================== the engine as net control 1, the test a member
static void test_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	out_n = 0;
	run(3000);

	// A member's HELLO from keyset 3: the net's active key back, flagged now (catch-up)
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	memset(&m, 0, sizeof m);
	m.keyset = 3;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && r.keyset == 4 && r.kid == 77 && (r.flags & OTAR_RK_NOW));
	// The same HELLO again a minute later (a replay, or a member that didn't take it): no second REKEY yet
	run(60000);
	int before = out_n;
	memset(&m, 0, sizeof m);
	m.keyset = 3;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(1000);
	CHECK(out_n == before);

	// Rekey by hand: the REKEY to the member, then an ACK with another key's check value doesn't count
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && r.keyset == 5);
	uint8_t right[3], wrong[3];
	CHECK(kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, r.tek, 32, right));
	kcv_of(0x99, wrong);
	memset(&m, 0, sizeof m);
	m.keyset = 5;
	m.ckr = 1;
	m.result = OTAR_ACK_STORED;
	memcpy(m.kcv, wrong, 3);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	uint32_t id;
	uint8_t state, tries;
	CHECK(ui_svc_net_rekey_member(0, &id, &state, &tries) && id == PEER_ID && state != UI_RK_OK);
	// The retry, then the right check value at once: OK
	int sent = out_n;
	for (int i = 0; i < 400 && out_n == sent; i++)
		run(1000);
	CHECK(out_n > sent && last_out(&r) && r.type == OTAR_REKEY && r.keyset == 5);
	memset(&m, 0, sizeof m);
	m.keyset = 5;
	m.ckr = 1;
	m.result = OTAR_ACK_STORED;
	memcpy(m.kcv, right, 3);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_rekey_member(0, &id, &state, &tries) && state == UI_RK_OK);
}

// ===================== message numbers: nothing goes until a reservation is in the flash (7.6)
// Run first: the engine's message numbers start from the settings once, as at power-on
static void test_msgnum(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	live.otar_msgnum = 1000;	// a reservation up to 1000 saved before the power went
	saved = live;
	auto_save = false;		// the next one doesn't reach the flash
	out_n = 0;
	run(25000);
	CHECK(out_n == 0);		// no HELLO: the reservation isn't saved
	auto_save = true;
	saved = live;
	run(1000);
	otar_msg_t r;
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_HELLO && r.msgnum > 1000);
}

int main(void)
{
	test_msgnum();
	test_member();
	test_ranks();
	test_nc();
	printf("otarEngineTest: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
