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
#include "dmr/call/dmr_lc.h"
#include "radio/silence.h"
#if CONFIG_POSITION
#include "position/position.h"
#endif
#include "FreeRTOS.h"

static int failures, checks;
#define ACK_WAIT_TEST_MS	21000u	// past the engine's ACK_WAIT_MS (20 s)
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
static int out_n_now(void);
// The wipe (Clear all keys): counted, with how many messages had gone by then; the net and key pair go, as on the radio
static int wipes, wipe_out_n;
bool ui_svc_clear_keys_start(void)
{
	wipes++;
	wipe_out_n = out_n_now();
	memset(&live.otar_net, 0, sizeof live.otar_net);
	return true;
}
// A WIPE's wipe (keys and codeplug): counted apart from Clear all keys
static int wipe_alls;
bool ui_svc_wipe_all_start(void)
{
	wipe_alls++;
	wipe_out_n = out_n_now();
	memset(&live.otar_net, 0, sizeof live.otar_net);
	return true;
}
static int noise_wants;
void ui_svc_noise_want(uint32_t ms) { (void)ms; noise_wants++; }
// The radio silence setting as the UI saves it (a net control's SILENCE): counted, and the flag the radio core sets
static int sil_sets;
bool ui_svc_setting_set(uint8_t id, int32_t value)
{
	if (id == UI_SET_SILENCE)
		sil_sets++;
	(void)value;
	return true;
}
void ui_svc_apply(uint8_t id, int32_t value) { (void)id; (void)value; }

// --- randomness: deterministic, always full (the engine's own key presses aren't what is tested here)
static uint8_t rnd_ctr;
static unsigned pool_bits = ENTROPY_FULL;	// what the pool holds (a test empties it)
unsigned entropy_bits(void) { return pool_bits; }
void entropy_take(uint8_t *out, size_t n) { for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(0xA5 ^ (rnd_ctr++ * 31u)); }
void entropy_stir(const void *d, size_t n, unsigned bits) { (void)d; (void)n; (void)bits; }

// --- the radio core: the engine's requests applied to a keyset state, as radio_aes.c does
static otar_keys_t keys;
static int req_time, req_now, req_drop_prev;
static int drop_mode;		// DROP_NEXT: 0 made, 1 the next one lost, 2 held until drop_release, 3 never made
static int drop_asks;
static uint32_t drop_held = 0xFFFFu;
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
	case RADIO_OTAR_DROP_NEXT:
		drop_asks++;
		if (drop_mode == 1) {	// lost
			drop_mode = 0;
			break;
		}
		if (drop_mode == 2) {	// held: the radio task hasn't got to it yet (drop_release)
			drop_held = value;
			break;
		}
		if (drop_mode == 3)	// never made (the request keeps being lost)
			break;
		// As radio_aes.c: only the next keyset named, its key erased
		if ((keys.flags & OTAR_F_NEXT) && keys.kid_next[0] == (uint8_t)value) {
			otar_clear_next(&keys);
			tek[value & 0xFFu].used = false;
		}
		break;
	case RADIO_OTAR_TIME: req_time++; break;
	case RADIO_OTAR_RESET: {
		// As radio_aes.c: the keysets start again on the key ID at the keyset number, every other key erased
		static const uint8_t which[] = { OTAR_ACTIVE, OTAR_NEXT, OTAR_PREV };
		uint8_t old;
		for (unsigned i = 0; i < sizeof which; i++)
			if (otar_kid(&keys, which[i], 1, &old) && old != (uint8_t)value)
				tek[old].used = false;
		uint8_t sys = otar_system(&keys);
		otar_start(&keys, sys, (uint8_t)value);
		keys.ks_active = (uint16_t)(value >> 8);
		break;
	}
	case RADIO_OTAR_DROP_PREV: {
		// As radio_aes.c: the previous keyset ended now, its keys erased
		uint8_t kids[OTAR_CKRS];
		req_drop_prev++;
		uint8_t nk = otar_drop_prev(&keys, kids);
		for (uint8_t i = 0; i < nk; i++)
			tek[kids[i]].used = false;
		break;
	}
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
	view.otar.changeover = keys.changeover;
	view.otar.clock_ok = true;
	view.otar.now_min = 30u * 1440u + now_ms / 60000u;
	view.otar.clock_src = UTC_SRC_GPS;
	return &view;
}

// --- radio silence, and where the radio is (the position service: fake_fix, or none)
#if CONFIG_RADIO_SILENCE
volatile bool radio_silence_flag;
#endif
static bool fake_fix;
static int32_t fake_lat, fake_lon, fake_alt;
static uint32_t fake_ms;
#if CONFIG_POSITION
static uint8_t fake_position(position_fix_t *out)
{
	memset(out, 0, sizeof *out);
	if (!fake_fix)
		return POSITION_SRC_NONE;
	out->lat = fake_lat;
	out->lon = fake_lon;
	out->alt_m = fake_alt;
	out->ms = fake_ms;
	return POSITION_SRC_GPS;
}
uint8_t position_report(position_fix_t *out, uint32_t *err_m, uint32_t now) { (void)now; *err_m = 5; return fake_position(out); }
uint8_t position_fix(position_fix_t *out, uint32_t now) { (void)now; return fake_position(out); }
#endif
// From here to there: 1 m per 100 units (1e-5 degree) of latitude, the bearing north or south (enough to see it carried)
void dmr_gps_range(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2, uint32_t *meters, uint16_t *bearing)
{
	(void)lon1; (void)lon2;
	int32_t d = lat2 - lat1;
	*meters = (uint32_t)(d < 0 ? -d : d) / 100u;
	*bearing = d < 0 ? 180u : 0u;
}

// --- the transport
typedef struct { uint32_t src, dst; bool group; int len; uint8_t m[OTAR_MSG_MAX]; uint32_t at; } pkt_t;
static pkt_t inbox[8], outbox[16];
static int in_n, out_n;
void otar_svc_open(bool open) { (void)open; }
bool otar_send(uint32_t dst, bool group, const uint8_t *msg, int len)
{
	if (out_n < 16) {
		outbox[out_n] = (pkt_t){ ENGINE_ID, dst, group, len, { 0 }, 0 };
		memcpy(outbox[out_n].m, msg, (size_t)len);
		outbox[out_n].at = now_ms;
		out_n++;
	}
	return true;
}
static otar_send_state_t send_state = OTAR_SEND_SENT;	// what the transport says of the last message
otar_send_state_t otar_send_state(void) { return send_state; }
void otar_note_ack(otar_ack_note_t what, uint8_t result) { (void)what; (void)result; }
static int out_n_now(void) { return out_n; }
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
	inbox[in_n] = (pkt_t){ src, dst, group, len, { 0 }, 0 };
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
	in_n = 0;
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
	case OTAR_ZEROIZE: return otar_zeroize_build(out, &a, kmac, m);
	case OTAR_INVENTORY: return otar_inventory_build(out, &a, kmac, m);
	case OTAR_LOCATE: return otar_locate_build(out, &a, kmac, m);
	case OTAR_POSITION: return otar_position_build(out, &a, kmac, m);
	case OTAR_NETCHAN: return otar_netchan_build(out, &a, kmac, m);
	case OTAR_WITHDRAW: return otar_withdraw_build(out, &a, kmac, m);
	case OTAR_WIPE: return otar_wipe_build(out, &a, kmac, m);
	case OTAR_SILENCE: return otar_silence_build(out, &a, kmac, m);
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

	// The same message again, recorded and played back: never ACKed (otar.md 23.1); once, the "old message number"
	// answer with the last number taken (7.6), then nothing
	uint32_t first_num = m.msgnum;
	out_n = 0;
	deliver(PEER_ID, ENGINE_ID, false, replay, replay_n);
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_MSGNUM && r.keyset == first_num &&
	      r.echo == first_num && r.ckr == 0);
	deliver(PEER_ID, ENGINE_ID, false, replay, replay_n);
	run(1000);
	CHECK(out_n == 1);

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
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && r.echo == m.msgnum);

	// The net changed over by hand while this radio was off: the catch-up names keyset 7, which it holds as next.
	// HELD, and it changes over (9)
	now_before = req_now;
	rekey_msg(&m, 7, 81, 0x71, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_HELD && req_now == now_before + 1 && keys.ks_active == 7);

	// Too far ahead (one sender parking the net on a number nobody reaches), or a key ID in use: refused (7.1)
	rekey_msg(&m, 7 + 9, 90, 0x90, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && keys.ks_active == 7);
	rekey_msg(&m, 8, 81, 0x82, 0);		// 81 is the active key's ID
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && tek[81].k[0] == 0x71);
	// The authority's catch-up, flagged now, however far ahead: the net's own number (a radio off through many
	// rekeys, or cleared and joined again; found on air at keyset 1 against the net's 12)
	now_before = req_now;
	rekey_msg(&m, 7 + 9, 90, 0x90, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && req_now == now_before + 1 && keys.ks_active == 16);
	CHECK(tek[90].used && tek[90].k[0] == 0x90);
	// Never past 65535, flagged now or not
	rekey_msg(&m, 0x10000u, 91, 0x91, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && keys.ks_active == 16);
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
	uint8_t xpub[32];
	memset(xpub, 0x31, 32);
	roster_add(4688888u, 0, xpub);
	roster_add(4688889u, 0, xpub);
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

	// NC 2 adding a member, or changing a member's public key: refused, only the authority (NC 1) does (10)
	memset(&e, 0, sizeof e);
	e.id = 4677777u;
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && !otar_roster_find(4677777u, &e));
	memset(&e, 0, sizeof e);
	e.id = 4688888u;
	memset(e.pub, 0x99, 32);
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && otar_roster_find(4688888u, &e) && e.pub[0] == 0x31);

	// NC 2 revoking a member: taken. Un-revoking it again: refused, by anyone (10)
	memset(&e, 0, sizeof e);
	e.id = 4688888u;
	e.flags = OTAR_M_REVOKED;
	memcpy(e.pub, xpub, 32);
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && r.echo == m.msgnum && otar_roster_find(4688888u, &e) &&
	      (e.flags & OTAR_M_REVOKED));
	e.flags = 0;
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && otar_roster_find(4688888u, &e) && (e.flags & OTAR_M_REVOKED));

	// NC 2's counter: a message with one of its old numbers isn't taken, answered only "old message number" with the
	// last number taken; a fresh one is taken
	uint32_t keep = peer_msgnum;
	peer_msgnum = 10;
	memset(&e, 0, sizeof e);
	e.id = 4688889u;
	e.flags = OTAR_M_REVOKED;
	memcpy(e.pub, xpub, 32);
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	int before = out_n;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(out_n == before + 1 && last_out(&r) && r.result == OTAR_ACK_MSGNUM && r.keyset == keep && r.echo == 11);
	CHECK(otar_roster_find(4688889u, &e) && !(e.flags & OTAR_M_REVOKED));
	peer_msgnum = keep;
	e.flags = OTAR_M_REVOKED;
	memset(&m, 0, sizeof m);
	m.rank = 2;
	otar_member_pack(&e, m.rec);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ROSTER, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && r.echo == m.msgnum);
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
	// The same HELLO played back a minute later: no second REKEY
	int hn = build(OTAR_HELLO, &m, buf);	// m.msgnum kept: the same message again
	run(60000);
	int before = out_n;
	deliver(PEER_ID, ENGINE_ID, false, buf, hn);
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
	m.echo = r.msgnum;		// answers that REKEY
	memcpy(m.kcv, wrong, 3);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	uint32_t id;
	uint8_t state, tries;
	// It answered: "refused", not "no answer"
	CHECK(ui_svc_net_rekey_member(0, &id, &state, &tries) && id == PEER_ID && state == UI_RK_REFUSED);
	// The retry, then the right check value at once: OK
	int sent = out_n;
	for (int i = 0; i < 400 && out_n == sent; i++)
		run(1000);
	CHECK(out_n > sent && last_out(&r) && r.type == OTAR_REKEY && r.keyset == 5);
	uint32_t first = r.msgnum;
	// An ACK echoing an older REKEY (a recording of the first try's answer): doesn't count (7.2)
	memset(&m, 0, sizeof m);
	m.keyset = 5;
	m.ckr = 1;
	m.result = OTAR_ACK_STORED;
	m.echo = first - 1u;
	memcpy(m.kcv, right, 3);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(300);
	CHECK(ui_svc_net_rekey_member(0, &id, &state, &tries) && state == UI_RK_SENT);
	memset(&m, 0, sizeof m);
	m.keyset = 5;
	m.ckr = 1;
	m.result = OTAR_ACK_STORED;
	m.echo = first;
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
	// A REKEY now: stored, but its ACK would carry message number 0 (a counter block two messages could share). Not
	// sent; the net control's retry gets it once a reservation is saved
	otar_msg_t rq;
	uint8_t rbuf[OTAR_MSG_MAX];
	rekey_msg(&rq, 2, 50, 0x50, 0);
	deliver(PEER_ID, ENGINE_ID, false, rbuf, build(OTAR_REKEY, &rq, rbuf));
	run(1000);
	CHECK(out_n == 0);
	auto_save = true;
	saved = live;
	run(1000);
	otar_msg_t r;
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_HELLO && r.msgnum > 1000);
}

// A radio whose keys were all cleared joins on its AES channel: it manages the channel's keys though it holds none,
// and says HELLO, so the net control sends it the active key (found on air: it stayed unmanaged and never caught up)
static void test_join_without_key(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_stop(&keys);
	memset(tek, 0, sizeof tek);
	view.ch.mode = RADIO_MODE_DMR;
	view.ch.kind = CODEPLUG_KIND_DMR_AES;
	view.ch.aes_ref = 78;
	CHECK(live.otar_wipe == 0);
	ui_svc_net_joined();
	// Remote wipe on in a net (otar.md 7.5), whatever the radio had
	CHECK(live.otar_wipe == 1 && saved.otar_wipe == 1);
	out_n = 0;
	run(25000);
	CHECK(otar_on(&keys));
	otar_msg_t r;
	CHECK(out_n >= 1 && outbox[0].dst == PEER_ID && last_out(&r) && r.type == OTAR_HELLO);

	// A radio that manages keys already (left the net and joins again) keeps its keysets: not back to keyset 1
	keys.ks_active = 12;
	keys.kid_active[0] = 89;
	ui_svc_net_joined();
	run(1000);
	CHECK(otar_on(&keys) && keys.ks_active == 12 && keys.kid_active[0] == 89);
	memset(&view.ch, 0, sizeof view.ch);
}

// The engine's message i to the test's radio, opened
static bool out_open(int i, otar_msg_t *m)
{
	if (i < 0 || i >= out_n)
		return false;
	otar_addr_t a = { ENGINE_ID, outbox[i].dst };
	return outbox[i].dst == PEER_ID && otar_open(outbox[i].m, outbox[i].len, &a, ukek, kmac, m);
}

// ===================== ZEROIZE answered (otar.md 7.5): the engine a member, the test its net control
static void test_zeroize_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;

	// Remote wipe off: REFUSED, under the pair's keys, echoing the ZEROIZE; nothing wiped
	wipes = 0;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.target = ENGINE_ID;
	out_n = 0;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ZEROIZE, &m, buf));
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_REFUSED && r.echo == m.msgnum);
	CHECK(wipes == 0 && (live.otar_net.flags & OTAR_NET_IN));

	// Remote wipe on: the WIPED ACK is built and handed over first; while the transport still sends it nothing else is
	// answered (an INVENTORY waiting) and nothing is wiped yet
	live.otar_wipe = 1;
	saved = live;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.target = ENGINE_ID;
	out_n = 0;
	send_state = OTAR_SEND_SENDING;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ZEROIZE, &m, buf));
	uint32_t zz_num = m.msgnum;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_INVENTORY, &m, buf));
	run(5000);
	CHECK(out_n == 1 && out_open(0, &r) && r.type == OTAR_ACK && r.result == OTAR_ACK_WIPED && r.echo == zz_num &&
	      r.ckr == 0);
	CHECK(wipes == 0);
	// The send done: the wipe, after the ACK went (and the INVENTORY still unanswered: the net is gone)
	send_state = OTAR_SEND_SENT;
	run(2000);
	CHECK(wipes == 1 && wipe_out_n == 1 && out_n == 1);

	// A transport that never finishes: the wipe goes all the same, a minute on
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	run(1000);
	live.otar_wipe = 1;
	saved = live;
	wipes = 0;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.target = ENGINE_ID;
	out_n = 0;
	send_state = OTAR_SEND_SENDING;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ZEROIZE, &m, buf));
	run(30000);
	CHECK(wipes == 0 && out_n == 1);
	run(31000);
	CHECK(wipes == 1);
	send_state = OTAR_SEND_SENT;
}

// ===================== ZEROIZE retried until answered (otar.md 7.5): the engine net control 1, the test a member
static void test_zeroize_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	out_n = 0;
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, false) == UI_NET_OK);
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, false) == UI_NET_BUSY);
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ZEROIZE && r.target == PEER_ID);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_SENDING);
	// An ACK echoing something else doesn't answer it; the right one does: wiped, and no more tries
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_WIPED;
	m.echo = r.msgnum - 1u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_SENDING);
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_WIPED;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_WIPED);
	run(90000);
	CHECK(out_n == 1);

	// No answer: 3 tries, 20 s apart, then shown as no answer
	out_n = 0;
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, false) == UI_NET_OK);
	run(90000);
	int zz = 0;
	for (int i = 0; i < out_n; i++)
		zz += out_open(i, &r) && r.type == OTAR_ZEROIZE;
	CHECK(zz == 3 && out_n == 3);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_NO_ANSWER);

	// Refused (its Remote wipe off): shown as refused
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, false) == UI_NET_OK);
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_ZEROIZE);
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_REFUSED;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_REFUSED);
}

// ===================== WIPE, the whole radio (otar.md 7.10): the engine a member, then net control 1
static void test_wipe_radio(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	// Remote wipe off: REFUSED, nothing wiped
	wipes = wipe_alls = 0;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.target = ENGINE_ID;
	out_n = 0;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WIPE, &m, buf));
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_REFUSED && r.echo == m.msgnum);
	CHECK(wipes == 0 && wipe_alls == 0);
	// On: WIPED first, then the whole radio (keys and codeplug), not Clear all keys
	live.otar_wipe = 1;
	saved = live;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.target = ENGINE_ID;
	out_n = 0;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WIPE, &m, buf));
	run(2000);
	CHECK(out_open(0, &r) && r.type == OTAR_ACK && r.result == OTAR_ACK_WIPED && r.echo == m.msgnum);
	CHECK(wipe_alls == 1 && wipes == 0 && wipe_out_n == 1);

	// The net control: WIPE sent, not ZEROIZE, and shown as the whole radio's
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	run(3000);
	out_n = 0;
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, true) == UI_NET_OK);
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_WIPE && r.target == PEER_ID);
	CHECK(ui_svc_net_wipe_whole(PEER_ID) && !ui_svc_net_wipe_whole(OTHER_NC));
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_WIPED;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_WIPED);
}

// ===================== SILENCE answered (otar.md 7.11): the engine a member, the test its net control
static int silence_msg(uint8_t on, uint8_t *buf, otar_msg_t *m)
{
	memset(m, 0, sizeof *m);
	m->rank = 1;
	m->on = on;
	return build(OTAR_SILENCE, m, buf);
}

static void test_silence_remote_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	run(25000);
	radio_silence_flag = false;
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	ui_net_view_t nv;
	// On: SILENT answered first, then silence, marked as the net control's
	out_n = 0;
	sil_sets = 0;
	send_state = OTAR_SEND_SENDING;
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(1, buf, &m));
	run(2000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_SILENT && r.echo == m.msgnum);
	CHECK(!radio_silence_flag && sil_sets == 0);	// not before the ACK has gone
	send_state = OTAR_SEND_SENT;
	run(1000);
	CHECK(radio_silence_flag && sil_sets == 1 && (live.otar_sil & SETTINGS_OSIL_BY_NC));
	ui_svc_net_view(&nv);
	CHECK(nv.silenced_by_nc && nv.remote_silence);
	// Silent: another SILENCE on gets no answer
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(1, buf, &m));
	run(1000);
	CHECK(out_n == 1);
	// Off: the net control's silence ends, then SPEAKING
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(0, buf, &m));
	run(1000);
	CHECK(!radio_silence_flag && !(live.otar_sil & SETTINGS_OSIL_BY_NC));
	CHECK(out_n == 2 && last_out(&r) && r.result == OTAR_ACK_SPEAKING && r.echo == m.msgnum);
	// The user's own silence: a SILENCE off never ends it, and nothing is answered under it
	radio_silence_flag = true;
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(0, buf, &m));
	run(1000);
	CHECK(radio_silence_flag && out_n == 2);
	// A silence the net control turned on that the user ended: not the net control's any more
	radio_silence_flag = false;
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(1, buf, &m));
	run(2000);
	CHECK(radio_silence_flag && (live.otar_sil & SETTINGS_OSIL_BY_NC));
	radio_silence_flag = false;	// the user turns it off
	run(500);
	CHECK(!(live.otar_sil & SETTINGS_OSIL_BY_NC));
	radio_silence_flag = true;	// ... and on again: theirs, which a SILENCE off leaves
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(0, buf, &m));
	run(1000);
	CHECK(radio_silence_flag);
	radio_silence_flag = false;
	// Remote silence off: REFUSED, nothing changes
	ui_svc_net_set_remote_silence(false);
	ui_svc_net_view(&nv);
	CHECK(!nv.remote_silence);
	int before = out_n;
	deliver(PEER_ID, ENGINE_ID, false, buf, silence_msg(1, buf, &m));
	run(1000);
	CHECK(out_n == before + 1 && last_out(&r) && r.result == OTAR_ACK_REFUSED && !radio_silence_flag);
	ui_svc_net_set_remote_silence(true);
	// A join sets it on again
	ui_svc_net_set_remote_silence(false);
	ui_svc_net_joined();
	ui_svc_net_view(&nv);
	CHECK(nv.remote_silence);
}

// ===================== SILENCE retried until answered (otar.md 7.11): the engine net control 1, the test a member
static void test_silence_remote_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	bool asked;
	out_n = 0;
	CHECK(ui_svc_net_silence(v_now(), ENGINE_ID, true) == UI_NET_NO_MEMBER);
	CHECK(ui_svc_net_silence(v_now(), PEER_ID, true) == UI_NET_OK);
	CHECK(ui_svc_net_silence(v_now(), PEER_ID, false) == UI_NET_BUSY);
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_SILENCE && r.on == 1);
	CHECK(ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_SENDING && asked);
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_SILENT;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_ON);
	// Off, answered
	CHECK(ui_svc_net_silence(v_now(), PEER_ID, false) == UI_NET_OK);
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_SILENCE && r.on == 0);
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_SPEAKING;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_OFF && !asked);
	// No answer (a radio already silent says nothing): 3 tries, then no answer
	out_n = 0;
	CHECK(ui_svc_net_silence(v_now(), PEER_ID, true) == UI_NET_OK);
	run(90000);
	int n = 0;
	for (int i = 0; i < out_n; i++)
		n += out_open(i, &r) && r.type == OTAR_SILENCE;
	CHECK(n == 3 && ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_NO_ANSWER);
	// Refused
	CHECK(ui_svc_net_silence(v_now(), PEER_ID, true) == UI_NET_OK);
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_SILENCE);
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_REFUSED;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(500);
	CHECK(ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_REFUSED);
}

// ===================== a silent revoke (otar.md 7.12): the engine a member taking the throwaway key, then net control 1
static void test_silent_revoke_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	// A REKEY flagged now and drop: stored, changed over to, and the key it held (77) erased at once
	req_drop_prev = 0;
	out_n = 0;
	rekey_msg(&m, 5, 200, 0x3C, OTAR_RK_NOW | OTAR_RK_DROP);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_active == 5 && otar_kid(&keys, OTAR_ACTIVE, 1, &r.kid) && r.kid == 200);
	CHECK(req_drop_prev == 1 && !tek[77].used && !(keys.flags & OTAR_F_PREV));
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_STORED && r.keyset == 5);
	// Without drop (a missed changeover's catch-up): the overlap stays
	tek[200].used = true;
	rekey_msg(&m, 6, 201, 0x3D, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_active == 6 && req_drop_prev == 1 && (keys.flags & OTAR_F_PREV) && tek[200].used);
}

static int count_to(uint32_t id, uint8_t type)
{
	int n = 0;
	otar_msg_t r;
	for (int i = 0; i < out_n; i++)
		n += outbox[i].dst == id && out_open(i, &r) && r.type == type;
	return n;
}

static void test_silent_revoke_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 9;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	otar_member_t e;
	out_n = 0;
	CHECK(ui_svc_net_silent_revoke(v_now(), ENGINE_ID) == UI_NET_NO_MEMBER);
	CHECK(ui_svc_net_silent_revoke(v_now(), PEER_ID) == UI_NET_OK);
	CHECK(ui_svc_net_silent_revoke(v_now(), PEER_ID) == UI_NET_BUSY);
	CHECK(ui_svc_net_revoke(v_now(), PEER_ID) == UI_NET_BUSY);	// nothing else reaches it meanwhile
	run(1000);
	// The throwaway key: to the member alone, flagged now and drop, above the net's number, not the net's key ID,
	// and never stored on this radio
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_REKEY && (r.flags & (OTAR_RK_NOW | OTAR_RK_DROP)) ==
	      (OTAR_RK_NOW | OTAR_RK_DROP) && r.keyset == 10 && r.kid != 77 && r.kid != 0);
	CHECK(!tek[r.kid].used && keys.ks_active == 9);
	CHECK(ui_svc_net_silent_revoke_state(PEER_ID) == UI_SR_SENDING);
	CHECK(otar_roster_find(PEER_ID, &e) && !(e.flags & OTAR_M_REVOKED));
	// Its ACK: done, and revoked here without a ROSTER to it
	uint8_t kcv_tek[3];
	CHECK(kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, r.tek, 32, kcv_tek));
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_STORED;
	m.keyset = r.keyset;
	m.ckr = 1;
	m.echo = r.msgnum;
	memcpy(m.kcv, kcv_tek, 3);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(2000);
	CHECK(ui_svc_net_silent_revoke_state(PEER_ID) == UI_SR_DONE);
	CHECK(otar_roster_find(PEER_ID, &e) && (e.flags & OTAR_M_REVOKED));
	run(60000);
	CHECK(count_to(PEER_ID, OTAR_ROSTER) == 0);
	CHECK(ui_svc_net_silent_revoke(v_now(), PEER_ID) == UI_NET_NO_MEMBER);	// revoked already

	// No answer (the radio is off or lost): 3 tries, then revoked all the same
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	run(3000);
	out_n = 0;
	CHECK(ui_svc_net_silent_revoke(v_now(), PEER_ID) == UI_NET_OK);
	run(90000);
	CHECK(count_to(PEER_ID, OTAR_REKEY) == 3 && ui_svc_net_silent_revoke_state(PEER_ID) == UI_SR_NO_ANSWER);
	run(2000);
	CHECK(otar_roster_find(PEER_ID, &e) && (e.flags & OTAR_M_REVOKED) && count_to(PEER_ID, OTAR_ROSTER) == 0);

	// The pool empty (a key fill just took it): the throwaway key waits, and the receiver's noise is asked for, as for a
	// rekey's key. Found on the bench: it waited for good, still "sending"
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	run(3000);
	out_n = 0;
	pool_bits = 0;
	noise_wants = 0;
	CHECK(ui_svc_net_silent_revoke(v_now(), PEER_ID) == UI_NET_OK);
	run(5000);
	CHECK(count_to(PEER_ID, OTAR_REKEY) == 0 && noise_wants > 0 && ui_svc_net_silent_revoke_state(PEER_ID) == UI_SR_SENDING);
	pool_bits = ENTROPY_FULL;
	run(1000);
	CHECK(count_to(PEER_ID, OTAR_REKEY) == 1);
	run(90000);
	noise_wants = 0;
	run(1000);
	CHECK(noise_wants == 0);	// done: no more noise asked for

	// A radio joined again: what it answered before isn't shown (found on the bench: "Radio wipe: wiped" stayed)
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	run(3000);
	bool asked;
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, true) == UI_NET_OK && ui_svc_net_silence(v_now(), PEER_ID, true) == UI_NET_OK);
	run(90000);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_NO_ANSWER && ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_NO_ANSWER);
	ui_svc_net_member_added(OTHER_NC);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_NO_ANSWER);	// another radio's join: kept
	ui_svc_net_member_added(PEER_ID);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_NONE && ui_svc_net_silence_state(PEER_ID, &asked) == UI_SIL_NONE &&
	      !ui_svc_net_wipe_whole(PEER_ID));
	// One still sending is left to finish
	CHECK(ui_svc_net_wipe(v_now(), PEER_ID, false) == UI_NET_OK);
	ui_svc_net_member_added(PEER_ID);
	CHECK(ui_svc_net_wipe_state(PEER_ID) == UI_ZZ_SENDING);
	run(90000);
}

// ===================== a radio silently revoked joins again (otar.md 7.12): net control 1's reset, the engine a member
static void test_rejoin_reset_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	// On a silent revoke's throwaway: keyset 17, key 201, above the net's 15
	otar_start(&keys, 0, 201);
	tek[201].used = true;
	keys.ks_active = 17;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	// Not joined lately: the net's keyset flagged reset is older, refused
	out_n = 0;
	rekey_msg(&m, 15, 77, 0x11, OTAR_RK_NOW | OTAR_RK_RESET);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_active == 17 && tek[201].used && last_out(&r) && r.result == OTAR_ACK_OLD);
	// Joined by key fill just now: taken; the keysets start again from the net's 15 and the throwaway is erased
	ui_svc_net_joined();
	rekey_msg(&m, 15, 77, 0x11, OTAR_RK_NOW | OTAR_RK_RESET);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_active == 15 && otar_kid(&keys, OTAR_ACTIVE, 1, &r.kid) && r.kid == 77 && !tek[201].used && tek[77].used);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_STORED && r.keyset == 15);
	// Then a normal rekey above it is taken as ever
	rekey_msg(&m, 16, 78, 0x12, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_next == 16 && last_out(&r) && r.result == OTAR_ACK_STORED);
	// Past the window after the join: a reset is refused again
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 201);
	tek[201].used = true;
	keys.ks_active = 17;
	ui_svc_net_joined();
	run(25000);
	run(600000);
	rekey_msg(&m, 15, 77, 0x11, OTAR_RK_NOW | OTAR_RK_RESET);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_active == 17 && last_out(&r) && r.result == OTAR_ACK_OLD);
	// From a net control that isn't the authority: refused however soon after the join
	setup(0);
	roster_add(PEER_ID, 2, peer_pub);
	roster_add(OTHER_NC, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 201);
	tek[201].used = true;
	keys.ks_active = 17;
	ui_svc_net_joined();
	run(25000);
	rekey_msg(&m, 15, 77, 0x11, OTAR_RK_NOW | OTAR_RK_RESET);
	m.rank = 2;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	CHECK(keys.ks_active == 17 && tek[201].used);
}

// ... and net control 1 sending it: a HELLO naming a keyset this net never had gets the active key flagged reset; one
// naming the net's next keyset doesn't
static void test_rejoin_reset_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 15;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	out_n = 0;
	memset(&m, 0, sizeof m);
	m.keyset = 17;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && (r.flags & (OTAR_RK_NOW | OTAR_RK_RESET)) == (OTAR_RK_NOW | OTAR_RK_RESET) &&
	      r.keyset == 15 && r.kid == 77);
	// Behind (keyset 12): the catch-up as before, not flagged reset
	run(130000);
	memset(&m, 0, sizeof m);
	m.keyset = 12;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && (r.flags & OTAR_RK_NOW) && !(r.flags & OTAR_RK_RESET) && r.keyset == 15);
	// Just added by key fill, naming the net's own number (a throwaway under it): the active key flagged reset all the
	// same, for the reset window; another radio naming that number is up to date
	run(130000);
	ui_svc_net_member_added(PEER_ID);
	memset(&m, 0, sizeof m);
	m.keyset = 15;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && (r.flags & OTAR_RK_RESET) && r.keyset == 15 && r.kid == 77);
	run(130000);
	ui_svc_net_member_added(OTHER_NC);
	memset(&m, 0, sizeof m);
	m.keyset = 15;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT);
	// Past the window after the add: up to date again
	ui_svc_net_member_added(PEER_ID);
	run(610000);
	memset(&m, 0, sizeof m);
	m.keyset = 15;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT);
	// The net's next keyset (16) held already: up to date, no reset
	CHECK(otar_set_next(&keys, 1, 78, 0, false));
	keys.ks_next = 16;
	tek[78].used = true;
	run(130000);
	memset(&m, 0, sizeof m);
	m.keyset = 16;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT);
}

// A further member k of the engine's net: its ID, public key and pair MAC key with the engine
static void other_member(int k, uint32_t *id, uint8_t pub[32], uint8_t km[32])
{
	x25519_ws_t ws;
	uint8_t priv[32], uk[32];
	for (int i = 0; i < 32; i++)
		priv[i] = (uint8_t)(i * 5 + 11 + k * 17);
	x25519_public(pub, priv, &ws);
	*id = 4690000u + (uint32_t)k;
	CHECK(otar_pair_keys(priv, eng_pub, NET_ID, *id, ENGINE_ID, uk, km, &ws));
}

static int hello_from(uint32_t id, const uint8_t km[32], uint32_t keyset, uint32_t msgnum, uint8_t *out)
{
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.net_id = NET_ID;
	m.msgnum = msgnum;
	m.keyset = keyset;
	otar_addr_t a = { id, ENGINE_ID };
	return otar_hello_build(out, &a, km, &m);
}

static int sent_to(uint32_t id)
{
	int k = 0;
	for (int i = 0; i < out_n; i++)
		k += outbox[i].dst == id;
	return k;
}

// ===================== HELLO always answered (otar.md 9): the engine net control 1, the test members
static void test_hello_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	uint32_t ids[10];
	uint8_t pubs[10][32], kms[10][32];
	for (int k = 0; k < 10; k++) {
		other_member(k, &ids[k], pubs[k], kms[k]);
		roster_add(ids[k], 0, pubs[k]);
	}
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;

	// Up to date: an ACK, CURRENT, echoing the HELLO, with the net control's active keyset, under the pair's keys
	out_n = 0;
	memset(&m, 0, sizeof m);
	m.keyset = 4;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT && r.echo == m.msgnum &&
	      r.keyset == 4 && r.ckr == 0);
	// Its HELLO played back within 2 minutes: nothing
	uint8_t old[OTAR_MSG_MAX];
	int on = build(OTAR_HELLO, &m, old);	// m.msgnum kept: the same message again
	run(30000);
	deliver(PEER_ID, ENGINE_ID, false, old, on);
	run(1000);
	CHECK(out_n == 1);
	// A newer HELLO from it within 2 minutes (its answer was lost; it restarted): answered at once
	run(3000);	// past HELLO_GAP_MS since the played-back one
	memset(&m, 0, sizeof m);
	m.keyset = 4;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(1000);
	CHECK(out_n == 2 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT && r.echo == m.msgnum);
	// ... and the older one played back after it: still nothing
	deliver(PEER_ID, ENGINE_ID, false, old, on);
	run(3000);
	CHECK(out_n == 2);
	out_n = 1;
	// Behind, 2 minutes on: the catch-up REKEY is the answer
	run(120000);
	memset(&m, 0, sizeof m);
	m.keyset = 3;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(1000);
	CHECK(out_n == 2 && last_out(&r) && r.type == OTAR_REKEY && r.keyset == 4 && (r.flags & OTAR_RK_NOW));

	// Two members' recorded HELLOs played back in turn, 3 s apart, for a minute: each answered once
	run(130000);
	out_n = 0;
	int n0 = hello_from(ids[0], kms[0], 3, 500, buf);
	uint8_t buf1[OTAR_MSG_MAX];
	int n1 = hello_from(ids[1], kms[1], 3, 500, buf1);
	for (int i = 0; i < 20; i++) {
		if (i & 1)
			deliver(ids[1], ENGINE_ID, false, buf1, n1);
		else
			deliver(ids[0], ENGINE_ID, false, buf, n0);
		run(3000);
	}
	CHECK(sent_to(ids[0]) == 1 && sent_to(ids[1]) == 1);

	// Ten members asking at once: no more than 8 answers in 2 minutes, whoever asks
	run(130000);
	out_n = 0;
	for (int k = 0; k < 10; k++) {
		deliver(ids[k], ENGINE_ID, false, buf, hello_from(ids[k], kms[k], 4, 600, buf));
		run(3000);
	}
	CHECK(out_n == 8 && sent_to(ids[8]) == 0 && sent_to(ids[9]) == 0);
	// ... and the last two once that time is past
	run(120000);
	for (int k = 8; k < 10; k++) {
		deliver(ids[k], ENGINE_ID, false, buf, hello_from(ids[k], kms[k], 4, 601, buf));
		run(3000);
	}
	CHECK(out_n == 10 && sent_to(ids[8]) == 1 && sent_to(ids[9]) == 1);
}

// ===================== HELLO said again until answered (otar.md 9): the engine a member, the test its net control
static void test_hello_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	out_n = 0;
	uint32_t t0 = now_ms;
	// No answer: HELLO 20 s after start, then 1, 5 and 15 minutes on, then every 15 minutes
	run(3082000u);		// to just past the 6th
	otar_msg_t r;
	CHECK(out_n == 6);
	static const uint32_t want_s[] = { 20, 80, 380, 1280, 2180, 3080 };
	for (int i = 0; i < 6 && i < out_n; i++) {
		uint32_t s = (outbox[i].at - t0) / 1000u;
		CHECK(s >= want_s[i] && s <= want_s[i] + 1u);
		CHECK(out_open(i, &r) && r.type == OTAR_HELLO && r.keyset == 4);
	}
	ui_net_view_t nv;
	ui_svc_net_view(&nv);
	CHECK(nv.hello == UI_HELLO_ASKING);

	// An ACK echoing an older HELLO doesn't answer it; one echoing the last does: up to date, asked no more
	CHECK(out_open(out_n - 1, &r));
	uint32_t last = r.msgnum;
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.result = OTAR_ACK_CURRENT;
	m.echo = last - 1u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
	ui_svc_net_view(&nv);
	CHECK(nv.hello == UI_HELLO_ASKING);
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.result = OTAR_ACK_CURRENT;
	m.echo = last;
	m.keyset = 4;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
	ui_svc_net_view(&nv);
	CHECK(nv.hello == UI_HELLO_CURRENT);
	int before = out_n;
	run(3600000u);
	CHECK(out_n == before);

	// Request keys: a HELLO at once (not twice within 10 s); the net control's catch-up REKEY answers it
	CHECK(ui_svc_net_request_keys(v_now()) == UI_NET_OK);
	run(500);
	CHECK(out_n == before + 1 && out_open(out_n - 1, &r) && r.type == OTAR_HELLO);
	CHECK(ui_svc_net_request_keys(v_now()) == UI_NET_BUSY);
	rekey_msg(&m, 5, 78, 0x58, OTAR_RK_NOW);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(2000);
	ui_svc_net_view(&nv);
	CHECK(nv.hello == UI_HELLO_GOT && keys.ks_active == 5);
	before = out_n;
	run(3600000u);
	CHECK(out_n == before);
}

// The engine's "old message number" ACKs to the test's radio so far
static int msgnum_acks(void)
{
	int k = 0;
	otar_msg_t q;
	for (int i = 0; i < out_n; i++)
		k += out_open(i, &q) && q.type == OTAR_ACK && q.result == OTAR_ACK_MSGNUM;
	return k;
}

// ===================== an old message number answered, rate-limited (otar.md 7.6): the engine a member
static void test_oos_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_INVENTORY, &m, buf));
	run(1000);
	uint32_t last = m.msgnum;
	// A bad MAC: nothing, whatever its number
	out_n = 0;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.msgnum = 5;
	int n = build(OTAR_INVENTORY, &m, buf);
	buf[n - 1] ^= 1u;
	deliver(PEER_ID, ENGINE_ID, false, buf, n);
	run(1000);
	CHECK(out_n == 0);
	// An old number with its MAC right: one answer, MSGNUM, the last number taken, under the pair's keys
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.msgnum = 5;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_INVENTORY, &m, buf));
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_MSGNUM && r.keyset == last &&
	      r.echo == 5);
	// More within 5 minutes, of any type: nothing; after them, one again
	for (int i = 0; i < 4; i++) {
		memset(&m, 0, sizeof m);
		m.rank = 1;
		m.msgnum = 6u + (uint32_t)i;
		m.target = ENGINE_ID;
		deliver(PEER_ID, ENGINE_ID, false, buf, build(i & 1 ? OTAR_ZEROIZE : OTAR_INVENTORY, &m, buf));
		run(60000);
	}
	CHECK(msgnum_acks() == 1);
	run(60000);
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.msgnum = 20;
	m.time_s = 1;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_TIME, &m, buf));
	run(1000);
	CHECK(msgnum_acks() == 2 && last_out(&r) && r.result == OTAR_ACK_MSGNUM && r.keyset == last && r.echo == 20);
}

// ===================== a member's "old message number" (otar.md 7.6): the engine net control 1
static void test_oos_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	out_n = 0;
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(3000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_REKEY);
	uint32_t sent = r.msgnum;
	// Echoing a number it didn't send: ignored
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_MSGNUM;
	m.keyset = sent + 1000u;
	m.echo = sent - 1u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
	CHECK(out_n == 1);
	// The member took up to sent + 1000 from this radio (its settings went back): its numbers skip past, and the
	// REKEY goes again at once
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_MSGNUM;
	m.keyset = sent + 1000u;
	m.echo = sent;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(2000);
	CHECK(out_n == 2 && last_out(&r) && r.type == OTAR_REKEY && r.msgnum > sent + 1000u);
	CHECK(!ui_svc_net_out_of_sync(PEER_ID));
	// Far beyond a skip: out of sync, rejoin; not tried again
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_MSGNUM;
	m.keyset = r.msgnum + 10000000u;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
	uint32_t id;
	uint8_t state, tries;
	CHECK(ui_svc_net_out_of_sync(PEER_ID) && ui_svc_net_rekey_member(0, &id, &state, &tries) && state == UI_RK_SYNC);
	run(300000);
	CHECK(out_n == 2);
}

// The engine's POSITIONs to the test's radio so far
static int positions(void)
{
	int k = 0;
	otar_msg_t q;
	for (int i = 0; i < out_n; i++)
		k += out_open(i, &q) && q.type == OTAR_POSITION;
	return k;
}

static int locate_msg(otar_msg_t *m, uint8_t *buf)
{
	memset(m, 0, sizeof *m);
	m->rank = 1;
	return build(OTAR_LOCATE, m, buf);
}

// ===================== LOCATE answered (otar.md 7.7): the engine a member, the test its net control
static void test_locate_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	uint32_t other;
	uint8_t other_pub[32], other_km[32];
	other_member(3, &other, other_pub, other_km);
	roster_add(other, 0, other_pub);
	live.otar_loc_off = 0;
	saved = live;
	run(1000);
	uint8_t buf[OTAR_MSG_MAX], buf2[OTAR_MSG_MAX];
	otar_msg_t m, r;
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_NOT_NC);	// a member asks no one

	// A fix 40 s old, south of the equator, east: POSITION under the pair's keys, echoing the LOCATE
	fake_fix = true;
	fake_lat = -338688500;
	fake_lon = 1512093000;
	fake_alt = 58;
	fake_ms = now_ms - 40000u;
	out_n = 0;
	int n1 = locate_msg(&m, buf);
	deliver(PEER_ID, ENGINE_ID, false, buf, n1);
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_POSITION && r.echo == m.msgnum && r.result == OTAR_POS_OK &&
	      r.lat == -338688500 && r.lon == 1512093000 && r.alt_m == 58 && r.age_s >= 40 && r.age_s <= 41);
	CHECK(outbox[0].dst == PEER_ID && !outbox[0].group);
	// The same LOCATE played back at once, and 11 s on: never a second POSITION (at most "old message number")
	deliver(PEER_ID, ENGINE_ID, false, buf, n1);
	run(1000);
	CHECK(out_n == 1);
	run(10000);
	deliver(PEER_ID, ENGINE_ID, false, buf, n1);
	run(1000);
	CHECK(positions() == 1);
	// A fresh one within 10 s of an answer: not answered; past the 10 s: answered (altitude unknown, a fix of now)
	run(10000);
	fake_alt = POSITION_ALT_NONE;
	fake_ms = now_ms;
	deliver(PEER_ID, ENGINE_ID, false, buf, locate_msg(&m, buf));
	run(1000);
	CHECK(positions() == 2 && last_out(&r) && r.echo == m.msgnum && r.alt_m == OTAR_ALT_NONE && r.age_s <= 1);
	int before = out_n;
	deliver(PEER_ID, ENGINE_ID, false, buf, locate_msg(&m, buf));
	run(2000);
	CHECK(out_n == before);

	// Share location off: refused, and no position in it
	live.otar_loc_off = 1;
	ui_net_view_t nv;
	ui_svc_net_view(&nv);
	CHECK(!nv.share_location);
	run(10000);
	deliver(PEER_ID, ENGINE_ID, false, buf, locate_msg(&m, buf));
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_POSITION && r.echo == m.msgnum && r.result == OTAR_POS_REFUSED &&
	      r.lat == 0 && r.lon == 0);
	// On again, no fix: "no fix"
	ui_svc_net_set_share_location(true);
	CHECK(live.otar_loc_off == 0 && saved.otar_loc_off == 0);
	ui_svc_net_view(&nv);
	CHECK(nv.share_location);
	fake_fix = false;
	run(11000);
	deliver(PEER_ID, ENGINE_ID, false, buf, locate_msg(&m, buf));
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_POSITION && r.echo == m.msgnum && r.result == OTAR_POS_NO_FIX && r.lat == 0);
	fake_fix = true;

	// Radio silence: nothing at all
	run(11000);
	before = out_n;
#if CONFIG_RADIO_SILENCE
	radio_silence_flag = true;
	deliver(PEER_ID, ENGINE_ID, false, buf, locate_msg(&m, buf));
	run(2000);
	CHECK(out_n == before);
	radio_silence_flag = false;
#endif

	// Not from a net control: a member of the roster saying it is one, a radio off the roster, a bad MAC
	memset(&m, 0, sizeof m);
	m.net_id = NET_ID;
	m.rank = 1;
	m.msgnum = 900;
	otar_addr_t oa = { other, ENGINE_ID };
	deliver(other, ENGINE_ID, false, buf2, otar_locate_build(buf2, &oa, other_km, &m));
	run(2000);
	CHECK(out_n == before);
	otar_addr_t xa = { 4699999u, ENGINE_ID };
	deliver(4699999u, ENGINE_ID, false, buf2, otar_locate_build(buf2, &xa, other_km, &m));
	run(2000);
	CHECK(out_n == before);
	int n = locate_msg(&m, buf);
	buf[n - 1] ^= 1u;
	deliver(PEER_ID, ENGINE_ID, false, buf, n);
	run(2000);
	CHECK(out_n == before);
	// ... and the net control's next one is answered as ever
	deliver(PEER_ID, ENGINE_ID, false, buf, locate_msg(&m, buf));
	run(1000);
	CHECK(out_n == before + 1 && last_out(&r) && r.type == OTAR_POSITION && r.result == OTAR_POS_OK);

	// A join sets Share location on again
	live.otar_loc_off = 1;
	ui_svc_net_joined();
	CHECK(live.otar_loc_off == 0 && saved.otar_loc_off == 0);
	fake_fix = false;
}

// A POSITION from the test's radio, answering LOCATE number echo
static int position_msg(uint32_t echo, uint8_t result, int32_t lat, int32_t lon, uint16_t age, uint8_t *buf)
{
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.echo = echo;
	m.result = result;
	m.lat = lat;
	m.lon = lon;
	m.alt_m = 12;
	m.age_s = age;
	return build(OTAR_POSITION, &m, buf);
}

// ===================== LOCATE asked until answered (otar.md 7.7): the engine net control 1, the test a member
static void test_locate_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	uint32_t other;
	uint8_t other_pub[32], other_km[32];
	other_member(4, &other, other_pub, other_km);
	roster_add(other, 0, other_pub);
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t r;
	ui_loc_view_t lv;
	fake_fix = false;

	// A POSITION nobody asked for: nothing shown
	deliver(PEER_ID, ENGINE_ID, false, buf, position_msg(1, OTAR_POS_OK, 1, 1, 0, buf));
	run(500);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_NONE);

	out_n = 0;
	CHECK(ui_svc_net_locate(v_now(), ENGINE_ID) == UI_NET_NO_MEMBER);
	CHECK(ui_svc_net_locate(v_now(), 4699999u) == UI_NET_NO_MEMBER);
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_OK);
	CHECK(ui_svc_net_locate(v_now(), other) == UI_NET_BUSY);	// one at a time
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_LOCATE && r.rank == 1);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_ASKING);
	uint32_t asked = r.msgnum;
	// Echoing another number, or from a radio it didn't ask: not the answer
	deliver(PEER_ID, ENGINE_ID, false, buf, position_msg(asked - 1u, OTAR_POS_OK, 1, 1, 0, buf));
	run(500);
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.net_id = NET_ID;
	m.msgnum = 77;
	m.echo = asked;
	m.lat = 5;
	otar_addr_t oa = { other, ENGINE_ID };
	deliver(other, ENGINE_ID, false, buf, otar_position_build(buf, &oa, other_km, &m));
	run(500);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_ASKING);
	ui_svc_net_locate_view(other, &lv);
	CHECK(lv.state == UI_LOC_NONE);
	// The answer: shown with its age, which goes on counting; no range without this radio's own position
	deliver(PEER_ID, ENGINE_ID, false, buf, position_msg(asked, OTAR_POS_OK, -338688500, -1512093000, 40, buf));
	run(500);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_GOT && lv.lat == -338688500 && lv.lon == -1512093000 && lv.alt_m == 12 &&
	      lv.age_s >= 40 && lv.age_s <= 41 && !lv.range);
	run(60000);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.age_s >= 100 && lv.age_s <= 101 && out_n == 1);	// and no more tries
#if CONFIG_POSITION
	// With this radio's own position: the distance and bearing from it
	fake_fix = true;
	fake_lat = -338688500 + 85000;	// 850 m north of the member
	fake_lon = -1512093000;
	fake_alt = 0;
	fake_ms = now_ms;
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.range && lv.dist_m == 850 && lv.bearing == 180);
	fake_fix = false;
#endif
	// Another POSITION echoing the same LOCATE (a replay): changes nothing
	run(1000);
	deliver(PEER_ID, ENGINE_ID, false, buf, position_msg(asked, OTAR_POS_REFUSED, 0, 0, 0, buf));
	run(500);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_GOT);

	// No answer: 3 tries, 20 s apart, then shown as no answer (a radio from before drops type 10 unread)
	out_n = 0;
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_OK);
	run(90000);
	int tries = 0;
	for (int i = 0; i < out_n; i++)
		tries += out_open(i, &r) && r.type == OTAR_LOCATE;
	CHECK(tries == 3 && out_n == 3);
	CHECK(out_n == 3 && outbox[1].at - outbox[0].at >= 20000u && outbox[2].at - outbox[1].at >= 20000u);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_NO_ANSWER);

	// Refused, and no fix, as the member says; a second try's answer counts (each echoes its own try)
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_OK);
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_LOCATE);
	deliver(PEER_ID, ENGINE_ID, false, buf, position_msg(r.msgnum, OTAR_POS_REFUSED, 0, 0, 0, buf));
	run(500);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_REFUSED);
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_OK);
	run(21000);
	CHECK(out_n == 6 && last_out(&r) && r.type == OTAR_LOCATE);
	deliver(PEER_ID, ENGINE_ID, false, buf, position_msg(r.msgnum, OTAR_POS_NO_FIX, 0, 0, 0, buf));
	run(500);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_NO_FIX && lv.age_s == 0);
	// ... with its age, so an old "no fix" isn't taken for a new one (found on the bench, 2026-11-27)
	run(60000);
	ui_svc_net_locate_view(PEER_ID, &lv);
	CHECK(lv.state == UI_LOC_NO_FIX && lv.age_s >= 60 && lv.age_s <= 61);

	// During a rekey run (one by the clocks stays open until its changeover): asked at once all the same, not held
	// back until the run ends (found on the bench: "asking" for as long as the run)
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(1000);
	CHECK(ui_svc_net_rekey(v_now(), 60) == UI_NET_OK);
	run(3000);
	out_n = 0;
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_OK);
	run(25000);
	int asked_in_run = 0;
	for (int i = 0; i < out_n; i++)
		asked_in_run += out_open(i, &r) && r.type == OTAR_LOCATE;
	ui_rekey_view_t rv;
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.on && asked_in_run >= 1);
}

// ===================== the net's channel (otar.md 7.8)
static void dmr_channel(const char *name, uint32_t hz, uint8_t cc, uint8_t ts)
{
	memset(&view.ch, 0, sizeof view.ch);
	snprintf(view.ch.name, sizeof view.ch.name, "%s", name);
	view.ch.mode = RADIO_MODE_DMR;
	view.ch.rx_hz = hz;
	view.ch.tx_hz = hz;
	view.ch.color_code = cc;
	view.ch.timeslot = ts;
}

static void chan_msg(otar_msg_t *m, uint32_t hz, uint8_t cc_ts, const char *name)
{
	memset(m, 0, sizeof *m);
	m->rank = 1;
	m->chan.rx_hz = hz;
	m->chan.tx_hz = hz;
	m->chan.cc_ts = cc_ts;
	memcpy(m->chan.name, name, strlen(name));
}

// The engine's ACK to `to` echoing `echo`, opened under km; its result, or -1 for none
static int ack_of(uint32_t to, const uint8_t km[32], uint32_t echo)
{
	for (int i = 0; i < out_n; i++) {
		otar_msg_t r;
		otar_addr_t a = { ENGINE_ID, to };
		if (outbox[i].dst == to && otar_open(outbox[i].m, outbox[i].len, &a, NULL, km, &r) && r.type == OTAR_ACK &&
		    r.echo == echo)
			return r.result;
	}
	return -1;
}

// The engine a member: it takes the net's channel from net control 1, not from a backup one; joining sets the one it
// joined on
static void test_netchan_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	uint32_t nc2;
	uint8_t nc2_pub[32], nc2_km[32];
	other_member(0, &nc2, nc2_pub, nc2_km);
	roster_add(nc2, 2, nc2_pub);
	dmr_channel("SNT TAC A", 451650000u, 1, 2);
	run(1000);
	out_n = 0;

	// Joined on SNT TAC A: that is the net's channel until net control 1 says another
	ui_svc_net_joined();
	run(500);
	CHECK(live.otar_chan.rx_hz == 451650000u && live.otar_chan.cc_ts == (1u | OTAR_CHAN_TS2) &&
	      memcmp(live.otar_chan.name, "SNT TAC A", 9) == 0);
	CHECK(ui_svc_net_on_chan(v_now()));

	// Net control 1's NETCHAN: stored, ACKed STORED echoing it
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m;
	chan_msg(&m, 464500000u, 1u, "AES TEST");
	int len = build(OTAR_NETCHAN, &m, buf);
	CHECK(len == (int)OTAR_NETCHAN_LEN);
	deliver(PEER_ID, ENGINE_ID, false, buf, len);
	run(1000);
	CHECK(ack_of(PEER_ID, kmac, m.msgnum) == OTAR_ACK_STORED);
	CHECK(live.otar_chan.rx_hz == 464500000u && live.otar_chan.cc_ts == 1u &&
	      memcmp(live.otar_chan.name, "AES TEST", 9) == 0);
	// Tuned to SNT TAC A it is away from it; on 464.5 with color code 1 on timeslot 1 it is on it, whatever the name
	CHECK(!ui_svc_net_on_chan(v_now()));
	dmr_channel("ANOTHER NAME", 464500000u, 1, 1);
	CHECK(ui_svc_net_on_chan(v_now()));
	dmr_channel("AES TEST", 464500000u, 2, 1);	// another color code
	CHECK(!ui_svc_net_on_chan(v_now()));
	view.ch.color_code = 1;
	view.ch.mode = RADIO_MODE_FM;
	CHECK(!ui_svc_net_on_chan(v_now()));
	view.ch.mode = RADIO_MODE_DMR;

	// A backup net control's: refused, nothing stored
	otar_msg_t b;
	chan_msg(&b, 446000000u, 3u, "ELSEWHERE");
	b.rank = 2;
	b.net_id = NET_ID;
	b.msgnum = 900;
	otar_addr_t a2 = { nc2, ENGINE_ID };
	len = otar_netchan_build(buf, &a2, nc2_km, &b);
	deliver(nc2, ENGINE_ID, false, buf, len);
	run(1000);
	CHECK(ack_of(nc2, nc2_km, 900) == OTAR_ACK_REFUSED);
	CHECK(live.otar_chan.rx_hz == 464500000u);

	// Played back: not taken again (an old message number); a control character in the name: dropped unanswered
	int before = out_n;
	chan_msg(&m, 446000000u, 1u, "OLD");
	m.msgnum = peer_msgnum - 1u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_NETCHAN, &m, buf));
	run(1000);
	CHECK(live.otar_chan.rx_hz == 464500000u);
	chan_msg(&m, 446000000u, 1u, "BAD\x01");
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_NETCHAN, &m, buf));
	run(1000);
	CHECK(live.otar_chan.rx_hz == 464500000u && ack_of(PEER_ID, kmac, m.msgnum) == -1);
	(void)before;

	// Leave: the net's channel goes with the net
	ui_svc_net_leave();
	CHECK(live.otar_chan.rx_hz == 0);
}

// The engine net control 1: Net channel sends the channel on view to every member, an ACK counts it; a HELLO answered
// is followed by the channel; off DMR, or as a backup net control, it isn't set
static void test_netchan_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	dmr_channel("AES TEST", 464500000u, 1, 1);
	run(3000);
	out_n = 0;

	view.ch.mode = RADIO_MODE_FM;
	CHECK(ui_svc_net_set_channel(v_now()) == UI_NET_NOT_DMR);
	view.ch.mode = RADIO_MODE_DMR;
	CHECK(ui_svc_net_set_channel(v_now()) == UI_NET_OK);
	CHECK(live.otar_chan.rx_hz == 464500000u && memcmp(live.otar_chan.name, "AES TEST", 9) == 0);
	CHECK(ui_svc_net_set_channel(v_now()) == UI_NET_BUSY);	// one run at a time
	run(1000);
	otar_msg_t r;
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_NETCHAN && r.chan.rx_hz == 464500000u && r.chan.cc_ts == 1u &&
	      memcmp(r.chan.name, "AES TEST", 9) == 0);
	ui_roster_view_t rv;
	ui_svc_net_roster_view(&rv);
	CHECK(rv.on && rv.chan_only && rv.sent == 0);
	// The member's ACK: counted, the run done (one member)
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_STORED;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
	ui_svc_net_roster_view(&rv);
	CHECK(!rv.on && rv.done && rv.sent == 1 && rv.failed == 0 && out_n == 1);

	// No answer: tried 3 times, then counted
	CHECK(ui_svc_net_set_channel(v_now()) == UI_NET_OK);
	run(70000);
	ui_svc_net_roster_view(&rv);
	CHECK(!rv.on && rv.failed == 1 && out_n == 4);

	// Send the roster: the net's channel goes after the member's entries
	out_n = 0;
	CHECK(ui_svc_net_roster_send(0) == UI_NET_OK);
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_ROSTER);
	memset(&m, 0, sizeof m);
	m.result = OTAR_ACK_STORED;
	m.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_NETCHAN && r.chan.rx_hz == 464500000u);

	// A member's HELLO, up to date: CURRENT, then the net's channel
	run(200000);
	out_n = 0;
	memset(&m, 0, sizeof m);
	m.keyset = 4;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(2000);
	CHECK(out_n == 2 && out_open(0, &r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT);
	CHECK(out_open(1, &r) && r.type == OTAR_NETCHAN && r.chan.rx_hz == 464500000u);

	// A backup net control doesn't set it: members take it from net control 1 only
	setup(2);
	roster_add(OTHER_NC, 1, peer_pub);
	roster_add(ENGINE_ID, 2, eng_pub);
	run(1000);
	CHECK(ui_svc_net_set_channel(v_now()) == UI_NET_NOT_FIRST);
}

// ===================== the planned change (otar.md 7.9): the engine a member, the test its net control
static void withdraw_msg(otar_msg_t *m, uint32_t keyset, uint8_t kid)
{
	memset(m, 0, sizeof *m);
	m->rank = 1;
	m->keyset = keyset;
	m->kid = kid;
}

static void test_planned_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	// The next keyset 5 by the clocks
	uint32_t at = v_now()->otar.now_min + 60u;
	rekey_msg(&m, 5, 78, 0x55, OTAR_RK_CLOCK);
	m.changeover = at;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_STORED && keys.ks_next == 5 && keys.changeover == at);

	// Move the change: the same keyset again with another changeover. HELD, and the changeover moved; by hand too
	rekey_msg(&m, 5, 78, 0x55, OTAR_RK_CLOCK);
	m.changeover = at + 300u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_HELD && keys.changeover == at + 300u && (keys.flags & OTAR_F_OWN_CLOCK));
	rekey_msg(&m, 5, 78, 0x55, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_HELD && keys.changeover == 0 && !(keys.flags & OTAR_F_OWN_CLOCK));
	// ... but never with another key under that number
	rekey_msg(&m, 5, 78, 0x66, OTAR_RK_CLOCK);
	m.changeover = at;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && keys.changeover == 0);

	// WITHDRAW naming another key ID under keyset 5: refused, kept
	withdraw_msg(&m, 5, 99);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WITHDRAW, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_REFUSED && keys.ks_next == 5);
	// The right one: dropped, its key erased, ACK DROPPED for keyset 5 (CKR 1: a keyset's answer) echoing it
	withdraw_msg(&m, 5, 78);
	int wn = build(OTAR_WITHDRAW, &m, buf);
	uint8_t replay[OTAR_MSG_MAX];
	memcpy(replay, buf, (size_t)wn);
	deliver(PEER_ID, ENGINE_ID, false, buf, wn);
	run(1000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_DROPPED && r.keyset == 5 && r.ckr == 1 &&
	      r.echo == m.msgnum);
	CHECK(!(keys.flags & OTAR_F_NEXT) && !tek[78].used && keys.ks_active == 4 && keys.kid_active[0] == 77);
	// Played back: not answered as DROPPED again
	int before = out_n;
	deliver(PEER_ID, ENGINE_ID, false, replay, wn);
	run(1000);
	CHECK(out_n == before || (last_out(&r) && r.result == OTAR_ACK_MSGNUM));
	// Not held (any more): DROPPED all the same; the active keyset: OLD (too late)
	withdraw_msg(&m, 5, 78);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WITHDRAW, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_DROPPED);
	withdraw_msg(&m, 4, 77);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WITHDRAW, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_OLD && keys.ks_active == 4 && tek[77].used);
	// From a member (rank 0 in the roster): not answered
	roster_add(PEER_ID, 0, peer_pub);
	before = out_n;
	withdraw_msg(&m, 5, 78);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WITHDRAW, &m, buf));
	run(1000);
	CHECK(out_n == before);
}

// The engine net control 1, the test a member
static uint32_t cut_of(void)
{
	return (uint32_t)live.otar_cut[0] << 8 | live.otar_cut[1];
}

static void ack_rekey(uint32_t keyset, const otar_msg_t *sent, uint8_t result, uint8_t *buf)
{
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.keyset = keyset;
	m.ckr = 1;
	m.result = result;
	m.echo = sent->msgnum;
	(void)kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, sent->tek, 32, m.kcv);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
}

static void test_planned_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t r;
	ui_rekey_view_t rv;
	// Nothing planned: nothing to move or cancel
	CHECK(ui_svc_net_move(v_now(), 60) == UI_NET_NO_NEXT && ui_svc_net_cancel_change(v_now()) == UI_NET_NO_NEXT);
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && r.keyset == 5 && r.changeover == 0);
	uint8_t kid = r.kid;
	ack_rekey(5, &r, OTAR_ACK_STORED, buf);
	run(500);
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.on && !rv.cancel && rv.done == 1);

	// Move the change to an hour from now: this radio's next moved, the member sent the REKEY again with it
	uint32_t want = v_now()->otar.now_min + 60u;
	CHECK(ui_svc_net_move(v_now(), 60) == UI_NET_OK);
	CHECK(keys.changeover == want && (keys.flags & OTAR_F_OWN_CLOCK));
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.done == 0 && rv.changeover == want);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && r.keyset == 5 && r.kid == kid && r.changeover == want &&
	      (r.flags & OTAR_RK_CLOCK));
	ack_rekey(5, &r, OTAR_ACK_HELD, buf);
	run(500);
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.done == 1);

	// Cancel the change: this radio's next and its key gone, the withdrawn keyset kept, WITHDRAW to the member
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_OK);
	CHECK(!(keys.flags & OTAR_F_NEXT) && !tek[kid].used && keys.ks_active == 4 && cut_of() == 5 && live.otar_cut_kid == kid);
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_NO_NEXT);	// once
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.on && rv.cancel && rv.done == 0);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_WITHDRAW && r.keyset == 5 && r.kid == kid);
	// An ACK HELD (a late answer to the REKEY) doesn't count; DROPPED does, and the run ends
	otar_msg_t a;
	memset(&a, 0, sizeof a);
	a.keyset = 5;
	a.ckr = 1;
	a.result = OTAR_ACK_DROPPED;
	a.echo = r.msgnum;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &a, buf));
	run(500);
	ui_svc_net_rekey_view(&rv);
	CHECK(!rv.on);

	// The member, off during the cancel run, says HELLO still holding keyset 5 next: WITHDRAW it
	otar_msg_t h;
	memset(&h, 0, sizeof h);
	h.keyset = 4;
	h.next_keyset = 5;
	h.flags = 1;
	run(3000);
	out_n = 0;
	int before = out_n;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &h, buf));
	run(2000);
	CHECK(out_n > before && last_out(&r) && r.type == OTAR_WITHDRAW && r.keyset == 5 && r.kid == kid);
	// Holding another next keyset: an ACK CURRENT, no WITHDRAW
	memset(&h, 0, sizeof h);
	h.keyset = 4;
	h.next_keyset = 6;
	h.flags = 1;
	run(130000);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &h, buf));
	run(2000);
	CHECK(last_out(&r) && r.type == OTAR_ACK && r.result == OTAR_ACK_CURRENT);

	// The next rekey numbers its keyset past the withdrawn one: 6, this radio's next keyset too
	out_n = 0;
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && r.keyset == 6 && keys.ks_next == 6);
	// Cancelled with the member not answering: a new Rekey now replaces the cancel run at once
	ack_rekey(6, &r, OTAR_ACK_STORED, buf);
	run(500);
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_OK && cut_of() == 6);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_WITHDRAW && r.keyset == 6);
	run(ACK_WAIT_TEST_MS);
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(3000);
	CHECK(last_out(&r) && r.type == OTAR_REKEY && r.keyset == 7 && keys.ks_next == 7);
	// Leaving the net forgets the withdrawn keyset
	ui_svc_net_leave();
	CHECK(cut_of() == 0 && live.otar_cut_kid == 0);
}

// ===================== radio silence (radio-silence.md 3): a reply is dropped, only what the user starts goes
#if CONFIG_RADIO_SILENCE
static void test_silence_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	radio_silence_flag = true;
	out_n = 0;
	// The automatic HELLO at start waits
	run(25000);
	CHECK(out_n == 0);
	// A REKEY is taken (the radio keeps up with the net) but not ACKed; a ZEROIZE wipes without its ACK
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	rekey_msg(&m, 5, 78, 0x55, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(out_n == 0 && keys.ks_next == 5 && keys.kid_next[0] == 78);
	memset(&m, 0, sizeof m);
	m.rank = 1;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_INVENTORY, &m, buf));
	run(1000);
	CHECK(out_n == 0);
	// The user's Request keys goes
	CHECK(ui_svc_net_request_keys(v_now()) == UI_NET_OK);
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_HELLO);
	// Silence ends: the radio answers again
	radio_silence_flag = false;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_INVENTORY, &m, buf));
	run(1000);
	CHECK(out_n > 1 && last_out(&r) && r.type == OTAR_ACK);
	// Remote wipe under silence: the keys go, no ACK
	radio_silence_flag = true;
	live.otar_wipe = 1;
	saved = live;
	wipes = 0;
	int before = out_n;
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.target = ENGINE_ID;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ZEROIZE, &m, buf));
	run(2000);
	CHECK(wipes == 1 && out_n == before);
	radio_silence_flag = false;
}

static void test_silence_nc(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	radio_silence_flag = true;
	out_n = 0;
	// A member's HELLO (behind, up to date): no answer of any kind
	memset(&m, 0, sizeof m);
	m.keyset = 3;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(3000);
	memset(&m, 0, sizeof m);
	m.keyset = 4;
	run(3000);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(3000);
	CHECK(out_n == 0);
	// The user's Rekey now goes, and so do its retries
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(3000);
	CHECK(out_n == 1 && last_out(&r) && r.type == OTAR_REKEY && r.keyset == 5);
	run(90000);
	CHECK(out_n >= 2 && last_out(&r) && r.type == OTAR_REKEY);
	radio_silence_flag = false;
	// Silence ends: a HELLO is answered again
	out_n = 0;
	memset(&m, 0, sizeof m);
	m.keyset = 4;
	run(130000);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_HELLO, &m, buf));
	run(3000);
	CHECK(out_n >= 1);
}
// A scheduled rekey is the user's own: under radio silence it goes, and so does its CHANGEOVER at the changeover
static void test_silence_sched(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(3000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t r;
	radio_silence_flag = true;
	uint32_t due = v_now()->otar.now_min;
	live.otar_sched = 1;
	live.otar_sched_at[0] = (uint8_t)(due >> 16);
	live.otar_sched_at[1] = (uint8_t)(due >> 8);
	live.otar_sched_at[2] = (uint8_t)due;
	saved = live;
	out_n = 0;
	run(15000);
	int rekeys = 0;
	for (int i = 0; i < out_n; i++)
		rekeys += out_open(i, &r) && r.type == OTAR_REKEY && r.keyset == 5;
	CHECK(rekeys >= 1);
	// The member ACKs; the clocks change the net over: CHANGEOVER to the talkgroup all the same
	CHECK(last_out(&r) && r.type == OTAR_REKEY);
	ack_rekey(5, &r, OTAR_ACK_STORED, buf);
	run(500);
	view.dmr.target_id = 9;
	view.dmr.target_private = false;
	(void)otar_change_over(&keys);
	out_n = 0;
	run(10000);
	int co = 0;
	for (int i = 0; i < out_n; i++)
		co += outbox[i].group && outbox[i].m[2] == OTAR_CHANGEOVER;
	CHECK(co >= 1);
	view.dmr.target_id = 0;
	radio_silence_flag = false;
	live.otar_sched = 0;
	memset(live.otar_sched_at, 0, sizeof live.otar_sched_at);
	saved = live;
}

// A schedule in hours: the rekey when due, its changeover a quarter of the way to the next (15 min of an hour), the next
// due an hour on
static void test_sched_hourly(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	run(3000);
	otar_msg_t r;
	uint32_t due = v_now()->otar.now_min;
	live.otar_sched = OTAR_SCHED_HOURS | 1u;
	live.otar_sched_at[0] = (uint8_t)(due >> 16);
	live.otar_sched_at[1] = (uint8_t)(due >> 8);
	live.otar_sched_at[2] = (uint8_t)due;
	saved = live;
	out_n = 0;
	run(15000);
	int rekeys = 0;
	uint32_t co = 0;
	for (int i = 0; i < out_n; i++)
		if (out_open(i, &r) && r.type == OTAR_REKEY && r.keyset == 5) {
			rekeys++;
			co = r.changeover;
		}
	CHECK(rekeys >= 1);
	uint32_t now = v_now()->otar.now_min;
	CHECK(co >= now + 14u && co <= now + 15u);
	uint32_t next = ((uint32_t)live.otar_sched_at[0] << 16) | ((uint32_t)live.otar_sched_at[1] << 8) |
			live.otar_sched_at[2];
	CHECK(next >= now + 59u && next <= now + 60u);
	live.otar_sched = 0;
	memset(live.otar_sched_at, 0, sizeof live.otar_sched_at);
	saved = live;
}
#endif

// ===================== the second review (2026-11-27): cancel and move, made safe
static int count_type(uint8_t type)
{
	int k = 0;
	otar_msg_t r;
	for (int i = 0; i < out_n; i++)
		k += out_open(i, &r) && r.type == type;
	return k;
}

static void drop_release(void)
{
	uint32_t v = drop_held;
	drop_held = 0xFFFFu;
	drop_mode = 0;
	if (v != 0xFFFFu)
		radio_req_otar(RADIO_OTAR_DROP_NEXT, v);
}

static void nc_with_next(uint16_t mins, otar_msg_t *sent, uint8_t *buf)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	drop_mode = 0;
	run(3000);
	CHECK(ui_svc_net_rekey(v_now(), mins) == UI_NET_OK);
	run(3000);
	CHECK(last_out(sent) && sent->type == OTAR_REKEY && sent->keyset == 5);
	ack_rekey(5, sent, OTAR_ACK_STORED, buf);
	run(500);
}

static void test_review2_nc(void)
{
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t r, a;
	ui_rekey_view_t rv;

	// A cancel run stays open past the withdrawn changeover, so a member on air that missed it is still told before
	// its clock would change it over; its tries back off (1, 2, 5, 15 minutes)
	nc_with_next(60, &r, buf);
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_OK);
	out_n = 0;
	for (int i = 0; i < 30; i++)
		run(60000);	// 30 minutes, the member silent
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.on && rv.cancel);
	int tries = count_type(OTAR_WITHDRAW);
	CHECK(tries >= 3 && tries <= 7);
	for (int i = 0; i < 40; i++)
		run(60000);	// past the changeover (60 min) and its 5 min spare
	ui_svc_net_rekey_view(&rv);
	CHECK(!rv.on);

	// Not within 2 minutes of the changeover by the clocks
	nc_with_next(5, &r, buf);
	run(4u * 60000u);
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_TOO_LATE);
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.on && !rv.cancel);

	// This radio's own drop lost: asked again until made
	nc_with_next(60, &r, buf);
	drop_mode = 1;
	drop_asks = 0;
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_OK);
	CHECK(keys.flags & OTAR_F_NEXT);	// the first request lost
	run(5000);
	CHECK(drop_asks >= 2 && !(keys.flags & OTAR_F_NEXT));

	// Too late on this radio (it changed over before its drop was made): the cancel becomes the key sent flagged now,
	// the withdrawn number forgotten
	nc_with_next(60, &r, buf);
	drop_mode = 3;
	uint8_t kid = r.kid;
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_OK);
	(void)otar_change_over(&keys);	// its clock, first
	out_n = 0;
	run(5000);
	CHECK(last_out(&a) && a.type == OTAR_REKEY && a.keyset == 5 && a.kid == kid && (a.flags & OTAR_RK_NOW));
	CHECK(live.otar_cut[0] == 0 && live.otar_cut[1] == 0);
	CHECK(count_type(OTAR_WITHDRAW) == 0);
	drop_mode = 0;
	ack_rekey(5, &a, OTAR_ACK_HELD, buf);
	run(1000);
	ui_svc_net_rekey_view(&rv);
	CHECK(!rv.on);

	// A scheduled rekey doesn't replace a cancel run; Rekey now does, once its run exists
	nc_with_next(60, &r, buf);
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_OK);
	uint32_t due = v_now()->otar.now_min;
	live.otar_sched = 1;
	live.otar_sched_at[0] = (uint8_t)(due >> 16);
	live.otar_sched_at[1] = (uint8_t)(due >> 8);
	live.otar_sched_at[2] = (uint8_t)due;
	saved = live;
	run(15000);
	ui_svc_net_rekey_view(&rv);
	CHECK(rv.on && rv.cancel);
	live.otar_sched = 0;
	memset(live.otar_sched_at, 0, sizeof live.otar_sched_at);
	saved = live;

	// A failed send is its own job's: a LOCATE that fails while a REKEY's ACK is awaited leaves the REKEY waiting
	nc_with_next(0, &r, buf);
	CHECK(ui_svc_net_move(v_now(), 60) == UI_NET_OK);
	run(3000);	// the REKEY again, its ACK awaited
	CHECK(last_out(&r) && r.type == OTAR_REKEY);
	CHECK(ui_svc_net_locate(v_now(), PEER_ID) == UI_NET_OK);
	send_state = OTAR_SEND_FAILED;
	run(1500);
	send_state = OTAR_SEND_SENT;
	uint32_t id;
	uint8_t state, t2;
	CHECK(ui_svc_net_rekey_member(0, &id, &state, &t2) && state == UI_RK_SENT);

	// After a move, an ACK of the REKEY sent before it never counts, even while another request makes ACKs wanted
	nc_with_next(0, &r, buf);
	uint32_t old = r.msgnum;
	CHECK(ui_svc_net_inventory(v_now(), PEER_ID) == UI_NET_OK);
	run(1000);
	CHECK(ui_svc_net_move(v_now(), 60) == UI_NET_OK);
	memset(&a, 0, sizeof a);
	a.keyset = 5;
	a.ckr = 1;
	a.result = OTAR_ACK_STORED;
	a.echo = old;
	(void)kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, r.tek, 32, a.kcv);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &a, buf));
	run(300);
	CHECK(ui_svc_net_rekey_member(0, &id, &state, &t2) && state != UI_RK_OK);

	// Only net control 1 cancels: a backup net control is refused
	nc_with_next(60, &r, buf);
	uint32_t nc1;
	uint8_t nc1_pub[32], nc1_km[32];
	other_member(5, &nc1, nc1_pub, nc1_km);
	roster_add(nc1, 1, nc1_pub);
	roster_add(ENGINE_ID, 2, eng_pub);
	CHECK(ui_svc_net_cancel_change(v_now()) == UI_NET_NOT_FIRST);
}

// The member's side: DROPPED only once the drop is made; OLD when its clock got there first; WITHDRAW from net control
// 1 only; an INVENTORY's answers apart from a REKEY's ACK; a changeover past 24 bits refused
static void test_review2_member(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	drop_mode = 0;
	run(25000);
	uint8_t buf[OTAR_MSG_MAX];
	otar_msg_t m, r;
	rekey_msg(&m, 5, 78, 0x55, OTAR_RK_CLOCK);
	m.changeover = v_now()->otar.now_min + 60u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(keys.ks_next == 5);

	// Held: no answer yet; made: DROPPED
	drop_mode = 2;
	out_n = 0;
	withdraw_msg(&m, 5, 78);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WITHDRAW, &m, buf));
	run(1000);
	CHECK(out_n == 0);
	drop_release();
	run(1000);
	CHECK(out_n == 1 && last_out(&r) && r.result == OTAR_ACK_DROPPED && r.echo == m.msgnum);

	// The clock first: the drop comes too late, the answer is OLD
	rekey_msg(&m, 6, 79, 0x66, OTAR_RK_CLOCK);
	m.changeover = v_now()->otar.now_min + 60u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(keys.ks_next == 6);
	drop_mode = 2;
	out_n = 0;
	withdraw_msg(&m, 6, 79);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_WITHDRAW, &m, buf));
	run(500);
	(void)otar_change_over(&keys);
	drop_release();
	run(3000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_OLD && keys.ks_active == 6);

	// A changeover past the radio's 24 bits: refused
	rekey_msg(&m, 7, 80, 0x77, OTAR_RK_CLOCK);
	m.changeover = 0x1000000u;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(last_out(&r) && r.result == OTAR_ACK_REFUSED && !(keys.flags & OTAR_F_NEXT));

	// INVENTORY, then a REKEY before its second answer: each ACK echoes its own message, the REKEY's its own keyset
	rekey_msg(&m, 7, 80, 0x77, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(1000);
	CHECK(keys.ks_next == 7);
	out_n = 0;
	otar_msg_t inv;
	memset(&inv, 0, sizeof inv);
	inv.rank = 1;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_INVENTORY, &inv, buf));
	rekey_msg(&m, 8, 81, 0x88, 0);
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_REKEY, &m, buf));
	run(3000);
	uint8_t k8[3];
	kcv_of(0x88, k8);
	bool rk_ok = true, inv_ok = true;
	int rk_n = 0, inv_n = 0;
	for (int i = 0; i < out_n; i++) {
		if (!out_open(i, &r) || r.type != OTAR_ACK)
			continue;
		if (r.echo == m.msgnum) {
			rk_n++;
			rk_ok &= r.keyset == 8 && memcmp(r.kcv, k8, 3) == 0;
		} else if (r.echo == inv.msgnum) {
			inv_n++;
			inv_ok &= r.keyset == 6 || r.keyset == 7;
		}
	}
	CHECK(rk_n == 1 && rk_ok && inv_n >= 1 && inv_ok);

	// WITHDRAW from a backup net control (not net control 1): not answered, nothing dropped
	uint32_t nc2;
	uint8_t nc2_pub[32], nc2_km[32];
	other_member(6, &nc2, nc2_pub, nc2_km);
	roster_add(nc2, 2, nc2_pub);
	out_n = 0;
	memset(&m, 0, sizeof m);
	m.net_id = NET_ID;
	m.rank = 2;
	m.msgnum = 500;
	m.keyset = 8;
	m.kid = 81;
	otar_addr_t a2 = { nc2, ENGINE_ID };
	int wn = otar_withdraw_build(buf, &a2, nc2_km, &m);
	deliver(nc2, ENGINE_ID, false, buf, wn);
	run(2000);
	CHECK(out_n == 0 && keys.ks_next == 8);
}

#if CONFIG_RADIO_SILENCE
// Request keys under radio silence: a few HELLOs only, as no answer comes under it
static void test_review2_silence(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	radio_silence_flag = true;
	run(25000);
	out_n = 0;
	CHECK(ui_svc_net_request_keys(v_now()) == UI_NET_OK);
	for (int i = 0; i < 120; i++)
		run(60000);	// two hours
	CHECK(count_type(OTAR_HELLO) == 3);
	radio_silence_flag = false;
}
#endif

// ===================== asking for keys on voice it can't decrypt (otar.md 30): the engine a member
// A call heard under key ID kid that the radio couldn't play (the call stack's count, through the radio view)
static void key_missed(uint8_t kid)
{
	view.dmr.key_missed++;
	view.dmr.key_missed_alg = DMR_AES_ALG_AES256;
	view.dmr.key_missed_kid = kid;
}

// The net control's ACK of the engine's last HELLO: up to date
static void hello_up_to_date(void)
{
	otar_msg_t r, m;
	uint8_t buf[OTAR_MSG_MAX];
	CHECK(last_out(&r) && r.type == OTAR_HELLO);
	memset(&m, 0, sizeof m);
	m.rank = 1;
	m.result = OTAR_ACK_CURRENT;
	m.echo = r.msgnum;
	m.keyset = 4;
	deliver(PEER_ID, ENGINE_ID, false, buf, build(OTAR_ACK, &m, buf));
	run(1000);
}

static void test_auto_request(void)
{
	setup(0);
	roster_add(PEER_ID, 1, peer_pub);
	roster_add(ENGINE_ID, 0, eng_pub);
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	view.ch.mode = RADIO_MODE_DMR;	// on the channel whose keys it manages (system 0)
	view.ch.kind = CODEPLUG_KIND_DMR_AES;
	view.ch.system = 0;
	run(25000);		// the HELLO at start, answered
	hello_up_to_date();
	ui_net_view_t nv;
	ui_svc_net_view(&nv);
	CHECK(nv.hello == UI_HELLO_CURRENT);
	out_n = 0;

	// The net's voice under key 90, which it doesn't hold: one HELLO, shown as asking
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 1 && out_n == 1);
	ui_svc_net_view(&nv);
	CHECK(nv.hello == UI_HELLO_ASKING);
	// ... unanswered: the HELLO's own retries, a minute on, and no more for further calls meanwhile
	key_missed(90);
	run(61000);
	CHECK(count_type(OTAR_HELLO) == 2);
	hello_up_to_date();
	// Again within 3 minutes of the first: none
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 2);
	// Past them: another
	run(120000);
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 3);
	// ... left unanswered: its retry a minute on; past 3 minutes a further call while it is still pending asks nothing
	run(61000);
	CHECK(count_type(OTAR_HELLO) == 4);
	run(121000);
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 4);
	hello_up_to_date();
	run(181000);
	// Under a key it holds (a call it couldn't play for another reason): none
	key_missed(77);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 4);
	// Another algorithm: none
	view.dmr.key_missed++;
	view.dmr.key_missed_alg = 0x21;
	view.dmr.key_missed_kid = 90;
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 4);
	// On another channel (not the managed system's): none
	view.ch.system = 3;
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 4);
	view.ch.system = 0;
#if CONFIG_RADIO_SILENCE
	// Under radio silence: none, nor once it ends (the call was heard under it)
	radio_silence_flag = true;
	key_missed(90);
	run(1000);
	radio_silence_flag = false;
	run(60000);
	CHECK(count_type(OTAR_HELLO) == 4);
#endif
	// Not managing keys: none
	otar_stop(&keys);
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 4);
	// ... nor later: managing keys again, nothing goes until such a call is heard again, which asks
	otar_start(&keys, 0, 77);
	keys.ks_active = 4;
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 4);
	key_missed(90);
	run(1000);
	CHECK(count_type(OTAR_HELLO) == 5);

	// A net control: none
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	otar_start(&keys, 0, 77);
	keys.ks_active = 4;
	run(3000);
	out_n = 0;
	key_missed(90);
	run(30000);
	CHECK(out_n == 0);
	memset(&view.ch, 0, sizeof view.ch);
}

// ===================== Check all members (otar.md 30): the engine net control 1, the test its members
// The engine's message i to member id, opened under that pair's MAC key
static bool open_to(int i, uint32_t id, const uint8_t km[32], otar_msg_t *r)
{
	otar_addr_t a = { ENGINE_ID, id };
	return i >= 0 && i < out_n && outbox[i].dst == id && otar_open(outbox[i].m, outbox[i].len, &a, NULL, km, r);
}

// Member id's ACK of an INVENTORY (echo) for one keyset
static void inv_answer(uint32_t id, const uint8_t km[32], uint32_t echo, uint8_t result, uint32_t keyset,
		       const uint8_t kcv[3])
{
	otar_msg_t m;
	uint8_t buf[OTAR_MSG_MAX];
	memset(&m, 0, sizeof m);
	m.net_id = NET_ID;
	m.msgnum = ++peer_msgnum;
	m.ckr = 1;
	m.result = result;
	m.keyset = keyset;
	m.echo = echo;
	if (kcv != NULL)
		memcpy(m.kcv, kcv, 3);
	otar_addr_t a = { id, ENGINE_ID };
	deliver(id, ENGINE_ID, false, buf, otar_ack_build(buf, &a, km, &m));
}

static int rc_asking(void)
{
	int k = 0;
	ui_rc_member_t m;
	for (uint16_t i = 0; ui_svc_net_rollcall_member(i, &m); i++)
		k += m.state == UI_RC_ASKING;
	return k;
}

static bool rc_of(uint32_t id, ui_rc_member_t *out)
{
	for (uint16_t i = 0; ui_svc_net_rollcall_member(i, out); i++)
		if (out->id == id)
			return true;
	return false;
}

static void test_rollcall(void)
{
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	uint32_t ids[4];
	uint8_t pubs[4][32], kms[4][32];
	ids[0] = PEER_ID;
	memcpy(pubs[0], peer_pub, 32);
	memcpy(kms[0], kmac, 32);
	roster_add(PEER_ID, 0, peer_pub);
	for (int k = 1; k < 4; k++) {
		other_member(k, &ids[k], pubs[k], kms[k]);
		roster_add(ids[k], 0, pubs[k]);
	}
	otar_member_t rv;	// the fourth revoked: never asked
	CHECK(otar_roster_find(ids[3], &rv));
	rv.flags |= OTAR_M_REVOKED;
	CHECK(otar_roster_put(&rv));
	otar_start(&keys, 0, 77);
	tek[77].used = true;
	keys.ks_active = 4;
	CHECK(otar_set_next(&keys, 1, 78, 0, false));	// a next keyset, 5, here
	keys.ks_next = 5;
	tek[78].used = true;
	memset(tek[78].k, 0x78, 32);
	uint8_t kcv4[3], kcv5[3], kcv_x[3];
	CHECK(kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, tek[77].k, 32, kcv4));
	kcv_of(0x78, kcv5);
	kcv_of(0x31, kcv_x);
	run(3000);
	out_n = 0;

	CHECK(ui_svc_net_rollcall(v_now()) == UI_NET_OK);
	CHECK(ui_svc_net_rollcall(v_now()) == UI_NET_BUSY);		// running: not started again
	CHECK(ui_svc_net_inventory(v_now(), PEER_ID) == UI_NET_BUSY);	// one INVENTORY at a time
	ui_rc_view_t cv;
	ui_svc_net_rollcall_view(&cv);
	CHECK(cv.on && !cv.done && cv.members == 3 && cv.ok == 0);
	// One in flight: the first member asked, unanswered for 15 s, and no one else
	run(15000);
	int inv = 0;
	otar_msg_t r;
	for (int i = 0; i < out_n; i++)
		for (int k = 0; k < 4; k++)
			inv += open_to(i, ids[k], kms[k], &r) && r.type == OTAR_INVENTORY;
	CHECK(inv == 1 && rc_asking() == 1);

	// The first on the roster doesn't answer at all (asked 3 times); the second answers its active keyset, 3 (behind);
	// the third its active and next keysets, both this radio's (OK, next 5)
	int asked[4] = { 0 }, order[16], on = 0, seen = 0, most = 0;
	for (int step = 0; step < 600 && cv.on; step++) {
		for (; seen < out_n; seen++) {
			for (int k = 0; k < 4; k++) {
				if (!open_to(seen, ids[k], kms[k], &r) || r.type != OTAR_INVENTORY)
					continue;
				asked[k]++;
				if (on < 16)
					order[on++] = k;
				if (k == 2) {
					inv_answer(ids[2], kms[2], r.msgnum, OTAR_ACK_HELD, 4, kcv4);
					inv_answer(ids[2], kms[2], r.msgnum, OTAR_ACK_HELD, 5, kcv5);
				} else if (k == 1) {
					inv_answer(ids[1], kms[1], r.msgnum, OTAR_ACK_HELD, 3, kcv_x);
				}
			}
		}
		run(500);
		int a = rc_asking();
		most = a > most ? a : most;
		ui_svc_net_rollcall_view(&cv);
	}
	CHECK(!cv.on && cv.done && cv.members == 3 && cv.ok == 1);
	CHECK(asked[0] == 3 && asked[1] == 1 && asked[2] == 1 && asked[3] == 0 && most == 1);
	// Each member asked once before one is asked again (the first, unanswered, not again at once)
	CHECK(on >= 3 && order[0] != order[1] && order[1] != order[2] && order[0] != order[2]);
	ui_rc_member_t mr;
	CHECK(rc_of(ids[2], &mr) && mr.state == UI_RC_OK && mr.keyset == 4 && mr.next == 5);
	CHECK(rc_of(ids[1], &mr) && mr.state == UI_RC_BEHIND && mr.keyset == 3);
	CHECK(rc_of(ids[0], &mr) && mr.state == UI_RC_NO_ANSWER);
	CHECK(!rc_of(ids[3], &mr));
	// Done: the answers stay; Ask its keys goes again
	run(60000);
	ui_svc_net_rollcall_view(&cv);
	CHECK(cv.done && cv.ok == 1);
	CHECK(ui_svc_net_inventory(v_now(), PEER_ID) == UI_NET_OK);
	run(21000);

	// Started again once done: every member waiting, then asked again. The first holds its active keyset alone (OK, no
	// next); the second keyset 4 under another key; the third manages no keys
	CHECK(ui_svc_net_rollcall(v_now()) == UI_NET_OK);
	ui_svc_net_rollcall_view(&cv);
	CHECK(cv.on && cv.ok == 0);
	CHECK(rc_of(ids[0], &mr) && (mr.state == UI_RC_WAIT || mr.state == UI_RC_ASKING));
	memset(asked, 0, sizeof asked);
	seen = out_n;
	for (int step = 0; step < 600 && cv.on; step++) {
		for (; seen < out_n; seen++) {
			for (int k = 0; k < 4; k++) {
				if (!open_to(seen, ids[k], kms[k], &r) || r.type != OTAR_INVENTORY)
					continue;
				asked[k]++;
				if (k == 0)
					inv_answer(ids[0], kms[0], r.msgnum, OTAR_ACK_HELD, 4, kcv4);
				else if (k == 1)
					inv_answer(ids[1], kms[1], r.msgnum, OTAR_ACK_HELD, 4, kcv_x);
				else if (k == 2)
					inv_answer(ids[2], kms[2], r.msgnum, OTAR_ACK_NOT_MANAGED, 0, NULL);
			}
		}
		run(500);
		ui_svc_net_rollcall_view(&cv);
	}
	CHECK(!cv.on && cv.ok == 1 && asked[0] == 1 && asked[1] == 1 && asked[2] == 1);
	CHECK(rc_of(ids[0], &mr) && mr.state == UI_RC_OK && mr.keyset == 4 && mr.next == 0);
	CHECK(rc_of(ids[1], &mr) && mr.state == UI_RC_OTHER && mr.keyset == 4);
	CHECK(rc_of(ids[2], &mr) && mr.state == UI_RC_NO_KEYS);

#if CONFIG_RADIO_SILENCE
	// Under radio silence: the user started it, so it goes
	radio_silence_flag = true;
	out_n = 0;
	CHECK(ui_svc_net_rollcall(v_now()) == UI_NET_OK);
	run(1000);
	inv = 0;
	for (int i = 0; i < out_n; i++)
		for (int k = 0; k < 4; k++)
			inv += open_to(i, ids[k], kms[k], &r) && r.type == OTAR_INVENTORY;
	CHECK(inv == 1);
	radio_silence_flag = false;
#endif

	// Alongside a rekey run: its REKEYs go while the check waits for an answer
	setup(1);
	roster_add(ENGINE_ID, 1, eng_pub);
	roster_add(PEER_ID, 0, peer_pub);
	for (int k = 1; k < 3; k++)
		roster_add(ids[k], 0, pubs[k]);
	otar_start(&keys, 0, 77);
	keys.ks_active = 4;
	run(3000);
	out_n = 0;
	CHECK(ui_svc_net_rollcall(v_now()) == UI_NET_OK);
	run(1000);
	CHECK(ui_svc_net_rekey(v_now(), 0) == UI_NET_OK);
	run(5000);
	int rekeys = 0;
	inv = 0;
	for (int i = 0; i < out_n; i++)
		for (int k = 0; k < 3; k++) {
			rekeys += outbox[i].dst == ids[k] && outbox[i].m[2] == OTAR_REKEY;	// its type, in the clear
			inv += open_to(i, ids[k], kms[k], &r) && r.type == OTAR_INVENTORY;
		}
	CHECK(rekeys >= 1 && inv == 1);
	// Leaving the net forgets it
	ui_svc_net_leave();
	run(1000);
	ui_svc_net_rollcall_view(&cv);
	CHECK(!cv.on && !cv.done && cv.members == 0);
}

int main(void)
{
	test_msgnum();
	test_member();
	test_ranks();
	test_nc();
	test_join_without_key();
	test_zeroize_member();
	test_zeroize_nc();
	test_wipe_radio();
	test_silence_remote_member();
	test_silence_remote_nc();
	test_silent_revoke_member();
	test_silent_revoke_nc();
	test_rejoin_reset_member();
	test_rejoin_reset_nc();
	test_hello_nc();
	test_hello_member();
	test_oos_member();
	test_oos_nc();
	test_locate_member();
	test_locate_nc();
	test_netchan_member();
	test_netchan_nc();
	test_planned_member();
	test_planned_nc();
#if CONFIG_RADIO_SILENCE
	test_silence_member();
	test_silence_nc();
	test_silence_sched();
	test_sched_hourly();
#endif
	test_review2_nc();
	test_review2_member();
#if CONFIG_RADIO_SILENCE
	test_review2_silence();
#endif
	test_auto_request();
	test_rollcall();
	printf("otarEngineTest: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
