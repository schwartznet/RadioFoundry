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
#include "otar/otar_api.h"
#include "otar/otar_crypto.h"
#include "otar/otar_keys.h"
#include "otar/otar_msg.h"
#include "otar/otar_net.h"
#include "radio/radio.h"
#include "support/kcv.h"
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
	volatile bool put_done, put_ok;	// the last put: done, and stored
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

static void eng_view(ui_net_view_t *v);

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
	v->remote_wipe = SETTINGS_FIELD(otar_wipe) == 1u;
	eng_view(v);
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
	if (net.job == 1) {
		net.put_ok = otar_roster_put(&net.member);
		net.put_done = true;
	} else if (net.job == 2)
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

static bool engine_tick(const radio_view_t *v, uint32_t now);

bool ui_svc_net_tick(const radio_view_t *v, uint32_t now)
{
	bool changed = engine_tick(v, now);
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

uint8_t ui_svc_net_member_flags(uint16_t i)
{
	uint32_t id;
	uint8_t rank, fp[3];
	if (!ui_svc_net_member(i, &id, &rank, fp))
		return 0;
	return net.page[i - net.page_first].flags;
}

// ======================= Rekeying (otar.md 7, 9; phase 3) =======================
// On the UI task: X25519 for a pair's keys takes a moment. One message out at a time (the transport's); a net
// control's run sends REKEY to each member in turn, waits for its ACK, and tries the ones that didn't answer again

#define ACK_WAIT_MS	20000u		// a member's ACK after its REKEY went
#define RETRY_MS	60000u		// a member that didn't answer is tried again after this
#define HELLO_AFTER_MS	20000u		// a member says HELLO this long after start (and after joining)
#define CO_COPIES	3u		// CHANGEOVER copies to the talkgroup
#define CO_GAP_MS	2000u

typedef struct {
	uint32_t id;
	uint8_t state;		// UI_RK_*
	uint8_t tries;
	uint32_t due;		// when it is sent (again)
} rk_member_t;

typedef struct {
	bool keyed;		// the TEK is made and stored here
	bool store_due, stored;
	bool armed;		// this radio's view shows the key as next: from then on, its going ends the run
	uint32_t armed_by;	// ... which it must within this time of the request
	uint8_t tek[OTAR_KEY_LEN];
	uint8_t kid;
	uint8_t system;
	uint32_t keyset;
	uint32_t changeover;
	uint8_t n;
	uint8_t cur;		// the member whose ACK is awaited, 0xFF none
	uint32_t ack_by;
	rk_member_t m[OTAR_ROSTER_MAX - 1u];
} rekey_t;

static struct {
	bool open;
	bool sending;
	// The message waiting for the transport
	uint8_t out[OTAR_MSG_MAX];
	uint8_t out_len;
	uint8_t in[OTAR_MSG_MAX];	// the message taken from the transport (static: off the UI task's stack)
	uint32_t out_dst;
	bool out_group;
	// A member's keys with its net control, kept once worked out
	uint32_t pair_id;
	bool pair_ok;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	// A member: the TEK of a REKEY being stored, then its ACK
	bool tek_due;
	volatile bool tek_job, tek_done, tek_ok;
	uint8_t tek[OTAR_KEY_LEN];
	uint8_t tek_system, tek_kid;
	uint32_t tek_at;	// the changeover
	otar_msg_t ack;		// the ACK to send once stored
	uint32_t ack_to;
	// HELLO
	uint32_t started_ms;
	bool hello_sent;
	// CHANGEOVER copies to send
	uint8_t co_left;
	uint32_t co_next;
	uint8_t co_msg[OTAR_MSG_MAX];
	uint8_t co_len;
	uint32_t co_tg;
	bool co_then_local;
	rekey_t *rk;		// the net control's run, on the heap
	// A member: a ROSTER entry being stored (net.member), then its ACK
	bool ros_due;
	// The net control's roster run: each wanted (member, entry) pair in roster order, one at a time, ACKed
	struct {
		bool on, done, waiting;
		bool one, to_it;	// only's entry alone, to every member (and to only itself when to_it)
		uint32_t only;		// 0: every entry to every member; else this member's entry to all, and all to it
		uint16_t dst_i, ent_i;	// the roster positions of the member sent to, and of the entry sent
		uint32_t dst;		// the member whose ACK is awaited
		uint8_t tries;
		uint32_t ack_by;
		uint16_t sent, failed, asked;
	} ros;
	// A member: a take over to ask the user about (otar.md 10): the lost net control's entry, revoked, and who says so
	struct {
		bool on;
		uint8_t from_rank;
		otar_member_t e;
	} pend;
	uint32_t zz_to;		// a net control: ZEROIZE to send to this member (0 none)
	// Scratch off the UI task's stack: the roster run's member and entry, and its message
	otar_member_t ros_d, ros_e;
	otar_msg_t ros_m;
} eng;

#define ROS_TRIES	3u	// a roster entry no ACK came for is sent this many times, then counted as failed
#define ROS_SCAN	4u	// roster pairs looked at per tick
static void ros_start(uint32_t only, bool one, bool to_it);

// A net control's message number: true when above the last taken from that rank's net control (then kept), so a
// replay or an old message is refused. Rank 1 in otar_seen, ranks 2-4 in otar_seen_nc (otar.md 7)
static bool take_msgnum(uint8_t rank, uint32_t msgnum, uint32_t now)
{
	if (rank < 1u || rank > OTAR_RANK_MAX)
		return false;
	settings_t *st = settings_begin();
	uint32_t *seen = rank == 1u ? &st->otar_seen : &st->otar_seen_nc[rank - 2u];
	bool fresh = msgnum > *seen;
	if (fresh)
		*seen = msgnum;
	settings_end(now);
	return fresh;
}

static uint32_t next_msgnum(uint32_t now)
{
	settings_t *st = settings_begin();
	uint32_t n = ++st->otar_msgnum;
	settings_end(now);
	return n;
}

// The pair keys with radio id (whose public key is in the roster): false when it isn't, or X25519 refuses
__attribute__((noinline)) static bool pair_keys(uint32_t own, uint32_t id, uint16_t net_id, uint8_t ukek[OTAR_KEY_LEN], uint8_t kmac[OTAR_KEY_LEN])
{
	otar_member_t m;
	if (!otar_roster_find(id, &m))
		return false;
	x25519_ws_t *ws = pvPortMalloc(sizeof *ws);
	if (ws == NULL)
		return false;
	otar_net_t n;
	net_read(&n);
	bool ok = has_key(&n) && otar_pair_keys(n.priv, m.pub, net_id, own, id, ukek, kmac, ws);
	crypto_wipe(&n, sizeof n);
	vPortFree(ws);
	return ok;
}

// A message built straight into eng.out (only while it is free)
static void out_set(uint32_t dst, bool group, int len)
{
	if (len <= 0 || len > (int)OTAR_MSG_MAX)
		return;
	eng.out_len = (uint8_t)len;
	eng.out_dst = dst;
	eng.out_group = group;
}

static void queue_out(uint32_t dst, bool group, const uint8_t *msg, int len)
{
	if (len <= 0 || len > (int)OTAR_MSG_MAX)
		return;
	memcpy(eng.out, msg, (size_t)len);
	eng.out_len = (uint8_t)len;
	eng.out_dst = dst;
	eng.out_group = group;
}

static void tek_job(void *ctx)
{
	(void)ctx;
	eng.tek_ok = codeplug_traffic_key_set(eng.tek_system, DMR_AES_ALG_AES256, eng.tek_kid, eng.tek, OTAR_KEY_LEN);
	eng.tek_done = true;
	eng.tek_job = false;
}

// A member: a REKEY from its net control (7.1)
__attribute__((noinline)) static void on_rekey(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src, const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED) || eng.tek_due || eng.tek_job ||
	    eng.ros_due || eng.out_len != 0)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t m;
	if (!otar_open(msg, len, &a, eng.ukek, eng.kmac, &m) || m.net_id != n->net_id) {
		crypto_wipe(&m, sizeof m);
		return;
	}
	bool fresh = take_msgnum(nc.rank, m.msgnum, now);
	memset(&eng.ack, 0, sizeof eng.ack);
	eng.ack.net_id = n->net_id;
	eng.ack.keyset = m.keyset;
	eng.ack.ckr = m.ckr;
	eng.ack_to = src;
	(void)kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, m.tek, OTAR_KEY_LEN, eng.ack.kcv);
	if (!v->otar.on) {
		eng.ack.result = OTAR_ACK_NOT_MANAGED;
	} else if (v->otar.has_next && v->otar.next_kid == m.kid && ui_svc_aes_key_there(v->otar.system, m.kid)) {
		eng.ack.result = OTAR_ACK_HELD;	// a resend: already stored
	} else if (!fresh) {
		eng.ack.result = OTAR_ACK_OLD;
	} else {
		// Stored by the housekeeping task, then made the next keyset, then ACKed (engine_tick)
		memcpy(eng.tek, m.tek, OTAR_KEY_LEN);
		eng.tek_system = v->otar.system;
		eng.tek_kid = m.kid;
		eng.tek_at = m.changeover;
		eng.tek_due = true;
		crypto_wipe(&m, sizeof m);
		return;
	}
	crypto_wipe(&m, sizeof m);
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, &eng.ack));
}

// A ROSTER (7.5) from a net control: one roster entry, stored (net.member, the housekeeping task), then ACKed. Refused:
// an entry that would change a net control of higher rank than the sender's, or would revoke this radio (both wait for
// phase 4's confirmation on the radio, otar.md 10). An entry for this radio sets its rank
static __attribute__((noinline)) void on_roster(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED) || eng.tek_due || eng.tek_job ||
	    eng.ros_due || eng.out_len != 0 || net.want_put || net.job_running)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || !take_msgnum(nc.rank, m->msgnum, now))
		return;
	memset(&eng.ack, 0, sizeof eng.ack);
	eng.ack.net_id = n->net_id;
	eng.ack.rank = n->rank;
	eng.ack_to = src;
	otar_member_t *e = &eng.ros_e, *old = &eng.ros_d;
	bool ok = otar_member_unpack(m->rec, OTAR_ROSTER_REC, e) && e->id != 0;
	if (ok)
		otar_fingerprint(e->pub, eng.ack.kcv);
	bool found = ok && otar_roster_find(e->id, old);
	bool same = found && old->rank == e->rank && old->flags == e->flags && memcmp(old->pub, e->pub, X25519_LEN) == 0;
	bool higher = found && !same && old->rank != 0 && old->rank < nc.rank;
	// A lower net control saying a higher one is lost: revoking it, nothing else changed. Asked on this radio
	bool takeover = higher && e->rank == old->rank && (e->flags & OTAR_M_REVOKED) && !(old->flags & OTAR_M_REVOKED) &&
			memcmp(old->pub, e->pub, X25519_LEN) == 0;
	if (!ok || (higher && !takeover) || (e->id == v->dmr.own_id && (e->flags & OTAR_M_REVOKED))) {
		eng.ack.result = OTAR_ACK_REFUSED;
	} else if (takeover) {
		if (!eng.pend.on || eng.pend.e.id == e->id) {
			eng.pend.on = true;
			eng.pend.from_rank = nc.rank;
			eng.pend.e = *e;
		}
		eng.ack.result = OTAR_ACK_ASKED;
	} else if (same) {
		eng.ack.result = OTAR_ACK_HELD;
	} else {
		net.member = *e;	// stored by the housekeeping task, then ACKed (engine_tick)
		net.put_done = false;
		net.want_put = true;
		eng.ros_due = true;
		return;
	}
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, &eng.ack));
}

// A member: the ROSTER entry stored (or not): this radio's own rank when it was the entry, then the ACK
static __attribute__((noinline)) void ros_stored(const radio_view_t *v, uint32_t now)
{
	eng.ros_due = false;
	eng.ack.result = net.put_ok ? OTAR_ACK_STORED : OTAR_ACK_STORE_FAILED;
	if (net.put_ok && net.member.id == v->dmr.own_id && net.member.rank <= OTAR_RANK_MAX) {
		settings_t *st = settings_begin();
		st->otar_net.rank = net.member.rank;
		settings_end(now);
	}
	net.page_ok = false;
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, eng.ack_to };
	out_set(eng.ack_to, false, otar_ack_build(eng.out, &a, eng.kmac, &eng.ack));
}

// ZEROIZE (7.5) from a net control on the roster: this radio's keys wiped (Clear all keys, then a restart), only when
// its Remote wipe is on. No answer
static __attribute__((noinline)) void on_zeroize(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						 const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (SETTINGS_FIELD(otar_wipe) != 1u || !otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED))
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || m->target != v->dmr.own_id ||
	    !take_msgnum(nc.rank, m->msgnum, now))
		return;
#if CONFIG_ZEROIZE
	(void)ui_svc_clear_keys_start();
#endif
}

// A net control: the ZEROIZE asked for (ui_svc_net_wipe), once the transport is free
static __attribute__((noinline)) void zz_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.zz_to;
	eng.zz_to = 0;
	if (!eng.pair_ok || eng.pair_id != to) {
		eng.pair_ok = pair_keys(v->dmr.own_id, to, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = to;
	}
	if (!eng.pair_ok)
		return;
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->msgnum = next_msgnum(now);
	m->target = to;
	otar_addr_t a = { v->dmr.own_id, to };
	out_set(to, false, otar_zeroize_build(eng.out, &a, eng.kmac, m));
}

// A member: CHANGEOVER from its net control, under the key from the next TEK (7.3)
__attribute__((noinline)) static void on_changeover(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src, uint32_t dst,
			  const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!v->otar.on || !v->otar.has_next || !otar_roster_find(src, &nc) || nc.rank == 0)
		return;
	uint8_t tek[OTAR_KEY_LEN], k[OTAR_KEY_LEN];
	if (codeplug_traffic_key(v->otar.system, DMR_AES_ALG_AES256, v->otar.next_kid, tek, sizeof tek) != (int)sizeof tek)
		return;
	otar_group_mac_key(tek, k);
	crypto_wipe(tek, sizeof tek);
	otar_addr_t a = { src, dst };
	otar_msg_t m;
	bool ok = otar_open(msg, len, &a, NULL, k, &m) && m.net_id == n->net_id && m.kid == v->otar.next_kid;
	crypto_wipe(k, sizeof k);
	if (ok) {
		radio_req_otar(RADIO_OTAR_NOW, 0);
		(void)now;
	}
}

// The net control: an ACK or a HELLO from a member
__attribute__((noinline)) static void on_member(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src, const otar_net_t *n, uint32_t now)
{
	rekey_t *rk = eng.rk;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	if (!pair_keys(v->dmr.own_id, src, n->net_id, ukek, kmac))
		return;
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t m;
	bool ok = otar_open(msg, len, &a, NULL, kmac, &m) && m.net_id == n->net_id;
	crypto_wipe(ukek, sizeof ukek);
	crypto_wipe(kmac, sizeof kmac);
	if (!ok)
		return;
	if (m.type == OTAR_ACK && m.ckr == 0) {		// a roster entry's
		if (eng.ros.on && eng.ros.waiting && src == eng.ros.dst) {
			eng.ros.waiting = false;
			if (m.result == OTAR_ACK_STORED || m.result == OTAR_ACK_HELD)
				eng.ros.sent++;
			else if (m.result == OTAR_ACK_ASKED)
				eng.ros.asked++;
			else
				eng.ros.failed++;
			eng.ros.ent_i++;
			eng.ros.tries = 0;
		}
		return;
	}
	if (rk == NULL)
		return;
	for (uint8_t i = 0; i < rk->n; i++) {
		rk_member_t *mm = &rk->m[i];
		if (mm->id != src)
			continue;
		if (m.type == OTAR_ACK && m.keyset == rk->keyset) {
			mm->state = m.result == OTAR_ACK_STORED || m.result == OTAR_ACK_HELD ? UI_RK_OK : UI_RK_FAIL;
			if (rk->cur == i)
				rk->cur = 0xFF;
			if (mm->state == UI_RK_FAIL)
				mm->due = now + RETRY_MS;
		} else if (m.type == OTAR_HELLO && mm->state != UI_RK_OK) {
			mm->due = now;		// back on: its REKEY at once (warm start)
			if (mm->state == UI_RK_FAIL)
				mm->state = UI_RK_WAIT;
		}
	}
}

static void rk_free(void)
{
	if (eng.rk != NULL) {
		crypto_wipe(eng.rk, sizeof *eng.rk);
		vPortFree(eng.rk);
		eng.rk = NULL;
	}
}

// The net control's run: make and store the key, set it as this radio's next, then REKEY each member in turn
__attribute__((noinline)) static bool rk_step(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	rekey_t *rk = eng.rk;
	if (rk == NULL)
		return false;
	if (!rk->keyed) {
		if (entropy_bits() < ENTROPY_FULL)
			return true;	// the screen counts the presses down
		entropy_take(rk->tek, OTAR_KEY_LEN);
		rk->keyed = true;
		rk->store_due = true;
		memcpy(eng.tek, rk->tek, OTAR_KEY_LEN);
		eng.tek_system = rk->system;
		eng.tek_kid = rk->kid;
		eng.tek_job = true;
		eng.tek_done = false;
		if (!storage_job_post(tek_job, NULL))
			eng.tek_job = false;
		return true;
	}
	if (rk->store_due) {
		if (eng.tek_job)
			return false;
		if (!eng.tek_done) {
			eng.tek_job = true;
			if (!storage_job_post(tek_job, NULL))
				eng.tek_job = false;
			return false;
		}
		eng.tek_done = false;
		crypto_wipe(eng.tek, sizeof eng.tek);
		rk->store_due = false;
		if (!eng.tek_ok) {
			rk_free();
			return true;
		}
		radio_req_otar(RADIO_OTAR_NEXT_AT, rk->kid | (rk->changeover << 8));
		rk->armed_by = now + 30000u;	// the radio makes it between overs (radio_aes_otar_defer)
		return true;
	}
	// The radio task takes the request on its next turn: the run starts once the view shows the key as next, and
	// ends once the net has changed over (this radio's next keyset is gone)
	bool shown = v->otar.has_next && v->otar.next_kid == rk->kid;
	if (!rk->armed) {
		if (shown) {
			rk->armed = true;
		} else {
			if ((int32_t)(now - rk->armed_by) >= 0)
				rk_free();	// the radio didn't take it: no run
			return false;
		}
	}
	if (!shown) {
		rk_free();
		return true;
	}
	if (rk->cur != 0xFF) {
		if ((int32_t)(now - rk->ack_by) >= 0) {
			rk->m[rk->cur].state = UI_RK_FAIL;
			rk->m[rk->cur].due = now + RETRY_MS;
			rk->cur = 0xFF;
			return true;
		}
		return false;
	}
	if (eng.out_len != 0 || eng.sending)
		return false;
	for (uint8_t i = 0; i < rk->n; i++) {
		rk_member_t *mm = &rk->m[i];
		if (mm->state == UI_RK_OK || (int32_t)(now - mm->due) < 0)
			continue;
		uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
		if (!pair_keys(v->dmr.own_id, mm->id, n->net_id, ukek, kmac)) {
			mm->state = UI_RK_FAIL;
			mm->due = now + RETRY_MS;
			continue;
		}
		otar_msg_t m;
		memset(&m, 0, sizeof m);
		m.net_id = n->net_id;
		m.rank = n->rank;
		m.msgnum = next_msgnum(now);
		m.keyset = rk->keyset;
		m.ckr = 1;
		m.kid = rk->kid;
		m.changeover = rk->changeover;
		m.flags = rk->changeover != 0 ? 1u : 0u;
		memcpy(m.tek, rk->tek, OTAR_KEY_LEN);
		otar_addr_t a = { v->dmr.own_id, mm->id };
		int len = otar_rekey_build(eng.out, &a, ukek, kmac, &m);
		crypto_wipe(&m, sizeof m);
		crypto_wipe(ukek, sizeof ukek);
		crypto_wipe(kmac, sizeof kmac);
		out_set(mm->id, false, len);
		mm->state = UI_RK_SENT;
		mm->tries++;
		rk->cur = i;
		rk->ack_by = now + ACK_WAIT_MS;
		return true;
	}
	return false;
}

// The net control's roster run: is entry e wanted at member d?
static bool ros_wanted(const otar_member_t *d, const otar_member_t *e, uint32_t own)
{
	if (d->id == own || (d->flags & OTAR_M_REVOKED))
		return false;
	if (eng.ros.one)
		return e->id == eng.ros.only && (d->id != eng.ros.only || eng.ros.to_it);
	if (e->id == d->id)
		return false;
	if (eng.ros.only == 0)
		return true;
	return e->id != own && ((d->id == eng.ros.only) != (e->id == eng.ros.only));
}

// The net control's roster run: the next wanted pair, its ROSTER out, then its ACK (on_member) or a try again
static __attribute__((noinline)) bool ros_step(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	if (!eng.ros.on || eng.rk != NULL || net.want_put || net.job_running)
		return false;	// this radio's own roster write goes first (a rank or a revoke)
	if (eng.ros.waiting) {
		if ((int32_t)(now - eng.ros.ack_by) < 0)
			return false;
		eng.ros.waiting = false;
		if (++eng.ros.tries >= ROS_TRIES) {
			eng.ros.failed++;
			eng.ros.ent_i++;
			eng.ros.tries = 0;
		}
		return true;
	}
	if (eng.out_len != 0 || eng.sending)
		return false;
	otar_member_t *d = &eng.ros_d, *e = &eng.ros_e;
	for (unsigned k = 0; k < ROS_SCAN; k++) {
		uint16_t total = 0;
		if (otar_roster_window(eng.ros.dst_i, d, 1, &total) != 1) {
			eng.ros.on = false;	// every member done
			eng.ros.done = true;
			return true;
		}
		if (eng.ros.ent_i >= total) {
			eng.ros.dst_i++;
			eng.ros.ent_i = 0;
			continue;
		}
		if (otar_roster_window(eng.ros.ent_i, e, 1, &total) != 1 || !ros_wanted(d, e, v->dmr.own_id)) {
			eng.ros.ent_i++;
			continue;
		}
		if (!eng.pair_ok || eng.pair_id != d->id) {
			eng.pair_ok = pair_keys(v->dmr.own_id, d->id, n->net_id, eng.ukek, eng.kmac);
			eng.pair_id = d->id;
		}
		if (!eng.pair_ok) {
			eng.ros.failed++;
			eng.ros.ent_i++;
			return true;
		}
		otar_msg_t *m = &eng.ros_m;
		memset(m, 0, sizeof *m);
		m->net_id = n->net_id;
		m->rank = n->rank;
		m->msgnum = next_msgnum(now);
		otar_member_pack(e, m->rec);
		otar_addr_t a = { v->dmr.own_id, d->id };
		out_set(d->id, false, otar_roster_build(eng.out, &a, eng.kmac, m));
		eng.ros.dst = d->id;
		eng.ros.waiting = true;
		eng.ros.ack_by = now + ACK_WAIT_MS;
		return true;
	}
	return false;
}

// A member: its TEK stored (or not), the next keyset, then the ACK
static __attribute__((noinline)) void tek_stored(const radio_view_t *v, uint32_t now)
{
	eng.tek_due = false;
	eng.tek_done = false;
	crypto_wipe(eng.tek, sizeof eng.tek);
	eng.ack.result = eng.tek_ok ? OTAR_ACK_STORED : OTAR_ACK_STORE_FAILED;
	if (eng.tek_ok)
		radio_req_otar(RADIO_OTAR_NEXT_AT, eng.tek_kid | (eng.tek_at << 8));
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, eng.ack_to };
	out_set(eng.ack_to, false, otar_ack_build(eng.out, &a, eng.kmac, &eng.ack));
}

// A member back on says HELLO to its net control (warm start, 9)
static __attribute__((noinline)) void say_hello(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	eng.hello_sent = true;
	otar_member_t nc;
	bool found = false;
	uint16_t total = 0;
	for (uint16_t i = 0; i < 4u && !found; i++) {
		if (otar_roster_window(i, &nc, 1, &total) != 1)
			break;
		found = nc.rank != 0 && !(nc.flags & OTAR_M_REVOKED);
	}
	if (!found || !pair_keys(v->dmr.own_id, nc.id, n->net_id, eng.ukek, eng.kmac))
		return;
	eng.pair_id = nc.id;
	eng.pair_ok = true;
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.net_id = n->net_id;
	m.msgnum = next_msgnum(now);
	m.active_kid = v->otar.kid;
	m.next_kid = v->otar.next_kid;
	m.flags = v->otar.has_next ? 1u : 0u;
	otar_addr_t a = { v->dmr.own_id, nc.id };
	out_set(nc.id, false, otar_hello_build(eng.out, &a, eng.kmac, &m));
}

static bool engine_tick(const radio_view_t *v, uint32_t now)
{
	bool changed = false;
	otar_net_t n;
	net_read(&n);
	bool in = (n.flags & OTAR_NET_IN) != 0 && v->dmr.own_id != 0;
	if (in != eng.open) {
		otar_svc_open(in);
		eng.open = in;
		eng.started_ms = now;
		eng.hello_sent = false;
		eng.pair_ok = false;
		memset(&eng.ros, 0, sizeof eng.ros);
		eng.ros_due = false;
		eng.pend.on = false;
		eng.zz_to = 0;
		if (!in)
			rk_free();
	}
	if (!in) {
		crypto_wipe(&n, sizeof n);
		return false;
	}
	// The transport
	if (eng.sending) {
		otar_send_state_t st = otar_send_state();
		if (st != OTAR_SEND_SENDING) {
			eng.sending = false;
			if (st == OTAR_SEND_FAILED && eng.rk != NULL && eng.rk->cur != 0xFF) {
				eng.rk->m[eng.rk->cur].state = UI_RK_FAIL;	// not delivered: tried again later
				eng.rk->m[eng.rk->cur].due = now + RETRY_MS;
				eng.rk->cur = 0xFF;
				changed = true;
			}
			if (st == OTAR_SEND_FAILED && eng.ros.waiting)
				eng.ros.ack_by = now;	// not delivered: a try gone

		}
	}
	if (eng.out_len != 0 && !eng.sending) {
		if (otar_send(eng.out_dst, eng.out_group, eng.out, eng.out_len))
			eng.sending = true;
		crypto_wipe(eng.out, sizeof eng.out);
		eng.out_len = 0;
	}
	// A member's stored TEK: the next keyset, then the ACK
	if (eng.tek_due && !eng.tek_job && eng.rk == NULL) {
		if (!eng.tek_done) {
			eng.tek_job = true;
			if (!storage_job_post(tek_job, NULL))
				eng.tek_job = false;
		} else {
			tek_stored(v, now);
			changed = true;
		}
	}
	// A member's stored ROSTER entry: the ACK
	if (eng.ros_due && !net.want_put && !net.job_running && net.put_done) {
		ros_stored(v, now);
		changed = true;
	}
	// Messages in
	uint8_t *msg = eng.in;
	uint32_t src, dst;
	bool group;
	int len = otar_take(msg, &src, &dst, &group);
	if (len > 0) {
		otar_msg_t h;
		if (otar_peek(msg, len, &h) && h.net_id == n.net_id) {
			// A net control of another rank rekeys a backup net control as any member (otar.md 10)
			if (h.type == OTAR_REKEY && !group && src != v->dmr.own_id && eng.rk == NULL)
				on_rekey(v, msg, len, src, &n, now);
			else if (h.type == OTAR_CHANGEOVER && group && src != v->dmr.own_id)
				on_changeover(v, msg, len, src, dst, &n, now);
			else if (h.type == OTAR_ZEROIZE && !group)
				on_zeroize(v, msg, len, src, &n, now);
			else if (h.type == OTAR_ROSTER && !group)
				on_roster(v, msg, len, src, &n, now);
			else if ((h.type == OTAR_ACK || h.type == OTAR_HELLO) && !group && n.rank != 0)
				on_member(v, msg, len, src, &n, now);
			changed = true;
		}
		crypto_wipe(msg, OTAR_MSG_MAX);
	}
	// A member back on says HELLO to its net control (warm start, 9)
	if (n.rank == 0 && !eng.hello_sent && v->otar.on && (uint32_t)(now - eng.started_ms) >= HELLO_AFTER_MS &&
	    eng.out_len == 0 && !eng.sending)
		say_hello(v, &n, now);
	// A ZEROIZE asked for
	if (eng.zz_to != 0 && n.rank != 0 && eng.out_len == 0 && !eng.sending && !eng.ros.waiting && eng.rk == NULL) {
		zz_send(v, &n, now);
		changed = true;
	}
	// CHANGEOVER copies, then this radio
	if (eng.co_left > 0 && eng.out_len == 0 && !eng.sending && (int32_t)(now - eng.co_next) >= 0) {
		queue_out(eng.co_tg, true, eng.co_msg, eng.co_len);
		eng.co_left--;
		eng.co_next = now + CO_GAP_MS;
		if (eng.co_left == 0 && eng.co_then_local) {
			radio_req_otar(RADIO_OTAR_NOW, 0);
			crypto_wipe(eng.co_msg, sizeof eng.co_msg);
		}
		changed = true;
	}
	if (n.rank != 0) {
		changed = rk_step(v, &n, now) || changed;
		changed = ros_step(v, &n, now) || changed;
	}
	crypto_wipe(&n, sizeof n);
	return changed;
}

uint8_t ui_svc_net_rekey(const radio_view_t *v, uint16_t mins)
{
	otar_net_t n;
	net_read(&n);
	bool nc = (n.flags & OTAR_NET_IN) && n.rank != 0;
	crypto_wipe(&n, sizeof n);
	if (!nc)
		return UI_NET_NOT_NC;
	if (!v->otar.on)
		return UI_NET_NOT_MANAGED;
	if (eng.rk != NULL || eng.tek_due || eng.tek_job || eng.ros.on)
		return UI_NET_BUSY;
	// The key ID: the first free one after the key in use
	uint8_t kid = v->otar.kid;
	bool free_found = false;
	for (unsigned i = 0; i < 255u && !free_found; i++) {
		kid = (uint8_t)(kid + 1u);
		free_found = !ui_svc_aes_key_there(v->otar.system, kid);
	}
	if (!free_found)
		return UI_NET_NO_KID;
	rekey_t *rk = pvPortMalloc(sizeof *rk);
	if (rk == NULL)
		return UI_NET_BUSY;
	memset(rk, 0, sizeof *rk);
	rk->kid = kid;
	rk->system = v->otar.system;
	rk->keyset = (uint32_t)v->otar.keyset + 1u;
	rk->changeover = mins != 0 && v->otar.clock_ok ? v->otar.now_min + mins : 0;	// by the clocks, else by hand
	rk->cur = 0xFF;
	uint16_t total = 0, first = 0;
	otar_member_t page[2];
	do {
		uint16_t got = otar_roster_window(first, page, 2, &total);
		for (uint16_t i = 0; i < got; i++)
			if (page[i].id != v->dmr.own_id && !(page[i].flags & OTAR_M_REVOKED) && rk->n < OTAR_ROSTER_MAX - 1u)
				rk->m[rk->n++] = (rk_member_t){ .id = page[i].id, .state = UI_RK_WAIT };
		first = (uint16_t)(first + got);
		if (got == 0)
			break;
	} while (first < total);
	eng.rk = rk;
	return UI_NET_OK;
}

uint8_t ui_svc_net_change_over(const radio_view_t *v)
{
	otar_net_t n;
	net_read(&n);
	bool nc = (n.flags & OTAR_NET_IN) && n.rank != 0;
	uint16_t net_id = n.net_id;
	uint8_t rank = n.rank;
	crypto_wipe(&n, sizeof n);
	if (!nc)
		return UI_NET_NOT_NC;
	if (!v->otar.on || !v->otar.has_next)
		return UI_NET_NO_NEXT;
	if (v->dmr.target_private || v->dmr.target_id == 0)
		return UI_NET_NO_TG;
	uint8_t tek[OTAR_KEY_LEN], k[OTAR_KEY_LEN];
	if (codeplug_traffic_key(v->otar.system, DMR_AES_ALG_AES256, v->otar.next_kid, tek, sizeof tek) != (int)sizeof tek)
		return UI_NET_NO_NEXT;
	otar_group_mac_key(tek, k);
	crypto_wipe(tek, sizeof tek);
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.net_id = net_id;
	m.rank = rank;
	m.msgnum = next_msgnum(hal_millis());
	m.keyset = (uint32_t)v->otar.keyset + 1u;
	m.kid = v->otar.next_kid;
	otar_addr_t a = { v->dmr.own_id, v->dmr.target_id };
	eng.co_len = (uint8_t)otar_changeover_build(eng.co_msg, &a, k, &m);
	crypto_wipe(k, sizeof k);
	eng.co_tg = v->dmr.target_id;
	eng.co_left = CO_COPIES;
	eng.co_next = hal_millis();
	eng.co_then_local = true;
	return UI_NET_OK;
}

void ui_svc_net_rekey_view(ui_rekey_view_t *r)
{
	memset(r, 0, sizeof *r);
	rekey_t *rk = eng.rk;
	if (rk == NULL)
		return;
	r->on = true;
	r->kid = rk->kid;
	r->members = rk->n;
	for (uint8_t i = 0; i < rk->n; i++)
		r->done = (uint8_t)(r->done + (rk->m[i].state == UI_RK_OK));
	r->changeover = rk->changeover;
	unsigned bits = entropy_bits();
	r->presses = !rk->keyed && bits < ENTROPY_FULL ?
		(uint8_t)((ENTROPY_FULL - bits + ENTROPY_KEY_BITS - 1u) / ENTROPY_KEY_BITS) : 0;
}

bool ui_svc_net_rekey_member(uint16_t i, uint32_t *id, uint8_t *state, uint8_t *tries)
{
	rekey_t *rk = eng.rk;
	if (rk == NULL || i >= rk->n)
		return false;
	*id = rk->m[i].id;
	*state = rk->m[i].state;
	*tries = rk->m[i].tries;
	return true;
}
uint8_t ui_svc_net_roster_send(uint32_t only)
{
	otar_net_t n;
	net_read(&n);
	bool nc = (n.flags & OTAR_NET_IN) && n.rank != 0;
	crypto_wipe(&n, sizeof n);
	if (!nc)
		return UI_NET_NOT_NC;
	if (eng.rk != NULL)
		return UI_NET_BUSY;
	uint32_t keep = eng.ros.on && (eng.ros.only != only || eng.ros.one) ? 0 : only;	// two at once: the whole roster
	ros_start(keep, false, false);
	return UI_NET_OK;
}

void ui_svc_net_roster_view(ui_roster_view_t *r)
{
	memset(r, 0, sizeof *r);
	r->on = eng.ros.on;
	r->done = eng.ros.done;
	r->sent = eng.ros.sent;
	r->failed = eng.ros.failed;
	r->asked = eng.ros.asked;
}

static void eng_view(ui_net_view_t *v)
{
	v->pend = eng.pend.on;
	v->pend_from = eng.pend.from_rank;
	v->pend_lost = eng.pend.e.rank;
}

// This radio's rank in its net, 0 when not in one or a member
static uint8_t own_rank(void)
{
	otar_net_t n;
	net_read(&n);
	uint8_t r = (n.flags & OTAR_NET_IN) ? n.rank : 0;
	crypto_wipe(&n, sizeof n);
	return r;
}

static bool net_busy(void)
{
	return eng.rk != NULL || eng.ros.on || net.want_put || net.job_running;
}

static void ros_start(uint32_t only, bool one, bool to_it)
{
	memset(&eng.ros, 0, sizeof eng.ros);
	eng.ros.on = true;
	eng.ros.only = only;
	eng.ros.one = one;
	eng.ros.to_it = to_it;
}

// m into this radio's roster (the housekeeping task), then its entry to the net
static void put_and_tell(const otar_member_t *m, bool to_it)
{
	net.member = *m;
	net.put_done = false;
	net.want_put = true;
	net.page_ok = false;
	ros_start(m->id, true, to_it);
}

uint8_t ui_svc_net_set_rank(const radio_view_t *v, uint32_t id, uint8_t rank)
{
	uint8_t own = own_rank();
	if (own == 0)
		return UI_NET_NOT_NC;
	if (own != 1u)
		return UI_NET_NOT_FIRST;
	if (net_busy())
		return UI_NET_BUSY;
	otar_member_t m;
	if (rank == 1u || rank > OTAR_RANK_MAX || id == v->dmr.own_id || !otar_roster_find(id, &m) ||
	    (m.flags & OTAR_M_REVOKED))
		return UI_NET_NO_MEMBER;
	m.rank = rank;
	put_and_tell(&m, true);
	return UI_NET_OK;
}

uint8_t ui_svc_net_revoke(const radio_view_t *v, uint32_t id)
{
	uint8_t own = own_rank();
	if (own == 0)
		return UI_NET_NOT_NC;
	if (net_busy())
		return UI_NET_BUSY;
	otar_member_t m;
	if (id == v->dmr.own_id || !otar_roster_find(id, &m) || (m.flags & OTAR_M_REVOKED))
		return UI_NET_NO_MEMBER;
	if (m.rank != 0 && m.rank <= own)
		return UI_NET_HIGHER;
	m.flags |= OTAR_M_REVOKED;
	put_and_tell(&m, false);
	return UI_NET_OK;
}

uint8_t ui_svc_net_take_over(const radio_view_t *v, uint8_t *lost)
{
	(void)v;
	uint8_t own = own_rank();
	*lost = 0;
	if (own < 2u)
		return UI_NET_NOT_NC;
	if (net_busy())
		return UI_NET_BUSY;
	otar_member_t m, best;
	uint16_t total = 0;
	bool found = false;
	for (uint16_t i = 0; i < OTAR_ROSTER_MAX; i++) {
		if (otar_roster_window(i, &m, 1, &total) != 1)
			break;
		if (m.rank != 0 && m.rank < own && !(m.flags & OTAR_M_REVOKED) && (!found || m.rank < best.rank)) {
			best = m;
			found = true;
		}
	}
	if (!found)
		return UI_NET_NO_LOST;
	*lost = best.rank;
	best.flags |= OTAR_M_REVOKED;
	put_and_tell(&best, false);
	return UI_NET_OK;
}

uint8_t ui_svc_net_wipe(const radio_view_t *v, uint32_t id)
{
	if (own_rank() == 0)
		return UI_NET_NOT_NC;
	otar_member_t m;
	if (id == v->dmr.own_id || !otar_roster_find(id, &m) || (m.flags & OTAR_M_REVOKED))
		return UI_NET_NO_MEMBER;
	if (eng.zz_to != 0)
		return UI_NET_BUSY;
	eng.zz_to = id;
	return UI_NET_OK;
}

void ui_svc_net_accept(bool yes)
{
	if (!eng.pend.on)
		return;
	if (yes) {
		if (net.want_put || net.job_running)
			return;		// a roster write is under way: asked again
		net.member = eng.pend.e;
		net.put_done = false;
		net.want_put = true;
		net.page_ok = false;
	}
	eng.pend.on = false;
}

void ui_svc_net_set_remote_wipe(bool on)
{
	settings_t *st = settings_begin();
	st->otar_wipe = on ? 1u : 0u;
	settings_end(hal_millis());
}

#endif
