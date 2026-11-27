// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// The ui_svc.h calls for Net keys (docs/spec/otar.md 8): what the screen checks in the codeplug before it asks the
// radio task for a change
#include "config.h"

#if CONFIG_OTAR
#include <string.h>
#include <stddef.h>
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
#include "dmr/call/dmr_lc.h"
#include "radio/radio.h"
#include "radio/silence.h"
#if CONFIG_POSITION
#include "position/position.h"
#endif
#include "support/kcv.h"
#include "settings/settings.h"
#include "storage/storage.h"
#include "support/entropy.h"
#include "support/hkdf.h"
#include "support/utc_clock.h"
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
	bool chan_due;		// started or joined a net: the channel on view becomes the net's (otar.md 7.8)
} net;

// ---- The net's channel (otar.md 7.8) ----
// The channel on view as a net channel: false off DMR (then *c is none)
static bool chan_of(const radio_view_t *v, otar_chan_t *c)
{
	memset(c, 0, sizeof *c);
	if (v->ch.mode != RADIO_MODE_DMR || v->ch.rx_hz == 0)
		return false;
	c->rx_hz = v->ch.rx_hz;
	c->tx_hz = v->ch.tx_hz;
	c->cc_ts = (uint8_t)((v->ch.color_code & 0x0Fu) | (v->ch.timeslot == 2u ? OTAR_CHAN_TS2 : 0u));
	size_t n = strlen(v->ch.name);
	memcpy(c->name, v->ch.name, n < OTAR_CHAN_NAME ? n : OTAR_CHAN_NAME);
	return true;
}

static void chan_get(otar_chan_t *c)
{
	settings_t *st = settings_begin();
	*c = st->otar_chan;
	settings_end(0);
}

static void chan_put(const otar_chan_t *c, uint32_t now)
{
	settings_t *st = settings_begin();
	st->otar_chan = *c;
	settings_end(now);	// saved only when it changed
}

bool ui_svc_net_on_chan(const radio_view_t *v)
{
	otar_chan_t c, here;
	chan_get(&c);
	return c.rx_hz == 0 ||
	       (chan_of(v, &here) && here.rx_hz == c.rx_hz && here.tx_hz == c.tx_hz && here.cc_ts == c.cc_ts);
}

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

// X25519's workspace (640 bytes), reserved rather than from the heap: a net control's check of a member's ACK needs it,
// and a heap short of one such block would drop the ACK silently, the member showing "no answer" (suspected on the
// bench, 2026-11-27, gone after a restart). Only the UI task uses it, one call at a time; x25519 wipes it before return
static x25519_ws_t x_ws;

// The fingerprint of this radio's public key, worked out once per key (X25519 takes a moment)
static void fingerprint(const otar_net_t *n)
{
	if (net.fp_ok && memcmp(net.fp_of, n->priv, sizeof net.fp_of) == 0)
		return;
	uint8_t pub[X25519_LEN];
	x25519_public(pub, n->priv, &x_ws);
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
	v->share_location = SETTINGS_FIELD(otar_loc_off) == 0u;
	v->removed = (n.flags & OTAR_NET_REMOVED) != 0;
	if (v->in_net)
		chan_get(&v->chan);
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

static void otar_seen_clear(settings_t *st);
static bool key_kcv(uint8_t system, uint8_t kid, uint8_t kcv[KCV_LEN]);

void ui_svc_net_leave(void)
{
	settings_t *st = settings_begin();
	st->otar_net.net_id = 0;
	st->otar_net.rank = 0;
	st->otar_net.flags = 0;
	// The key pair goes with the net: the next join or start makes a new one, so no message recorded in this net
	// checks under the next one's pair keys, and the message numbers can start again (otar.md 7.6)
	crypto_wipe(st->otar_net.priv, sizeof st->otar_net.priv);
	otar_seen_clear(st);
	memset(&st->otar_chan, 0, sizeof st->otar_chan);	// the net's channel goes with the net (7.8)
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
	memcpy(st->otar_net.priv, rnd, X25519_LEN);	// a new key pair for each net (otar.md 7.6)
	uint16_t id = (uint16_t)((rnd[X25519_LEN] << 8) | rnd[X25519_LEN + 1]);
	st->otar_net.net_id = id != 0 ? id : 1u;
	st->otar_net.rank = 1;
	st->otar_net.flags = OTAR_NET_IN;
	st->otar_wipe = 1u;	// Remote wipe on in a net (otar.md 7.5): a backup net control may be wiped by net control 1
	st->otar_loc_off = 0u;	// ... and Share location (7.7)
	otar_seen_clear(st);
	otar_net_t n = st->otar_net;
	settings_end(now);
	crypto_wipe(rnd, sizeof rnd);
	memset(&net.member, 0, sizeof net.member);
	net.member.id = net.own;
	net.member.rank = 1;
	x25519_public(net.member.pub, n.priv, &x_ws);
	net.want_clear = true;	// a roster from an earlier net goes first
	net.want_put = true;
	crypto_wipe(&n, sizeof n);
	net.starting = false;
	net.page_ok = false;
	net.chan_due = true;	// the net's channel: the one it was started on (7.8)
}

static bool engine_tick(const radio_view_t *v, uint32_t now);

static bool pool_wanted(void);

bool ui_svc_net_tick(const radio_view_t *v, uint32_t now)
{
	// A rekey's key or a new net's key pair waits for randomness: the receiver's noise (here, not deep in the run)
	if (pool_wanted())
		ui_svc_noise_want(now);
	bool changed = false;
	if (net.chan_due) {	// started or joined: the channel it is on (none off DMR), until a net control says another
		net.chan_due = false;
		otar_chan_t c;
		(void)chan_of(v, &c);
		chan_put(&c, now);
		changed = true;
	}
	changed = engine_tick(v, now) || changed;
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
#define KEYSET_STEP_MAX	8u	// a REKEY's keyset at most this far above the active one (7.1)
#define HELLO_GAP_MS	2000u	// a net control works on at most one HELLO this often
#define CU_GAP_MS	120000u	// ... and answers one member's HELLO at most this often
#define HELLO_ANS_N	8u	// ... keeping the last members answered: at most this many answers per CU_GAP_MS
#define HELLO_REQ_MS	10000u	// a member's Request keys: not again within this of its last HELLO
#define CANCEL_RUN_MS	600000u	// a cancel run tries the members this long; one that was off is told at its HELLO (7.9)

typedef struct {
	uint32_t id;
	uint8_t state;		// UI_RK_*
	uint8_t tries;
	uint32_t due;		// when it is sent (again)
	uint32_t sent;		// the message number of its last REKEY: its ACK echoes it
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
	uint32_t changeover;	// set when the key is made: mins from then (a run waits for key presses first)
	uint8_t kcv[3];		// the key's check value: an ACK counts only with it
	uint16_t mins;
	uint8_t n;
	uint8_t cur;		// the member whose ACK is awaited, 0xFF none
	uint32_t ack_by;
	bool cancel;		// Cancel the change (otar.md 7.9): a WITHDRAW to each member instead, until cancel_by
	uint32_t cancel_by;
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
	bool tek_now;		// OTAR_RK_NOW: the net's active key, changed over to once stored
	uint32_t tek_ks;	// its keyset number, the net's
	uint32_t tek_at;	// the changeover
	uint32_t cu_to;		// a net control: the net's active key to send this member, which said HELLO without it
	uint32_t wd_to;		// ... and the withdrawn keyset (otar_cut) to this member, which said HELLO holding it (7.9)
	uint32_t ch_to;		// ... and the net's channel to this member, whose HELLO it answered (7.8)
	struct {
		uint32_t id, at;
		uint32_t num;	// the message number of the HELLO answered: a newer one is answered at once
	} hans[HELLO_ANS_N];	// ... the members whose HELLO it answered last, and when (hello_slot)
	uint32_t hello_at;	// a net control: when the last HELLO was worked on
	otar_msg_t ack;		// the ACK to send once stored
	uint32_t ack_to;
	// A member's HELLO (9): said until its net control answers, with longer and longer gaps (hello_gap)
	struct {
		bool on;		// not answered yet
		uint8_t state;		// UI_HELLO_*
		uint8_t n;		// said this many times
		uint32_t to, num;	// the net control it went to, its message number (the answer echoes it)
		uint32_t due, sent_at;
	} hello;
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
		bool chan_only;		// the net's channel alone, to every member (7.8)
		uint32_t only;		// 0: every entry to every member; else this member's entry to all, and all to it
		uint16_t dst_i, ent_i;	// the roster positions of the member sent to, and of the entry sent
		uint32_t dst;		// the member whose ACK is awaited
		uint8_t tries;
		uint32_t ack_by;
		uint16_t sent, failed, asked;
		uint32_t sent_num;	// the message number of the ROSTER waiting for its ACK
	} ros;
	// A member: a take over to ask the user about (otar.md 10): the lost net control's entry, revoked, and who says so
	struct {
		bool on;
		uint8_t from_rank;
		otar_member_t e;
	} pend;
	// A net control: the ZEROIZE asked for (ui_svc_net_wipe), sent up to ZZ_TRIES times until its ACK comes
	struct {
		uint32_t id;		// the member (0 none)
		uint8_t state;		// UI_ZZ_*
		bool send, waiting;	// a try to send; one sent, its ACK awaited
		uint8_t tries;
		uint32_t sent_num, ack_by;
	} zz;
	// A member: a ZEROIZE taken, its ACK built; the wipe starts once the transport has let the ACK go, or by this time
	bool zz_wipe;
	uint32_t zz_wipe_by;
	// A member: when it last told each net control counter's sender its number was old (fresh_or_tell; mask: ever)
	uint8_t oos_mask;
	uint32_t oos_at[4];
	// A net control: a member that said this radio's numbers are behind its own, beyond what this radio can skip
	uint32_t oos_id;
	// Scratch off the UI task's stack: the roster run's member and entry, and its message
	otar_member_t ros_d, ros_e;
	otar_msg_t ros_m;
	// A net control: TIME copies to send to the talkgroup (otar.md 7.4)
	uint16_t tm_left;	// roster entries still to look at (one TIME to each member, otar.md 7.4)
	uint16_t tm_i;		// the next roster entry
	uint32_t tm_next;
	// A net control: INVENTORY to send, and what the member answered (otar.md 9)
	uint32_t inv_to;
	struct {
		uint32_t id, by;
		uint32_t sent_num;	// the INVENTORY's message number: its ACKs echo it
		uint8_t state, n;	// UI_INV_*
		uint16_t keyset[2];
		bool same[2];
	} inv;
	// A net control: the LOCATE asked for (ui_svc_net_locate), sent up to LOC_TRIES times until its POSITION comes, and
	// what that said (otar.md 7.7)
	struct {
		uint32_t id;		// the member (0 none)
		uint8_t state;		// UI_LOC_*
		bool send, waiting;	// a try to send; one sent, its POSITION awaited
		uint8_t tries;
		uint32_t sent_num, ans_by;
		int32_t lat, lon;
		int16_t alt_m;
		uint16_t age_s;		// the member's fix's age when it answered
		uint32_t got_at;	// ... and when that was
	} loc;
	// A member: the net controls whose LOCATE it answered last, and when (loc_slot)
	struct {
		uint32_t id, at;
	} lans[4];
	bool inv_next;		// a member: the next keyset's ACK of an INVENTORY still to send
	bool manage_due;	// a member just joined: manage the channel's keys if it doesn't yet (ui_svc_net_joined)
	bool co_hand;		// Change over the net by hand: the run's end sends no CHANGEOVER of its own
	uint32_t sched_ms;	// the schedule last looked at
} eng;

// A rekey's key or a new net's key pair still waits for randomness
static bool pool_wanted(void)
{
	return (eng.rk != NULL && !eng.rk->keyed) || net.starting;
}

#define ROS_TRIES	3u	// a roster entry no ACK came for is sent this many times, then counted as failed
#define ZZ_TRIES	3u	// ... and a ZEROIZE, then shown as no answer
#define LOC_TRIES	3u	// ... and a LOCATE
#define LOC_GAP_MS	10000u	// a member answers one net control's LOCATE at most this often (on_locate)
#define ZZ_SEND_MS	60000u	// a member wiping: its ACK's send given this long (the transport's own limit is 10 s)
#define OOS_GAP_MS	300000u	// a member says "old message number" to one net control at most this often (7.6)
#define MSGNUM_SKIP_MAX	65536u	// a net control skips its numbers past a member's at most this far (oos_got)
#define ROS_SCAN	4u	// roster pairs looked at per tick
#define SCHED_LOOK_MS	10000u	// the rekey schedule is looked at this often
#define SCHED_CO_MIN	60u	// a scheduled rekey's changeover: this many minutes after it starts, by the clocks
static void ros_start(uint32_t only, bool one, bool to_it);
static void rk_free(void);
static bool co_start(const radio_view_t *v, uint8_t kid, uint32_t keyset, uint16_t net_id, uint8_t rank, bool then_local);

// A net control's message number: true when above the last taken from that sender (then kept), so a replay or an old
// message is refused. Four counters, each with the DMR ID it belongs to (otar.md 7.6): a sender's, not a rank's, so a
// change of ranks can't let one net control's old messages pass against another's counter
static uint32_t *seen_of(settings_t *st, unsigned i)
{
	return i == 0 ? &st->otar_seen : &st->otar_seen_nc[i - 1u];
}

static void otar_seen_clear(settings_t *st)
{
	memset(st->otar_cut, 0, sizeof st->otar_cut);	// a withdrawn keyset belongs to the net left (7.9)
	st->otar_cut_kid = 0;
	st->otar_seen = 0;
	memset(st->otar_seen_nc, 0, sizeof st->otar_seen_nc);
	memset(st->otar_seen_id, 0, sizeof st->otar_seen_id);
}

void ui_svc_net_seen_clear(uint32_t now)
{
	settings_t *st = settings_begin();
	otar_seen_clear(st);
	settings_end(now);
}

// A net control's last withdrawn next keyset (otar.md 7.9): its number (0 none) and key ID
static uint32_t cut_get(uint8_t *kid)
{
	settings_t *st = settings_begin();
	uint32_t ks = (uint32_t)st->otar_cut[0] << 8 | st->otar_cut[1];
	*kid = st->otar_cut_kid;
	settings_end(0);
	return ks;
}

static void cut_put(uint32_t ks, uint8_t kid, uint32_t now)
{
	settings_t *st = settings_begin();
	st->otar_cut[0] = (uint8_t)(ks >> 8);
	st->otar_cut[1] = (uint8_t)ks;
	st->otar_cut_kid = kid;
	settings_end(now);
}

static bool take_msgnum_at(uint32_t src, uint32_t msgnum, uint32_t now, int *slot_out, uint32_t *last_out);

static bool take_msgnum(uint32_t src, uint32_t msgnum, uint32_t now)
{
	int slot;
	uint32_t last;
	return take_msgnum_at(src, msgnum, now, &slot, &last);
}

// ... and the counter it was checked against (-1 none) with the last number it held
static bool take_msgnum_at(uint32_t src, uint32_t msgnum, uint32_t now, int *slot_out, uint32_t *last_out)
{
	*slot_out = -1;
	*last_out = 0;
	if (src == 0)
		return false;
	// The sender's counter, else a free one, else one whose sender is no longer a net control here (looked up
	// outside the settings: the roster is read from flash)
	uint32_t ids[4];
	settings_t *st = settings_begin();
	memcpy(ids, st->otar_seen_id, sizeof ids);
	settings_end(0);
	int slot = -1;
	for (int i = 0; i < 4 && slot < 0; i++)
		if (ids[i] == src)
			slot = i;
	for (int i = 0; i < 4 && slot < 0; i++)
		if (ids[i] == 0)
			slot = i;
	// Else one whose sender is gone from the roster or revoked (never un-revoked over the air, 10). Not one that was a
	// net control and is now a member: promoted again, its old messages would pass a counter started from 0
	for (int i = 0; i < 4 && slot < 0; i++) {
		otar_member_t m;
		if (!otar_roster_find(ids[i], &m) || (m.flags & OTAR_M_REVOKED))
			slot = i;
	}
	if (slot < 0)
		return false;
	st = settings_begin();
	uint32_t *seen = seen_of(st, (unsigned)slot);
	if (st->otar_seen_id[slot] != src) {
		st->otar_seen_id[slot] = src;
		*seen = 0;
	}
	bool fresh = msgnum > *seen;
	*slot_out = slot;
	*last_out = *seen;
	if (fresh)
		*seen = msgnum;
	settings_end_soon(now);	// saved at the next poll, not after changes rest: a power loss loses at most that much
	return fresh;
}

// This radio's message numbers (otar.md 7.6): settings_t.otar_msgnum holds the end of a reservation, and a number is
// used only once the reservation holding it is in the flash (settings_u32_is_saved), as the voice MI's (dmr-voice.md
// 5.1). After a restart numbering goes on past the saved end, so a number, and with it a body's counter block, never
// repeats, whatever was unsaved when the power went
#define MSGNUM_BLOCK	64u
static struct {
	uint32_t next, end, pending;	// next to use; the last usable (saved); a reservation waiting to be saved
} mn;

static void msgnum_tick(uint32_t now)
{
	uint32_t stored = SETTINGS_FIELD(otar_msgnum);
	if (mn.next == 0) {
		mn.next = stored + 1u;		// what was reserved before the restart may have been used
		mn.end = stored;
	}
	if (mn.pending != 0) {
		if (stored != mn.pending)
			mn.pending = 0;		// overwritten (a restore): asked again
		else if (settings_u32_is_saved(offsetof(settings_t, otar_msgnum), stored)) {
			mn.end = stored;
			mn.pending = 0;
		}
		return;
	}
	if (mn.end < mn.next + MSGNUM_BLOCK / 2u) {
		mn.pending = mn.next + MSGNUM_BLOCK;
		settings_t *st = settings_begin();
		st->otar_msgnum = mn.pending;
		settings_end_soon(now);
	}
}

static bool msgnum_ready(void)
{
	return mn.next != 0 && mn.next <= mn.end;
}

// 0 when no saved reservation holds the next number yet: a receiver refuses 0 as a replay, and the sender tries again
static uint32_t next_msgnum(uint32_t now)
{
	(void)now;
	return msgnum_ready() ? mn.next++ : 0u;
}

// The pair keys with radio id (whose public key is in the roster): false when it isn't, or X25519 refuses
__attribute__((noinline)) static bool pair_keys(uint32_t own, uint32_t id, uint16_t net_id, uint8_t ukek[OTAR_KEY_LEN], uint8_t kmac[OTAR_KEY_LEN])
{
	otar_member_t m;
	if (!otar_roster_find(id, &m))
		return false;
	otar_net_t n;
	net_read(&n);
	bool ok = has_key(&n) && otar_pair_keys(n.priv, m.pub, net_id, own, id, ukek, kmac, &x_ws);
	crypto_wipe(&n, sizeof n);
	return ok;
}

// A message built straight into eng.out (only while it is free)
static void out_set(uint32_t dst, bool group, int len)
{
	if (len <= 0 || len > (int)OTAR_MSG_MAX)
		return;
	// Built with message number 0 (no saved reservation yet, 7.6): never sent. Two such messages would share a
	// counter block; the request is answered when it comes again
	if ((eng.out[5] | eng.out[6] | eng.out[7] | eng.out[8]) == 0) {
		crypto_wipe(eng.out, sizeof eng.out);
		return;
	}
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

// A member: a net control's message whose MAC checked under the pair keys (eng.kmac, with src), its number taken; true
// when it is fresh. Else, at most once per OOS_GAP_MS for that sender's counter, an ACK MSGNUM carrying the last number
// taken from it (7.6), so a net control whose numbers went back (its settings restored) sees why it isn't heard. Never
// for a message whose MAC fails (that stays silent), and never more often: a recording played back makes this radio
// transmit at most once per OOS_GAP_MS per net control, and learns nothing, the reply being encrypted
static bool fresh_or_tell(const radio_view_t *v, const otar_net_t *n, uint32_t src, uint32_t msgnum, uint32_t now)
{
	int slot;
	uint32_t last;
	if (take_msgnum_at(src, msgnum, now, &slot, &last))
		return true;
	if (slot < 0 || eng.out_len != 0 || !eng.pair_ok || eng.pair_id != src ||
	    ((eng.oos_mask & (1u << slot)) && (uint32_t)(now - eng.oos_at[slot]) < OOS_GAP_MS))
		return false;
	otar_msg_t *a = &eng.ros_m;
	memset(a, 0, sizeof *a);
	a->net_id = n->net_id;
	a->rank = n->rank;
	a->keyset = last;
	a->result = OTAR_ACK_MSGNUM;
	a->echo = msgnum;
	a->msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, a));
	if (eng.out_len != 0) {
		eng.oos_mask = (uint8_t)(eng.oos_mask | (1u << slot));
		eng.oos_at[slot] = now;
	}
	return false;
}

static void tek_job(void *ctx)
{
	(void)ctx;
	eng.tek_ok = codeplug_traffic_key_set(eng.tek_system, DMR_AES_ALG_AES256, eng.tek_kid, eng.tek, OTAR_KEY_LEN);
	eng.tek_done = true;
	eng.tek_job = false;
}

// A member: a REKEY from its net control (7.1)
static uint32_t authority(void);

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
	// An old message number: a replay (a net control's retry always has a new one). Never ACKed: at most the
	// rate-limited "old message number" (fresh_or_tell), so a recording can't make this radio transmit at will
	if (!fresh_or_tell(v, n, src, m.msgnum, now)) {
		crypto_wipe(&m, sizeof m);
		return;
	}
	if (eng.hello.on && src == eng.hello.to) {	// the answer to its HELLO (9): asked no more
		eng.hello.on = false;
		eng.hello.state = UI_HELLO_GOT;
	}
	memset(&eng.ack, 0, sizeof eng.ack);
	eng.ack.net_id = n->net_id;
	eng.ack.keyset = m.keyset;
	eng.ack.ckr = m.ckr;
	eng.ack.echo = m.msgnum;
	eng.ack_to = src;
	(void)kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, m.tek, OTAR_KEY_LEN, eng.ack.kcv);
	// A resend of the keyset this radio holds: the same key ID and the same key (its check value), else refused
	bool now_ks = (m.flags & OTAR_RK_NOW) != 0;
	bool is_next = v->otar.has_next && m.keyset == v->otar.next_keyset && v->otar.next_kid == m.kid;
	bool is_active = now_ks && m.keyset == v->otar.keyset && v->otar.kid == m.kid;
	uint8_t have[KCV_LEN];
	if (!v->otar.on) {
		eng.ack.result = OTAR_ACK_NOT_MANAGED;
	} else if (is_next || is_active) {
		eng.ack.result = key_kcv(v->otar.system, m.kid, have) && memcmp(have, eng.ack.kcv, KCV_LEN) == 0 ?
				 OTAR_ACK_HELD : OTAR_ACK_REFUSED;
		// The net's active key flagged now, and this radio holds it as its next: it missed the changeover by hand.
		// Change over now (9)
		if (eng.ack.result == OTAR_ACK_HELD && now_ks && is_next)
			radio_req_otar(RADIO_OTAR_NOW, 0);
		// The next keyset sent again with another changeover: the net control moved the change (Move the change, 7.9)
		else if (eng.ack.result == OTAR_ACK_HELD && is_next && m.changeover != v->otar.changeover)
			radio_req_otar(RADIO_OTAR_NEXT_AT, m.kid | (m.changeover << 8));
	} else if (m.keyset <= v->otar.keyset || (v->otar.has_next && m.keyset < v->otar.next_keyset)) {
		eng.ack.result = OTAR_ACK_OLD;	// keyset numbers only go up (7.1): never back to an older key
	} else if ((m.keyset > (uint32_t)v->otar.keyset + KEYSET_STEP_MAX && !(now_ks && src == authority())) ||
		   m.keyset > 0xFFFFu || m.kid == v->otar.kid || (v->otar.has_prev && m.kid == v->otar.prev_kid)) {
		// Too far ahead (one sender could park the net on a number nobody else reaches), or a key ID in use: the
		// active key's record would be overwritten (7.1). The authority's catch-up (flagged now) is the net's own
		// number however far: a radio off through many rekeys, or cleared and joined again, takes it (found on air: a
		// rejoined radio on keyset 1 refused the net's 12 and never caught up)
		eng.ack.result = OTAR_ACK_REFUSED;
	} else {
		// Stored by the housekeeping task, then made the next keyset, then ACKed (engine_tick)
		memcpy(eng.tek, m.tek, OTAR_KEY_LEN);
		eng.tek_system = v->otar.system;
		eng.tek_kid = m.kid;
		eng.tek_at = m.changeover;
		eng.tek_ks = m.keyset;
		eng.tek_now = now_ks;
		eng.tek_due = true;
		crypto_wipe(&m, sizeof m);
		return;
	}
	crypto_wipe(&m, sizeof m);
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, &eng.ack));
}

// A member: a WITHDRAW from a net control (7.9): the next keyset it names dropped and its key erased, before the
// changeover. ACK DROPPED once that keyset is not held (also when it never was: what the net control wants is true);
// REFUSED when this radio's next keyset under that number is another key; OLD when it is already the active one (too
// late: the radio changed over)
__attribute__((noinline)) static void on_withdraw(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						  const otar_net_t *n, uint32_t now)
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
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || !fresh_or_tell(v, n, src, m->msgnum, now))
		return;
	if (eng.hello.on && src == eng.hello.to) {	// the answer to its HELLO (9)
		eng.hello.on = false;
		eng.hello.state = UI_HELLO_GOT;
	}
	uint32_t ks = m->keyset, echo = m->msgnum;
	uint8_t kid = m->kid, result;
	if (!v->otar.on)
		result = OTAR_ACK_NOT_MANAGED;
	else if (v->otar.has_next && v->otar.next_keyset == ks)
		result = v->otar.next_kid == kid ? OTAR_ACK_DROPPED : OTAR_ACK_REFUSED;
	else if (v->otar.keyset == ks)
		result = OTAR_ACK_OLD;
	else
		result = OTAR_ACK_DROPPED;
	if (result == OTAR_ACK_DROPPED && v->otar.has_next && v->otar.next_keyset == ks)
		radio_req_otar(RADIO_OTAR_DROP_NEXT, kid);
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->keyset = ks;
	m->ckr = 1;		// a keyset's answer (CKR 0 is a roster entry's, 7.2)
	m->result = result;
	m->echo = echo;
	m->msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, m));
}

// The best-ranked net control not revoked on this radio's roster (0: none)
static uint32_t authority(void)
{
	static otar_member_t c;
	uint32_t id = 0;
	uint8_t best = 0;
	uint16_t total = 0;
	for (uint16_t i = 0; otar_roster_window(i, &c, 1, &total) == 1; i++)
		if (c.rank != 0 && !(c.flags & OTAR_M_REVOKED) && (best == 0 || c.rank < best)) {
			best = c.rank;
			id = c.id;
		}
	return id;
}

// A ROSTER (7.5) from a net control: one roster entry, stored (net.member, the housekeeping task), then ACKed. Refused:
// an entry that would change a net control of higher rank than the sender's (a take over is asked, otar.md 10), or
// would revoke this radio from a net control not above it. An entry for this radio sets its rank; one revoking it
// makes the radio show Removed from the net
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
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || !fresh_or_tell(v, n, src, m->msgnum, now))
		return;
	memset(&eng.ack, 0, sizeof eng.ack);
	eng.ack.net_id = n->net_id;
	eng.ack.rank = n->rank;
	eng.ack.echo = m->msgnum;
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
	bool self_out = ok && e->id == v->dmr.own_id && (e->flags & OTAR_M_REVOKED);
	// Ranks (otar.md 10): no entry ranked above its sender, no change to the sender's own entry, and only net
	// control 1 gives or changes a rank. So a backup net control can't make itself net control 1, or add one, and
	// then revoke the real one without the question a take over asks
	bool above = ok && e->rank != 0 && e->rank < nc.rank;
	bool own = ok && e->id == src && !same;
	// The authority is the best-ranked net control not revoked (net control 1 until a take over): only it gives or
	// changes ranks, adds entries or changes a public key. And nobody un-revokes over the air: a radio revoked stays
	// so until it joins again (otar.md 10, 23.2)
	bool auth = src == authority();
	bool rank_set = ok && !same && !auth && ((found && old->rank != e->rank) || (!found && e->rank != 0));
	bool new_or_key = ok && !auth && (!found || memcmp(old->pub, e->pub, X25519_LEN) != 0);
	bool unrevoke = found && (old->flags & OTAR_M_REVOKED) && !(e->flags & OTAR_M_REVOKED);
	if (!ok || (higher && !takeover) || above || own || rank_set || new_or_key || unrevoke ||
	    (self_out && n->rank != 0 && nc.rank >= n->rank)) {
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

// A NETCHAN (7.8) from a net control: the net's channel, stored and ACKed. Taken only from the authority (the
// best-ranked net control not revoked, 10), as ranks are: a backup net control can't move where the net is shown
static __attribute__((noinline)) void on_netchan(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						 const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED) || eng.out_len != 0)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || !fresh_or_tell(v, n, src, m->msgnum, now))
		return;
	bool auth = src == authority();
	if (auth)
		chan_put(&m->chan, now);
	uint32_t echo = m->msgnum;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->result = auth ? OTAR_ACK_STORED : OTAR_ACK_REFUSED;
	m->echo = echo;
	m->msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, m));
}

// A member: the ROSTER entry stored (or not): this radio's own rank when it was the entry, then the ACK
static __attribute__((noinline)) void ros_stored(const radio_view_t *v, uint32_t now)
{
	eng.ros_due = false;
	eng.ack.result = net.put_ok ? OTAR_ACK_STORED : OTAR_ACK_STORE_FAILED;
	if (net.put_ok && net.member.id == v->dmr.own_id && net.member.rank <= OTAR_RANK_MAX) {
		settings_t *st = settings_begin();
		st->otar_net.rank = net.member.rank;
		if (net.member.flags & OTAR_M_REVOKED)
			st->otar_net.flags |= OTAR_NET_REMOVED;
		settings_end(now);
	}
	net.page_ok = false;
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, eng.ack_to };
	out_set(eng.ack_to, false, otar_ack_build(eng.out, &a, eng.kmac, &eng.ack));
	eng.pair_ok = false;	// a public key may have changed: the pair keys are worked out again
}

// ZEROIZE (7.5) from a net control on the roster: this radio's keys wiped (Clear all keys, then a restart), only when
// its Remote wipe is on and the sender ranks above it. Answered either way: WIPED, built and sent first, then the wipe
// (engine_tick, once the transport has let it go); REFUSED when the wipe is off or the sender doesn't rank above it
static __attribute__((noinline)) void on_zeroize(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						 const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (eng.zz_wipe || !otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED))
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
	    !fresh_or_tell(v, n, src, m->msgnum, now))
		return;
	// A net control is wiped only by one above it (7.5)
	bool wipe = CONFIG_ZEROIZE && SETTINGS_FIELD(otar_wipe) == 1u && !(n->rank != 0 && nc.rank >= n->rank);
	uint32_t echo = m->msgnum;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->result = wipe ? OTAR_ACK_WIPED : OTAR_ACK_REFUSED;
	m->echo = echo;
	m->msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	if (!wipe) {
		if (eng.out_len == 0)
			out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, m));
		return;
	}
	// Wiping: the ACK takes the place of any message waiting (none matters now). From here the engine keeps only that
	// ciphertext: the pair keys, a TEK being stored, a rekey run's key go at once, and nothing else is taken or sent
	// until the wipe starts
	out_set(src, false, otar_ack_build(eng.out, &back, eng.kmac, m));
	crypto_wipe(m, sizeof *m);
	crypto_wipe(eng.ukek, sizeof eng.ukek);
	crypto_wipe(eng.kmac, sizeof eng.kmac);
	eng.pair_ok = false;
	crypto_wipe(eng.tek, sizeof eng.tek);
	eng.tek_due = false;
	crypto_wipe(&eng.ack, sizeof eng.ack);
	rk_free();
	eng.zz_wipe = true;
	eng.zz_wipe_by = now + ZZ_SEND_MS;
}

// A net control: a try of the ZEROIZE asked for (ui_svc_net_wipe), once the transport is free; its ACK within
// ACK_WAIT_MS (on_member), else another try (engine_tick)
static __attribute__((noinline)) void zz_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.zz.id;
	eng.zz.send = false;
	if (!eng.pair_ok || eng.pair_id != to) {
		eng.pair_ok = pair_keys(v->dmr.own_id, to, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = to;
	}
	if (!eng.pair_ok) {
		eng.zz.state = UI_ZZ_NO_ANSWER;
		return;
	}
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->msgnum = next_msgnum(now);
	m->target = to;
	otar_addr_t a = { v->dmr.own_id, to };
	out_set(to, false, otar_zeroize_build(eng.out, &a, eng.kmac, m));
	eng.zz.sent_num = m->msgnum;
	eng.zz.waiting = true;
	eng.zz.tries++;
	eng.zz.ack_by = now + ACK_WAIT_MS;
}

// The check value of system's key kid: false when the codeplug doesn't hold it
static bool key_kcv(uint8_t system, uint8_t kid, uint8_t kcv[KCV_LEN])
{
	uint8_t k[OTAR_KEY_LEN];
	bool ok = codeplug_traffic_key(system, DMR_AES_ALG_AES256, kid, k, sizeof k) == (int)sizeof k &&
		  kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, k, OTAR_KEY_LEN, kcv);
	crypto_wipe(k, sizeof k);
	return ok;
}

// A member's ACK of an INVENTORY for one keyset: its number and its key's check value (never the key)
static void inv_ack(const radio_view_t *v, bool next, uint32_t now)
{
	eng.ack.keyset = next ? v->otar.next_keyset : v->otar.keyset;
	eng.ack.ckr = 1;
	memset(eng.ack.kcv, 0, sizeof eng.ack.kcv);
	bool held = v->otar.on && key_kcv(v->otar.system, next ? v->otar.next_kid : v->otar.kid, eng.ack.kcv);
	eng.ack.result = held ? OTAR_ACK_HELD : OTAR_ACK_NOT_MANAGED;
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, eng.ack_to };
	out_set(eng.ack_to, false, otar_ack_build(eng.out, &a, eng.kmac, &eng.ack));
}

// INVENTORY (9) from a net control: an ACK for the active keyset, then one for the next (engine_tick)
static __attribute__((noinline)) void on_inventory(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						   const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED) || eng.out_len != 0 ||
	    eng.tek_due || eng.ros_due)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || !fresh_or_tell(v, n, src, m->msgnum, now))
		return;
	memset(&eng.ack, 0, sizeof eng.ack);
	eng.ack.net_id = n->net_id;
	eng.ack.rank = n->rank;
	eng.ack.echo = m->msgnum;
	eng.ack_to = src;
	inv_ack(v, false, now);
	eng.inv_next = v->otar.on && v->otar.has_next;
}

// TIME (7.4) from a net control to this radio, under the pair's keys: only a net control can make it, not a radio
// that merely holds the net's traffic key. The radio task keeps it only when this radio has no other clock
static __attribute__((noinline)) void on_time(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
					      const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!v->otar.on || !otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED) ||
	    eng.tek_due || eng.tek_job || eng.ros_due)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (otar_open(msg, len, &a, NULL, eng.kmac, m) && m->net_id == n->net_id && fresh_or_tell(v, n, src, m->msgnum, now))
		radio_req_otar(RADIO_OTAR_TIME, (uint32_t)(OTAR_EPOCH_UNIX + (int64_t)m->time_s));
}

// A net control: one TIME copy to the talkgroup, the time taken as it goes
static __attribute__((noinline)) void tm_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	eng.tm_next = now + CO_GAP_MS;
	otar_member_t *d = &eng.ros_d;
	uint16_t total = 0;
	// The next member on the roster: not this radio, not revoked
	for (;;) {
		if (eng.tm_left == 0 || otar_roster_window(eng.tm_i, d, 1, &total) != 1) {
			eng.tm_left = 0;
			return;
		}
		eng.tm_i++;
		eng.tm_left--;
		if (d->id != v->dmr.own_id && !(d->flags & OTAR_M_REVOKED))
			break;
	}
	int64_t s;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	if (!utc_clock_now(now, &s, NULL) || s < OTAR_EPOCH_UNIX || !pair_keys(v->dmr.own_id, d->id, n->net_id, ukek, kmac))
		return;
	crypto_wipe(ukek, sizeof ukek);
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->msgnum = next_msgnum(now);
	m->time_s = (uint32_t)(s - OTAR_EPOCH_UNIX);
	otar_addr_t a = { v->dmr.own_id, d->id };
	out_set(d->id, false, otar_time_build(eng.out, &a, kmac, m));
	crypto_wipe(kmac, sizeof kmac);
}

// A net control: the INVENTORY asked for (ui_svc_net_inventory), once the transport is free
static __attribute__((noinline)) void inv_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.inv_to;
	eng.inv_to = 0;
	if (!eng.pair_ok || eng.pair_id != to) {
		eng.pair_ok = pair_keys(v->dmr.own_id, to, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = to;
	}
	if (!eng.pair_ok) {
		eng.inv.state = UI_INV_NO_ANSWER;
		return;
	}
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, to };
	out_set(to, false, otar_inventory_build(eng.out, &a, eng.kmac, m));
	eng.inv.sent_num = m->msgnum;
	eng.inv.by = now + ACK_WAIT_MS;
}

// A member: where it is now, from the position service, as an LRRP answer gets it (the GPS, a host, or the fixed
// position; the ambiguity setting applied). False: none. A short copy under the service's lock: never a wait
static bool own_fix(otar_msg_t *m, uint32_t now)
{
#if CONFIG_POSITION
	position_fix_t f;
	uint32_t err_m;
	if (position_report(&f, &err_m, now) == POSITION_SRC_NONE)
		return false;
	m->lat = f.lat;
	m->lon = f.lon;
	m->alt_m = f.alt_m == POSITION_ALT_NONE ? OTAR_ALT_NONE :
		   f.alt_m < -32767 ? (int16_t)-32767 : f.alt_m > 32767 ? (int16_t)32767 : (int16_t)f.alt_m;
	uint32_t age = (int32_t)(now - f.ms) < 0 ? 0u : (uint32_t)(now - f.ms) / 1000u;
	m->age_s = age > 0xFFFFu ? (uint16_t)0xFFFFu : (uint16_t)age;
	return true;
#else
	(void)m;
	(void)now;
	return false;
#endif
}

// A member: the slot of eng.lans for answering net control src's LOCATE now, -1 when it answered it less than
// LOC_GAP_MS ago (or the four slots all did, each that recently). A LOCATE played back (its number already taken) gets
// at most the rate-limited "old message number"; this keeps even a net control's fresh ones to one answer per 10 s
static int loc_slot(uint32_t src, uint32_t now)
{
	const unsigned n = sizeof eng.lans / sizeof eng.lans[0];
	for (unsigned i = 0; i < n; i++)
		if (eng.lans[i].id == src)
			return (uint32_t)(now - eng.lans[i].at) >= LOC_GAP_MS ? (int)i : -1;
	for (unsigned i = 0; i < n; i++)
		if (eng.lans[i].id == 0 || (uint32_t)(now - eng.lans[i].at) >= LOC_GAP_MS)
			return (int)i;
	return -1;
}

// LOCATE (7.7) from a net control on the roster, not revoked: POSITION back to it under the pair's keys, its body
// encrypted, echoing the LOCATE. Refused when Share location is off; no fix when the radio has no position. Never under
// radio silence (radio-silence.md): a radio that keeps quiet doesn't say where it is by itself
static __attribute__((noinline)) void on_locate(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						 const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (radio_silent() || !otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED) ||
	    eng.out_len != 0 || eng.tek_due || eng.ros_due)
		return;
	int slot = loc_slot(src, now);
	if (slot < 0)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || !fresh_or_tell(v, n, src, m->msgnum, now))
		return;
	uint32_t echo = m->msgnum;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->echo = echo;
	if (SETTINGS_FIELD(otar_loc_off) != 0u)
		m->result = OTAR_POS_REFUSED;
	else if (!own_fix(m, now))
		m->result = OTAR_POS_NO_FIX;
	else
		m->result = OTAR_POS_OK;
	m->msgnum = next_msgnum(now);
	otar_addr_t back = { v->dmr.own_id, src };
	out_set(src, false, otar_position_build(eng.out, &back, eng.kmac, m));
	crypto_wipe(m, sizeof *m);
	if (eng.out_len != 0) {
		eng.lans[slot].id = src;
		eng.lans[slot].at = now;
	}
}

// A net control: a try of the LOCATE asked for (ui_svc_net_locate), once the transport is free; its POSITION within
// ACK_WAIT_MS (on_position), else another try (engine_tick)
static __attribute__((noinline)) void loc_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.loc.id;
	eng.loc.send = false;
	if (!eng.pair_ok || eng.pair_id != to) {
		eng.pair_ok = pair_keys(v->dmr.own_id, to, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = to;
	}
	if (!eng.pair_ok) {
		eng.loc.state = UI_LOC_NO_ANSWER;
		eng.loc.got_at = now;
		return;
	}
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, to };
	out_set(to, false, otar_locate_build(eng.out, &a, eng.kmac, m));
	eng.loc.sent_num = m->msgnum;
	eng.loc.waiting = true;
	eng.loc.tries++;
	eng.loc.ans_by = now + ACK_WAIT_MS;
}

// A net control: the POSITION it waits for, from the member it asked, echoing its last LOCATE. Anything else is
// dropped before the X25519 its MAC needs: a stream of forged ones can't tie this radio up
static __attribute__((noinline)) void on_position(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						   const otar_net_t *n, uint32_t now)
{
	if (!eng.loc.waiting || src != eng.loc.id)
		return;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	if (!pair_keys(v->dmr.own_id, src, n->net_id, ukek, kmac))
		return;
	crypto_wipe(ukek, sizeof ukek);
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	bool ok = otar_open(msg, len, &a, NULL, kmac, m) && m->net_id == n->net_id && m->echo == eng.loc.sent_num;
	crypto_wipe(kmac, sizeof kmac);
	if (ok) {
		bool pos = m->result == OTAR_POS_OK;
		eng.loc.waiting = false;
		eng.loc.state = pos ? UI_LOC_GOT : m->result == OTAR_POS_NO_FIX ? UI_LOC_NO_FIX : UI_LOC_REFUSED;
		eng.loc.lat = pos ? m->lat : 0;
		eng.loc.lon = pos ? m->lon : 0;
		eng.loc.alt_m = pos ? m->alt_m : OTAR_ALT_NONE;
		eng.loc.age_s = m->age_s;
		eng.loc.got_at = now;
		if (src == eng.oos_id)
			eng.oos_id = 0;		// it answers again
	}
	crypto_wipe(m, sizeof *m);
}

// A net control: an INVENTORY's ACK, one keyset the member holds, checked against this radio's key of that keyset
static void inv_got(const radio_view_t *v, const otar_msg_t *m)
{
	eng.inv.state = UI_INV_GOT;
	if (eng.inv.n >= 2u || m->result != OTAR_ACK_HELD)
		return;
	uint8_t kcv[KCV_LEN];
	bool same = false;
	if (v->otar.on && m->keyset == v->otar.keyset)
		same = key_kcv(v->otar.system, v->otar.kid, kcv) && memcmp(kcv, m->kcv, KCV_LEN) == 0;
	else if (v->otar.on && v->otar.has_next && m->keyset == v->otar.next_keyset)
		same = key_kcv(v->otar.system, v->otar.next_kid, kcv) && memcmp(kcv, m->kcv, KCV_LEN) == 0;
	eng.inv.keyset[eng.inv.n] = (uint16_t)m->keyset;
	eng.inv.same[eng.inv.n] = same;
	eng.inv.n++;
}

// A member: CHANGEOVER from its net control, under the key from the next TEK (7.3)
__attribute__((noinline)) static void on_changeover(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src, uint32_t dst,
			  const otar_net_t *n, uint32_t now)
{
	otar_member_t nc;
	if (!v->otar.on || !v->otar.has_next || !otar_roster_find(src, &nc) || nc.rank == 0 || (nc.flags & OTAR_M_REVOKED))
		return;
	uint8_t tek[OTAR_KEY_LEN], k[OTAR_KEY_LEN];
	if (codeplug_traffic_key(v->otar.system, DMR_AES_ALG_AES256, v->otar.next_kid, tek, sizeof tek) != (int)sizeof tek)
		return;
	otar_group_mac_key(tek, OTAR_GK_CO, k);
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

// The net control: the slot of eng.hans for answering member src's HELLO (message number num, its MAC checked) now, -1
// when it can't be: answered less than CU_GAP_MS ago with a HELLO at least as new, or HELLO_ANS_N others were. A HELLO
// newer than the one answered is answered at once: the member said it again after its answer was lost (it restarted,
// or was off air; found on the bench: a member restarted during the answer waited 5 min for its next try). A recorded
// HELLO played back is never newer, so it still makes this radio answer at most HELLO_ANS_N times per CU_GAP_MS
static int hello_slot(uint32_t src, uint32_t num, uint32_t now)
{
	for (unsigned i = 0; i < HELLO_ANS_N; i++)
		if (eng.hans[i].id == src)
			return (uint32_t)(now - eng.hans[i].at) >= CU_GAP_MS || num > eng.hans[i].num ? (int)i : -1;
	for (unsigned i = 0; i < HELLO_ANS_N; i++)
		if (eng.hans[i].id == 0 || (uint32_t)(now - eng.hans[i].at) >= CU_GAP_MS)
			return (int)i;
	return -1;
}

// The net control: a member's HELLO (9) answered, always, within hello_slot's limit: the rekey run's REKEY when the
// member hasn't its key yet; the net's active key flagged now when the member is behind it (outside a run, otar.md 9);
// else an ACK, CURRENT with this radio's active keyset (NOT_MANAGED when it manages no keys), echoing the HELLO
static __attribute__((noinline)) void hello_answer(const radio_view_t *v, const otar_msg_t *m, uint32_t src,
						   const otar_net_t *n, const uint8_t kmac[OTAR_KEY_LEN], uint32_t now)
{
	int slot = hello_slot(src, m->msgnum, now);
	if (slot < 0)
		return;
	rekey_t *rk = eng.rk;
	bool behind = v->otar.on && m->keyset < v->otar.keyset;
	bool answered = false;
	for (uint8_t i = 0; rk != NULL && i < rk->n; i++) {
		rk_member_t *mm = &rk->m[i];
		if (mm->id == src && mm->state != UI_RK_OK && mm->state != UI_RK_SYNC) {
			mm->due = now;		// back on: its REKEY at once
			if (mm->state == UI_RK_FAIL || mm->state == UI_RK_REFUSED)
				mm->state = UI_RK_WAIT;
			answered = true;
		}
	}
	// Holding the keyset this radio withdrew as its next (off during the cancel run, 7.9): WITHDRAW it first
	uint8_t cut_kid;
	uint32_t cut = cut_get(&cut_kid);
	if (rk == NULL && cut != 0 && cut > v->otar.keyset && (m->flags & 1u) && m->next_keyset == cut) {
		eng.wd_to = src;
		answered = true;
	}
	if (!answered && behind && rk == NULL) {
		eng.cu_to = src;	// sent by cu_send once the transport is free
		answered = true;
	}
	if (!answered && !behind && eng.out_len == 0) {
		otar_msg_t *a = &eng.ros_m;
		memset(a, 0, sizeof *a);
		a->net_id = n->net_id;
		a->rank = n->rank;
		a->keyset = v->otar.on ? v->otar.keyset : 0u;
		a->result = v->otar.on ? OTAR_ACK_CURRENT : OTAR_ACK_NOT_MANAGED;
		a->echo = m->msgnum;
		a->msgnum = next_msgnum(now);
		otar_addr_t back = { v->dmr.own_id, src };
		out_set(src, false, otar_ack_build(eng.out, &back, kmac, a));
		answered = eng.out_len != 0;
	}
	// Behind with a run going and its key held: nothing yet (the member asks again; the run's end lets it catch up)
	if (answered) {
		eng.hans[slot].id = src;
		eng.hans[slot].at = now;
		eng.hans[slot].num = m->msgnum;
		// ... then the net's channel (7.8), so a member that was off when it changed learns it at its next start
		otar_chan_t c;
		chan_get(&c);
		if (c.rx_hz != 0)
			eng.ch_to = src;
	}
}

// A net control's numbers skipped past last, a member's last taken from it (7.6): true when they are past it now. Only
// up to MSGNUM_SKIP_MAX at once, so even a member with valid pair keys can't use up the 32-bit space
static bool msgnum_skip(uint32_t last)
{
	if (last < mn.next)
		return true;
	if (last - mn.next >= MSGNUM_SKIP_MAX || last >= 0xFFFFFF00u)
		return false;
	mn.next = last + 1u;	// used once a reservation above it is saved (msgnum_tick)
	return true;
}

// The net control: a member's ACK MSGNUM (7.6): the message it answers, which this radio waits for, came with a number
// not above the last the member took from this radio (its settings went back, a restore). The numbers skip past it
// and the message is tried again at once; beyond the skip, the member shows "Out of sync: rejoin"
static __attribute__((noinline)) void oos_got(const otar_msg_t *m, uint32_t src, uint32_t now)
{
	uint32_t last = m->keyset, echo = m->echo;
	rekey_t *rk = eng.rk;
	rk_member_t *mm = rk != NULL && rk->cur != 0xFF && rk->m[rk->cur].id == src && rk->m[rk->cur].sent == echo ?
			  &rk->m[rk->cur] : NULL;
	bool ros = eng.ros.waiting && eng.ros.dst == src && eng.ros.sent_num == echo;
	bool inv = eng.inv.state == UI_INV_ASKING && eng.inv.id == src && eng.inv.sent_num == echo;
	bool zz = eng.zz.waiting && eng.zz.id == src && eng.zz.sent_num == echo;
	bool loc = eng.loc.waiting && eng.loc.id == src && eng.loc.sent_num == echo;
	if (last < echo || (mm == NULL && !ros && !inv && !zz && !loc))
		return;		// not about a message this radio waits on
	bool skipped = msgnum_skip(last);
	if (!skipped)
		eng.oos_id = src;
	if (mm != NULL) {
		mm->state = skipped ? UI_RK_WAIT : UI_RK_SYNC;
		mm->due = now;
		rk->cur = 0xFF;
	}
	if (ros)
		eng.ros.ack_by = now;		// a try gone; the next goes with a fresh number
	if (inv) {
		if (skipped) {
			eng.inv_to = src;
			eng.inv.by = now + 2u * ACK_WAIT_MS;
		} else {
			eng.inv.state = UI_INV_NO_ANSWER;
		}
	}
	if (zz) {
		if (skipped) {
			eng.zz.ack_by = now;
		} else {
			eng.zz.waiting = false;
			eng.zz.state = UI_ZZ_NO_ANSWER;
		}
	}
	if (loc) {
		if (skipped) {
			eng.loc.ans_by = now;
		} else {
			eng.loc.waiting = false;
			eng.loc.state = UI_LOC_NO_ANSWER;
			eng.loc.got_at = now;
		}
	}
}

// The net control: an ACK or a HELLO from a member
__attribute__((noinline)) static void on_member(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src, const otar_net_t *n, uint32_t now)
{
	rekey_t *rk = eng.rk;
	// Only an ACK this radio waits for, or a HELLO at most every HELLO_GAP_MS, is worked on: each costs an X25519
	// before its MAC can be checked, so a stream of forged ones (any member's ID as the source) can't tie up this radio
	bool want = msg[2] == OTAR_ACK &&
		    ((rk != NULL && rk->cur != 0xFF && rk->m[rk->cur].id == src) || (eng.ros.waiting && eng.ros.dst == src) ||
		     (eng.inv.state != UI_INV_NONE && eng.inv.id == src) || (eng.zz.waiting && eng.zz.id == src) ||
	     (eng.loc.waiting && eng.loc.id == src));	// a LOCATE's "old message number"
	bool ack = msg[2] == OTAR_ACK;
	if (ack)
		otar_note_ack(OTAR_AN_IN, 0);
	if (msg[2] == OTAR_HELLO && (uint32_t)(now - eng.hello_at) >= HELLO_GAP_MS) {
		eng.hello_at = now;
		want = true;
	}
	if (!want) {
		if (ack)
			otar_note_ack(OTAR_AN_UNWANTED, 0);
		return;
	}
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	if (!pair_keys(v->dmr.own_id, src, n->net_id, ukek, kmac)) {
		if (ack)
			otar_note_ack(OTAR_AN_NO_PAIR, 0);
		return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t m;
	bool ok = otar_open(msg, len, &a, NULL, kmac, &m) && m.net_id == n->net_id;
	if (ack && !ok)
		otar_note_ack(OTAR_AN_BAD_MAC, 0);
	crypto_wipe(ukek, sizeof ukek);
	if (ok && m.type == OTAR_HELLO)
		hello_answer(v, &m, src, n, kmac, now);
	crypto_wipe(kmac, sizeof kmac);
	if (!ok || m.type == OTAR_HELLO)
		return;
	if (m.type == OTAR_ACK && m.result == OTAR_ACK_MSGNUM) {
		oos_got(&m, src, now);
		return;
	}
	if (m.type == OTAR_ACK && src == eng.oos_id)
		eng.oos_id = 0;		// it answers again: rejoined
	// A ZEROIZE's: wiped, or refused (its Remote wipe off, or this radio not above it)
	if (m.type == OTAR_ACK && eng.zz.waiting && src == eng.zz.id && m.echo == eng.zz.sent_num) {
		eng.zz.waiting = false;
		eng.zz.state = m.result == OTAR_ACK_WIPED ? UI_ZZ_WIPED : UI_ZZ_REFUSED;
		return;
	}
	if (m.type == OTAR_ACK && m.ckr == 0) {		// a roster entry's
		if (eng.ros.on && eng.ros.waiting && src == eng.ros.dst && m.echo == eng.ros.sent_num) {
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
	if (m.type == OTAR_ACK && src == eng.inv.id && eng.inv.state != UI_INV_NONE && m.echo == eng.inv.sent_num)
		inv_got(v, &m);
	if (rk == NULL)
		return;
	bool counted = false;
	for (uint8_t i = 0; i < rk->n; i++) {
		rk_member_t *mm = &rk->m[i];
		if (mm->id != src)
			continue;
		if (m.type == OTAR_ACK && m.keyset == rk->keyset && m.echo == mm->sent) {
			counted = true;
			// OK only with the check value of the key this run sent: an old ACK of the same keyset (a run stopped
			// and started again) or another net control's key under the same number doesn't count
			// A cancel run's WITHDRAW: OK once dropped; OLD (changed over already, too late) shows out of sync,
			// not tried again (7.9)
			bool same = memcmp(m.kcv, rk->kcv, sizeof rk->kcv) == 0;
			otar_note_ack(OTAR_AN_COUNTED, (uint8_t)(m.result | (same ? 0u : 0x80u)));	// 0x80: another key's check value
			if (rk->cancel)
				mm->state = m.result == OTAR_ACK_DROPPED ? UI_RK_OK : m.result == OTAR_ACK_OLD ? UI_RK_SYNC : UI_RK_REFUSED;
			else
				mm->state = (m.result == OTAR_ACK_STORED || m.result == OTAR_ACK_HELD) && same ? UI_RK_OK : UI_RK_REFUSED;
			if (rk->cur == i)
				rk->cur = 0xFF;
			if (mm->state == UI_RK_REFUSED)
				mm->due = now + RETRY_MS;
		}
	}
	if (!counted && m.type == OTAR_ACK)
		otar_note_ack(OTAR_AN_NO_MATCH, 0);
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
		(void)kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, DMR_AES_ALG_AES256, rk->tek, OTAR_KEY_LEN, rk->kcv);
		rk->keyed = true;
		// The changeover counts from now, not from Rekey now: the key presses may have taken longer than the choice,
		// and a changeover already past would change this radio over before any member had the key (seen on air)
		rk->changeover = rk->mins != 0 && v->otar.clock_ok && v->otar.now_min != 0 ? v->otar.now_min + rk->mins : 0;
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
		if (rk->keyset != (uint32_t)v->otar.keyset + 1u)
			radio_req_otar(RADIO_OTAR_NEXT_KS, rk->keyset);	// numbered past a withdrawn keyset (7.9)
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
	if (rk->cancel) {
		// A cancel run (7.9): ends once every member dropped the keyset (or is out of sync), or after CANCEL_RUN_MS;
		// a member that was off is told at its HELLO (hello_answer)
		bool left = false;
		for (uint8_t i = 0; i < rk->n; i++)
			left |= rk->m[i].state != UI_RK_OK && rk->m[i].state != UI_RK_SYNC;
		if ((!left || (int32_t)(now - rk->cancel_by) >= 0) && rk->cur == 0xFF) {
			rk_free();
			return true;
		}
	} else if (!shown) {
		// Changed over by the clock (not by hand): CHANGEOVER for the members that have no clock (otar.md 9)
		if (rk->changeover != 0 && !eng.co_hand && v->otar.on && v->otar.kid == rk->kid)
			(void)co_start(v, rk->kid, rk->keyset, n->net_id, n->rank, false);
		eng.co_hand = false;
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
		if (mm->state == UI_RK_OK || mm->state == UI_RK_SYNC || (int32_t)(now - mm->due) < 0)
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
		m.flags = rk->changeover != 0 ? OTAR_RK_CLOCK : 0u;
		otar_addr_t a = { v->dmr.own_id, mm->id };
		int len;
		if (rk->cancel) {
			len = otar_withdraw_build(eng.out, &a, kmac, &m);
		} else {
			memcpy(m.tek, rk->tek, OTAR_KEY_LEN);
			len = otar_rekey_build(eng.out, &a, ukek, kmac, &m);
		}
		crypto_wipe(&m, sizeof m);
		crypto_wipe(ukek, sizeof ukek);
		crypto_wipe(kmac, sizeof kmac);
		out_set(mm->id, false, len);
		mm->sent = (uint32_t)eng.out[5] << 24 | (uint32_t)eng.out[6] << 16 | (uint32_t)eng.out[7] << 8 | eng.out[8];
		mm->state = UI_RK_SENT;
		mm->tries++;
		rk->cur = i;
		rk->ack_by = now + ACK_WAIT_MS;
		return true;
	}
	return false;
}

// A NETCHAN (7.8) to member `to` under the pair's MAC key: the net's channel as this radio holds it. Its message number
static uint32_t chan_out(const radio_view_t *v, const otar_net_t *n, uint32_t to, const uint8_t kmac[OTAR_KEY_LEN],
			 uint32_t now)
{
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	m->net_id = n->net_id;
	m->rank = n->rank;
	m->msgnum = next_msgnum(now);
	chan_get(&m->chan);
	otar_addr_t a = { v->dmr.own_id, to };
	out_set(to, false, otar_netchan_build(eng.out, &a, kmac, m));
	return m->msgnum;
}

// The net control's roster run: the net's channel wanted at member d, after its entries (7.8): on every run to every
// member and on one to a member just added; not on one entry's run (a rank, a revoke)
static bool ros_chan_wanted(const otar_member_t *d, uint32_t own)
{
	otar_chan_t c;
	chan_get(&c);
	return c.rx_hz != 0 && d->id != own && !(d->flags & OTAR_M_REVOKED) && !eng.ros.one &&
	       (eng.ros.chan_only || eng.ros.only == 0 || d->id == eng.ros.only);
}

// The net control's roster run: is entry e wanted at member d?
static bool ros_wanted(const otar_member_t *d, const otar_member_t *e, uint32_t own)
{
	if (d->id == own || ((d->flags & OTAR_M_REVOKED) && !(eng.ros.one && d->id == eng.ros.only)))
		return false;	// a radio just revoked still gets its own entry (Removed from the net)
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
		if (eng.ros.chan_only && eng.ros.ent_i < total)
			eng.ros.ent_i = total;		// the net's channel alone
		// After the entries, the net's channel (7.8): entry position total. Its ACK, as an entry's, moves past it
		bool chan = eng.ros.ent_i == total && ros_chan_wanted(d, v->dmr.own_id);
		if (eng.ros.ent_i >= total && !chan) {
			eng.ros.dst_i++;
			eng.ros.ent_i = 0;
			continue;
		}
		if (chan) {
			if (!eng.pair_ok || eng.pair_id != d->id) {
				eng.pair_ok = pair_keys(v->dmr.own_id, d->id, n->net_id, eng.ukek, eng.kmac);
				eng.pair_id = d->id;
			}
			if (!eng.pair_ok) {
				eng.ros.failed++;
				eng.ros.ent_i++;
				return true;
			}
			eng.ros.sent_num = chan_out(v, n, d->id, eng.kmac, now);
			eng.ros.dst = d->id;
			eng.ros.waiting = true;
			eng.ros.ack_by = now + ACK_WAIT_MS;
			return true;
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
		eng.ros.sent_num = m->msgnum;
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
	if (eng.tek_ok) {
		radio_req_otar(RADIO_OTAR_NEXT_AT, eng.tek_kid | (eng.tek_at << 8));
		radio_req_otar(RADIO_OTAR_NEXT_KS, eng.tek_ks);	// the net's number, not this radio's own count
		if (eng.tek_now)
			radio_req_otar(RADIO_OTAR_NOW, 0);	// the net's active key: this radio catches up (otar.md 9)
	}
	eng.tek_now = false;
	eng.ack.msgnum = next_msgnum(now);
	otar_addr_t a = { v->dmr.own_id, eng.ack_to };
	out_set(eng.ack_to, false, otar_ack_build(eng.out, &a, eng.kmac, &eng.ack));
}

// A net control: the net's active key to a member that said HELLO without it (otar.md 9), as a REKEY with
// OTAR_RK_NOW. Sent once: the member says HELLO again at its next start if it didn't take it
static __attribute__((noinline)) void cu_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.cu_to;
	eng.cu_to = 0;
	otar_member_t mm;
	if (!v->otar.on || !otar_roster_find(to, &mm) || (mm.flags & OTAR_M_REVOKED))
		return;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	if (pair_keys(v->dmr.own_id, to, n->net_id, ukek, kmac) &&
	    codeplug_traffic_key(v->otar.system, DMR_AES_ALG_AES256, v->otar.kid, m->tek, OTAR_KEY_LEN) == (int)OTAR_KEY_LEN) {
		m->net_id = n->net_id;
		m->rank = n->rank;
		m->msgnum = next_msgnum(now);
		m->keyset = v->otar.keyset;
		m->ckr = 1;
		m->kid = v->otar.kid;
		m->flags = OTAR_RK_NOW;
		otar_addr_t a = { v->dmr.own_id, to };
		out_set(to, false, otar_rekey_build(eng.out, &a, ukek, kmac, m));
	}
	crypto_wipe(m, sizeof *m);
	crypto_wipe(ukek, sizeof ukek);
	crypto_wipe(kmac, sizeof kmac);
}

// A net control: the withdrawn keyset (otar_cut, 7.9) to a member whose HELLO said it holds it as its next (it was off
// during the cancel run). Sent once: the member says HELLO again at its next start
static __attribute__((noinline)) void wd_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.wd_to;
	eng.wd_to = 0;
	otar_member_t mm;
	uint8_t kid;
	uint32_t ks = cut_get(&kid);
	if (ks == 0 || !otar_roster_find(to, &mm) || (mm.flags & OTAR_M_REVOKED))
		return;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	otar_msg_t *m = &eng.ros_m;
	memset(m, 0, sizeof *m);
	if (pair_keys(v->dmr.own_id, to, n->net_id, ukek, kmac)) {
		m->net_id = n->net_id;
		m->rank = n->rank;
		m->msgnum = next_msgnum(now);
		m->keyset = ks;
		m->kid = kid;
		otar_addr_t a = { v->dmr.own_id, to };
		out_set(to, false, otar_withdraw_build(eng.out, &a, kmac, m));
	}
	crypto_wipe(m, sizeof *m);
	crypto_wipe(ukek, sizeof ukek);
	crypto_wipe(kmac, sizeof kmac);
}

// A net control: the net's channel to a member whose HELLO it answered (7.8). Sent once, its ACK not waited for: the
// member asks again at its next start
static __attribute__((noinline)) void ch_send(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	uint32_t to = eng.ch_to;
	eng.ch_to = 0;
	otar_member_t mm;
	if (!otar_roster_find(to, &mm) || (mm.flags & OTAR_M_REVOKED))
		return;
	uint8_t ukek[OTAR_KEY_LEN], kmac[OTAR_KEY_LEN];
	if (pair_keys(v->dmr.own_id, to, n->net_id, ukek, kmac))
		(void)chan_out(v, n, to, kmac, now);
	crypto_wipe(ukek, sizeof ukek);
	crypto_wipe(kmac, sizeof kmac);
}

// Joined: Remote wipe and Share location on (otar.md 7.5, 7.7), as every net control's other remote controls are; the
// user may turn them off
void ui_svc_net_joined(void)
{
	eng.manage_due = true;
	net.chan_due = true;	// the net's channel: the one it joined on, until its net control says another (7.8)
	settings_t *st = settings_begin();
	st->otar_wipe = 1u;
	st->otar_loc_off = 0u;	// Share location the same (7.7)
	settings_end(hal_millis());
}

// A member just joined that doesn't manage keys: it starts on the AES channel it is on, with that channel's key as
// its active one, as Net keys > Manage keys does. Its HELLO then tells the net control which key it holds, and the net
// control sends the net's active key if that isn't it (9). On another channel it stays unmanaged
static void manage_joined(const radio_view_t *v)
{
	eng.manage_due = false;
	// Whether or not the radio holds the channel's key: one whose keys were cleared (or never loaded) manages them
	// all the same, says HELLO and gets the net's active key as a REKEY flagged now (9), all in the clear (dmr-data.md
	// 13.5). Found on air: a radio rejoined after Clear all keys stayed "Keys not managed" and never caught up
	// Only a radio not managing keys yet: starting again would reset its keysets to keyset 1 and with them its place
	// against older keysets (7.1). Leave the net keeps them, so a member that leaves and joins again keeps its keys
	if (!v->otar.on && v->ch.mode == RADIO_MODE_DMR && v->ch.kind == CODEPLUG_KIND_DMR_AES && v->ch.aes_ref != 0)
		radio_req_otar(RADIO_OTAR_START, (uint8_t)(v->ch.aes_ref - 1u));
}

// The wait before a member's next HELLO, after its n-th went unanswered: 1 min, 5 min, then every 15 min. A net
// control away or off costs the channel one short message a quarter of an hour
static uint32_t hello_gap(uint8_t n)
{
	return n <= 1u ? 60000u : n == 2u ? 300000u : 900000u;
}

// A member asks its net control for keys (rekey request, 9): HELLO with the keysets it holds
static __attribute__((noinline)) void say_hello(const radio_view_t *v, const otar_net_t *n, uint32_t now)
{
	if (eng.hello.n < 0xFFu)
		eng.hello.n++;
	eng.hello.due = now + hello_gap(eng.hello.n);
	eng.hello.state = UI_HELLO_ASKING;
	// To the best-ranked net control not revoked (net control 1 when it is there): a backup net control's keys may be
	// older
	otar_member_t *nc = &eng.ros_d, *c = &eng.ros_e;
	nc->rank = 0;
	uint16_t total = 0;
	for (uint16_t i = 0; otar_roster_window(i, c, 1, &total) == 1; i++)
		if (c->rank != 0 && !(c->flags & OTAR_M_REVOKED) && (nc->rank == 0 || c->rank < nc->rank))
			*nc = *c;
	if (nc->rank == 0 || !pair_keys(v->dmr.own_id, nc->id, n->net_id, eng.ukek, eng.kmac))
		return;
	uint32_t to = nc->id;
	eng.pair_id = to;
	eng.pair_ok = true;
	otar_msg_t m;
	memset(&m, 0, sizeof m);
	m.net_id = n->net_id;
	m.msgnum = next_msgnum(now);
	m.keyset = v->otar.keyset;
	m.next_keyset = v->otar.has_next ? v->otar.next_keyset : 0u;
	m.flags = v->otar.has_next ? 1u : 0u;
	otar_addr_t a = { v->dmr.own_id, to };
	out_set(to, false, otar_hello_build(eng.out, &a, eng.kmac, &m));
	eng.hello.to = to;
	eng.hello.num = m.msgnum;
	eng.hello.sent_at = now;
}

// A member: its net control's ACK of its HELLO (9): up to date (or the net control manages no keys). Asked no more
static __attribute__((noinline)) void on_hello_ack(const radio_view_t *v, const uint8_t *msg, int len, uint32_t src,
						   const otar_net_t *n, uint32_t now)
{
	if (!eng.hello.on || src != eng.hello.to || eng.hello.num == 0)
		return;
	if (!eng.pair_ok || eng.pair_id != src) {
		eng.pair_ok = pair_keys(v->dmr.own_id, src, n->net_id, eng.ukek, eng.kmac);
		eng.pair_id = src;
		if (!eng.pair_ok)
			return;
	}
	otar_addr_t a = { src, v->dmr.own_id };
	otar_msg_t *m = &eng.ros_m;
	if (!otar_open(msg, len, &a, NULL, eng.kmac, m) || m->net_id != n->net_id || m->echo != eng.hello.num ||
	    (m->result != OTAR_ACK_CURRENT && m->result != OTAR_ACK_NOT_MANAGED) || !take_msgnum(src, m->msgnum, now))
		return;
	eng.hello.on = false;
	eng.hello.state = m->result == OTAR_ACK_CURRENT ? UI_HELLO_CURRENT : UI_HELLO_NONE;
}

uint8_t ui_svc_net_request_keys(const radio_view_t *v)
{
	otar_net_t n;
	net_read(&n);
	bool member = (n.flags & OTAR_NET_IN) && n.rank == 0 && !(n.flags & OTAR_NET_REMOVED);
	crypto_wipe(&n, sizeof n);
	if (!member)
		return UI_NET_NO_MEMBER;
	if (!v->otar.on)
		return UI_NET_NOT_MANAGED;
	uint32_t now = hal_millis();
	if (eng.hello.n != 0 && (uint32_t)(now - eng.hello.sent_at) < HELLO_REQ_MS)
		return UI_NET_BUSY;
	eng.hello.on = true;
	eng.hello.n = 0;
	eng.hello.due = now;
	return UI_NET_OK;
}

// The rekey schedule (settings_t.otar_sched, otar_sched_at): every this many days, and when the next is due
static uint8_t sched_get(uint32_t *at)
{
	settings_t *st = settings_begin();
	uint8_t days = st->otar_sched;
	*at = ((uint32_t)st->otar_sched_at[0] << 16) | ((uint32_t)st->otar_sched_at[1] << 8) | st->otar_sched_at[2];
	settings_end(0);
	return days;
}

static void sched_put(uint8_t days, uint32_t at, uint32_t now)
{
	settings_t *st = settings_begin();
	st->otar_sched = days;
	st->otar_sched_at[0] = (uint8_t)(at >> 16);
	st->otar_sched_at[1] = (uint8_t)(at >> 8);
	st->otar_sched_at[2] = (uint8_t)at;
	settings_end(now);
}

// A net control's scheduled rekey (otar.md 9): when it is due by the clock and nothing else runs, a rekey whose
// changeover is SCHED_CO_MIN later by the clocks. Its key waits for the pool like Rekey now's: the radio's key presses
// fill it. A next key already waiting (a rekey not changed over yet) holds it back
static __attribute__((noinline)) bool sched_tick(const radio_view_t *v, uint32_t now)
{
	uint32_t at;
	uint8_t days = sched_get(&at);
	if (days == 0 || !v->otar.on || !v->otar.clock_ok || v->otar.now_min == 0)
		return false;
	uint32_t next = v->otar.now_min + (uint32_t)days * 1440u;
	if (at == 0) {
		sched_put(days, next, now);
		return true;
	}
	if (v->otar.now_min < at || v->otar.has_next)
		return false;
	if (ui_svc_net_rekey(v, SCHED_CO_MIN) != UI_NET_OK)
		return false;
	sched_put(days, next, now);
	return true;
}

// A member: the wipe a ZEROIZE asked for, its ACK gone first (on_zeroize)
static void zz_wipe_start(void)
{
	eng.zz_wipe = false;
	crypto_wipe(eng.out, sizeof eng.out);
	eng.out_len = 0;
#if CONFIG_ZEROIZE
	(void)ui_svc_clear_keys_start();
#endif
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
		memset(&eng.hello, 0, sizeof eng.hello);
		eng.hello.on = true;
		eng.hello.due = now + HELLO_AFTER_MS;
		memset(eng.hans, 0, sizeof eng.hans);
		eng.oos_mask = 0;
		eng.oos_id = 0;
		eng.pair_ok = false;
		memset(&eng.ros, 0, sizeof eng.ros);
		eng.ros_due = false;
		eng.pend.on = false;
		memset(&eng.zz, 0, sizeof eng.zz);
		memset(&eng.loc, 0, sizeof eng.loc);
		memset(eng.lans, 0, sizeof eng.lans);
		eng.inv_to = 0;
		eng.cu_to = 0;
		eng.wd_to = 0;
		eng.ch_to = 0;
		eng.inv_next = false;
		eng.tm_left = 0;
		memset(&eng.inv, 0, sizeof eng.inv);
		if (!in)
			rk_free();
	}
	if (!in) {
		crypto_wipe(&n, sizeof n);
		if (eng.zz_wipe)
			zz_wipe_start();	// out of the net meanwhile: the wipe all the same
		return false;
	}
	msgnum_tick(now);
	bool mn_ok = msgnum_ready();
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
			if (st == OTAR_SEND_FAILED && eng.zz.waiting)
				eng.zz.ack_by = now;
			if (st == OTAR_SEND_FAILED && eng.loc.waiting)
				eng.loc.ans_by = now;

		}
	}
	if (eng.out_len != 0 && !eng.sending) {
		if (otar_send(eng.out_dst, eng.out_group, eng.out, eng.out_len))
			eng.sending = true;
		crypto_wipe(eng.out, sizeof eng.out);
		eng.out_len = 0;
	}
	// A member wiping (on_zeroize): its ACK handed to the transport and gone (sent or failed), or out of time. Nothing
	// else runs meanwhile
	if (eng.zz_wipe) {
		if ((eng.out_len == 0 && !eng.sending) || (int32_t)(now - eng.zz_wipe_by) >= 0)
			zz_wipe_start();
		crypto_wipe(&n, sizeof n);
		return true;
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
			else if (h.type == OTAR_INVENTORY && !group && src != v->dmr.own_id)
				on_inventory(v, msg, len, src, &n, now);
			else if (h.type == OTAR_TIME && !group && src != v->dmr.own_id)
				on_time(v, msg, len, src, &n, now);
			else if (h.type == OTAR_LOCATE && !group && src != v->dmr.own_id)
				on_locate(v, msg, len, src, &n, now);
			else if (h.type == OTAR_POSITION && !group && n.rank != 0)
				on_position(v, msg, len, src, &n, now);
			else if (h.type == OTAR_NETCHAN && !group && src != v->dmr.own_id)
				on_netchan(v, msg, len, src, &n, now);
			else if (h.type == OTAR_WITHDRAW && !group && src != v->dmr.own_id && eng.rk == NULL)
				on_withdraw(v, msg, len, src, &n, now);
			else if ((h.type == OTAR_ACK || h.type == OTAR_HELLO) && !group && n.rank != 0)
				on_member(v, msg, len, src, &n, now);
			else if (h.type == OTAR_ACK && !group && n.rank == 0)
				on_hello_ack(v, msg, len, src, &n, now);
			changed = true;
		}
		crypto_wipe(msg, OTAR_MSG_MAX);
		mn_ok = msgnum_ready();		// a member's "old message number" may have skipped them past the reservation
	}
	// A member: the next keyset's ACK of an INVENTORY
	if (eng.inv_next && eng.out_len == 0 && !eng.sending) {
		eng.inv_next = false;
		if (eng.pair_ok && eng.pair_id == eng.ack_to)
			inv_ack(v, true, now);
	}
	if (eng.manage_due && n.rank == 0)
		manage_joined(v);
	// A member back on asks its net control for keys with HELLO (9), again until it is answered; not once it is
	// removed from the net
	if (n.rank == 0 && eng.hello.on && v->otar.on && !(n.flags & OTAR_NET_REMOVED) && mn_ok &&
	    (int32_t)(now - eng.hello.due) >= 0 && eng.out_len == 0 && !eng.sending) {
		say_hello(v, &n, now);
		changed = true;
	}
	// A net control: TIME copies, an INVENTORY and its answer's wait, the rekey schedule
	if (eng.tm_left > 0 && mn_ok && eng.out_len == 0 && !eng.sending && !eng.ros.waiting && (int32_t)(now - eng.tm_next) >= 0) {
		tm_send(v, &n, now);
		changed = true;
	}
	if (eng.wd_to != 0 && n.rank != 0 && mn_ok && eng.out_len == 0 && !eng.sending && eng.rk == NULL && !eng.ros.waiting &&
	    !eng.ros_due) {
		wd_send(v, &n, now);
		changed = true;
	}
	if (eng.cu_to != 0 && eng.wd_to == 0 && n.rank != 0 && mn_ok && eng.out_len == 0 && !eng.sending && eng.rk == NULL &&
	    !eng.ros.waiting && !eng.ros_due) {
		cu_send(v, &n, now);
		changed = true;
	}
	if (eng.ch_to != 0 && eng.cu_to == 0 && n.rank != 0 && mn_ok && eng.out_len == 0 && !eng.sending && eng.rk == NULL &&
	    !eng.ros.waiting && !eng.ros_due) {
		ch_send(v, &n, now);
		changed = true;
	}
	// INVENTORY and LOCATE go during a rekey run too: a run by the clocks stays open until its changeover, up to a day,
	// and both were held back all that time (found on the bench, 2026-11-27: Get location stuck on "asking")
	if (eng.inv_to != 0 && n.rank != 0 && mn_ok && eng.out_len == 0 && !eng.sending && !eng.ros.waiting) {
		inv_send(v, &n, now);
		changed = true;
	}
	if (eng.inv.state == UI_INV_ASKING && eng.inv_to == 0 && (int32_t)(now - eng.inv.by) >= 0) {
		eng.inv.state = UI_INV_NO_ANSWER;
		changed = true;
	}
	if (n.rank != 0 && (uint32_t)(now - eng.sched_ms) >= SCHED_LOOK_MS) {
		eng.sched_ms = now;
		changed = sched_tick(v, now) || changed;
	}
	// A ZEROIZE asked for: a try, its ACK's wait, the next try
	if (eng.zz.waiting && (int32_t)(now - eng.zz.ack_by) >= 0) {
		eng.zz.waiting = false;
		if (eng.zz.tries < ZZ_TRIES)
			eng.zz.send = true;
		else
			eng.zz.state = UI_ZZ_NO_ANSWER;
		changed = true;
	}
	if (eng.zz.send && n.rank != 0 && mn_ok && eng.out_len == 0 && !eng.sending && !eng.ros.waiting && eng.rk == NULL) {
		zz_send(v, &n, now);
		changed = true;
	}
	// A LOCATE asked for: the same
	if (eng.loc.waiting && (int32_t)(now - eng.loc.ans_by) >= 0) {
		eng.loc.waiting = false;
		if (eng.loc.tries < LOC_TRIES) {
			eng.loc.send = true;
		} else {
			eng.loc.state = UI_LOC_NO_ANSWER;
			eng.loc.got_at = now;
		}
		changed = true;
	}
	if (eng.loc.send && n.rank != 0 && mn_ok && eng.out_len == 0 && !eng.sending && !eng.ros.waiting) {
		loc_send(v, &n, now);
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
	if (n.rank != 0 && mn_ok) {
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
	if (eng.rk != NULL && eng.rk->cancel && eng.rk->cur == 0xFF)
		rk_free();	// a cancel run gives way: the new keyset replaces the withdrawn one where a member still holds it
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
	// Above the last keyset withdrawn (7.9): a member that missed the WITHDRAW still holds that number with the old key,
	// and would refuse another key under it
	uint8_t cut_kid;
	uint32_t cut = cut_get(&cut_kid);
	if (cut >= rk->keyset && cut < (uint32_t)v->otar.keyset + KEYSET_STEP_MAX)
		rk->keyset = cut + 1u;
	if (rk->keyset > 0xFFFFu) {
		vPortFree(rk);
		return UI_NET_BUSY;	// keyset numbers end at 65535: a new net from here
	}
	rk->mins = v->otar.clock_ok ? mins : 0u;	// by the clocks, else by hand; counted from when the key is made
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
	eng.co_hand = false;
	if (rk->mins != 0)
		(void)ui_svc_net_send_time(v);	// the members without a clock get this one first (7.4)
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
	uint32_t next_ks = v->otar.next_keyset != 0 ? v->otar.next_keyset : (uint32_t)v->otar.keyset + 1u;
	if (!co_start(v, v->otar.next_kid, next_ks, net_id, rank, true))
		return UI_NET_NO_NEXT;
	eng.co_hand = eng.rk != NULL;
	return UI_NET_OK;
}

// CHANGEOVER copies to the talkgroup for key kid (keyset), under its group key "co" (7.3); then this radio too when
// then_local. False: no talkgroup, or the codeplug doesn't hold the key
static bool co_start(const radio_view_t *v, uint8_t kid, uint32_t keyset, uint16_t net_id, uint8_t rank, bool then_local)
{
	uint8_t tek[OTAR_KEY_LEN], k[OTAR_KEY_LEN];
	if (v->dmr.target_private || v->dmr.target_id == 0 ||
	    codeplug_traffic_key(v->otar.system, DMR_AES_ALG_AES256, kid, tek, sizeof tek) != (int)sizeof tek)
		return false;
	otar_group_mac_key(tek, OTAR_GK_CO, k);
	crypto_wipe(tek, sizeof tek);
	static otar_msg_t m;	// off the UI task's stack: the build below goes deep (otar_msg.c's body key)
	memset(&m, 0, sizeof m);
	m.net_id = net_id;
	m.rank = rank;
	m.msgnum = next_msgnum(hal_millis());
	m.keyset = keyset;
	m.kid = kid;
	otar_addr_t a = { v->dmr.own_id, v->dmr.target_id };
	eng.co_len = (uint8_t)otar_changeover_build(eng.co_msg, &a, k, &m);
	crypto_wipe(k, sizeof k);
	eng.co_tg = v->dmr.target_id;
	eng.co_left = CO_COPIES;
	eng.co_next = hal_millis();
	eng.co_then_local = then_local;
	return true;
}

// The rekey run a move or a cancel applies to: made, stored and this radio's next (not a cancel run already)
static rekey_t *run_planned(const radio_view_t *v, uint8_t *why)
{
	otar_net_t n;
	net_read(&n);
	bool nc = (n.flags & OTAR_NET_IN) && n.rank != 0;
	crypto_wipe(&n, sizeof n);
	rekey_t *rk = eng.rk;
	*why = !nc ? UI_NET_NOT_NC : UI_NET_NO_NEXT;
	if (!nc || rk == NULL || !rk->armed || rk->cancel || !v->otar.has_next || v->otar.next_kid != rk->kid)
		return NULL;
	*why = UI_NET_OK;
	return rk;
}

// Every member asked again (a move's REKEY, a cancel's WITHDRAW), except one out of sync
static void run_again(rekey_t *rk, uint32_t now)
{
	for (uint8_t i = 0; i < rk->n; i++)
		if (rk->m[i].state != UI_RK_SYNC) {
			rk->m[i].state = UI_RK_WAIT;
			rk->m[i].due = now;
			rk->m[i].tries = 0;
		}
	rk->cur = 0xFF;		// an ACK still awaited no longer counts: its echo is an older message number
}

uint8_t ui_svc_net_move(const radio_view_t *v, uint16_t mins)
{
	uint8_t why;
	rekey_t *rk = run_planned(v, &why);
	if (rk == NULL)
		return why;
	if (mins != 0 && (!v->otar.clock_ok || v->otar.now_min == 0))
		return UI_NET_NO_CLOCK;
	uint32_t now = hal_millis();
	rk->changeover = mins != 0 ? v->otar.now_min + mins : 0u;
	rk->mins = mins;
	radio_req_otar(RADIO_OTAR_NEXT_AT, rk->kid | (rk->changeover << 8));
	run_again(rk, now);
	eng.co_hand = false;
	if (mins != 0)
		(void)ui_svc_net_send_time(v);	// the members without a clock get this one first (7.4)
	return UI_NET_OK;
}

uint8_t ui_svc_net_cancel_change(const radio_view_t *v)
{
	uint8_t why;
	rekey_t *rk = run_planned(v, &why);
	if (rk == NULL)
		return why;
	uint32_t now = hal_millis();
	rk->cancel = true;
	rk->cancel_by = now + CANCEL_RUN_MS;
	crypto_wipe(rk->tek, sizeof rk->tek);	// sent no more
	cut_put(rk->keyset, rk->kid, now);
	radio_req_otar(RADIO_OTAR_DROP_NEXT, rk->kid);
	run_again(rk, now);
	eng.co_hand = false;
	return UI_NET_OK;
}

void ui_svc_net_rekey_view(ui_rekey_view_t *r)
{
	memset(r, 0, sizeof *r);
	rekey_t *rk = eng.rk;
	if (rk == NULL)
		return;
	r->on = true;
	r->cancel = rk->cancel;
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

uint8_t ui_svc_net_set_channel(const radio_view_t *v)
{
	otar_net_t n;
	net_read(&n);
	bool nc = (n.flags & OTAR_NET_IN) && n.rank != 0;
	crypto_wipe(&n, sizeof n);
	if (!nc)
		return UI_NET_NOT_NC;
	if (authority() != v->dmr.own_id)
		return UI_NET_NOT_FIRST;	// members take the net's channel from the authority only (7.8)
	otar_chan_t c;
	if (!chan_of(v, &c))
		return UI_NET_NOT_DMR;
	if (eng.rk != NULL || eng.ros.on)
		return UI_NET_BUSY;
	chan_put(&c, hal_millis());
	ros_start(0, false, false);
	eng.ros.chan_only = true;
	return UI_NET_OK;
}

void ui_svc_net_roster_view(ui_roster_view_t *r)
{
	memset(r, 0, sizeof *r);
	r->on = eng.ros.on;
	r->chan_only = eng.ros.chan_only;
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
	v->hello = eng.hello.state;
	v->sched_days = sched_get(&v->sched_at);
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
	put_and_tell(&m, true);		// the radio is told too: Removed from the net (7.5)
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
	if (id == v->dmr.own_id || !otar_roster_find(id, &m) || (m.flags & OTAR_M_REVOKED) ||
	    (m.rank != 0 && m.rank <= own_rank()))
		return UI_NET_NO_MEMBER;	// not a net control of this rank or above (7.5)
	if (eng.zz.state == UI_ZZ_SENDING)
		return UI_NET_BUSY;
	memset(&eng.zz, 0, sizeof eng.zz);
	eng.zz.id = id;
	eng.zz.state = UI_ZZ_SENDING;
	eng.zz.send = true;
	return UI_NET_OK;
}

bool ui_svc_net_out_of_sync(uint32_t id)
{
	return id != 0 && id == eng.oos_id;
}

uint8_t ui_svc_net_wipe_state(uint32_t id)
{
	return id != 0 && id == eng.zz.id ? eng.zz.state : (uint8_t)UI_ZZ_NONE;
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

void ui_svc_net_set_share_location(bool on)
{
	settings_t *st = settings_begin();
	st->otar_loc_off = on ? 0u : 1u;
	settings_end(hal_millis());
}

uint8_t ui_svc_net_locate(const radio_view_t *v, uint32_t id)
{
	if (own_rank() == 0)
		return UI_NET_NOT_NC;
	otar_member_t m;
	if (id == v->dmr.own_id || !otar_roster_find(id, &m) || (m.flags & OTAR_M_REVOKED))
		return UI_NET_NO_MEMBER;
	if (eng.loc.state == UI_LOC_ASKING)
		return UI_NET_BUSY;
	memset(&eng.loc, 0, sizeof eng.loc);
	eng.loc.id = id;
	eng.loc.state = UI_LOC_ASKING;
	eng.loc.send = true;
	return UI_NET_OK;
}

void ui_svc_net_locate_view(uint32_t id, ui_loc_view_t *r)
{
	memset(r, 0, sizeof *r);
	if (id == 0 || id != eng.loc.id)
		return;
	r->state = eng.loc.state;
	uint32_t now = hal_millis();
	if (r->state != UI_LOC_GOT) {
		// No position: the answer's own age (a "no fix" from hours ago isn't today's)
		if (r->state != UI_LOC_ASKING)
			r->age_s = (uint32_t)(now - eng.loc.got_at) / 1000u;
		return;
	}
	r->lat = eng.loc.lat;
	r->lon = eng.loc.lon;
	r->alt_m = eng.loc.alt_m;
	r->age_s = eng.loc.age_s + (uint32_t)(now - eng.loc.got_at) / 1000u;
#if CONFIG_POSITION
	// From where this radio is, exactly (no ambiguity: it is only shown here)
	position_fix_t f;
	if (position_fix(&f, now) != POSITION_SRC_NONE) {
		r->range = true;
		dmr_gps_range(f.lat, f.lon, eng.loc.lat, eng.loc.lon, &r->dist_m, &r->bearing);
	}
#endif
}

uint8_t ui_svc_net_send_time(const radio_view_t *v)
{
	if (own_rank() == 0)
		return UI_NET_NOT_NC;
	if (!v->otar.on || !v->otar.clock_ok || v->otar.clock_src == UTC_SRC_NET)
		return UI_NET_NO_CLOCK;	// a time from the net itself isn't sent on
	if (eng.tm_left != 0)
		return UI_NET_BUSY;
	otar_member_t first;
	uint16_t total = 0;
	(void)otar_roster_window(0, &first, 1, &total);
	eng.tm_i = 0;
	eng.tm_left = total;	// each member in turn (7.4)
	eng.tm_next = hal_millis();
	return UI_NET_OK;
}

uint8_t ui_svc_net_set_schedule(const radio_view_t *v, uint8_t days)
{
	if (own_rank() == 0)
		return UI_NET_NOT_NC;
	if (days != 0 && !v->otar.clock_ok)
		return UI_NET_NO_CLOCK;
	sched_put(days, days != 0 ? v->otar.now_min + (uint32_t)days * 1440u : 0, hal_millis());
	return UI_NET_OK;
}

uint8_t ui_svc_net_inventory(const radio_view_t *v, uint32_t id)
{
	if (own_rank() == 0)
		return UI_NET_NOT_NC;
	otar_member_t m;
	if (id == v->dmr.own_id || !otar_roster_find(id, &m) || (m.flags & OTAR_M_REVOKED))
		return UI_NET_NO_MEMBER;
	if (eng.inv_to != 0 || eng.inv.state == UI_INV_ASKING)
		return UI_NET_BUSY;
	memset(&eng.inv, 0, sizeof eng.inv);
	eng.inv.id = id;
	eng.inv.state = UI_INV_ASKING;
	eng.inv.by = hal_millis() + 2u * ACK_WAIT_MS;	// a rekey or a roster run may go first
	eng.inv_to = id;
	return UI_NET_OK;
}

void ui_svc_net_inventory_view(uint32_t id, ui_inv_view_t *r)
{
	memset(r, 0, sizeof *r);
	if (id != eng.inv.id)
		return;
	r->state = eng.inv.state;
	r->n = eng.inv.n;
	for (unsigned i = 0; i < 2u; i++) {
		r->keyset[i] = eng.inv.keyset[i];
		r->same[i] = eng.inv.same[i];
	}
}

#endif
