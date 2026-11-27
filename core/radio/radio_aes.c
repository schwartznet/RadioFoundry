// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
#include "config.h"
#if CONFIG_DMR_AES
#include <string.h>
#include "board.h"
#include "codeplug/codeplug_records.h"
#include "dmr/dmrAes.h"
#include "dmr/dmrData.h"
#include "dmr/dmrPrivacy.h"
#include "radio/radio.h"
#include "radio/radio_aes.h"
#include "settings/settings.h"
#if CONFIG_OTAR
#include "otar/otar_keys.h"
#include "storage/storage.h"
#include "support/utc_clock.h"
#include "hal_rtc.h"
#if CONFIG_SATELLITE_TLE
#include "position/position.h"
#endif
#endif

static dmrAesState_t channel_keys;
static uint16_t channel_key_ref;
static uint8_t channel_key_system;
static bool channel_tx_allowed;
static dmrAesSeq_t aes_seq;		// the radio's MI sequence, every key

#if CONFIG_OTAR
// OTAR keysets (docs/spec/otar.md 8): the radio task's copy of settings_t.otar, written back on every change
static otar_keys_t otar;
static bool prev_live;			// the previous keyset is in its overlap (RAM: a restart ends it)
static uint32_t prev_end_ms;
static uint32_t gps_ms;			// when the GPS time was last taken
static uint8_t rtc_check;		// the board's clock after a start: 0 not read, 1 read once, 2 done
static int64_t rtc_first_s;		// its first read, and when
static uint32_t rtc_first_ms;
static uint32_t rtc_set_ms;		// when this radio last set it from GPS (0: not since the start)

#define RTC_KEEP_MS	(6u * 3600u * 1000u)	// GPS sets the board's clock again after this
#define RTC_CHECK_MS	3000u	// the board's clock is read twice this far apart: it must have counted that time
#define OTAR_TIME_MOVE_S	(48 * 3600)	// a net control's TIME moves a clock it set at most this far (otar.md 7.4)

// The board's real-time clock (hal_rtc.h): set from a GPS or hand-set time, and marked as holding UTC
static void rtc_keep(int64_t unix_s, uint32_t now_ms)
{
	if (!hal_rtc_set(unix_s))
		return;
	rtc_set_ms = now_ms | 1u;
	settings_t *st = settings_begin();
	bool mark = st->otar_rtc != 1u;
	st->otar_rtc = 1;
	settings_end(mark ? now_ms : 0);
}
// The previous keyset's keys to erase, by the housekeeping task (a storage job)
static struct {
	volatile bool posted;
	uint8_t system, n;
	uint8_t kids[OTAR_CKRS];
} erase;

static void otar_save(uint32_t now_ms)
{
	settings_t *st = settings_begin();
	st->otar = otar;
	settings_end(now_ms);
}

static void erase_job(void *ctx)
{
	(void)ctx;
	for (uint8_t j = 0; j < erase.n; j++)
		(void)codeplug_traffic_key_remove(erase.system, DMR_AES_ALG_AES256, erase.kids[j]);
	erase.n = 0;
	erase.posted = false;
}

// The previous keyset ends: no longer heard, and its keys that no keyset still names erased from the codeplug
static void drop_prev(uint32_t now_ms)
{
	prev_live = false;
	if (erase.posted)
		return;		// the last erase hasn't run: this one waits for the next poll
	erase.system = otar_system(&otar);
	erase.n = otar_drop_prev(&otar, erase.kids);
	otar_save(now_ms);
	if (erase.n != 0) {
		erase.posted = true;
		if (!storage_job_post(erase_job, NULL)) {
			erase.posted = false;	// the keys stay; the record says nothing is previous now
			erase.n = 0;
		}
	}
}

static void change_over(uint32_t now_ms)
{
	if (otar.flags & OTAR_F_PREV)
		drop_prev(now_ms);	// an older previous keyset: its overlap is cut short
	if (!otar_change_over(&otar))
		return;
	prev_live = true;
	prev_end_ms = now_ms + OTAR_GRACE_MS;
	otar_save(now_ms);
}

static bool clock_minutes(uint32_t now_ms, uint32_t *min)
{
	int64_t s;
	if (!utc_clock_now(now_ms, &s, NULL))
		return false;
	*min = otar_minutes(s);
	return *min != 0;
}

// Between overs: the GPS time taken once a minute, a due changeover made, the overlap ended. True: the keys changed
static bool otar_poll(uint32_t now_ms)
{
	// After a restart: the board's clock, when this firmware set it, and only when it counts. Read twice RTC_CHECK_MS
	// apart, it must have moved on by that time (within a second): a clock chip that holds a time but doesn't run
	// (seen on a radio, otar.md 20) is left out and the radio waits for GPS
	if (rtc_check == 0) {
		rtc_check = 2;
		if (SETTINGS_FIELD(otar_rtc) == 1u && hal_rtc_get(&rtc_first_s)) {
			rtc_first_ms = now_ms;
			rtc_check = 1;
		}
	} else if (rtc_check == 1 && (uint32_t)(now_ms - rtc_first_ms) >= RTC_CHECK_MS) {
		rtc_check = 2;
		int64_t s;
		uint8_t src = UTC_SRC_NONE;
		int64_t had;
		bool clock = utc_clock_now(now_ms, &had, &src);
		if (hal_rtc_get(&s) && !(clock && src == UTC_SRC_GPS)) {
			int64_t counted = s - rtc_first_s, passed = (int64_t)((now_ms - rtc_first_ms) / 1000u);
			if (counted >= passed - 1 && counted <= passed + 1)
				utc_clock_set(s, now_ms, UTC_SRC_RTC);
		}
	}
#if CONFIG_SATELLITE_TLE
	if (gps_ms == 0 || (uint32_t)(now_ms - gps_ms) >= 60000u) {
		uint32_t d, t;
		gps_ms = now_ms | 1u;
		if (position_utc_fields(&d, &t, now_ms)) {
			// ddmmyy and hhmmss, as the GPS sends them
			uint32_t m = otar_from_civil((uint16_t)(2000u + d % 100u), (uint8_t)((d / 100u) % 100u),
						     (uint8_t)(d / 10000u), (uint8_t)(t / 10000u), (uint8_t)((t / 100u) % 100u));
			if (m != 0) {
				int64_t s = OTAR_EPOCH_UNIX + (int64_t)m * 60 + (int64_t)(t % 100u);
				utc_clock_set(s, now_ms, UTC_SRC_GPS);
				if (rtc_set_ms == 0 || (uint32_t)(now_ms - rtc_set_ms) >= RTC_KEEP_MS)
					rtc_keep(s, now_ms);
			}
		}
	}
#else
	(void)gps_ms;
#endif
	if (!otar_on(&otar))
		return false;
	uint32_t min = 0;
	bool clock_ok = clock_minutes(now_ms, &min);
	if (otar_due(&otar, clock_ok, min)) {
		change_over(now_ms);
		return true;
	}
	if (prev_live && (int32_t)(now_ms - prev_end_ms) >= 0) {
		drop_prev(now_ms);
		return true;
	}
	if (!prev_live && (otar.flags & OTAR_F_PREV) && !erase.posted) {
		drop_prev(now_ms);	// held from before a restart, or an erase that couldn't be posted
		return true;
	}
	return false;
}

bool radio_aes_otar_request(uint8_t op, uint32_t value, const channel_t *ch, uint32_t now_ms)
{
	uint32_t min = 0;
	switch (op) {
	case RADIO_OTAR_START:
		if (ch->kind != CODEPLUG_KIND_DMR_AES)
			return false;
		prev_live = false;
		otar_start(&otar, ch->system, (uint8_t)value);
		break;
	case RADIO_OTAR_STOP:
		prev_live = false;
		otar_stop(&otar);
		break;
	case RADIO_OTAR_NEXT: {
		// value: the key ID in bits 0-7, the minutes to the changeover in bits 8-23 (0: by hand)
		uint32_t mins = (value >> 8) & 0xFFFFu;
		if (mins != 0 && !clock_minutes(now_ms, &min))
			return false;	// no clock to change over by
		if (!otar_set_next(&otar, 1, (uint8_t)value, mins != 0 ? min + mins : 0, mins != 0))
			return false;
		break;
	}
	case RADIO_OTAR_NEXT_AT: {
		uint32_t at = value >> 8;	// UTC minutes since 2026, 24 bits: 31 years
		if (!otar_set_next(&otar, 1, (uint8_t)value, at, at != 0))
			return false;
		break;
	}
	case RADIO_OTAR_CLEAR_NEXT:
		otar_clear_next(&otar);
		break;
	case RADIO_OTAR_NEXT_KS:
		// The net's keyset number for the next keyset (otar.md 7.1): only above the active one, so a radio never goes
		// back to an older keyset
		if (!(otar.flags & OTAR_F_NEXT) || value <= otar.ks_active || value > 0xFFFFu)
			return false;
		otar.ks_next = (uint16_t)value;
		break;
	case RADIO_OTAR_NOW:
		if (!(otar.flags & OTAR_F_NEXT))
			return false;
		change_over(now_ms);
		return true;	// saved by change_over
	case RADIO_OTAR_CLOCK:
		utc_clock_set((int64_t)value, now_ms, UTC_SRC_HAND);
		rtc_keep((int64_t)value, now_ms);
		return false;
	case RADIO_OTAR_TIME: {
		// otar.md 7.4: only a radio with no clock but the net's takes it, and moves that one at most 48 hours. Not
		// kept in the board's clock: GPS, the board's clock or a time set by hand stays first
		int64_t had = 0;
		uint8_t src = UTC_SRC_NONE;
		bool clock = utc_clock_now(now_ms, &had, &src);
		int64_t d = (int64_t)value - had;
		if (!clock || (src == UTC_SRC_NET && d <= OTAR_TIME_MOVE_S && d >= -OTAR_TIME_MOVE_S))
			utc_clock_set((int64_t)value, now_ms, UTC_SRC_NET);
		return false;
	}
	default:
		return false;
	}
	otar_save(now_ms);
	return true;
}

bool radio_aes_otar_view(radio_otar_view_t *v, uint32_t now_ms)
{
	radio_otar_view_t n;
	memset(&n, 0, sizeof n);
	n.on = otar_on(&otar);
	n.system = otar_system(&otar);
	n.keyset = otar.ks_active;
	n.next_keyset = otar.ks_next;
	n.has_kid = otar_kid(&otar, OTAR_ACTIVE, 1, &n.kid);
	n.has_next = otar_kid(&otar, OTAR_NEXT, 1, &n.next_kid);
	n.has_prev = prev_live && otar_kid(&otar, OTAR_PREV, 1, &n.prev_kid);
	n.changeover = otar.changeover;
	n.by_clock = (otar.flags & OTAR_F_OWN_CLOCK) != 0;
	int64_t s;
	n.clock_ok = utc_clock_now(now_ms, &s, &n.clock_src);
	n.now_min = n.clock_ok ? otar_minutes(s) : 0;
	bool changed = memcmp(&n, v, sizeof n) != 0;
	*v = n;
	return changed;
}

// Load the key ID's key of system into slot: false when the codeplug doesn't hold it
static bool load_slot(uint8_t slot, uint8_t system, uint8_t kid)
{
	uint8_t key[DMR_AES_KEY_BYTES];
	bool ok = codeplug_traffic_key(system, DMR_AES_ALG_AES256, kid, key, sizeof key) == sizeof key &&
		  dmrAesSetKey(&channel_keys, slot, DMR_AES_ALG_AES256, kid, key);
	dmrAesWipe(key, sizeof key);
	return ok;
}
#endif

void radio_aes_start(uint32_t saved)
{
	dmrAesSeqStart(&aes_seq, saved);	// TX waits for the next reservation
#if CONFIG_OTAR
	settings_t *st = settings_begin();
	otar = st->otar;
	settings_end(0);
	prev_live = false;	// a previous keyset kept over a restart is dropped at the first poll
#endif
}

uint8_t radio_aes_tx_deny(const channel_t *ch)
{
	if (!ch->aes_ref || channel_key_ref != ch->aes_ref || channel_key_system != ch->system || !channel_tx_allowed)
		return TXDENY_AES_KEY;
	return aes_seq.left == 0 ? TXDENY_AES_WAIT : TXDENY_NONE;
}

typedef struct {
	int tx_id;		// the channel's TX key ID, -1 = none
	uint8_t next;		// the next free slot for another key
} load_ctx_t;

static bool load_key(uint16_t key_id, const uint8_t *key, int len, void *ctx)
{
	load_ctx_t *l = (load_ctx_t *)ctx;

	// The PI header carries 8 bits of key ID: a key past them can't be named by a call
	if (len != DMR_AES_KEY_BYTES || key_id > 0xFF)
		return true;
	if ((int)key_id == l->tx_id) {
		dmrAesSetKey(&channel_keys, 0, DMR_AES_ALG_AES256, (uint8_t)key_id, key);
	} else if (l->next < DMR_AES_KEY_SLOTS) {
		dmrAesSetKey(&channel_keys, l->next++, DMR_AES_ALG_AES256, (uint8_t)key_id, key);
	}
	// Full: walk on only while the TX key may be still to come
	return l->next < DMR_AES_KEY_SLOTS || (l->tx_id >= 0 && channel_keys.keys[0].alg == 0);
}

bool radio_aes_configure(const channel_t *ch, dmr_call_config_t *cfg)
{
	// The call stack refuses an over it can't encrypt, even if it gets past the radio task's TX check.
	cfg->tx_crypt_required = ch->kind == CODEPLUG_KIND_DMR_AES;
	if (!cfg->tx_crypt_required) {
		if (channel_key_ref != 0 || dmrAesHasKeys(&channel_keys)) {
			dmrAesClearKeys(&channel_keys);
			channel_key_ref = 0;
			channel_tx_allowed = false;
		}
		return false;
	}

	codeplug_system_t sys;
	uint8_t block[CODEPLUG_SYS_HDR];
	channel_tx_allowed = false;
	channel_key_ref = 0;
	channel_key_system = ch->system;
	dmrAesClearKeys(&channel_keys);
	bool sys_ok = codeplug_system(ch->system, &sys, block, 0) >= 0 && sys.type == CODEPLUG_SYSTYPE_DMR_AES;
#if CONFIG_OTAR
	if (sys_ok && ch->aes_ref && ch->aes_ref <= 256 && otar_on(&otar) && otar_system(&otar) == ch->system) {
		// A managed system (otar.md 8): the channel's reference is a CKR; TX with the active keyset's key, RX with
		// the active, the next and, through the overlap, the previous one, chosen by each call's key ID
		uint8_t ckr = otar_ckr(ch->aes_ref), kid;
		if (otar_kid(&otar, OTAR_ACTIVE, ckr, &kid) && load_slot(0, ch->system, kid)) {
			dmrAesSetTx(&channel_keys, 0);
			channel_key_ref = ch->aes_ref;
			channel_tx_allowed = (sys.flags & CODEPLUG_SYS_TX) != 0;
		}
		if (otar_kid(&otar, OTAR_NEXT, ckr, &kid))
			(void)load_slot(1, ch->system, kid);
		if (prev_live && otar_kid(&otar, OTAR_PREV, ckr, &kid))
			(void)load_slot(2, ch->system, kid);
	} else
#endif
	if (sys_ok) {
		// Every AES-256 key of the system: slot 0 for the channel's TX key, the rest heard by the PI header's
		// key ID
		load_ctx_t l = { .tx_id = ch->aes_ref && ch->aes_ref <= 256 ? (int)ch->aes_ref - 1 : -1, .next = 1 };
		codeplug_traffic_keys(ch->system, DMR_AES_ALG_AES256, load_key, &l);
		if (dmrAesSetTx(&channel_keys, 0)) {
			channel_key_ref = ch->aes_ref;
			channel_tx_allowed = (sys.flags & CODEPLUG_SYS_TX) != 0;
		}
	}
	channel_keys.seq = &aes_seq;
	if (!dmrAesHasKeys(&channel_keys))
		return false;
	cfg->crypt = dmrAesCallHook;
	cfg->crypt_ctx = &channel_keys;
	if (!dmrAesTxKey(&channel_keys, &cfg->tx_crypt_alg, &cfg->tx_crypt_key_id))
		return false;
	cfg->crypt_mi = dmrAesNewMi;
	cfg->tx_fid = DMR_PRIVACY_FID;
	cfg->tx_svc |= DMR_PRIVACY_SERVICE_OPTION;
	return true;
}

void radio_aes_wipe(void)
{
	dmrAesClearKeys(&channel_keys);	// keeps the MI sequence: positions already sent stay used
	channel_key_ref = 0;
	channel_key_system = 0;
	channel_tx_allowed = false;
}

bool radio_aes_data_config(const channel_t *ch, dmrDataPrivacy_t *p)
{
	if (ch->kind != CODEPLUG_KIND_DMR_AES)
		return false;
	// AES-256 OFB, a new MI from the radio's sequence for every packet. Without the key no data packet goes, and none
	// is sent in the clear
	memset(p, 0, sizeof *p);
	uint8_t alg, kid;
	if (!dmrAesTxKey(&channel_keys, &alg, &kid)) {
		p->mode = DMR_DATA_PRIVACY_BLOCK;
		return true;
	}
	p->mode = DMR_DATA_PRIVACY_ENCRYPT;
	p->alg = DMR_AES_DATA_ALG;
	p->keyId = kid;
	p->crypt = dmrAesDataCrypt;
	p->newMi = dmrAesDataMi;
	p->ctx = &channel_keys;
	return true;
}

#if CONFIG_OTAR
// Requests held over an over (radio_aes_otar_defer). A net control asks to change over right as its last CHANGEOVER
// copy goes out, and a member to make a stored key next while traffic may be on: neither may be lost
#define OTAR_DEFER	4u
static struct {
	uint8_t op;
	uint32_t value;
} deferred[OTAR_DEFER];
static uint8_t deferred_n;

void radio_aes_otar_defer(uint8_t op, uint32_t value)
{
	if (deferred_n < OTAR_DEFER) {
		deferred[deferred_n].op = op;
		deferred[deferred_n].value = value;
		deferred_n++;
	}
}
#endif

bool radio_aes_poll(const channel_t *ch, uint32_t own_id, uint32_t now_ms)
{
	bool keys = false;
#if CONFIG_OTAR
	for (uint8_t i = 0; i < deferred_n; i++)
		keys = radio_aes_otar_request(deferred[i].op, deferred[i].value, ch, now_ms) || keys;
	deferred_n = 0;
	keys = otar_poll(now_ms) || keys;
#endif
	dmrAesSeqSettle(&aes_seq);
	uint32_t stored = SETTINGS_FIELD(aes_mi_res);

	if (aes_seq.pending != 0) {
		if (stored != aes_seq.pending) {
			dmrAesSeqDropPending(&aes_seq);		// overwritten by a restore: ask again
		} else if (settings_u32_is_saved(offsetof(settings_t, aes_mi_res), stored)) {
			dmrAesSeqReserved(&aes_seq, stored);
		}
		return keys;
	}
	// Repair a restored reservation even off AES channels, without rewinding or allocating positions.
	if (aes_seq.end != 0 && stored != aes_seq.end) {
		settings_t *st = settings_begin();
		st->aes_mi_res = aes_seq.end;
		settings_end(now_ms);
		return keys;
	}
	if (ch->kind != CODEPLUG_KIND_DMR_AES)
		return keys;
	if (aes_seq.next == 0) {
		if (channel_key_ref == 0)
			return keys;
		hal_chip_t chip;
		memset(&chip, 0, sizeof(chip));
		if (board.system == NULL || board.system->chip == NULL || !board.system->chip(&chip))
			memset(chip.uid, 0, sizeof(chip.uid));
		aes_seq.next = dmrAesSeqSeed(channel_keys.keys[0].key, chip.uid, own_id, now_ms);	// the TX key
	}
	uint32_t r = dmrAesSeqReserve(&aes_seq);
	if (r != 0) {
		settings_t *st = settings_begin();
		st->aes_mi_res = r;
		settings_end(now_ms);
	}
	return keys;
}
#endif
