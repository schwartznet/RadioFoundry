// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// Generate a key (docs/spec/group-key-fill.md 8) through the group key session (core/ui/ui_svc_groupkey.c), with the
// randomness pool and the check value real and the transport, store, heap and codeplug faked: no key before the pool is
// full, the key ID it offers, the "replaces" warning, the key the store is handed and its check value, two keys never
// the same, and the session's block wiped on every way out (saved, left, the emergency wipe).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "keyfill/groupkey.h"
#include "keyfill/groupkey_api.h"
#include "support/entropy.h"
#include "support/kcv.h"
#include "codeplug/codeplug.h"
#include "codeplug/codeplug_records.h"
#include "codeplug/key_store.h"
#include "storage/storage.h"
#include "radio/radio.h"
#include "ui/ui_svc.h"
#include "board.h"
#include "FreeRTOS.h"

static int failures;

#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

const board_t board;
static uint32_t now, micros;
uint32_t hal_millis(void) { return now; }
uint32_t hal_micros(void) { return micros += 977u; }

static size_t nonzero(const void *p, size_t n)
{
	const uint8_t *b = p;
	size_t k = 0;
	for (size_t i = 0; i < n; i++)
		k += b[i] != 0;
	return k;
}

// The heap: a block freed is checked for leftovers first
static void *heap_block;
static size_t heap_size, freed_leftover;
static int frees;
void *pvPortMalloc(size_t n)
{
	heap_block = malloc(n);
	heap_size = n;
	return heap_block;
}
void vPortFree(void *p)
{
	freed_leftover = nonzero(p, heap_size);
	frees++;
	free(p);
	heap_block = NULL;
}

// The transport: never used by Generate
static int transport_calls;
void group_key_open(bool open) { (void)open; }
void group_key_cancel(void) { transport_calls++; }
int group_key_take(uint8_t out[GK_MSG_LEN], uint32_t *src) { (void)out; (void)src; transport_calls++; return 0; }
bool group_key_send(uint32_t tg, const uint8_t msg[GK_MSG_LEN]) { (void)tg; (void)msg; transport_calls++; return false; }
gk_send_state_t group_key_send_state(void) { return GK_SEND_IDLE; }

// The codeplug: the channel's system holds AES-256 keys under the IDs in stored[]
#define SYSTEM	2u
static bool stored[256];
int codeplug_traffic_key(uint8_t system, uint8_t alg, uint16_t key_id, uint8_t *key, uint16_t cap)
{
	if (system != SYSTEM || alg != GK_ALG_AES256 || key_id > 255 || !stored[key_id] || cap < GK_KEY_LEN)
		return -1;
	memset(key, 0xA5, GK_KEY_LEN);
	return GK_KEY_LEN;
}

// The store: the key it is handed, kept for the checks; its job held until the test runs it
static storage_job_fn job_fn;
static void *job_ctx;
static key_put_t put;
static uint8_t put_key[GK_KEY_LEN];
static int stores;
bool storage_job_post(storage_job_fn fn, void *ctx)
{
	if (job_fn != NULL)
		return false;
	job_fn = fn;
	job_ctx = ctx;
	return true;
}
uint16_t key_store_count(void) { return 0; }
bool key_store_get(uint16_t i, key_entry_t *e, uint8_t *key) { (void)i; (void)e; (void)key; return false; }
bool ui_svc_key(uint16_t i, key_entry_t *e) { (void)i; (void)e; return false; }
int key_store_identity(uint8_t system, uint8_t *out, uint8_t cap)
{
	if (system != SYSTEM || cap < 1)
		return -1;
	out[0] = (uint8_t)system;
	return 1;
}
uint8_t key_store_put(const key_put_t *p, uint8_t kcv[KCV_LEN])
{
	put = *p;
	memcpy(put_key, p->key, GK_KEY_LEN);
	put.key = put_key;
	stores++;
	return kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, p->alg, p->key, p->key_len, kcv) ? KEY_PUT_STORED : KEY_PUT_BAD;
}

static radio_view_t view(bool aes, uint16_t aes_ref)
{
	radio_view_t v;
	memset(&v, 0, sizeof v);
	v.ch.mode = aes ? RADIO_MODE_DMR : RADIO_MODE_FM;
	v.ch.kind = aes ? CODEPLUG_KIND_DMR_AES : 0;
	v.ch.aes_ref = aes_ref;
	v.ch.system = SYSTEM;
	return v;
}

static void tick(const radio_view_t *v)
{
	now += 20;
	(void)ui_svc_gk_tick(v, now);
}

static void fill_pool(void)
{
	for (int i = 0; i < 64 && entropy_bits() < ENTROPY_FULL; i++) {
		uint32_t press = (uint32_t)i * 2654435761u;
		entropy_stir(&press, sizeof press, ENTROPY_KEY_BITS);
	}
}

static void run_job(void)
{
	storage_job_fn fn = job_fn;
	void *ctx = job_ctx;
	job_fn = NULL;
	if (fn != NULL)
		fn(ctx);
}

// Start, fill the pool and tick until the key is shown
static bool shown(const radio_view_t *v, ui_gk_view_t *g)
{
	if (ui_svc_gk_start(UI_GK_GENERATE, v) != UI_GK_WHY_NONE)
		return false;
	fill_pool();
	tick(v);
	return ui_svc_gk_view(g) && g->state == UI_GK_GOT;
}

static void end_session(const radio_view_t *v)
{
	ui_svc_gk_end();
	tick(v);
}

int main(void)
{
	radio_view_t fm = view(false, 0), aes = view(true, 4);	// the channel's key ID is 3
	ui_gk_view_t g;

	// Only on an AES channel; nothing allocated otherwise
	CHECK(ui_svc_gk_start(UI_GK_GENERATE, &fm) == UI_GK_WHY_GEN_CHANNEL && heap_block == NULL);
	CHECK(!ui_svc_gk_view(&g));

	// No key until the pool is full: the screen asks for presses
	entropy_wipe();
	CHECK(ui_svc_gk_start(UI_GK_GENERATE, &aes) == UI_GK_WHY_NONE);
	tick(&aes);
	CHECK(ui_svc_gk_view(&g) && g.gen && !g.send && g.state == UI_GK_RANDOM && g.presses > 0);
	CHECK(ui_svc_gk_start(UI_GK_GENERATE, &aes) == UI_GK_WHY_BUSY);
	fill_pool();
	tick(&aes);
	CHECK(ui_svc_gk_view(&g) && g.state == UI_GK_GOT && g.kcv_ok && !g.replaces);
	// Offered as the channel's own key ID while that is free
	CHECK(g.key_id == 3 && g.save_id == 3);
	ui_gk_view_t first = g;

	// OK stores it in the channel's system as an AES-256 traffic key; the check value shown is the stored key's
	ui_svc_gk_save();
	CHECK(ui_svc_gk_view(&g) && g.state == UI_GK_SAVING && job_fn != NULL);
	run_job();
	tick(&aes);
	CHECK(stores == 1 && put.cls == KCV_CLASS_TRAFFIC && put.type == CODEPLUG_SYSTYPE_DMR_AES &&
	      put.alg == GK_ALG_AES256 && put.key_id == 3 && put.key_len == GK_KEY_LEN && put.id_len == 1 &&
	      put.identity[0] == SYSTEM);
	CHECK(nonzero(put_key, sizeof put_key) > 20);
	uint8_t kcv[KCV_LEN];
	CHECK(kcv_traffic(CODEPLUG_SYSTYPE_DMR_AES, GK_ALG_AES256, put_key, GK_KEY_LEN, kcv) &&
	      memcmp(kcv, first.kcv, KCV_LEN) == 0);
	CHECK(ui_svc_gk_view(&g) && g.state == UI_GK_SAVED && g.save_id == 3);
	CHECK(transport_calls == 0);	// nothing went on air or was listened for
	end_session(&aes);
	CHECK(!ui_svc_gk_view(&g) && frees == 1 && freed_leftover == 0);
	uint8_t key1[GK_KEY_LEN];
	memcpy(key1, put_key, sizeof key1);

	// The channel's key ID taken: the first free one (1 is taken too, so 2). Typing a taken ID warns
	stored[3] = stored[1] = true;
	CHECK(shown(&aes, &g) && g.save_id == 2 && !g.replaces);
	ui_svc_gk_save_id(1);
	CHECK(ui_svc_gk_view(&g) && g.save_id == 1 && g.replaces);
	ui_svc_gk_save_id(9);
	CHECK(ui_svc_gk_view(&g) && g.save_id == 9 && !g.replaces);
	ui_svc_gk_save_id(3);
	ui_svc_gk_save();
	run_job();
	tick(&aes);
	CHECK(stores == 2 && put.key_id == 3 && ui_svc_gk_view(&g) && g.state == UI_GK_SAVED);
	// A second key is not the first
	CHECK(memcmp(key1, put_key, sizeof key1) != 0);
	end_session(&aes);
	CHECK(frees == 2 && freed_leftover == 0);

	// Back on the key: Drop does nothing (there is no window), leaving stores nothing and wipes the key
	CHECK(shown(&aes, &g));
	ui_svc_gk_drop();
	CHECK(ui_svc_gk_view(&g) && g.state == UI_GK_GOT);
	end_session(&aes);
	CHECK(stores == 2 && frees == 3 && freed_leftover == 0);

	// The emergency wipe with a key shown: wiped in place, freed by the next tick, nothing stored after
	CHECK(shown(&aes, &g));
	ui_svc_gk_zeroize();
	CHECK(heap_block != NULL && nonzero(heap_block, heap_size) <= 1);	// only the job state is kept
	tick(&aes);
	CHECK(frees == 4 && freed_leftover == 0 && stores == 2);

	// Every ID taken: offered the channel's own, and saving says it replaces
	memset(stored, 1, sizeof stored);
	CHECK(shown(&aes, &g) && g.save_id == 3 && g.replaces);
	end_session(&aes);

	if (failures == 0)
		printf("# keyGenTest PASSED\n");
	else
		printf("# keyGenTest FAILED (%d)\n", failures);
	return failures != 0;
}
