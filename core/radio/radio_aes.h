// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
#ifndef RFOUNDRY_RADIO_AES_H
#define RFOUNDRY_RADIO_AES_H

#include "codeplug/codeplug.h"
#include "dmr/call/dmr_call.h"
#include "dmr/dmrData.h"
#include "config.h"

// Radio-task-only integration for conventional DMR AES (docs/spec/dmr-voice.md 5.1).
void radio_aes_start(uint32_t saved);
uint8_t radio_aes_tx_deny(const channel_t *ch);
bool radio_aes_configure(const channel_t *ch, dmr_call_config_t *cfg);
// What an AES channel does with packet data (docs/spec/dmr-data.md 13.4): false, out untouched, off AES channels. On
// one: encrypted with the channel's key (AES-256 OFB, a new MI per packet), else held back (DMR_DATA_PRIVACY_BLOCK),
// never sent in the clear; signaling (CSBKs, link responses) and self-protected packets (13.5) still go
struct dmrDataPrivacy_s;
bool radio_aes_data_config(const channel_t *ch, struct dmrDataPrivacy_s *out);
// Call between overs only, including while tuned to another mode. True: the channel's keys changed (an OTAR changeover
// or the end of its overlap): configure the call stack again
bool radio_aes_poll(const channel_t *ch, uint32_t own_id, uint32_t now_ms);
// The emergency wipe (docs/spec/zeroize.md 4.2): the channel's key schedule zeroed, TX refused until a key is loaded
void radio_aes_wipe(void);
#if CONFIG_OTAR
#include "radio/radio.h"
// RREQ_OTAR (radio_req_otar): op RADIO_OTAR_*, value as radio.h says, on the channel ch. True: the keysets changed
bool radio_aes_otar_request(uint8_t op, uint32_t value, const channel_t *ch, uint32_t now_ms);
// A request that came during an over: held (a few, in order) and made by radio_aes_poll once the over has ended
void radio_aes_otar_defer(uint8_t op, uint32_t value);
// The keysets and the clock as the UI shows them into *v; true when that differs from what *v held
bool radio_aes_otar_view(radio_otar_view_t *v, uint32_t now_ms);
#endif

#endif
