# Radio silence

A setting under which the radio transmits only what its user starts: PTT, a message, a key fill, an emergency. It
never transmits by itself: no answers, acknowledgements, registrations, beacons, probes, repeating or traffic for a
host. Military radios call this emission control (EMCON). The use: a radio that must not give itself away, for
example to direction finding, or that must not answer anyone who asks where it is. Status: built and host-tested; not
yet tried on a radio.

Code: `core/radio/silence.{h,c}` (the flag), the checks at each source below, `core/ui/ui_menus.c` (the setting),
`core/ui/ui_app.c` (the side key), `core/ui/ui_screens.c` (Home's word).

## 1. Switch

`CONFIG_RADIO_SILENCE` (default on). Off: `radio_silent()` is always false, and there is no setting, key function or
word on Home. Its flash and RAM per radio: [feature-matrix.md](../feature-matrix.md).

## 2. The setting

| Where | Name | Values | Stored |
|---|---|---|---|
| Settings > Privacy, the last row | Radio silence | Off (default), On | `settings_t.rs_flags` bit 6 (`SETTINGS_RS_SILENCE`), with the radio core's settings: a record from before reads off |
| Settings > Keys, a side key's press or long press | Radio silence | toggles it, saved as the menu saves it | key function 22 (`KEYFN_SILENCE`, appended after `KEYFN_MONITOR_TOGGLE`) |

It is kept over a restart on purpose: a radio switched on again under silence must not register (ARS) or answer
before its user turns silence off. The radio core sets `radio_silence_flag` (`radio_silence_set`) whenever its
settings change (`use_settings`), and every source reads it with `radio_silent()`: one byte, read from any task.

## 3. What it stops, and what it lets through

The rule: a transmission the user starts now goes, including what follows from it (a message's retries, the
emergency's alarm repeats and hot mic, a key fill session's replies while its screen is open). Anything the radio
would send by itself does not. Each source checks the flag itself; a reply is dropped, not held for later.

| Source | Under radio silence | Where |
|---|---|---|
| Radio check answer, call alert ACK | Not sent. The alert still rings; the check is still counted | `dmrDataService.c` tick (`stats.silenceHeld`) |
| Confirmed data: ACK, NACK, selective ACK; TMS ACK | Not sent. The sender retries, then gives up | the same |
| LRRP: an immediate answer, a triggered report | Not sent; a request isn't queued. A running trigger keeps its timer and skips its reports | `lrrpReceived`, `lrrpTick` |
| ARS registration, refresh, deregistration (power off too) | None. The state is kept: registration resumes when silence ends | `arsTick`, `dmrDataServicePowerOff` |
| APRS beacon that falls due by itself (interval, SmartBeaconing, power on, after PTT), on FM or over DMR | Skipped, as if sent: the timers go on | `aprs.c` tick |
| APRS: Send now, a status, the user's message and its retries | Sent | |
| APRS ACK to a received message, digipeating, frames from a host (KISS) or the iGate | Not queued | `aprs_ax25.c` `silenced` |
| OTAR: a member's POSITION answering a net control's LOCATE (Get location) | Not sent; the LOCATE is dropped unread, and the net control shows "no answer" ([otar.md](otar.md) 7.7) | `on_locate` (`ui_svc_otar.c`) |
| OTAR: a member's other answers (the ACK of a REKEY, WITHDRAW, ROSTER, NETCHAN, ZEROIZE or INVENTORY, "old message number") | Not sent. What the message carries is still taken: a REKEY's key is stored, a WITHDRAW drops the keyset, a ZEROIZE wipes. The net control shows "no answer" and tries again later | `silenced` (`ui_svc_otar.c`) |
| OTAR: a member's HELLO at start | Waits until silence ends. Net > Request keys (the user's own) goes | `engine_tick` |
| OTAR: a member's HELLO on the net's voice under a key the radio doesn't hold ([otar.md](otar.md) 30.1) | Not started: a call heard under silence never makes the radio ask, then or later | `auto_req` |
| OTAR: a net control's answers to a member's HELLO, an ACK or POSITION to a higher net control | Not sent | `hello_answer`, `silenced` |
| OTAR: what the net control's user starts or scheduled (Rekey now and a scheduled rekey (Rekey every), their retries and the CHANGEOVER at a changeover by the clocks, Change over the net, Send the roster, Send the time, a wipe, Ask its keys, Check all members, Get location, the net's channel, Move or Cancel the change) | Sent: a schedule is the user's own | |
| DMR roaming wake probe | Not sent: the search listens only | `roam_probe` |
| SFR repeater role (repeating, idle beacon, CW ID) | Waits, as with TX inhibit: the radio is an ordinary channel | `sfr_rpt_wait` |
| Hotspot (MMDVM) and its CW ID | Not entered; a running hotspot's keying is dropped | `hotspot_enter`, `hotspot_arm` |
| IP over DMR from the PC (USB network, control station), SNMP answers and traps over the air | Not sent | `ipGatewayIPToAir`, `ipGatewayRawToAir`, `snmp_agent.c` `rf_poll` |
| Network audio (USRP) keying | Refused | `RREQ_PTT` with arg 2 |
| rigctld (CAT) PTT | Sent: a PTT the operator presses at the PC | |
| VOX | The mic never keys the radio; a VOX transmission on air when silence comes on ends | VOX poll, `use_settings` |
| Tier III trunking | Only the PTT's own call request goes. No registration, no answers to the control channel, no data over the system | `t3_send` |
| Tier III ambient listening (the system keys our mic) | Refused | `t3_als_tick` |
| P25 trunking | Only a burst while PTT is held. No registration or affiliation | `p25t_burst` |
| GPS Info in a voice call | Left out of the call (the call itself goes) | `dmr_gps_tx` |
| Crash report set to send at once | Asks instead, as with "Ask" | `ui_menus.c` |
| PTT voice, messages, call alert and radio check the user sends, zone share, key fill, emergency | Sent | |

What it does not change: receiving, decoding and showing calls, messages and positions heard; scanning; the talker
alias in the user's own call (it names the radio, not where it is).

Limits worth knowing:

- On a trunked system a radio that doesn't register may be refused service. Silence trades that away on purpose.
- Confirmed data sent to a silent radio is never acknowledged, so the sender's radio reports it as failed.
- A radio under silence is still found by direction finding while its user transmits. Silence stops what the user
  didn't choose to send, not what they did.

## 4. Seeing it

Home's status strip shows `SIL` (warning color) while radio silence is on, ahead of the other words (DUAL, SCAN,
ROAM, MON). The side key says what it did: "Radio silence: only PTT transmits" or "Radio silence off".

## 5. Tests

| Test | What |
|---|---|
| `dmrDataServiceTest` `testSilence` | A call alert and a radio check unanswered (`silenceHeld`), an LRRP request unanswered, no ARS registration and no deregistration to wait for; the user's text still sent; off again, answers and registration come back |
| `radioFeaturesTest` `test_vox_silence` | The setting saved (`rs_flags`) and shown (`view.silence`); VOX doesn't key under silence, PTT does; VOX on air ends when silence comes on |
| `radioCoreTest` (position) | Under silence a voice call goes without its GPS Info, even on a channel the codeplug asks it for |
| `aprsRadioTest` `test_silence` | No timed beacon for two intervals; Send now goes; off again, the timed beacon comes back |
| `uiFlowTest` | The Privacy row, the side key both ways, Home's `SIL` |
| `keyassignTest` | `KEYFN_SILENCE` is 22, appended |
