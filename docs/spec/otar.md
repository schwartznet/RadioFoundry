<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 The RadioFoundry Authors -->

# Over-the-air rekeying (OTAR)

Status: **phase 1 built** (keysets and the changeover, 14; section 17 says what it does), host-tested
(`otarKeysTest`, `radioCoreTest`, `uiFlowTest` flows `O ...`), untested on a radio. Phases 2-4 are a design, not
built.

A net of handhelds changes its AES-256 traffic keys over the air on a schedule, the way professional systems do, but
with no server: the key management facility is a handheld. One radio is **net control (NC)**. It makes new traffic
keys, sends each radio its copy wrapped under that radio's own key-encryption key, sees which radios acknowledged,
retries the rest, and schedules the changeover. If NC is lost, the next radio on the **succession list** takes over. A
lost radio is left out of the next rekey and can't read the net after the changeover.

## 1. How this follows professional OTAR

Professional OTAR (P25, TIA-102.AACA; TETRA and MOTOTRBO have their own, licensed with a key management facility) is
built from a small set of parts. This design keeps each of them and changes only where the server lives.

| Professional OTAR | Here |
|---|---|
| Key Management Facility (KMF): a server | Net control: a handheld, up to 4 ranked (the succession list). Each holds what it needs to act alone (5) |
| Key variable loader (KVL): loads a radio's first keys by cable | Key fill ([key-fill.md](key-fill.md)): radio to radio, X25519 and a six-digit code. Used once, to join (6) |
| Unique key-encryption key (UKEK) per radio, loaded by the KVL, held by the KMF | A UKEK per radio and NC pair, derived from X25519 key pairs (5). No NC holds a copy of every radio's secret |
| Traffic encryption key (TEK) wrapped under the UKEK | The same: AES-256 TEKs wrapped with AES key wrap ([RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), NIST SP 800-38F) |
| Key ID (KID) and algorithm ID sent with each call | Unchanged: DMRA AES-256, ALG 0x25 and the KID in the PI header and late-entry signaling |
| Keysets: active and inactive, switched at changeover | Two keysets, active and next, each up to 4 TEKs, one per common key reference (CKR) (8) |
| Key management messages (KMM): rekey, acknowledge, hello, warm start, inventory, changeover, zeroize | The same set (7), plus roster, time and takeover for the serverless parts |
| Message authentication and message numbers against replay | AES-256-CMAC (NIST SP 800-38B; [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493) is the same mode for AES-128) under keys from the UKEK; message numbers per sender (7) |
| The KMF queues updates for radios that are off | NC retries every few minutes; a radio coming back sends hello (warm start) and NC answers at once (9) |
| Crypto period: TEKs changed daily, weekly or monthly | NC's rekey schedule: by hand, or every 1, 7 or 30 days (9) |

It does not speak TIA-102.AACA's message formats: no P25 KMF can reach a DMR radio, and MOTOTRBO's OTAR is
proprietary, so there is nothing on DMR to interoperate with. The message formats are our own, built from public
standards (X25519 RFC 7748, HKDF RFC 5869, AES key wrap RFC 3394, AES-CMAC NIST SP 800-38B) on RadioFoundry's DMR data service.
The voice they protect stays standard DMRA AES-256: a radio of another make, loaded by hand with the current TEK under
its KID, still talks to the net.

## 2. Terms

| Term | Meaning |
|---|---|
| Net | The radios sharing one OTAR-managed AES system. A 2-octet net ID chosen at setup |
| Member | A radio on the net's roster |
| Net control (NC) | A member allowed to rekey and change the roster. Up to 4, rank 1 (first) to 4 |
| Radio key pair | Each member's own X25519 key pair, made on the radio from the randomness pool ([key-fill.md](key-fill.md) 6). The private key never leaves the radio |
| Roster | Each member's DMR ID, NC rank (0: not NC), revoked flag and public key. Public |
| UKEK | The key-encryption key of one member and one NC (5) |
| TEK | An AES-256 traffic key |
| CKR | Common key reference, 1-4: which of a net's TEKs a channel uses. A net with one key uses CKR 1 only |
| Keyset | Up to 4 TEKs (one per CKR), with a keyset number and a changeover time. A member holds the **active** keyset and at most one **next** |
| Keyset number | 1, 2, 3, ...; only ever goes up |
| Changeover | The moment the next keyset becomes the active one |

## 3. What it does

| Function | How |
|---|---|
| Rekey | NC makes new TEKs and sends each member a REKEY with each TEK wrapped under that member's UKEK |
| Acknowledgement | Each member answers ACK with each new key's check value. NC shows who has it |
| Retry and warm start | NC resends to members that haven't answered; a radio that was off sends HELLO when it comes back, and NC rekeys it |
| Scheduled changeover | Each keyset carries a UTC changeover time. Radios with a clock switch by themselves; NC's CHANGEOVER switches the rest |
| Overlap | Receivers hold the active and next keysets and choose by each over's KID, so radios that switch a little apart still hear each other (8) |
| Inventory | NC asks a member what it holds: keyset numbers, KIDs, check values. Never a key |
| Revocation | NC revokes a lost member and rekeys; the revoked radio gets no REKEY |
| Succession | Any NC can act. If NC 1 is lost, NC 2 takes over, revokes NC 1 and rekeys (10) |
| Roster changes | NC adds, ranks and revokes members over the air; a new member joins in person (6) |
| Time | NC broadcasts UTC for radios without a clock |
| Zeroize | Optional and off by default on each radio: NC tells one member to wipe its keys ([zeroize.md](zeroize.md)) |

## 4. Switches, files and size

| Item | Value |
|---|---|
| Switch | `CONFIG_OTAR`, on where `CONFIG_DMR_AES` and `CONFIG_KEY_FILL` are |
| Protocol | `core/otar/otar.{h,c}`: building, checking and opening messages; AES-KW and AES-CMAC over the AES-256 in `dmrAes.c`, which gains AES decryption for unwrapping (about 1 KB; it only encrypts today). Pure: no RTOS, no allocation |
| Service | `core/otar/otar_svc.c`: UDP port 4103, NC's rekey run, member answers, the changeover timer |
| Keys in use | `core/radio/radio_aes.c`: the active, next and previous keysets for an OTAR system; `DMR_AES_KEY_SLOTS` 1 to 3 |
| UI | Tools > Net keys (12), Settings > Privacy rows |
| Tests | `tests/host/otarTest.c` with the RFC 3394 and NIST SP 800-38B AES-256 test vectors, `uiFlowTest` flows `O ...` |

**Other modes later.** DMR only for now, but the code is split so P25 (or NXDN) can join without a rewrite:

| Layer | Knows about the mode? | Later for P25 |
|---|---|---|
| Key management: keysets, roster, UKEKs, the messages' contents, NC's logic (`otar.c`, most of `otar_svc.c`) | No: it moves bytes and keys | Nothing to change |
| Transport: send and take a message (`otar_svc.c`, one small adapter) | Yes: DMR data, UDP port 4103 | A P25 packet data adapter, or keep delivering on a DMR channel |
| Key users: the voice path asks the key store for "this net's active TEK for CKR n" | Yes: `radio_aes.c` for DMR | P25 AES voice asks the same store |

A keyset's TEKs carry no DMR-only fields, and a CKR is a reference any mode's channel can hold. Nothing for P25 is
built now.

Estimated from the key features already measured ([feature-matrix.md](../feature-matrix.md)): about 16-20 KB flash
over all phases (14), about 300 B static RAM, about 1 KB of RTOS heap while NC's net status screen is open (64
members). Phase 1's measured size is in the feature matrix; whether the rest fits is a board's free flash and RAM there.

## 5. UKEKs

Professional systems load one UKEK per radio and keep a copy of every radio's UKEK in the KMF, so whoever holds the
KMF's database holds every radio's UKEK. Here each member and each NC derive a UKEK they share without sending it, so
a backup NC needs no copy of anyone's secret:

```
shared = X25519(own private key, the other radio's public key)      all zeros: refused (RFC 7748 6.1)
PRK    = HKDF-Extract(salt = "RFOTAR1" | net ID | lower DMR ID (3) | higher DMR ID (3), IKM = shared)
UKEK   = HKDF-Expand(PRK, "RFOTAR1 ukek", 32)       AES-256 key wrap
K_mac  = HKDF-Expand(PRK, "RFOTAR1 mac", 32)        AES-CMAC
```

A member computes its UKEKs with the NCs (at most 4) at start-up and keeps them in RAM; an NC computes a member's
when it sends to it. Only the two radios can wrap for or authenticate as each other. Changing a radio's key pair
changes all its UKEKs (the professional "change UKEK"); NC sends the new public key with ROSTER.

## 6. Setup and joining (the key loader's job)

1. NC 1: Tools > Net keys > **Start a net**. The radio makes its key pair if it has none, a net ID, and the first
   keyset (Generate a key, [group-key-fill.md](group-key-fill.md) 8), and becomes rank 1 of a roster of one.
2. Each new member, in person with any NC: member **Join a net**, NC **Add a member** with its DMR ID. They run key
   fill's exchange ([key-fill.md](key-fill.md) 2-4, the six-digit code on both screens) with a new payload class 3:
   member to NC its public key; NC to member the net ID, the roster and the active (and next) keyset.
3. NC sends the new roster entry to every other member (ROSTER). NC 1 gives ranks 2-4 on the roster.

The roster can also be built in the web editor and written with the codeplug (public keys only). A radio's private
key never goes into the codeplug, a file or the editor.

## 7. Key management messages

UDP, port **4103**, over the data service's IP bearer on the net's AES channel, so every packet is also encrypted under
the active TEK by the channel's AES data privacy ([dmr-data.md](dmr-data.md) 13.4). At most 72 octets. Big-endian.

Header, 10 octets:

| Octets | Field |
|---|---|
| 0 | 0x4F ('O') |
| 1 | Version 1 |
| 2 | Type |
| 3-4 | Net ID |
| 5-8 | Message number: per sender, only goes up, saved across restarts |
| 9 | The sender's NC rank, 0 for a member |

Every message ends with an 8-octet MAC: AES-CMAC over the sender's and the receiver's DMR IDs (3 + 3; the receiver's
is the talkgroup for a group message) and every octet before the MAC, truncated to its first 8 octets.

| Type | Name | From, to | Carried | Body after the header | MAC key |
|---|---|---|---|---|---|
| 1 | REKEY | NC to a member | Individual, confirmed | keyset number (4), CKR (1), KID (1), changeover in UTC minutes (4), flags (1), TEK wrapped (40) | the pair's K_mac |
| 2 | ACK | member to NC | Individual, confirmed | keyset number (4), CKR (1), result (1), check value (3) | the pair's K_mac |
| 3 | CHANGEOVER | NC to the talkgroup | Group, 4 copies | keyset number (4) | from the next keyset (7.3) |
| 4 | HELLO | member to the talkgroup | Group, 2 copies | active keyset number (4), next keyset number (4) | from the active keyset |
| 5 | INVENTORY | NC to a member | Individual, confirmed | none: the member answers an ACK for each TEK it holds | the pair's K_mac |
| 6 | ROSTER | NC to a member | Individual, confirmed | DMR ID (3), rank (1), flags (1: revoked), public key (32) | the pair's K_mac |
| 7 | TIME | NC to the talkgroup | Group, 2 copies | UTC seconds (4) | from the active keyset |
| 8 | ZEROIZE | NC to a member | Individual, confirmed | the member's DMR ID (3) | the pair's K_mac |
| 9 | TAKEOVER | NC to the talkgroup | Group, 4 copies | DMR ID of the NC it replaces (3), the keyset number it will rekey to (4) | from the active keyset; each member then gets a ROSTER (10) |

A receiver drops and counts, and doesn't show, a message of another length, version or net, from a sender not on the
roster or revoked, with a message number not above the last one taken from that sender, or whose MAC doesn't check
(compared in constant time).

### 7.1 REKEY

The TEK is wrapped with AES-256 key wrap (RFC 3394) under the pair's UKEK: 32 octets in, 40 out, its integrity check
included. One TEK per message; a keyset of 4 TEKs is 4 messages. The member takes a REKEY only for a keyset number above
its active one, stores the TEK in its next keyset (replacing a lower-numbered next keyset, or the same number from a
lower-ranked NC), then ACKs with the check value ([key-check.md](key-check.md)) of what it stored. A REKEY for a TEK it
already holds, same check value, is ACKed again (NC's retry).

Changeover time: whole UTC minutes since 2026-01-01; 0 = on NC's CHANGEOVER only. Flags bit 0: the member may change
over by its own clock.

### 7.2 ACK results

0 stored, 1 already held, 2 older keyset refused, 3 couldn't store, 4 wrap check failed.

### 7.3 Group message keys

A group message can't use a pair's key, so its MAC key comes from a keyset:
`HKDF-Expand(HKDF-Extract("RFOTAR1 group", the keyset's CKR 1 TEK), label, 32)` with the label "co" for CHANGEOVER
(the next keyset), "hello" and "time" (the active one). A revoked radio never gets the next keyset, so it can't make a
CHANGEOVER; a member can, but all it can do with that is bring the changeover forward.

### 7.4 Clocks and TIME

A member's clock, in order: GPS; the RTC where the board keeps it through power-off (`board.toml` `clock` = "backed",
[feature-matrix.md](../feature-matrix.md)); a time set by hand; TIME. TIME only sets a clock that has none of the others, and moves it at
most 48 hours. A radio with no clock waits for CHANGEOVER.

### 7.5 ROSTER and ZEROIZE

ROSTER adds a member, changes a rank or a public key, or revokes. Revoking an NC of higher rank than the sender asks
the member's user first (10). A radio told it is revoked shows "Removed from the net".

ZEROIZE is taken only when the member's Settings > Privacy > **Remote wipe** is "From net control" (default Off). The
member wipes its keys only ([zeroize.md](zeroize.md) 3.2) and answers nothing.

## 8. Keys in use

On an OTAR system a channel names a CKR, not a key ID. The radio transmits with the active keyset's TEK for that CKR
and its KID. It receives with the active, next and, for 30 minutes after a changeover, the previous keyset, chosen by
the KID in the over's PI header or late-entry signaling. After those 30 minutes the previous TEKs are wiped: a radio
captured later can't read traffic from before the last changeover.

KIDs: NC picks them; by default from the keyset number so consecutive keysets never share one.

## 9. Net control

**Net status** (NC only): a row per member, "4670501 OK 7", "4670502 waiting", "4670511 revoked", and "18 of 20 have
keyset 7". OK on a row: inventory, resend, revoke, or (if that radio allows it) zeroize.

**Rekey:** by hand (Rekey now) or on a schedule (every 1, 7 or 30 days). NC fills the pool, generates the TEKs, takes
the changeover time (in 1 h, 6 h, 24 h, at a time, or on command), then sends REKEY to every member one at a time. It
retries unanswered members every 5 minutes until the changeover, in the background while NC stays on the net's
channel. A HELLO from a member behind gets its REKEY at once (warm start). At the changeover time NC sends CHANGEOVER.

## 10. Succession

Every NC on the roster can rekey and change the roster. Two rekeys at once: a member keeps the higher keyset number;
for the same number, the one from the NC of higher rank.

**Take over:** NC 2 (or 3, 4), Tools > Net keys > Take over, names the lost NC. It sends TAKEOVER, sends each member a
ROSTER revoking that NC, then rekeys without it. A member asked to revoke an NC of higher rank than the sender shows
"NC 2 says NC 1 is lost. Accept?" and acts only on OK, so a captured low-rank NC can't quietly take over a net. Confirm
on voice.

## 11. Security

| Threat | What stops it |
|---|---|
| A listener without keys | Every KMM is encrypted under the active TEK by the data layer, and each TEK inside REKEY is wrapped again under a UKEK |
| A lost member | Revoked and left out of the next rekey. Until the changeover it can still read the net; after it, not |
| A lost NC | The next NC takes over (10). Until members accept, the lost NC can still rekey: the confirmation on each radio and the voice check are the guard |
| A captured NC's database | There is none: an NC holds only its own private key. It can rekey until revoked, but can't impersonate other members to each other |
| A forged REKEY, ROSTER or ZEROIZE | Needs the pair's K_mac, which only that NC and that member can derive |
| A forged CHANGEOVER | Needs the next keyset, which a revoked radio doesn't have |
| Replay | Message numbers per sender and keyset numbers only go up |
| Past traffic from a captured radio | Previous TEKs are wiped 30 minutes after a changeover. Traffic since the last changeover isn't protected from that radio |
| Keys in flash | No secure element: anyone who opens a radio can read its flash ([settings-store.md](settings-store.md) 3.1). The emergency wipe and remote zeroize are the answers |
| Weak randomness | The pool's credit comes from key press timing ([key-fill.md](key-fill.md) 6); a hardware noise source would strengthen every key |
| Jamming | Nothing; a member that missed a rekey keeps its keys and asks again with HELLO |

## 12. Radio UI

| Where | Rows |
|---|---|
| Tools > Net keys (member) | Status (net, keyset, KID, next changeover, rekeyed by), Request keys (HELLO), Join a net |
| Tools > Net keys (NC adds) | Net status, Rekey now, Rekey schedule, Change over now, Add a member, Revoke a member, Take over, Send time |
| Settings > Privacy | Remote wipe: Off / From net control; clock source |
| Home | The AES256 badge as today; the KID on the chips line |

## 13. Storage

| What | Where | Size |
|---|---|---|
| Radio private key | Its own flash record, never the codeplug or a file; erased by the emergency wipe | 32 B |
| Net ID, rank, own public key | Settings record | about 40 B |
| Roster | Codeplug records (public) | 40 B per member, up to 64 |
| Keysets | Traffic key records of the OTAR system, plus a record with keyset numbers, changeover time and state | 32 B per TEK + 16 B |
| Message numbers | Settings record: own, and the last taken from each NC | 20 B |

## 14. Phases

| Phase | What | Flash (est.) | Needs |
|---|---|---|---|
| 1 | Keysets (active, next, previous) and CKRs; 3 receive slots by KID; changeover by clock or by hand | 3 KB | #758 |
| 2 | Radio key pair, roster, joining in person (key fill class 3), UKEKs; AES-256 decryption, AES-KW and AES-CMAC with their test vectors | 6 KB | #950 |
| 3 | REKEY, ACK, HELLO, INVENTORY, CHANGEOVER, TIME; NC's rekey run, schedule and net status | 5-6 KB | phases 1, 2 |
| 4 | ROSTER changes, revocation, succession and TAKEOVER, remote zeroize | 3 KB | phase 3, #951 |

Each phase is its own PR with host tests and UI flows, and useful alone: phase 1 already gives scheduled changeovers
with keys loaded by key fill or group key fill.

## 15. Open decisions

1. Roster size: 64 proposed.
2. Remote zeroize: in (off by default on each radio), or left out.
3. Grace time after a changeover: 30 minutes proposed.
4. Members change over by their own clock by default when they have GPS or a kept RTC: proposed yes.
5. Upstream: propose it to RadioFoundry as an issue first, since it goes beyond ETSI and DMRA.

## 16. Tests

`otarTest`: AES-256 decryption against FIPS-197 C.3, AES-KW against RFC 3394 4.6 (a 256-bit key wrapped under a 256-bit KEK), AES-256-CMAC against the NIST SP 800-38B examples; UKEKs agree both ways and differ
for every other pair; each message built and checked, every field and MAC octet altered, wrong net, wrong sender,
revoked sender, replayed message number; REKEY rules (keyset numbers, ranks, resend); changeover by time, by message
and with clock skew; the previous keyset's wipe; a revoked radio can't make a CHANGEOVER; takeover with and without
the user's OK. UI flows for each screen.

## 17. Phase 1 as built

| Part | What it does |
|---|---|
| State | `settings_t.otar` (`otar_keys_t`, [settings-store.md](settings-store.md)): one managed system, its active, next and previous keysets as key IDs per CKR, keyset numbers, the changeover minute and whether it goes by the radio's clock. The radio's own: the codeplug is shared and not written |
| Keys in use | `radio_aes.c`: on the managed system a channel's key reference 1-4 is its CKR, anything else CKR 1. TX uses the active keyset's key; RX holds the active, next and (through the 30-minute overlap) previous keys, `DMR_AES_KEY_SLOTS` 3, chosen by each call's key ID. Changes happen between overs only |
| Changeover | By hand (Change over now), or at the changeover minute when the radio has a clock. The overlap is RAM: a restart ends it. When it ends, the previous keyset's keys that no keyset still names are removed from the codeplug by a storage job (`codeplug_kv_remove`; the flash sector keeps the bytes until the area is rewritten, as for any removed record) |
| Clock | `core/support/utc_clock.c`, RAM only: GPS once a minute (`position_utc_fields`, with `CONFIG_SATELLITE_TLE`), or set by hand. A board's backed RTC is not read yet (each board's hardware spec has its registers) |
| UI | Tools > Key fill > 5 Net keys: Manage keys (the channel on view's system, its key as keyset 1), Next key (typed key ID, which the system must hold: load it by key fill, group key fill or Generate), Change over (by hand, in 1, 6 or 24 h), Change over now, Drop the next key, Set the clock (UTC, YYMMDDhhmm), Stop managing keys. The info above the rows: keyset and key, the next key and when, the old key in its overlap, UTC |
| Requests | `radio_req_otar` (RREQ_OTAR): START, STOP, NEXT, CLEAR_NEXT, NOW, CLOCK. Refused while transmitting, except CLOCK |
| Switch | `CONFIG_OTAR`, on where `DMR_AES` and `KEY_CHECK` are |

Not in phase 1: the UI manages CKR 1 only; no over-the-air rekeying (phases 2-4); the RTC; a changeover time typed
as a time of day.
