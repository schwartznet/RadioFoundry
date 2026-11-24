<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 The RadioFoundry Authors -->

# Over-the-air rekeying (OTAR)

Status: **phases 1-4 built** (keysets and the changeover; key pairs, the roster, joining; rekeying over the air: 14),
host-tested (`otarKeysTest`, `otarCryptoTest`, `keyStoreTest`, `radioCoreTest`, `settingsTest`, `uiFlowTest` flows
`O ...`). Phases 1 and 2 checked on air on three radios (17, 18); phase 3 and the work before phase 4 too (19, 20). Phase 4 is built and checked on air (21); the rest of 7 and 9 too (22).

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
| Key variable loader (KVL): loads a radio's first keys by cable | Key fill ([key-fill.md](key-fill.md)): radio to radio, X25519 and a six-digit code. Used once, to join (6); the net's active key follows over the air at once (9) |
| Unique key-encryption key (UKEK) per radio, loaded by the KVL, held by the KMF | A UKEK per radio and NC pair, derived from X25519 key pairs (5). No NC holds a copy of every radio's secret |
| Traffic encryption key (TEK) wrapped under the UKEK | The same: AES-256 TEKs wrapped with AES key wrap ([RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), NIST SP 800-38F) |
| Key ID (KID) and algorithm ID sent with each call | Unchanged: DMRA AES-256, ALG 0x25 and the KID in the PI header and late-entry signaling |
| Keysets: active and inactive, switched at changeover | Two keysets, active and next, each up to 4 TEKs, one per common key reference (CKR) (8) |
| Key management messages (KMM): rekey, acknowledge, hello, warm start, inventory, changeover, zeroize | The same set (7), plus roster, time and takeover for the serverless parts |
| The KMM encrypted as a whole (the outer layer, under a key the radio holds), the TEKs in it wrapped again under the KEK | The same two layers: each message body encrypted with AES-256-CTR ([NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)) under a key from that message's MAC key (7.6), the TEK inside wrapped under the UKEK. The outer key is the pair's (or, for a group message, the keyset's), never only the channel's, so a radio behind on keys can still be reached (23) |
| The KMM encrypted as a whole (the outer layer, under a key the radio holds), the TEKs in it wrapped again under the KEK | The same two layers: each message body encrypted with AES-256-CTR ([NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)) under a key from that message's MAC key (7.6), the TEK inside wrapped under the UKEK. The outer key is the pair's (or, for a group message, the keyset's), never only the channel's, so a radio behind on keys can still be reached (23) |
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
K_enc  = HKDF-Expand(K_mac, "RFOTAR2 enc", 32)      AES-256-CTR, the message body (7.6)
```

A member computes its UKEKs with the NCs (at most 4) at start-up and keeps them in RAM; an NC computes a member's
when it sends to it. Only the two radios can wrap for or authenticate as each other. Changing a radio's key pair
changes all its UKEKs (the professional "change UKEK"); NC sends the new public key with ROSTER.

## 6. Setup and joining (the key loader's job)

1. NC 1: Tools > Net keys > **Start a net**. The radio makes its key pair if it has none, a net ID, and the first
   keyset (Generate a key, [group-key-fill.md](group-key-fill.md) 8), and becomes rank 1 of a roster of one.
2. Each new member, in person with any NC: member **Join a net**, NC **Add a member** with its DMR ID. They run key
   fill's exchange ([key-fill.md](key-fill.md) 2-4, the six-digit code on both screens) with a new payload class 3:
   member to NC its public key; NC to member the net ID and its own rank and public key. The member's HELLO 20 s
   later gets the net's active key from the NC as a REKEY to change over to at once (9). A member that already holds
   it (its codeplug was loaded with it) needs nothing more. A member that didn't manage keys starts managing the AES
   channel it joined on, with that channel's key as its active one (as Net keys > Manage keys), so its HELLO goes out;
   joined on another channel, it stays unmanaged until Manage keys.
3. NC sends the new roster entry to every other member (ROSTER). NC 1 gives ranks 2-4 on the roster.

The roster can also be built in the web editor and written with the codeplug (public keys only). A radio's private
key never goes into the codeplug, a file or the editor.

## 7. Key management messages

UDP, port **4103**, over the data service's IP bearer on the net's AES channel. The messages protect themselves (7.6):
the body is encrypted and every message authenticated under keys only its sender and receivers hold, so the data layer
sends them without the channel's AES data privacy ([dmr-data.md](dmr-data.md) 13.5) and a radio that doesn't hold the
channel's current key still hears them. At most 72 octets. Big-endian.

Header, 10 octets:

| Octets | Field |
|---|---|
| 0 | 0x4F ('O') |
| 1 | Version 2 (1: the body in the clear, under the channel's key only) |
| 2 | Type |
| 3-4 | Net ID |
| 5-8 | Message number: per sender, only goes up, saved across restarts |
| 9 | The sender's NC rank, 0 for a member |

The body (every octet after the header, before the MAC) is encrypted (7.6). Every message ends with an 8-octet MAC:
AES-CMAC over the sender's and the receiver's DMR IDs (3 + 3; the receiver's is the talkgroup for a group message) and
every octet before the MAC, the encrypted body included (encrypt then MAC), truncated to its first 8 octets.

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

Changeover time: whole UTC minutes since 2026-01-01; 0 = on NC's CHANGEOVER only. Flags: bit 0 change over at the
changeover time by the member's clock; bit 1 the net's active key, which the member changes over to as soon as it is
stored (a member that joined after the rekey or missed the changeover, 9).

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

### 7.6 Body encryption

Each message's body is encrypted with AES-256 in counter mode (NIST SP 800-38A 6.5), then the MAC is taken over the
header and the ciphertext; a receiver checks the MAC first and decrypts only a message that passes.

| Item | Value |
|---|---|
| Key | K_enc = HKDF-Expand(the message's MAC key as the PRK, "RFOTAR2 enc", 32) (RFC 5869 2.3). Between two radios: from the pair's K_mac (5). A group message: from its group MAC key (7.3), so CHANGEOVER's comes from the next TEK and TIME's from the active one |
| Counter block | The sender's DMR ID (3), the receiver's (3; the talkgroup for a group message), the type (1), the message number (4), the sender's rank (1), then a 32-bit block counter from 0 |
| Uniqueness | A sender's message numbers only go up (saved with the settings), so no counter block repeats under one key. The save waits 2 s after a change; a radio that loses power in that time could send a number again after it starts, so each start moves the number on by 1024 first, saved before the first HELLO 20 s later |
| Length | Unchanged: counter mode adds nothing, and the header carries the counter block's parts |
| In the clear | The header: type, net ID, message number, the sender's rank. The data header shows the DMR IDs anyway |

A REKEY's TEK is wrapped under the UKEK inside the encrypted body: two layers, as P25's KMM (23).

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
the changeover time (in 5 min, 1 h, 6 h, 24 h, at a time, or on command), then sends REKEY to every member one at a time. It
retries unanswered members every 5 minutes until the changeover, in the background while NC stays on the net's
channel. A HELLO from a member behind gets its REKEY at once (warm start). At the changeover time NC sends CHANGEOVER.
Outside a rekey run, a HELLO whose active key isn't NC's gets NC's active key as a REKEY with flag bit 1: a member that
just joined, or that was off through a changeover, catches up and changes over to it at once. Its old key stays as the
overlap ([key-fill.md](key-fill.md)) as after any changeover.

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
| A listener without keys | Every KMM body is encrypted under a key from its pair's (or keyset's) secret (7.6), and each TEK inside REKEY is wrapped again under a UKEK. A listener sees the DMR IDs, the message types and their times: that a rekey happened and which radios took part, not a key or the roster |
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
| Rest | The rekey schedule, TIME, INVENTORY, a revoked radio told (22) | 3.6 KB flash, 48 B RAM as measured on one board ([feature-matrix.md](../feature-matrix.md)) | phase 4 |

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
| UI | Tools > Key fill > 5 Net keys: Manage keys (the channel on view's system, its key as keyset 1), Next key (typed key ID, which the system must hold: load it by key fill, group key fill or Generate), Change over (by hand, in 5 min, in 1, 6 or 24 h), Change over now, Drop the next key, Set the clock (UTC, YYMMDDhhmm), Stop managing keys. The info above the rows: keyset and key, the next key and when, the old key in its overlap, UTC |
| Requests | `radio_req_otar` (RREQ_OTAR): START, STOP, NEXT, CLEAR_NEXT, NOW, CLOCK. Refused while transmitting, except CLOCK |
| Switch | `CONFIG_OTAR`, on where `DMR_AES` and `KEY_CHECK` are |

Not in phase 1: the UI manages CKR 1 only; no over-the-air rekeying (phases 2-4); the RTC; a changeover time typed
as a time of day.

## 18. Phase 2 as built

| Part | What it does |
|---|---|
| Key pair | `settings_t.otar_net` (page 2 of the settings record, [settings-store.md](settings-store.md)): the net ID, this radio's rank, flags and its X25519 private key. Made from the randomness pool the first time the radio joins, adds a member or starts a net. The public key is worked out from it when needed. The emergency wipe of the keys clears it with them |
| Roster | Codeplug records 0x1E00-0x1E3F ([channel-modes.md](channel-modes.md) 3), 37 octets each: DMR ID (3), rank (1), flags (1), public key (32). Public: it may be shared with the codeplug |
| Joining | A key fill session ([key-fill.md](key-fill.md)) where both radios use their key pair instead of a fresh one: the six-digit code the users compare authenticates the two public keys themselves. The net control sends payload class 3 (5 octets: 3, net ID, its rank, 0). The new member stores the net control in its roster and the net in its settings, and answers DONE with its own public key's fingerprint; the net control stores the member in its roster only when that fingerprint is the key the session used. A radio receiving a key (not joining) refuses class 3, and a joining radio refuses classes 1 and 2 |
| UKEK | `otar_pair_keys` (`core/otar/otar_crypto.c`): X25519 of the two key pairs, HKDF-SHA-256 with salt "RFOTAR1", the net ID and both DMR IDs (lower first), expanded to the UKEK and the MAC key (5). Both sides get the same. Used by phase 3's REKEY |
| Crypto | AES-256 decryption (FIPS-197), AES key wrap and unwrap (RFC 3394), AES-256-CMAC (NIST SP 800-38B), checked against those documents' vectors (`otarCryptoTest`) |
| UI | Tools > Key fill > 6 Net. Not in a net: Start a net (this radio net control 1; random key presses first), Join a net (key fill's receiver). In a net: Members (each DMR ID, "NC" and its rank, and the fingerprint), Add a member (net control only: the member's DMR ID, then key fill's sender), Leave the net (the roster cleared, the key pair kept). The info line: the net ID and this radio's role, and its fingerprint |
| Settings record | Now 3 pages (508 octets); the tests' page arithmetic follows `SETTINGS_PAGES` |
| Size | Phases 1 and 2 together: see [feature-matrix.md](../feature-matrix.md) |

Not in phase 2: the roster isn't sent to other members (each member knows only its net control); rekeying over the
air (phase 3); revoking, succession and remote zeroize (phase 4).

## 19. Phase 3 as built

| Part | What it does |
|---|---|
| Messages | `core/otar/otar_msg.c`: REKEY, ACK, HELLO and CHANGEOVER as in 7, header 10 octets, MAC the first 8 octets of AES-256-CMAC over both DMR IDs and the message. REKEY's TEK wrapped with AES key wrap under the pair's UKEK. HELLO goes to the net control alone (under the pair's MAC key), not the talkgroup. INVENTORY, TIME, ROSTER and TAKEOVER are not built |
| Transport | `core/otar/otar_svc.c`: UDP port 4103 through the air queue (owner `AIRQ_OWNER_OTAR`); REKEY, ACK and HELLO individual and confirmed, CHANGEOVER to the channel's talkgroup unconfirmed, 3 copies 2 s apart. Up to 4 received messages held for the UI task while the radio is in a net. On an AES channel the data layer encrypts each packet under the active TEK as well |
| Net control | Net > Rekey now: random key presses, then a new TEK under the first free key ID after the one in use, stored in the managed system and made this radio's next keyset; the changeover by Net > Key change (in 5 min, 1 h, 6 h, 24 h, or by hand; 5 min first), by hand when the radio has no clock. A member's Net menu is Members and Leave the net. Then REKEY to each roster member in turn: an ACK within 20 s, else "no answer" and again after 60 s; a member's HELLO brings its REKEY at once. Net status lists each member (waiting, sent, OK, no answer) and "Key 34: 1 of 2 have it". Net > Change over the net: CHANGEOVER to the talkgroup, then this radio's own changeover. The run ends when this radio has changed over |
| Member | A REKEY from a net control on its roster, checked (MAC, unwrap, a message number above the last one taken), stores the TEK in the managed system (a storage job), makes it the next keyset with the REKEY's changeover time, and ACKs with its check value; a resend of a key it holds is ACKed "held". A member not managing keys answers "not managed". A CHANGEOVER checked under the next TEK changes over at once. 20 s after start (and after joining) a member says HELLO to its net control |
| Message numbers | `settings_t.otar_msgnum` (this radio's, one up per message) and `otar_seen` (the last taken from net control 1); 20 adds net controls 2-4 |
| Not yet | ACK and HELLO replay checks at the net control (their worst effect is a resend), several net controls, revocation, INVENTORY, TIME (radios use GPS or a hand-set clock) |

## 20. Before phase 4 (as built)

What succession needs before it can work, built on phase 3:

| Part | What it does |
|---|---|
| Message numbers per net control | A member keeps the last message number taken from each net control rank: `otar_seen` for rank 1, `otar_seen_nc[3]` for ranks 2-4 ([settings-store.md](settings-store.md)). The rank is the sender's on this radio's roster, not the header's. So NC 2's numbers, lower than NC 1's, aren't refused as replays. Starting, joining or leaving a net clears them: another net's net control 1 counts from its own numbers |
| ROSTER | Type 6 as in 7 (55 octets): one roster record under the pair's MAC key. A member takes it from a net control on its roster (not revoked; message number above the last from that rank), stores the entry (a storage job) and ACKs with CKR 0, keyset 0 and the entry's fingerprint as the check value: stored, already held, couldn't store, or refused (6). Refused: an entry that would change a net control of higher rank than the sender's, or would revoke this radio; both wait for phase 4's confirmation (10). An entry for the radio itself sets its rank (how NC 1 will name NC 2) |
| Roster run | The net control sends each wanted (member, entry) pair in roster order, one at a time, waiting 20 s for the ACK and sending each up to 3 times. After Add a member: the new member's entry to every other member and every entry but the net control's to the new member. Net > 7 Send the roster: every entry to every member. The Net screen shows "Roster: sending, 2 sent" and "Roster: 4 sent, no answer 1". A rekey and a roster run don't run at once |
| A member's Net keys | A net's member gets its next key and changeover from the net control: Net keys shows it Change over now (a CHANGEOVER missed while off), Set the clock and Stop managing keys, not Next key, Change over (when) or Drop |
| Clock across a restart | On a board whose real-time clock is backed (`board.toml` `clock` rtc = "backed", [feature-matrix.md](../feature-matrix.md); the board provides `hal_rtc.h`), the radio task sets it from GPS (the first fix after a start, then every 6 hours) and from Set the clock, counting days from 2026-01-01, and marks it trusted (`settings_t.otar_rtc`). After a restart it reads it twice, 3 s apart, and takes the time only when the clock counted those seconds (within one), unless GPS came first: the clock source is then "RTC" until GPS takes over. On one radio of three the chip held the loaded time but never ran (it read a date years off at 00:00:00): the check leaves such a clock out and the radio waits for GPS. Every read and set is logged with all registers (`rtc` lines in the debug log) A clock this firmware never set (another firmware's, or after a factory reset) isn't read. Boards without one link `hal_rtc_*` defaults that hold nothing |
| Requests during an over | The radio task holds an OTAR request that comes while it transmits (up to 4, in order) and makes it between overs, instead of dropping it: a net control asks to change over as its last CHANGEOVER copy goes out, and a member to make a stored key next while traffic may be on. Found on air: the net control's own changeover was lost, so it kept sending under the old key the members had erased |
| Net control's menu | 1 Members, 2 Add a member, 3 Rekey now, 4 Key change, 5 Net status, 6 Change over the net, 7 Send the roster, 8 Leave the net. A member's: 1 Members, 2 Leave the net |

## 21. Phase 4 as built

| Part | What it does |
|---|---|
| Ranks | Net control 1: Net > Members, OK on a radio, 1 Rank cycles member, NC 2, NC 3, NC 4. The entry is stored in its own roster, then sent to every member as ROSTER, the radio itself included, which takes its new rank (20). Only net control 1 sets ranks |
| Revoke | Any net control: 2 Revoke on a member or a lower net control. Its entry, flagged revoked, goes to every other member (not to the revoked radio). A rekey leaves revoked radios out, and no radio takes REKEY, ROSTER, CHANGEOVER or ZEROIZE from a revoked sender, nor sends HELLO to one. A net control of the same or higher rank can't be revoked this way: Take over is for that |
| Take over | Net control 2-4: Net > Take over takes the highest-ranked net control above it that isn't revoked as lost: revoked in its own roster and sent to every member. A member that gets a lower net control's ROSTER revoking a higher one (only the revoked flag changed) doesn't store it: it answers ACK result 7 (asked) and its Net screen shows "NC 2 says NC 1 is lost" with Accept the take over and Refuse the take over. The net control's Net screen counts these ("asked 2"). Then the net control rekeys without the lost one. The TAKEOVER group message (7, type 9) is not built: the per-member ROSTER carries it |
| Backup net controls | A net control takes REKEY and CHANGEOVER from another net control like any member, so a backup holds the net's keys; it doesn't while its own rekey run is going |
| Remote wipe | Net > Remote wipe: Off (default) or On, per radio (`settings_t.otar_wipe`). ZEROIZE (type 8, 21 octets: the target's DMR ID, under the pair's MAC key) from a net control on the roster, not revoked, with a fresh message number and this radio's ID wipes its keys as Clear all keys does ([zeroize.md](zeroize.md)) and restarts; no answer. With Remote wipe off it is dropped. A net control sends it with 3 Wipe its keys on a member |
| Member screen | Net > Members > OK on a radio (a net control only): 1 Rank, 2 Revoke, 3 Wipe its keys, and the radio's ID and fingerprint. Members shows "revoked" after a revoked radio's ID |

Checked on air 2026-11-23/24 with three radios: net control 1 made 4678512 net control 2, which wiped net control 1's
keys remotely, took over (the member asked first: "NC 2 says NC 1 is lost", then Accept), rekeyed to key 38 leaving
the revoked radio out ("Key 38: 1 of 1 have it"), and changed the net over: both calls AES-256 under key ID 0x26.

## 22. The rest of 7 and 9 (as built)

| Part | What it does |
|---|---|
| Rekey schedule | Net > Rekey every: Off (default), 1 day, 7 days, 30 days, on each net control (`settings_t.otar_sched` and `otar_sched_at`, [settings-store.md](settings-store.md)); it needs a clock. The Net screen shows "Next rekey: 2026-11-30 14:05". When it is due and no rekey, roster run or next key is under way, the net control starts a rekey whose changeover is 60 minutes later by the clocks, and sets the next one. Its key is made when the pool is full: the radio's own key presses fill it, as for Rekey now |
| CHANGEOVER at the changeover | A rekey run that changes over by the clocks ends with the net control's own changeover; it then sends CHANGEOVER (3 copies) for members without a clock. Not after Change over the net, which sent its own |
| TIME | Type 7 (22 octets: UTC seconds since 2026-01-01) to the talkgroup, 2 copies, under the active TEK's group key "time" (7.3). Net > Send the time, and at the start of every rekey that changes over by the clocks. Sent only from a clock that isn't the net's (GPS, the board's clock, or set by hand). A member takes it from a net control on its roster, not revoked, with a fresh message number, and the radio task keeps it only when the radio has no clock or only the net's (clock source "net"), moving that one at most 48 hours (7.4). It isn't written to the board's clock |
| INVENTORY | Type 5 (18 octets, no body) from a net control: Net > Members > OK on a radio > 4 Ask its keys. The member answers an ACK (result 1, CKR 1) for its active keyset and one for its next, each with that key's check value; never a key. The member screen shows "Keys: keyset 7 OK, keyset 8 OK" (the key matches this radio's of that keyset), "differs", "asking" or "no answer" |
| Removed from the net | Revoke now tells the revoked radio too: its own entry, revoked. It takes it from a net control above its own rank (any net control, for a member), stores it, ACKs, and its Net screen shows "Removed from the net"; it says no HELLO after that. Leave the net clears it. A take over still doesn't tell the lost net control |
| Joining after a rekey | Key fill goes in the clear on the AES channel ([dmr-data.md](dmr-data.md) 13.5), so a radio whose codeplug holds only an older key can still join. Found on air: before, the joining radio dropped the net control's key fill under the new key and the join failed. The join itself carries no key: on air the joined radio stayed on its old key, its HELLO and the net control's REKEYs each dropped under the other's channel key. Section 23 fixes that |
| TAKEOVER | Not built: the ROSTER each member gets (21) carries it and is answered member by member, which a group message wouldn't be. Type 9 stays reserved |
| Net control's menu | 1 Members, 2 Add a member, 3 Rekey now, 4 Key change, 5 Net status, 6 Change over the net, 7 Send the roster, (8 Take over on net control 2-4), Rekey every, Send the time, Remote wipe, Leave the net |

Checked on air 2026-11-24 (net control 2 and one member): Ask its keys showed "Keys: keyset 7 OK"; Rekey every 1 day showed the next rekey a day on; Send the time went out (the member, with GPS, kept its own clock, as 7.4 says; the rule for a radio without a clock is host-tested in `radioCoreTest`); revoking the member made it show "Removed from the net". Then, in a fresh net: a rekey to key 78 "in 5 min"; the member, its GPS turned off and restarted (its board clock doesn't run), had no clock and changed over at 01:23 on the net control's CHANGEOVER (3 data bursts 2 s apart at the changeover); Send the time then set its clock (source "net"). A scheduled rekey firing is not yet seen on air (host flows only).

## 23. Messages that protect themselves (as built)

Found on air 2026-11-24: a radio that joined net 8B16 after its rekey to key 78 held only key 77. The join worked
(key fill goes in the clear), but OTAR's messages went under the channel's AES data privacy, under each radio's own
active key: the member dropped the net control's 8 REKEY packets under key 78, and the net control dropped the member's
HELLO under key 77 (`data.privacy_rx_dropped`). A member switched off through a changeover would be stuck the same way.

| Part | What it does |
|---|---|
| Version 2 | The body encrypted under K_enc (7.6), encrypt then MAC. Version 1 messages are refused (all radios of a net run the same build) |
| In the clear at the data layer | Port 4103, like key fill's 4101 (`dmrDataUdpClear`, [dmr-data.md](dmr-data.md) 13.5): no privacy header, not refused on an AES channel, taken by any radio |
| Catching up | A HELLO outside a rekey run whose active key isn't the net control's gets its active key as a REKEY flagged "now" (7.1, 9) |
| Message numbers | Moved on by 1024 at each start (7.6) |
| Joining unmanaged | A radio that joins without managing keys starts managing the AES channel it is on (6). Found on air: a fresh radio joined, answered Ask its keys with "Keys: none", and said no HELLO, so it never caught up |

**Compared with P25 OTAR.** Public descriptions of TIA-102.AACA's KMM give it three protections: the TEKs inside wrapped
under the radio's KEK, the KMM body encrypted again under a traffic key (the outer layer), and a MAC with message
numbers against replay (TIA-102.AACA-1). Each has its counterpart here:

| P25 KMM | Here |
|---|---|
| TEK wrapped under the radio's UKEK | TEK wrapped under the pair's UKEK, AES-256 key wrap (RFC 3394 / NIST SP 800-38F KW) (5, 7.1) |
| KMM body encrypted (outer layer), the key named in the KMM | Body encrypted with AES-256-CTR (SP 800-38A) under the pair's or the keyset's K_enc (7.6). The key is implied by the sender, receiver and type, never the channel's alone |
| MAC and message numbers | AES-256-CMAC (SP 800-38B) truncated to 64 bits over both DMR IDs, the header and the ciphertext; message numbers per sender (7) |
| First keys loaded by a KVL in person | Key fill in person or over the air with the six-digit code ([key-fill.md](key-fill.md)); the active key follows by REKEY (6, 9) |
| UKEK held by the KMF | Derived by both radios from X25519 key pairs (RFC 7748) through HKDF-SHA-256 (RFC 5869); no radio holds another's |

What it is not: it doesn't speak TIA-102.AACA's formats (1), and no part is certified (no P25 CAP testing, no FIPS 140
validated module). The algorithms are the published ones above, each checked against its standard's test vectors in
`otarCryptoTest`. The KMM text of TIA-102.AACA itself wasn't read for this; the comparison is with its public
descriptions.

Checked on air 2026-11-24, net 8B16: both radios flashed with this build; the member, joined after the rekey and
still on key 77, restarted, said HELLO and got key 78 from the net control as a REKEY flagged now. 45 s after start its
Net keys showed "Keyset 2: key 78", old key 77 heard; `data.privacy_rx_dropped` stayed 0 on both (nothing went under
the channel's key).

Tests: `otarCryptoTest` (a body's octets aren't in the message, the same body under the next message number encrypts
differently, a changed ciphertext octet fails the MAC, opening leaves the message unchanged, version 1 refused);
`dmrDataServiceTest` (port 4103 goes in the clear, mixed ports don't).
