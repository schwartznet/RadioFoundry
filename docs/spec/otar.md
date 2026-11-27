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
| Key management messages (KMM): P25 defines several dozen (rekey, acknowledgement, hello, inventory, changeover, zeroize, and many more) | A small set of our own with the same jobs for the parts used here (7), plus roster, time and takeover for the serverless parts. Not P25's formats, and not all of its messages (23) |
| The KMM encrypted as a whole (the outer layer, under a key the radio holds), the TEKs in it wrapped again under the KEK | The same two layers: each message body encrypted with AES-256-CTR ([NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)) under a key from that message's MAC key (7.6), the TEK inside wrapped under the UKEK. The outer key is the pair's (or, for a group message, the keyset's), never only the channel's, so a radio behind on keys can still be reached (23) |
| Message authentication and message numbers against replay | AES-256-CMAC (NIST SP 800-38B; [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493) is the same mode for AES-128) under keys from the UKEK; message numbers per sender (7) |
| The KMF queues updates for radios that are off | NC retries every minute until the changeover; a radio coming back asks for keys with HELLO (a rekey request) until NC answers, and NC answers at once: its key, or "up to date" (9) |
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
| Retry and rekey request | NC resends to members that haven't answered; a radio that was off asks for keys with HELLO when it comes back, again until answered, and NC rekeys it or says it is up to date (resynchronization) |
| Scheduled changeover | Each keyset carries a UTC changeover time. Radios with a clock switch by themselves; NC's CHANGEOVER switches the rest |
| Overlap | Receivers hold the active and next keysets and choose by each over's KID, so radios that switch a little apart still hear each other (8) |
| Inventory | NC asks a member what it holds: keyset numbers, KIDs, check values. Never a key |
| Revocation | NC revokes a lost member and rekeys; the revoked radio gets no REKEY |
| Succession | Any NC can act. If NC 1 is lost, NC 2 takes over, revokes NC 1 and rekeys (10) |
| Roster changes | NC adds, ranks and revokes members over the air; a new member joins in person (6) |
| Time | NC broadcasts UTC for radios without a clock |
| Zeroize | On by default in a net, and each radio's user may turn it off: NC tells one member to wipe its keys ([zeroize.md](zeroize.md)) |
| Get location | On by default in a net, and each radio's user may turn it off: NC asks one member where it is, and the member answers with its position, encrypted and authenticated under their pair keys (7.7) |

## 4. Switches, files and size

| Item | Value |
|---|---|
| Switch | `CONFIG_OTAR`, on where `CONFIG_DMR_AES` and `CONFIG_KEY_FILL` are |
| Protocol | `core/otar/otar.{h,c}`: building, checking and opening messages; AES-KW and AES-CMAC over the AES-256 in `dmrAes.c`, which gains AES decryption for unwrapping (about 1 KB; it only encrypts today). Pure: no RTOS, no allocation |
| Service | `core/otar/otar_svc.c`: UDP port 4103, NC's rekey run, member answers, the changeover timer |
| Keys in use | `core/radio/radio_aes.c`: the active, next and previous keysets for an OTAR system; `DMR_AES_KEY_SLOTS` 1 to 3 |
| UI | Tools > Net keys (12), Settings > Privacy rows |
| Tests | `tests/host/otarCryptoTest.c` with the RFC 3394 and NIST SP 800-38B AES-256 test vectors, `otarEngineTest.c` (the engine's rules), `uiFlowTest` flows `O ...` |

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
| 1 | Version 4 (3: ACK without the echo; 2: HELLO with key IDs, TIME to the talkgroup; 1: the body in the clear, under the channel's key only) |
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
| 2 | ACK | member to NC; NC to member, answering its HELLO | Individual, confirmed | keyset number (4), CKR (1), result (1), check value (3), the message number of the message it answers (4) | the pair's K_mac |
| 3 | CHANGEOVER | NC to the talkgroup | Group, 3 copies 2 s apart | keyset number (4), KID (1) | from the next keyset (7.3) |
| 4 | HELLO | member to its best-ranked NC | Individual, confirmed | active keyset number (4), next keyset number (4, 0 none), flags (1) | the pair's K_mac |
| 5 | INVENTORY | NC to a member | Individual, confirmed | none: the member answers an ACK for each TEK it holds | the pair's K_mac |
| 6 | ROSTER | NC to a member | Individual, confirmed | DMR ID (3), rank (1), flags (1: revoked), public key (32) | the pair's K_mac |
| 7 | TIME | NC to each member in turn | Individual, confirmed | UTC seconds (4) | the pair's K_mac |
| 8 | ZEROIZE | NC to a member | Individual, confirmed | the member's DMR ID (3) | the pair's K_mac |
| 9 | TAKEOVER | NC to the talkgroup (reserved, not built: 22) | Group | DMR ID of the NC it replaces (3), the keyset number it will rekey to (4) | from the active keyset; each member then gets a ROSTER (10) |
| 10 | LOCATE | NC to a member | Individual, confirmed | none: the member answers POSITION (7.7) | the pair's K_mac |
| 11 | POSITION | member to the NC that asked | Individual, confirmed | the LOCATE's message number (4), result (1), latitude and longitude in 1e-7 degree (4 + 4, signed), altitude in meters (2, signed; 0x8000 unknown), the fix's age in seconds (2, at most 65535) | the pair's K_mac |
| 12 | NETCHAN | NC to a member | Individual, confirmed | the net's channel (7.8): receive and transmit frequencies in Hz (4 + 4), color code and timeslot (1), name (16) | the pair's K_mac |
| 13 | WITHDRAW | NC to a member | Individual, confirmed | keyset number (4), KID (1): the next keyset to drop (7.9) | the pair's K_mac |
| 14 | SILENCE | NC to a member | Individual, confirmed | on (1): 1 radio silence on, 0 off (7.11) | the pair's K_mac |
| 15 | WIPE | NC to a member | Individual, confirmed | the member's DMR ID (3): wipe the whole radio (7.10) | the pair's K_mac |

A receiver drops and counts, and doesn't show, a message of another length, version or net, from a sender not on the
roster or revoked, with a message number not above the last one taken from that sender, or whose MAC doesn't check
(compared in constant time). Nothing is ever sent in answer to a bad MAC. A message whose MAC checks but whose number
is old isn't acted on either; a member answers that one, at most once every few minutes, "old message number" (7.6).

### 7.1 REKEY

The TEK is wrapped with AES-256 key wrap (RFC 3394) under the pair's UKEK: 32 octets in, 40 out, its integrity check
included. One TEK per message; a keyset of 4 TEKs is 4 messages. The member takes a REKEY only for a keyset number above
its active one and not below its next one, stores the TEK in its next keyset under the net's keyset number (not a count
of its own), then ACKs with the check value ([key-check.md](key-check.md)) of what it stored. A REKEY for a TEK it
already holds, same keyset, key ID and check value, is ACKed again (NC's retry); the same keyset and key ID with
another key is refused. So no NC can move a member back to an older keyset. A keyset more than 8 above the active
one, above 65535, or a key ID the active or previous keyset uses is refused too: one sender can't park the net on a
number the others never reach, or overwrite the key in use. The exception is the catch-up (9): a REKEY flagged now
from the member's best-ranked net control is the net's own keyset, taken however far above the active one (never above
65535), so a radio off through many rekeys, or cleared and joined again, catches up (23.4). A REKEY flagged now for the
keyset the member holds as its next (it missed a changeover by hand) is HELD and changes it over.

Changeover time: whole UTC minutes since 2026-01-01; 0 = on NC's CHANGEOVER only. Flags: bit 0 change over at the
changeover time by the member's clock; bit 1 the net's active key, which the member changes over to as soon as it is
stored (a member that joined after the rekey or missed the changeover, 9); bit 2, with bit 1, drop the keyset changed
over from at once and erase its key, with no overlap (a silent revoke, 7.12).

### 7.2 ACK results

| Result | Meaning | Answers |
|---|---|---|
| 0 | stored | REKEY, ROSTER |
| 1 | already held (a resend, or INVENTORY's "I hold this keyset") | REKEY, ROSTER, INVENTORY |
| 2 | older keyset refused | REKEY |
| 3 | couldn't store | REKEY, ROSTER |
| 4 | wrap check failed | REKEY |
| 5 | not managed: the radio manages no keys | REKEY, INVENTORY, HELLO (from NC) |
| 6 | refused | REKEY, ROSTER, ZEROIZE |
| 7 | asked: the user is asked first (a take over, 10) | ROSTER |
| 8 | wiped: taken, the wipe follows this ACK (7.5) | ZEROIZE |
| 9 | up to date: NC has nothing to send; keyset is NC's active one (9) | HELLO (from NC) |
| 10 | old message number: keyset carries the last number taken from that sender (7.6) | REKEY, ROSTER, INVENTORY, ZEROIZE, TIME |
| 11 | dropped: the next keyset named isn't held (7.9) | WITHDRAW |
| 12 | silent: radio silence on once this ACK has gone (7.11) | SILENCE |
| 13 | speaking: radio silence off (7.11) | SILENCE |

Results 8-10 have CKR 0 and came without a new protocol version: a version 4 radio from before ignores an ACK it isn't
waiting for, and counts one it waits for with CKR 0 and an unknown result as a roster entry not taken. Mixed nets keep
working during an update; the older radios just don't answer ZEROIZE, HELLO or an old number the new way. A new
version would have cut such a net in two (any other version is dropped), so the version stays 4.

Each ACK echoes the message number of the REKEY, ROSTER, INVENTORY, ZEROIZE or HELLO it answers, and the NC counts it only for the
message it sent last to that member (and a REKEY's only with the sent key's check value). A recorded ACK of an earlier
message doesn't count. A radio never sends a message numbered 0 (no saved reservation yet, 7.6): its answer waits for
the sender's retry.

### 7.3 Group message keys

A group message can't use a pair's key, so its MAC key comes from a keyset:
`HKDF-Expand(HKDF-Extract("RFOTAR1 group", the keyset's CKR 1 TEK), label, 32)` with the label "co" for CHANGEOVER
(the next keyset), the only group message. HELLO and TIME went to the talkgroup under such keys once; both are now
individual, under the pair's keys (7.4). A revoked radio never gets the next keyset, so it can't make a
CHANGEOVER; a member can, but all it can do with that is bring the changeover forward.

### 7.4 Clocks and TIME

A member's clock, in order: GPS; the RTC where the board keeps it through power-off (`board.toml` `clock` = "backed",
[feature-matrix.md](../feature-matrix.md)); a time set by hand; TIME. TIME only sets a clock that has none of the others, and moves it at
most 48 hours. A radio with no clock waits for CHANGEOVER.

TIME goes to each member on its own, under the pair's keys, and is checked against that net control's message numbers.
It went to the talkgroup under a key from the active TEK until an independent review (2026-11-24) found that any radio
holding the TEK, a lost one included, could forge it: with the net control's ID and the highest message number it
moved every member's counter for that net control to the top, after which every REKEY, ROSTER and ZEROIZE from it was
refused as old, so the lost radio could stop the very rekey meant to shut it out (23).

### 7.5 ROSTER and ZEROIZE

ROSTER adds a member, changes a rank or a public key, or revokes. Revoking an NC of higher rank than the sender asks
the member's user first (10). A radio told it is revoked shows "Removed from the net".

ZEROIZE is taken only when the member's Net > **Remote wipe** is On. It is On by default, and set On again whenever
the radio joins or starts a net, so a radio updated from an older build gets it at its next join; the radio's user can
turn it Off. The reason: a net control is already trusted to rekey every member, and every other remote control
(REKEY, CHANGEOVER, TIME, INVENTORY, ROSTER) is always taken from it, so it is trusted to wipe a lost radio too. A
compromised net control is answered by revoking it (10), not by leaving every radio unwipeable; an owner who doesn't
want it opts out. The
member wipes its keys only ([zeroize.md](zeroize.md) 3.2). Net > **Share location** (7.7), which lets a net control ask where the radio is, is set the same way: On by default, On again at each join or start, Off by the user's choice.

It answers first, so NC learns the wipe happened: on a ZEROIZE it takes (MAC, fresh message number, its own ID) it
builds an ACK with result 8 (wiped), under the pair keys, echoing the ZEROIZE. From then the engine holds nothing secret
outside the flash: the pair keys, a TEK being stored and a rekey run's key are wiped in RAM, and the only thing kept is
the ACK's ciphertext. It takes and sends nothing else. Once the transport has let the ACK go (sent or failed, at most
10 s), or after 60 s whatever happens, the wipe starts. "Wiped" thus means "taken, wiping": a radio switched off in
those few seconds keeps its keys, as it would after an emergency wipe cut short. With Remote wipe Off, or from a
net control that doesn't rank above it, the member answers 6 (refused) and wipes nothing.

NC tries a ZEROIZE up to 3 times, 20 s apart, and stops at the answer. The member screen shows "Wipe: sending", "wiped",
"refused" or "no answer". No answer doesn't prove the radio kept its keys: it may be off, out of range, or wiped with
its answer lost. A net control is wiped only by one of
a better rank: NC 4 can't wipe NC 1 (the sender's menu refuses it too).

### 7.6 Body encryption

Each message's body is encrypted with AES-256 in counter mode (NIST SP 800-38A 6.5), then the MAC is taken over the
header and the ciphertext; a receiver checks the MAC first and decrypts only a message that passes.

| Item | Value |
|---|---|
| Key | K_enc = HKDF-Expand(the message's MAC key as the PRK, "RFOTAR2 enc", 32) (RFC 5869 2.3). Between two radios: from the pair's K_mac (5). A group message: from its group MAC key (7.3), so CHANGEOVER's comes from the next TEK and TIME's from the active one |
| Counter block | The sender's DMR ID (3), the receiver's (3; the talkgroup for a group message), the type (1), the message number (4), the sender's rank (1), then a 32-bit block counter from 0 |
| Uniqueness | A sender's message numbers only go up, so no counter block repeats under one key. They are reserved 64 at a time: `settings_t.otar_msgnum` holds the end of the reservation, saved at once (`settings_end_soon`), and a number is used only once the flash holds a reservation above it (`settings_u32_is_saved`), as the voice MI's. After a restart numbering goes on past the saved end, whatever was unsaved when the power went. Until a reservation is saved nothing is sent; a reply built meanwhile carries number 0, which every receiver refuses, and is tried again |
| Length | Unchanged: counter mode adds nothing, and the header carries the counter block's parts |
| In the clear | The header: type, net ID, message number, the sender's rank. The data header shows the DMR IDs anyway |

A REKEY's TEK is wrapped under the UKEK inside the encrypted body: two layers, as P25's KMM (23).

Replay state: a member keeps the last message number taken from each net control in four counters, each marked with
the DMR ID it belongs to (`settings_t.otar_seen_id`). A sender not yet counted takes a free counter, or one whose
owner is no longer a net control here. Joining, starting or leaving a net clears them, safely, because the radio then
has a new key pair: Start and Join make one, Leave wipes it.

Design rule: a group message never moves a counter that guards individual messages. A key that many radios hold (a
TEK, and so any group key from it) can be used by any of them to forge a group message; if such a message could raise
the counter that individual REKEY, ROSTER and ZEROIZE are checked against, one holder could lock a net control out of
every member (found and fixed 2026-11-24, 23.1). Today CHANGEOVER, the only group message, isn't checked against a
counter at all (an old one fails under another keyset's key). If a group message ever needs replay numbers, it gets a
counter of its own per sender, apart from the individual one. P25 keeps separate numbers per kind of destination for
the same reason.

**Old message number.** A message whose MAC checks under the pair keys but whose number isn't above the last taken from
its sender is not acted on. The member answers it with an ACK, result 10, whose keyset field carries the last number it
took from that sender and whose echo is the old message's number, at most once every 5 minutes per sender counter
(RAM only: a restart may send one more). The legitimate case is a net control whose own numbers went back (its
settings restored from an earlier copy): until now its members dropped it in silence, for good. NC takes the answer
only for a message it is waiting on (a rekey run's REKEY, a ROSTER, an INVENTORY, a ZEROIZE), from that member, echoing
that message's number. It then moves its own next number past the member's, if that is at most 65536 ahead, and sends
again at once; numbers only need to be unique and rising, so skipping some is always safe. Further ahead, the member
shows "Out of sync: rejoin" (a rejoin makes a new key pair, so counting starts again) and "out of sync" in Net
status, and the run doesn't try it again. The skip is capped so even a member with valid pair keys can't use up NC's
32-bit numbers.

Can this answer be abused? Only a message whose MAC checks gets it, so an outsider needs a recording of a real message
from a net control to this radio under the present key pair. Playing it back makes the member transmit one short ACK
at most once every 5 minutes per net control, up to four, whatever the rate of the replay: bounded, and less than the
HELLO retries a member sends on its own. The answer is encrypted and says nothing a listener can use: the message
numbers in the headers are in the clear anyway. It confirms the radio is on and in range, which its own traffic shows
too. A forged message (bad MAC) still gets no answer at all, so an attacker without a recording can't make the radio
transmit, and each forged message still costs at most the X25519 the receiver already pays for any message. The
counter isn't moved by an old number, and NC moves its own counter only forward, on an authenticated answer echoing a
message it sent. One case it doesn't fix: a net control restored from an old copy reuses its numbers, so the first
message after the restore to each member may repeat a counter block under that pair's key (its keystream) before the
member's answer comes. Its body is mostly a wrapped key or public data, but avoiding that needs a restored radio to
make a new key pair, left for later.

### 7.7 LOCATE and POSITION

A net control asks one member where it is: Net > Members > OK on a radio > 5 Get location. LOCATE (type 10, 18
octets, no body) goes under the pair's MAC key; the member answers POSITION (type 11, 35 octets) under the same pair
keys, so its position is encrypted (7.6) and authenticated like every other body: a listener sees only that a short
message went from the member to that net control.

The member takes a LOCATE only from a net control on its roster, not revoked, with a fresh message number (7.6), as it
takes INVENTORY and ZEROIZE; a radio that is only a member can't ask, and one that merely holds the traffic key can't
forge it. Its answer echoes the LOCATE's message number and carries a result:

| Result | Meaning |
|---|---|
| 0 | position: latitude, longitude, altitude (0x8000 when not known) and how old the fix is |
| 1 | no fix: the radio has no position now |
| 2 | refused: its Share location is Off |

The position is the one an LRRP answer would carry ([dmr-data.md](dmr-data.md)): the position service's (the board
GPS, a host feeding NMEA, or the fixed position, by the Position source setting), with the ambiguity setting applied.
A fixed position counts as a position, its age 0.

Net > **Share location** on the member, under Remote wipe: On by default, and set On again whenever the radio joins
or starts a net (`settings_t.otar_loc_off`, 0 = share, so a radio already in a net when it updates shares too), for the reason 7.5 gives for Remote wipe: a net control is trusted with
far more than this already. The radio's user can turn it Off; the net control then sees "refused" rather than silence.

Limits: a member answers one net control at most once every 10 s, whatever arrives; a LOCATE played back has an old
number and gets at most the rate-limited "old message number" (7.6), never a POSITION. Under radio silence
([radio-silence.md](radio-silence.md)) the member doesn't answer at all: where the radio is, said by itself, is the
last thing a radio that keeps quiet should send. The net control sees "no answer".

NC side: one LOCATE in flight at a time, tried up to 3 times 20 s apart until the POSITION echoing its last try comes;
it checks the POSITION only when it waits for one from that radio (the X25519 a MAC needs isn't spent on others). A
second Get location while one is asking says "Still asking". The answer shows on a screen of its own (the member
screen's body has room for two lines on a 128x64 display) and under the member screen's other lines once back:
"Location: asking", "no fix", "refused", "no answer", or "Location: -33.86885, 151.20930" (5 decimals) and below it the
distance and compass point from this radio's own position when it has one ("850 m NE", "1.2 km NE") with the fix's age
("40s ago", counting on while shown), or the age alone.

A radio from before LOCATE drops type 10 unread (an unknown type, `otar_peek`), so asking it ends in "no answer".
The protocol version stays 4, as for the ACK results of 7.2.

### 7.8 The net's channel (NETCHAN)

A net has no channel of its own: its messages go on whatever channel each radio is on, so a member tuned elsewhere
hears none of them and keeps asking for keys where nobody listens (found on the bench, 2026-11-26: a member on a
repeater channel said HELLO for minutes while net control 1 listened on the simplex channel, and nothing told its user
why; moved over, it had its keys in seconds). The net therefore has a channel that each radio knows, and the Net screen
says when the radio is away from it. The radios don't go there by themselves (not built; later).

**What it is.** Receive and transmit frequencies, color code and timeslot, and the channel's name for the screen
(`otar_chan_t`, in the settings record: [settings-store.md](settings-store.md) 3). It is described by those, not by a
channel number, because radios in a net don't always share a codeplug: a radio is on the net's channel when it is on
DMR with the same frequencies, color code and timeslot, whatever its channel is called there. The talkgroup isn't part
of it: the messages to one radio don't use one. The name is the net control's, so the screen says what its user calls it.

**Where it comes from.** A radio that starts a net, or joins one, takes the channel it is on (none when it isn't on
DMR). Net control 1 then sets the net's: Net > **Net channel**, on the channel wanted, asks "Make AES TEST the net's
channel? Every member is told" and on OK stores it and sends NETCHAN (type 12, 43 octets) to every member not revoked,
one at a time, each waiting for its ACK (CKR 0, result 0 stored) and tried up to 3 times, as the roster's entries are
(7.5); the Net screen counts "Channel: sending, 2 sent, no answer 1". It goes out again:

- after the entries of every Send the roster, and of Add a member's run to the new member, so a radio joined later
  learns it;
- after every HELLO net control 1 answers (9), once, its ACK not waited for: a member that was off when it changed
  learns it at its next start, on the net's channel.

**Who sets it.** A member takes NETCHAN only from the authority (10: the best-ranked net control not revoked, net
control 1 until a take over), with a fresh message number under the pair keys (7.6), and answers a backup net
control's with result 6 (refused), changing nothing: as with ranks, a backup net control can't move where its members
think the net is. On the net control's side the row says "Only net control 1 sets it". A member's Net channel row
shows it and says "Set by the net control".

**On the screen.** Net > Net channel shows its name (its frequency when it has none, "None" before one). Tuned away
from it, the Net screen says "The net is on AES TEST" under the net's name, above "Asking for keys", on a member and on
a net control alike. Leave the net clears it.

A radio from before NETCHAN drops type 12 unread (`otar_peek`): its net control sees "no answer" for it and nothing
else changes. The protocol version stays 4.

### 7.9 Moving or cancelling a planned change (WITHDRAW)

A rekey sends the next keyset ahead of its changeover (7.1), so a net control can change its mind before the key goes
live: a changeover set for the wrong time, or a key that shouldn't be used at all (made in a hurry, or the radio that
made it lost). Without a way back, the only fix was another rekey on top and a changeover at a time nobody planned.

**Move the change.** While a rekey run has its key made, the net control's Net screen shows Move the change and Cancel
the change after Send the roster (rows 8 and 9: Change over the net stays 6). It takes the Key change row's choice (by hand, in 5 min, 1 h, 6 h, 24 h, counted from now) and asks "Key 90:
change over in 1 h? Every member is told". On OK the net control's own next keyset takes the new changeover,
every member is marked waiting again and is sent the REKEY again (a new message number, the same keyset, key ID and
key, the new changeover and its flag), and TIME goes out first when it is by the clocks, as at a rekey (7.4). A member
that holds that keyset as its next, with the same key ID and key (its check value), answers HELD as before and now also
takes the changeover from it; a different key under that number is still refused (7.1). Net status counts them again,
"Key 90: 2 of 3 have it".

**Cancel the change.** Cancel the change asks "Key 90: cancel it? Every member drops it". On OK the net
control drops its own next keyset and erases its key from the codeplug (the radio task's `RADIO_OTAR_DROP_NEXT`: only
the next keyset named by that key ID, never the active or previous one), wipes the key from the run, keeps the keyset's
number and key ID in its settings (`otar_cut`, [settings-store.md](settings-store.md)), and turns the run into a cancel
run: each member is sent WITHDRAW (type 13, 23 octets: keyset number and key ID, under the pair keys, its body
encrypted) in turn, waiting for the ACK and trying again after a minute, as REKEY is. Net status shows "Key 90
cancelled: 1 of 2 dropped it".

A member takes WITHDRAW only from a net control on its roster, not revoked, with a fresh message number (7.6), and
answers with an ACK (CKR 1, the keyset's number, echoing the WITHDRAW):

| The member holds | It does | ACK result |
|---|---|---|
| That keyset as its next, under that key ID | Drops it and erases its key (`RADIO_OTAR_DROP_NEXT`) | 11 dropped |
| That keyset as its next, under another key ID | Nothing (another net control's key) | 6 refused |
| That keyset as its active one | Nothing: it changed over already, too late | 2 old |
| Neither (never got it, or dropped it already) | Nothing | 11 dropped |

The net control counts "dropped" as done; "old" shows the member out of sync and isn't tried again (it changed over
alone: it is back with the net at the next rekey's catch-up, which takes a number above it, below). The cancel run ends
once every member is done, or after 10 minutes. A member that was off meanwhile is told when it comes back: its HELLO
carries its next keyset (9), and a net control that withdrew that number (and isn't above it yet) answers with WITHDRAW
before anything else. That works after the net control's restart too, the number being in its settings.

**The next rekey.** The withdrawn number is never used again for another key: a member that missed the WITHDRAW still
holds it with the old key and would refuse a different one under it. Rekey now numbers its keyset above it (the step
limit of 7.1 still applies) and tells its own radio that number (`RADIO_OTAR_NEXT_KS`). A member holding the withdrawn
keyset takes the new one as its next in its place. Rekey now during a cancel run ends the run: the new keyset reaches
the members still holding the withdrawn one. Change over the net sends CHANGEOVER for the next keyset's own number.
Leaving, starting or joining a net forgets the withdrawn number.

A radio from before WITHDRAW drops type 13 unread (`otar_peek`): its net control sees "no answer" for it, and the
radio keeps the withdrawn keyset until the next rekey replaces it. It does take a moved changeover's REKEY, answering
HELD, but keeps its old changeover. The protocol version stays 4.

### 7.10 Wiping the whole radio (WIPE)

Net > Members > a member > **Wipe the radio** (asks first: "Wipe the whole radio? Keys and channels"). WIPE is ZEROIZE's
message under a type of its own, and takes ZEROIZE's path in every other way (7.5): only with the member's Remote wipe
on, only from a net control that ranks above it, WIPED answered first and the wipe after it (or a minute on), REFUSED
otherwise, 3 tries 20 s apart, the member screen showing "Radio wipe: sending, wiped, refused, no answer". The
member wipes its keys and its codeplug: the emergency wipe's Keys + codeplug scope ([zeroize.md](zeroize.md) 4),
whatever its own Wipe what says, then restarts on the built-in channels.

A type of its own, not a scope octet in ZEROIZE: a radio from before drops type 15 unread (its net control sees "no
answer"), and keeps taking ZEROIZE as it did. A wipe of the keys can't be read as a wipe of the radio, or the other way
round, by a radio of another build. The protocol version stays 4.

### 7.11 Radio silence from the net control (SILENCE)

Net > Members > a member > **Radio silence** turns that member's radio silence ([radio-silence.md](radio-silence.md))
on, or off when the last answer was on. It is taken only when the member's Net > **Remote silence** is On (the
default, set On again at each join or start, Off by the user's choice, as Remote wipe: the user's rule for remote
controls) and from a net control that ranks above it; otherwise REFUSED.

- **On:** the member answers SILENT first, then turns silence on once the transport has let the ACK go (or a minute
  on): nothing is answered under silence (radio-silence.md 3). The silence is saved as the user's own is, and marked
  as the net control's (settings `otar_sil`).
- **Off:** only a silence a net control turned on ends here, then SPEAKING. The user's own silence stays, and the
  radio can't answer under it: the net control sees "no answer". A silence the net control turned on that the user
  turned off is the user's from then on.
- **Already silent:** no answer, as under any silence. The net control shows "no answer"; it can't tell a silent
  radio from one that is off.

The member's user can always turn silence off themselves. The net control's screen shows "Silence: sending, On, Off,
refused, no answer". A radio from before drops type 14 unread.

### 7.12 Silent revoke

Net > Members > a member > **Silent revoke** (asks first: "Silent revoke? It isn't told. Can't be undone") takes a
radio out of the net without telling it:

1. The net control makes a throwaway key from the randomness pool and never stores it (with the pool short, as after a
   key fill, the receiver's noise is gathered first, as for a rekey's key). It sends it to that member
   alone as a REKEY flagged now and drop (7.1): a keyset number above every number of the net's (its active, its next
   and a withdrawn one), a key ID none of the net's keysets uses (a new one each try).
2. The member stores it, changes over to it at once and erases the key it held: no overlap. It answers STORED as for
   any REKEY. From then it can neither hear nor be heard on the net, and its screen shows nothing new.
3. The net control revokes it on its roster and the net's (a ROSTER to every other member), but sends the radio
   itself no ROSTER: it never shows "Removed from the net". Its HELLOs are dropped (a revoked sender), and no later
   rekey reaches it.

Tried 3 times 20 s apart. With no answer (off, out of range, or lost) the radio is revoked all the same, and the
screen says "Revoked, no key taken: rekey now": only a rekey of the net locks out a radio that still holds the key.
A rekey is also the answer when the radio's key may have been copied before the revoke. Nothing else runs meanwhile
(Revoke, Rekey now and the roster wait). Silent only in that the radio isn't told: its user will notice that the net
went quiet.

## 8. Keys in use

On an OTAR system a channel names a CKR, not a key ID. The radio transmits with the active keyset's TEK for that CKR
and its KID. It receives with the active, next and, for 30 minutes after a changeover, the previous keyset, chosen by
the KID in the over's PI header or late-entry signaling. After those 30 minutes the previous TEKs are wiped: a radio
captured later can't read traffic from before the last changeover.

KIDs: NC picks them: the first free key ID after the one in use, so consecutive keysets never share one.

As built, a keyset holds one TEK, CKR 1: a rekey sends CKR 1 only and INVENTORY answers for CKR 1. The format and the
keysets carry CKR 1-4, so CKR 2-4 can come without a format change.

## 9. Net control

**Net status** (NC only): a row per member, "4670501 OK 7", "4670502 waiting", "4670511 revoked", and "18 of 20 have
keyset 7". OK on a row: inventory, resend, revoke, or (if that radio allows it) zeroize. A member that answered a
REKEY without taking the key (refused, an older keyset, keys not managed, another key's check value) shows "refused",
one whose ACK didn't come "no answer"; both are tried again after a minute. Found on the bench 2026-11-27: a member
that answered each REKEY showed "no answer", and nothing told the two apart.

**Rekey:** by hand (Rekey now) or on a schedule (every 1, 7 or 30 days). NC fills the pool, generates the TEKs, takes
the changeover time (in 5 min, 1 h, 6 h, 24 h, at a time, or on command), then sends REKEY to every member one at a time. It
retries unanswered members every 60 s until the changeover, in the background while NC stays on the net's
channel. A HELLO from a member that hasn't the run's key gets its REKEY at once. At the changeover time NC sends
CHANGEOVER.
Outside a rekey run, a HELLO whose active keyset number is below NC's gets NC's active key as a REKEY with flag bit 1: a member that
just joined, or that was off through a changeover, catches up and changes over to it at once. Its old key stays as the
overlap ([key-fill.md](key-fill.md)) as after any changeover.

**Rekey request (HELLO).** A member asks for keys 20 s after it starts or joins, and with Net > Request keys. NC answers
every HELLO it works on: with the run's REKEY or the catch-up REKEY as above, or else with an ACK, result 9 (up to
date, its own active keyset) or 5 (it manages no keys). A member behind while a run is going, holding the run's key,
gets nothing yet; it asks again and catches up after the run. Unanswered, the member asks again after 1 minute, 5
minutes, 15 minutes and then every 15 minutes, until NC's ACK echoing its last HELLO, or a REKEY from that NC, comes. So
a member that came on while NC was off or out of range catches up when NC is back, without a restart, and a net
whose NC stays away costs the channel one short message per member every quarter of an hour. Its Net screen shows
"Asking for keys", "Keys up to date" or "Keys received".

NC doesn't check members' message numbers (19), so a recorded HELLO played back is valid. NC therefore works on at most
one HELLO every 2 s and answers each member at most once every 2 minutes, keeping the last 8 answered: at most 8
answers in any 2 minutes, however many recordings are played in turn. A HELLO newer than the one NC last answered from
that member (a higher message number, its MAC checked) is answered at once even within the 2 minutes: the member said
it again because the answer was lost (it restarted, or was off air; found on the bench, where a member restarted during
the answer waited 5 minutes for its next retry). A recording is never newer than what it recorded, so the bound above
holds. A genuine HELLO caught by the limit is asked again by its member's next retry. P25 has the same pair: a radio's rekey request answered either by keys or by "nothing
for you", and resynchronization of a radio's keys (23); P25's "warm start" is something else (a temporary key for a
radio that can't decrypt management messages), which the pair keys make unnecessary here.

## 10. Succession

Every NC on the roster can rekey and change the roster. Two rekeys at once: a member keeps the higher keyset number;
for the same number, the one it took first (the same key ID with another key is refused).

Ranks: a ROSTER entry is refused when it ranks a radio above its sender, when it changes the sender's own entry, or
when it gives or changes a rank, adds a radio or changes a public key and its sender isn't the authority: the
best-ranked NC not revoked on the receiving radio's roster (NC 1 until a take over). Any NC may revoke a member; nobody
un-revokes over the air (a radio revoked joins again). So a backup NC can't make itself or another radio NC 1, revoke
the real one without the question below, bring back a revoked radio, add radios of its own, or swap a member's key so
the authority's REKEYs go to someone else.

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
| A net control wiping radios | Remote wipe is on by default in a net (7.5): an NC is trusted with every member's keys already, so with their wipe too. A lost or captured NC could wipe the members until it is revoked (10), which it could make unable to talk by a rekey all the same. Only a better-ranked NC wipes an NC. A radio's owner can turn it off |
| A captured NC's database | There is none: an NC holds only its own private key. It can rekey until revoked, but can't impersonate other members to each other |
| A forged REKEY, ROSTER or ZEROIZE | Needs the pair's K_mac, which only that NC and that member can derive |
| A forged CHANGEOVER | Needs the next keyset, which a radio left out of the rekey doesn't have; a revoked sender is refused |
| A forged TIME | Needs the pair's K_mac (7.4): holding the traffic key isn't enough |
| Tracking a member | Only a net control of its roster can ask where it is (LOCATE, 7.7), under the pair keys; the answer is encrypted to that net control. A replay gets no position, a member answers one net control at most every 10 s, and never under radio silence. Its owner can turn Share location off |
| Replay | Message numbers per sender, kept by the sender's DMR ID (7.6), and keyset numbers only go up (7.1). A radio makes a new key pair for each net it joins or starts and Leave wipes it, so a message recorded before a rejoin doesn't check under the new pair keys |
| A backup NC raising its rank | Refused by the members (10) |
| A radio in the middle of a join | The six-digit code ([key-fill.md](key-fill.md) 4): the sender's fresh nonce is committed before the other radio answers, so even with long-lived public keys the code can't be steered (1 in a million) |
| Past traffic from a captured radio | Previous TEKs are wiped 30 minutes after a changeover. Traffic since the last changeover isn't protected from that radio |
| Keys in flash | No secure element: anyone who opens a radio can read its flash ([settings-store.md](settings-store.md) 3.1). The emergency wipe and remote zeroize are the answers |
| Weak randomness | The pool's credit comes from key press timing ([key-fill.md](key-fill.md) 6); a hardware noise source would strengthen every key |
| Jamming | Nothing; a member that missed a rekey keeps its keys and asks again with HELLO |

## 12. Radio UI

| Where | Rows |
|---|---|
| Net (member) | Members, Request keys (HELLO, 9; the status line under it), Remote wipe, Share location (7.7), Net channel (7.8), Leave the net |
| Tools > Net keys (NC adds) | Net status, Rekey now, Rekey schedule, Change over now, Add a member, Revoke a member, Take over, Send time |
| Net | Remote wipe: On (default in a net) / Off; Share location the same (7.7) |
| Settings > Privacy | Clock source |
| Home | The AES256 badge as today; the KID on the chips line |

As built, Change over the net and Leave the net ask first: only OK says yes, Back says no, a digit never does. Change
over names the key and how many members hold it, and warns that the others can't hear the net (23.3).

## 13. Storage

| What | Where | Size |
|---|---|---|
| Radio private key | Its own flash record, never the codeplug or a file; erased by the emergency wipe | 32 B |
| Net ID, rank, own public key | Settings record | about 40 B |
| Roster | Codeplug records (public) | 40 B per member, up to 64 |
| Keysets | Traffic key records of the OTAR system, plus a record with keyset numbers, changeover time and state | 32 B per TEK + 16 B |
| Message numbers | Settings record: own, and the last taken from each NC | 20 B |
| The net's channel (7.8) | Settings record | 28 B |

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
2. Remote zeroize: in, on by default in a net, each radio may opt out (decided 2026-11-26, 7.5).
3. Grace time after a changeover: 30 minutes proposed.
4. Members change over by their own clock by default when they have GPS or a kept RTC: proposed yes.
5. Upstream: propose it to RadioFoundry as an issue first, since it goes beyond ETSI and DMRA.

## 16. Tests

`otarCryptoTest`: AES-256 decryption against FIPS-197 C.3, AES-KW against RFC 3394 4.6 (a 256-bit key wrapped under a 256-bit KEK), AES-256-CMAC against the NIST SP 800-38B examples; UKEKs agree both ways and differ
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
| Net control | Net > Rekey now: random key presses, then a new TEK under the first free key ID after the one in use, stored in the managed system and made this radio's next keyset; the changeover by Net > Key change (in 5 min, 1 h, 6 h, 24 h, or by hand; 5 min first), by hand when the radio has no clock. A member's Net menu is Members and Leave the net. Then REKEY to each roster member in turn: an ACK within 20 s, else "no answer" and again after 60 s; a member's HELLO brings its REKEY at once. Net status lists each member (waiting, sent, OK, no answer, refused) and "Key 34: 1 of 2 have it". Net > Change over the net: CHANGEOVER to the talkgroup, then this radio's own changeover. The run ends when this radio has changed over |
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
| Remote wipe | Net > Remote wipe: On (the default, and set again at each join or start, 7.5) or Off, per radio (`settings_t.otar_wipe`). ZEROIZE (type 8, 21 octets: the target's DMR ID, under the pair's MAC key) from a net control on the roster, not revoked, with a fresh message number and this radio's ID wipes its keys as Clear all keys does ([zeroize.md](zeroize.md)) and restarts, after its ACK "wiped" has gone (7.5). With Remote wipe off it is answered "refused". A net control sends it with 3 Wipe its keys on a member, up to 3 times until answered |
| Member screen | Net > Members > OK on a radio (a net control only): 1 Rank, 2 Revoke, 3 Wipe its keys, and the radio's ID and fingerprint (later 4 Ask its keys, 22, and 5 Get location, 25). Members shows "revoked" after a revoked radio's ID |

Checked on air 2026-11-23/24 with three radios: net control 1 made 4678512 net control 2, which wiped net control 1's
keys remotely, took over (the member asked first: "NC 2 says NC 1 is lost", then Accept), rekeyed to key 38 leaving
the revoked radio out ("Key 38: 1 of 1 have it"), and changed the net over: both calls AES-256 under key ID 0x26.

## 22. The rest of 7 and 9 (as built)

| Part | What it does |
|---|---|
| Rekey schedule | Net > Rekey every: Off (default), 1 day, 7 days, 30 days, on each net control (`settings_t.otar_sched` and `otar_sched_at`, [settings-store.md](settings-store.md)); it needs a clock. The Net screen shows "Next rekey: 2026-11-30 14:05". When it is due and no rekey, roster run or next key is under way, the net control starts a rekey whose changeover is 60 minutes later by the clocks, and sets the next one. Its key is made when the pool is full: the radio's own key presses fill it, as for Rekey now |
| CHANGEOVER at the changeover | A rekey run that changes over by the clocks ends with the net control's own changeover; it then sends CHANGEOVER (3 copies) for members without a clock. Not after Change over the net, which sent its own |
| TIME | Type 7 (22 octets: UTC seconds since 2026-01-01) to each member in turn, under the pair's keys (7.4; it went to the talkgroup under a group key before 23.1). Net > Send the time, and at the start of every rekey that changes over by the clocks. Sent only from a clock that isn't the net's (GPS, the board's clock, or set by hand). A member takes it from a net control on its roster, not revoked, with a fresh message number, and the radio task keeps it only when the radio has no clock or only the net's (clock source "net"), moving that one at most 48 hours (7.4). It isn't written to the board's clock |
| INVENTORY | Type 5 (18 octets, no body) from a net control: Net > Members > OK on a radio > 4 Ask its keys. The member answers an ACK (result 1, CKR 1) for its active keyset and one for its next, each with that key's check value; never a key. The member screen shows "Keys: keyset 7 OK, keyset 8 OK" (the key matches this radio's of that keyset), "differs", "asking" or "no answer" |
| Removed from the net | Revoke now tells the revoked radio too: its own entry, revoked. It takes it from a net control above its own rank (any net control, for a member), stores it, ACKs, and its Net screen shows "Removed from the net"; it says no HELLO after that. Leave the net clears it. A take over still doesn't tell the lost net control |
| Joining after a rekey | Key fill goes in the clear on the AES channel ([dmr-data.md](dmr-data.md) 13.5), so a radio whose codeplug holds only an older key can still join. Found on air: before, the joining radio dropped the net control's key fill under the new key and the join failed. The join itself carries no key: on air the joined radio stayed on its old key, its HELLO and the net control's REKEYs each dropped under the other's channel key. Section 23 fixes that |
| TAKEOVER | Not built: the ROSTER each member gets (21) carries it and is answered member by member, which a group message wouldn't be. Type 9 stays reserved |
| Net control's menu | 1 Members, 2 Add a member, 3 Rekey now, 4 Key change, 5 Net status, 6 Change over the net, 7 Send the roster, (8 Take over on net control 2-4), Rekey every, Send the time, Remote wipe, Share location (25), Leave the net |

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
| Message numbers | Reserved 64 at a time and used only once the reservation is in the flash (7.6) |
| Joining unmanaged | A radio that joins without managing keys starts managing the AES channel it is on (6). Found on air: a fresh radio joined, answered Ask its keys with "Keys: none", and said no HELLO, so it never caught up |

**Compared with P25 OTAR.** A P25 key management message has three protections: the TEKs inside wrapped under the
radio's KEK, the message body encrypted again under a traffic key (the outer layer), and a MAC with message numbers
against replay. Each has its counterpart here:

| P25 KMM | Here |
|---|---|
| TEK wrapped under the radio's UKEK | TEK wrapped under the pair's UKEK, AES-256 key wrap (RFC 3394 / NIST SP 800-38F KW) (5, 7.1) |
| KMM body encrypted (outer layer), the key named in the KMM | Body encrypted with AES-256-CTR (SP 800-38A) under the pair's or the keyset's K_enc (7.6). The key is implied by the sender, receiver and type, never the channel's alone |
| MAC and message numbers | AES-256-CMAC (SP 800-38B) truncated to 64 bits over both DMR IDs, the header and the ciphertext; message numbers per sender (7) |
| First keys loaded by a KVL in person | Key fill in person or over the air with the six-digit code ([key-fill.md](key-fill.md)); the active key follows by REKEY (6, 9) |
| UKEK held by the KMF | Derived by both radios from X25519 key pairs (RFC 7748) through HKDF-SHA-256 (RFC 5869); no radio holds another's |

What it is not: it doesn't speak TIA-102.AACA's formats (1), and no part is certified (no P25 CAP testing, no FIPS 140
validated module). The algorithms are the published ones above, each checked against its standard's test vectors in
`otarCryptoTest`.

Checked against the standard (TIA-102.AACA-D, 2026-11-26, compared section by section, nothing taken from its text):
the inner layer is the same key wrap with the same key field (AACA-D 13.3); the MAC is the same AES-256 CMAC truncated
to 8 octets (13.5.2.2); and sending the messages self-protected over UDP with no link-layer encryption is the
standard's own model for IP delivery (12.3). The differences are deliberate: the outer layer's key here comes from the
pair (or the keyset for CHANGEOVER), where P25 uses a traffic key the radios share, so another radio holding that key
can neither read nor forge an individual message here; the outer mode is CTR with an implied counter block where P25
uses OFB with a sent MI; and the MAC key comes from HKDF over the pair secret, where P25 derives one per message from a
traffic key with an SP 800-108 KDF. Message numbers are 32-bit and only rise, where P25 uses 16 bits with a window.
The comparison also found the gaps this design now closes: ZEROIZE answered before the wipe (7.5), HELLO always
answered and retried (9), and an authenticated answer to an old message number (7.6); and the rule that group and
individual messages don't share a replay counter (7.6). What the comparison left open is settled in 26: withdrawing or
rescheduling a next keyset over the air is built (7.9); the other three aren't, for the reasons given there.

Checked on air 2026-11-24, net 8B16: both radios flashed with this build; the member, joined after the rekey and
still on key 77, restarted, said HELLO and got key 78 from the net control as a REKEY flagged now. 45 s after start its
Net keys showed "Keyset 2: key 78", old key 77 heard; `data.privacy_rx_dropped` stayed 0 on both (nothing went under
the channel's key).

Then a fourth radio, fresh from stock firmware with only key 77 in its codeplug and no keys managed, joined net 8B16
(code compared) on this section's last change. With no further step it started managing the channel's keys, said HELLO
and took key 78: the net control's Ask its keys showed "Keys: keyset 2 OK". All four radios hold key 78.

Missed changeover, on air the same day: with 4675810 switched off, the net control rekeyed by hand to key 79 (Net
status "Key 79: 2 of 3 have it", the off radio "no answer") and changed the net over. Switched back on, 4675810 said
HELLO from key 78 and took key 79 as a REKEY flagged now: 45 s after start its Net keys showed "Keyset 3: key 79", old
key 78 heard, `data.privacy_rx_dropped` 0.
A call from the net control then reached both cabled members as AES-256 (PI header algorithm 0x25) under key ID 79.

Tests: `otarCryptoTest` (a body's octets aren't in the message, the same body under the next message number encrypts
differently, a changed ciphertext octet fails the MAC, opening leaves the message unchanged, version 1 refused);
`dmrDataServiceTest` (port 4103 goes in the clear, mixed ports don't).

### 23.5 Through a repeater (not tested)

Result: not tested. The radios need to be farther apart. Every on-air check above is simplex. The bench tries on
2026-11-25 (below) gave no result either way. The test is planned for the week of 2026-11-30, with one radio moved
farther from the others.

Tried from the bench on two repeaters, neither could be used:

| Repeater | What happened |
|---|---|
| UHF pair 451.650 / 456.650, about 16.6 km | The net control, moved, reached it at times (voice through, both ways, at times); a member at the bench received its OTAR messages and ACKed them at the link layer, but none of its ACKs reached the net control. OTAR retried and reported "no answer", as it should |
| VHF pair 152.300 / 157.560, about 8.7 km (an AES tag put on a clear channel for the test, removed after) | `dmr.tx_error=no_repeater` on 9 of 10 wake-ups; once it opened, the over dropped within half a second. A stock-firmware radio at the same spot transmitted a clean call (SDR on the input: colour code 01, group call) that the repeater never repeated (SDR on the output: nothing): stock firmware talks without the repeater's answer, ours waits for it. With our net control (better placed) set to the stock radio's talkgroup, it heard none of those calls either; what sounded like a connection was the stock radio's own key-up beep. So the path, not the firmware |

To finish it: the radios farther apart, each with a solid path to the repeater (outdoors, a window, an outside
antenna, or a repeater with line of sight). Radios close together also fail through a repeater for another reason:
the repeater's output overloads a receiver next to the sender (key-fill.md 2.1). The test then is the roster, a rekey
and a changeover through it, as in 23.3.

### 23.4 A radio cleared and joined again (2026-11-25)

The test: 4674131 had every key cleared (Settings > Privacy > Clear all keys: traffic keys, key pair, net and keysets),
stayed on the AES TEST channel, joined net 8B16 again by key fill from the net control (code compared, OK on both), and
had to get the net's active key (keyset 12, key 89) over the air, all without the channel's key. Three bugs stood in the
way; each was fixed with a host test that fails without the fix, then checked on air.

| Found | Fix |
|---|---|
| The member heard key fill's offer and never answered: `data.tx_gave_up` 9. 13.5's queue let clear self-protected packets through, but the start of each transmission still asked for the channel's key | Each list carries whether it may go on `canTransmitClear` (a clear self-protected packet, a link response). `dmrDataServiceTest` now checks the list starts, not that it was built |
| Joined, it stayed "Keys not managed": a radio started managing the channel's keys on joining only when it held the channel's key, so it never said HELLO | A radio not managing keys yet starts on any AES channel (6); the catch-up brings the key (`otarEngineTest`). One that manages them already (Leave the net keeps them) keeps its keysets: starting again would put it back on keyset 1 (found in review) |
| Managing from keyset 1, it refused the net's catch-up REKEY for keyset 12: more than 8 ahead (23.2) | The best-ranked net control's catch-up, flagged now, is taken however far ahead (7.1). Any other REKEY keeps the limit, none passes 65535 |

After the three fixes: the rejoined member said HELLO 20 s after start, took key 89 as a REKEY flagged now and changed
over. Its Net keys showed "Keyset 12: key 89", and a 2 s call from it reached the net control as AES-256
(`call.rx_encrypted_calls` 1, 90 frames, none dropped). Both radios: `airq.failed` 0, `data.tx_gave_up` 0.

On air after the review's fix: a member on keyset 12 left the net and joined again by key fill (code compared on
both screens); its Net keys still showed "Keyset 12: key 89".

Left, documented (review): a member that a backup net control joined has only that net control on its roster until net
control 1 is added, and ROSTER from the backup can't add a better rank, so that backup is its authority and its catch-up
may jump the member's keyset. It needs a backup net control that is compromised or broken.

Also seen: with its keys cleared the radio refused PTT on the AES channel (no frame sent), so nothing went out in the
clear. The debug view's `tx_deny` shows the last refused PTT only, not whether the channel can transmit now.

### 23.3 On air, 2026-11-24 night and 2026-11-25

Four radios, net 8B16. Each finding below was fixed, tested on the host and then on air unless it says otherwise.

| Found | Fix |
|---|---|
| Storing a new traffic key reused a slot in use: the net control's active key 85 was overwritten | A new key goes after the highest slot in use, else the first free one (`codeplug_traffic_key_set`). The net control got key 85 back by key fill on a channel without encryption |
| An AES channel without its key refused every transmission, so that net control could send no OTAR message at all | Clear self-protected packets and link responses still go ([dmr-data.md](dmr-data.md) 13.5, `canSendClear`). Tested on the host only, not provoked on air |
| Link responses were dropped on a channel that encrypts data: every confirmed packet went its full tries and was reported failed (Send the roster: 3 failed, about 14 clear drops) | Responses are taken. Afterwards: net control 6 sent 0 failed, member 4 sent 0 failed, `data.clear_rx_dropped` 0 on both |
| A stray key press in Net changed the net over to key 87 before the members had it (one caught up by HELLO after a restart) | Change over the net and Leave the net ask first (12) |

2026-11-25: Rekey now by hand to key 89 from the receiver's noise, no key pressed. Net status went from sent to OK on
its own, "3 of 3 have it" about 40 s after the start. (The night before, the screen was thought not to refresh. It does:
it redraws every second, and `uiFlowTest` "a member's ACK" checks it.) Change over the net then showed "Change over to
key 89? 3 of 3 have it". A second 6 and then Back left the net on keyset 11; 6 then OK changed all four radios to keyset
12. On a member, Leave the net showed "Leave the net? Rejoining needs a key fill" and Back kept it in the net. The host
tests also pass under ASan and UBSan (91.1 % of lines).

### 23.2 Second review (2026-11-24)

A second reviewer, given the code and specs after 23.1, found among others these, each confirmed against the code and
fixed:

| Finding | Fix |
|---|---|
| One passing noise grab credited the whole pool; the health tests catch a broken source, not a crafted one: a strong carrier modulated into a staircase could pass them | Credited only on a quiet channel (signal at -100 dBm or below before and after the grab); a saved seed ([key-fill.md](key-fill.md) 6.1) |
| Any NC could un-revoke a radio, add radios or swap a member's public key on every radio, NC 1 included | Only the authority adds radios, changes keys or ranks; nobody un-revokes over the air (10) |
| Keyset numbers had no upper bound: one REKEY of keyset 65535 flagged now left every later rekey "old"; a REKEY's key ID could be the active key's | At most 8 above the active keyset, never above 65535, no key ID in use (7.1); an NC at 65535 starts a new net |
| A member holding the next keyset that missed a changeover by hand answered the catch-up HELD and stayed behind | HELD and changes over (7.1) |
| ZEROIZE ignored rank: NC 4 could wipe NC 1 | Only from a better rank, on both sides (7.5) |
| The NC took any ACK of the right keyset, roster ACKs with no check at all, so a recorded ACK could report a revocation as delivered; a member could send ACKs numbered 0, two sharing a counter block | ACK echoes the request's number (version 4, 7.2); nothing is sent numbered 0 |
| A member's replay counter was saved after changes rested; a demoted NC's counter could be reused from 0 | Saved at the next poll (`settings_end_soon`); a counter is reused only for a radio gone from the roster or revoked |

Left, documented: a roster change from a lower NC isn't held for NC 1's user (it is limited to revocations); a fifth
NC (after demotions) finds no counter while four NCs are on the roster; a TIME delivered up to 48 h late can move a
clockless member's clock back; replaying members' HELLOs in turn still makes the NC answer (this said once per 2 minutes each; the single slot it kept really let two members' HELLOs in turn through every 2 s, bounded since 2026-11-26 to 8 answers per 2 minutes, 9);
the noise grab blocks the radio task for about 120 ms; a Leave cut off by a power loss leaves the old roster for the
next join. `otarEngineTest` covers each new rule (56 checks, each rule disabled in turn fails it); the wipe's rank
check and the noise gate's signal reading are checked by reading the code and on air, not by host tests.

On air the same night, all four radios on this build: Rekey now on NC 1 with no key pressed made key 84 from the
receiver's noise (3 grabs: 2 credited nothing as "loud", the signal then -101 dBm against the -100 gate, 1 passed) and
reached all three members, each ACK echoing its REKEY ("Key 84: 3 of 3 have it"). The same radio's floor read -90 to
-92 dBm minutes later: a fixed -100 dBm gate turned many grabs down on a busy bench. The gate now follows a floor the
radio learns while idle, plus 6 dB, capped at -85 dBm ([key-fill.md](key-fill.md) 6.1).

### 23.1 Independent review (2026-11-24)

A reviewer given only the code and these specs found, among others, five issues confirmed against the code and fixed:

| Finding | Fix |
|---|---|
| TIME, under a key every TEK holder has, moved the counter that guards REKEY: one forged TIME blocked every later rekey (critical) | TIME goes to each member under the pair's keys (7.4) |
| A member ignored the REKEY's keyset number, so any NC could move it back to an older key; HELLO went to the first NC on the roster and compared 8-bit key IDs | Members take the net's keyset numbers (`RADIO_OTAR_NEXT_KS`) and only a higher keyset (7.1); a resend is HELD only with the same check value; HELLO carries keyset numbers and goes to the best-ranked NC (version 3) |
| A backup NC could raise its own rank to 1, then revoke NC 1 without the take-over question | Rank rules in ROSTER (10) |
| Message numbers cleared at a rejoin while the pair keys stayed the same: recorded REKEY, ROSTER and ZEROIZE replayed; counters were per rank | A new key pair per net, counters per sender ID (7.6) |
| The join's code didn't bind long-lived public keys: a radio in the middle could search a million keys offline | Key fill version 2: the sender's fresh nonce in the commitment ([key-fill.md](key-fill.md) 4.1) |

Also fixed: CHANGEOVER from a revoked NC is refused; a member works its pair keys out again after a ROSTER (a changed
public key); key presses a host injects over the debug link aren't counted as randomness ([key-fill.md](key-fill.md) 6).

On air the same day, all four radios on this build: a rekey "in 5 min" from NC 1 found every member waiting and the
net control's new key already due. The changeover had been fixed when Rekey now was chosen, and the 32 key presses
took longer than 5 minutes: the net control changed over by its own clock at once and no REKEY went out. It is now
counted from when the key is made. The three members, left on key 79, each said HELLO from keyset 3 after a restart
and took key 80 under the net's keyset number 4 ("keyset 4 OK"). The next rekey, to key 81, reached all three: Net
status "Key 81: 3 of 3 have it, change over at 19:47", the members "Next: key 81 at 19:47". At 19:47 the net control and
the member checked both showed "Keyset 5: key 81", old key 80 heard.

The review's lower findings, then fixed:

| Finding | Fix |
|---|---|
| An ACK counted for the keyset number alone: an old ACK of the same keyset (a run stopped and started again) or another NC's key under that number marked a member done | The NC counts an ACK only with the check value of the key its run sent |
| Message numbers were saved within 2 s but not before use: a power loss with more than 1024 unsaved could repeat a counter block | Reserved 64 at a time, used only once the reservation is in the flash (7.6) |
| A replayed REKEY still got an ACK, a replayed HELLO a catch-up REKEY each time, and any forged source made the NC work out X25519 before the MAC check | A member drops a REKEY with an old message number without ACKing it (since 2026-11-26 it answers "old message number" at most once every 5 minutes, 7.6); the NC sends one member the active key at most every 2 minutes, and works on an ACK only from a member it waits for and on at most one HELLO every 2 s |
| Key fill and OTAR went in the clear by port number alone, so a host could send its own traffic on those ports unencrypted through the gateway; and on an AES channel a clear packet reached every service, so anyone could inject a clear text | Clear only for the two services' own packets (`DMR_IPS_SELF_PROTECTED`); on a channel that encrypts data a clear packet is taken only on those ports ([dmr-data.md](dmr-data.md) 13.5) |

On air the same evening, all four radios on this build: a rekey to key 82 "in 5 min" from NC 1, with the ACK counted
only on the check value of the key sent: Net status "Key 82: 3 of 3 have it, change over at 21:00"; two members checked
on their own screens showed "Next: key 82 at 21:00", then at 21:00 "Keyset 6: key 82", old key 81 heard.

Left as they are, documented: CHANGEOVER has no message number (an old one is for another key and fails its MAC; a
radio holding the next key can only bring the changeover forward, and every member holds that key); K_enc comes from
K_mac as an HKDF PRK (sound, if less tidy than a third label from the pair's PRK); group keys don't name the net (each
comes from that net's own random TEK); X25519 uses a constant-time ladder and a fixed-exponent inversion, read but not
measured. Open: the randomness credit per key press is generous and the pool starts empty at each power-on (the
receiver's noise is the planned source, [key-fill.md](key-fill.md) 6). The engine's rules are host-tested in
`otarEngineTest`: the real engine, roster, messages and crypto, with the radio core, codeplug, settings and transport
faked, the test playing the other radio with real messages. It checks keyset order (an older keyset refused, a resend
HELD only with the same key, a REKEY flagged now changing over at once), a replayed REKEY getting no ACK, TIME taken
under the pair's keys and a forged group TIME ignored (with the counter attack after it), HELLO to the best-ranked net
control, each ROSTER rank rule on its own, counters per sender, the net control's catch-up and its 2-minute limit,
an ACK counted only with the sent key's check value, and nothing sent before a message number reservation is saved.
Each of those rules, disabled in turn, fails the test.

## 24. After the P25 comparison (as built, 2026-11-26)

| Part | What it does |
|---|---|
| ZEROIZE answered | The member's ACK "wiped" (or "refused") under the pair keys, handed to the transport before the wipe starts; NC's 3 tries and the member screen's "Wipe:" line (7.5) |
| HELLO answered and retried | NC answers every HELLO it works on, "up to date" when it has nothing to send; the member asks again after 1, 5, 15 minutes and every 15 minutes until answered; Net > Request keys (9) |
| Old message number | A rate-limited, authenticated answer with the last number taken; NC skips past it or shows "Out of sync: rejoin" (7.6) |
| HELLO limit | NC answers at most 8 members per 2 minutes, each at most once (9). The single slot before let two recorded HELLOs played in turn bring a catch-up REKEY every 2 s |
| Remote wipe | On by default in a net, set again at each join or start (7.5) |
| Protocol version | Still 4: the new ACK results are ignored or counted as "not taken" by version 4 radios (7.2) |

Tests: `otarEngineTest` (170 checks) adds the ZEROIZE ACK built and handed over before the wipe and nothing else
answered meanwhile, the wipe after 60 s when the transport never finishes, NC's tries and its stop at the answer;
HELLO answered "up to date", behind answered by the catch-up, a member not answered twice in 2 minutes, two recorded
HELLOs in turn answered once each, ten at once answered 8 and the others later; the member's HELLO schedule, its stop
at the answer, and Request keys; an old number answered once with the last number taken, not again within 5 minutes,
a bad MAC never answered; NC skipping its numbers and resending, and "out of sync" beyond the skip; Remote wipe on
after joining. Each fails against the engine from before (the behavior wasn't there); the old-number limit, the
ZEROIZE's order and the 8-member HELLO limit were also taken out one at a time, and the test fails each time. Not
checked on air yet.

## 25. Get location (as built, 2026-11-26)

| Part | What it does |
|---|---|
| LOCATE, POSITION | Types 10 and 11 (7, 7.7): a net control asks one member where it is, and the member answers under their pair keys, its position encrypted and authenticated. Type 9 stays reserved for TAKEOVER (22) |
| Share location | Net > Share location on every radio in a net, under Remote wipe: On by default and set again at each join or start (`settings_t.otar_loc_off`, [settings-store.md](settings-store.md)); Off answers "refused" |
| Get location | Net > Members > OK on a radio > 5 Get location: a screen with "Location: asking", then the position, the distance and compass point from this radio and the fix's age, or "no fix", "refused", "no answer" (3 tries, 20 s apart). Back returns to the member screen, which shows the same lines under its others |
| Limits | One LOCATE asked at a time; a member answers each net control at most once per 10 s, never a replay, never under radio silence (7.7) |
| During a rekey run | Get location (and Ask its keys) go at once during a rekey run too. Before 2026-11-27 they waited for the run to end, and a run by the clocks stays open until its changeover (up to a day), so Get location sat on "asking" (found on the bench) |
| How old | "no fix", "refused" and "no answer" show how long ago they came ("no fix - 9h ago"), as a position shows its age: an old answer isn't taken for today's |
| Old radios | Drop type 10 (an unknown type): "no answer". The protocol version stays 4 |

Tests: `otarEngineTest` adds the member's answer (position, south and west, altitude unknown, the fix's age), Share
location off answered "refused", no fix answered "no fix", nothing under radio silence, a LOCATE from a roster member
that isn't a net control, from a radio off the roster or with a bad MAC ignored, a replay never answered with a
position, a fresh one within 10 s not answered; the net control's tries (3, 20 s apart, then "no answer"), a POSITION
echoing another number or from a radio not asked ignored, the answer's age counting on, the distance from this radio's
own position, and Share location set again at a join. The authority check, the 10 s limit, radio silence and the
echo check were each taken out in turn, and the test fails each time. `otarCryptoTest` builds and opens both messages:
negative coordinates, altitude unknown, the body not in the clear, a MAC the other way round refused, an unknown result
or a latitude past the pole refused. `uiFlowTest` covers the row, asking, each answer, Back to the member screen, one
at a time, and Share location On after joining and Off once chosen; `uiSim --layout` checks the screens at every
display size. Not checked on air yet.

## 26. Moving or cancelling a planned change (as built, 2026-11-27)

| Part | What it does |
|---|---|
| Move the change | Net control, with a rekey run's key made: the Key change choice becomes the changeover, here and on every member (the REKEY sent again; a member holding it answers HELD and takes the new changeover) (7.9) |
| Cancel the change | Net control: its next keyset dropped and its key erased, then WITHDRAW (type 13) to each member, which drops it and erases its key, answering ACK 11 dropped (7.9) |
| A member that was off | Told at its HELLO: the withdrawn keyset is kept in the net control's settings (`otar_cut`, offsets 467-469) |
| Numbering | The next rekey takes a keyset number above the withdrawn one, so a member that still holds it never sees two keys under one number |
| Protocol version | Still 4: a radio from before drops WITHDRAW (net control: "no answer") |

The P25 comparison's other open items (23), and why they aren't built:

- **The net control checking members' message numbers.** Every message a member sends a net control answers one the
  net control sent (an ACK or POSITION echoes its message number, 7.2, 7.7), and the net control takes only an answer
  to a message it is still waiting for, so a recording of an old answer is never taken. The one exception, HELLO, is
  answered at most once per 2 minutes per member, at once only for a newer HELLO (9), and the answer goes under that
  member's pair keys, so a recording only brings the member a key it may already hold. A counter per member would cost a
  settings slot per member for no attack it stops.
- **A key-pair change after a restore.** The key pair lives in the radio's settings record, which no backup or
  codeplug tool writes back (a codeplug restore leaves it as it was, as on the bench 2026-11-26), and every join or start
  makes a new one (23.1). A radio whose settings went back anyway is caught by the message numbers: its net control's
  messages answer "old message number" and it shows "Out of sync: rejoin" (7.6).
- **An algorithm ID and a 16-bit key ID in the format.** The net carries one algorithm, AES-256, and DMR's privacy
  header names an 8-bit key ID, so the fields would always hold the same values. A second algorithm would be a new
  protocol version: the version byte already makes an older radio drop what it can't read.

Tests: `otarEngineTest` (305 checks) adds the member's side (a moved changeover by the clocks and back to by hand, a
moved changeover with another key refused, WITHDRAW of another key ID refused, the right one dropped with its key
erased, a replay not answered, not held answered "dropped", the active keyset answered "old", a WITHDRAW from a radio
that isn't a net control ignored) and the net control's (nothing to move or cancel without a run, the move here and in
the REKEY sent again, the cancel here with its key erased and the number kept, a late answer to the REKEY not counted,
"dropped" ending the run, a HELLO holding the withdrawn keyset answered by WITHDRAW and one holding another answered
"up to date", the next rekey numbered past it, Rekey now replacing a cancel run, and Leave forgetting it).
`settingsTest` pins the new offsets. `uiFlowTest` covers both rows: each asks first, a digit never says yes, Back
keeps the change, a move by the clocks needs one, the cancelled run in Net status and a member's answer counted, and
a cancelled change can't be changed over. Eighteen parts of the change were each taken out in turn, and the test fails
every time.

## 27. Radio silence (as built, 2026-11-27)

Under radio silence ([radio-silence.md](radio-silence.md) 3) OTAR sends only what its user starts. A member sends no
answers at all (its ACKs, POSITION, "old message number"), though it still takes what a message carries (a REKEY's
key is stored, a WITHDRAW drops the keyset, a ZEROIZE wipes); its HELLO at start waits until silence ends, and Net >
Request keys goes. A net control answers no HELLO and sends no ACK or POSITION. What its user starts or scheduled goes,
with its retries: Rekey now and a scheduled rekey (Rekey every, the user's own schedule) with the CHANGEOVER at their
changeover by the clocks (members without a clock wait for it), Change over the net, Send the roster, Send the time, a
wipe, Ask its keys, Get location, the net's channel and Move or Cancel the change. A reply is dropped, not held (`silenced`, counted in `eng.silence_dropped`).

Tests: `otarEngineTest` (333 checks) adds a member under silence (no HELLO at start, a REKEY stored without its ACK,
an INVENTORY unanswered, Request keys sent, answers again once silence ends, a ZEROIZE wiping with no ACK) and a net
control (no answer to a HELLO behind or up to date, Rekey now and its retry sent, a HELLO answered again after), and a
scheduled rekey under silence (its REKEY sent, then its CHANGEOVER to the talkgroup). Each gate was taken out in turn,
and the scheduled rekey and its CHANGEOVER held back in turn, and the test fails each time.

## 28. Third review: moving and cancelling made safe (2026-11-27)

Two independent reviews of 7.9, 26 and 27 (one by another model, given only the code and this spec) found ways a
cancel could leave members on a withdrawn key while the net control stayed on the old one, and smaller holes. Each was
traced in the code before it was fixed; each fix has a test that fails without it.

| Found | Fix |
|---|---|
| A cancel run gave up after 10 minutes. A member on air but out of reach meanwhile kept the withdrawn keyset and changed over to it alone by its clock (only a HELLO, at start, would have told it) | The run stays open until 5 minutes past the withdrawn changeover by the clocks (at least 10 minutes), its tries backing off to 1, 2, 5, then every 15 minutes. After a restart net control 1 takes the run up again while the withdrawn keyset is above the active one (`cut_resume`, open 25 hours: its changeover isn't known any more) |
| Rekey now ended a cancel run before its own checks, so a refused rekey (BUSY) left no run; a scheduled rekey fell due over a cancel run | The cancel run ends only once the new run exists. A schedule waits while any run is open |
| The net control's own drop of the keyset was asked once and never checked: lost, or made after its clock changed it over | The cancel run asks it again every 2 s until the view shows the keyset gone. If this radio changed over first, the cancel is too late: no more WITHDRAW, the withdrawn number forgotten, and every member sent the key flagged now instead, so the net stays together. Cancel the change is refused within 2 minutes of a changeover by the clocks ("Too close to the change over") |
| A member answered DROPPED as soon as it asked its radio task to drop the keyset; its clock could change it over first | DROPPED is answered once the view shows the keyset gone, OLD if it became the active one; asked again twice, then REFUSED (`wd_answer`). The answer is built under the pair keys of the net control that sent the WITHDRAW, worked out again if other traffic came meanwhile |
| Request keys under radio silence repeated its HELLO every 15 minutes for as long as silence lasted (no answer comes under it) | At most 3 HELLOs under silence; the HELLO waits for silence to end after that |
| A failed send was blamed on every job waiting for an answer (a LOCATE's failure marked the member in the rekey run as failed) | The transport's failure counts only for the job whose message it was (its type and receiver) |
| A member's INVENTORY answers were built in the REKEY ACK's fields: a REKEY between the two answers took the INVENTORY's echo or keyset | The INVENTORY's answers have their own fields |
| A withdrawn key stayed in the codeplug when the overlap's erase was running, the job couldn't be posted, or the remove failed; a next keyset replaced by another key ID left its old key | Erases are queued and made one job at a time; a key still there after its remove is queued again; a replaced next keyset's key is queued; a key a keyset names again is kept. The withdrawn key is saved as pending (settings `otar_erase`, [settings-store.md](settings-store.md)) and erased again after a restart |
| Any net control could cancel, but only net control 1's withdrawn number is known to members' HELLOs and to the next rekey | Cancel the change is net control 1's (the authority, 10) alone ("Only net control 1 cancels"); members take WITHDRAW from it alone |
| After a move, an ACK of the REKEY sent before it could still count when another request made that member's ACKs wanted | Move clears each member's last message number, so only an answer to the moved REKEY counts |
| A REKEY's changeover past the radio's 24-bit minute count would wrap | Refused |
| A catch-up REKEY, NETCHAN or WITHDRAW queued in answer to a HELLO went out after radio silence began | Dropped when silence begins |

Not changed, and why: the review's request IDs and generations for the radio task's requests (the request queue is in
order and each drop names the key ID it may drop, checked when made); a keyset number pushed past the 8-step window by
many cancels in a row without a changeover (each later rekey numbers above the last cut; past the window the next one
falls back to the active one plus one, which only a member that missed several WITHDRAWs and every later REKEY could
still hold).

Tests: `otarEngineTest` (420 checks) adds the cancel run past 10 minutes and its back-off, a cancel too late refused,
the own drop lost and asked again, a cancel overtaken by the clock turned into the key flagged now, a schedule over a
cancel run, a LOCATE's failure during a rekey's ACK, a stale ACK after a move with Ask its keys outstanding, a backup
net control refused, the member's DROPPED held until the drop and OLD when the clock came first, a changeover past 24
bits refused, an INVENTORY and a REKEY interleaved, a WITHDRAW from a backup net control ignored, and three HELLOs only
for Request keys under silence. `radioCoreTest` adds the withdrawn key erased while the overlap's erase runs, the
pending erase saved and cleared, and a replaced next key erased. Every fix was taken out in turn, and a test fails each
time.

## 29. Every action on one member (as built, 2026-11-27)

The member screen (Net > Members > a member) now holds everything the net does to one radio: Rank, Revoke, Wipe its
keys, Ask its keys, Get location, **Wipe the radio** (7.10), **Radio silence** (7.11) and **Silent revoke** (7.12).
Revoke, Silent revoke and both wipes wait for OK. The Net screen gains **Remote silence**, after Share location.

New: messages 14 (SILENCE) and 15 (WIPE), ACK results 12 and 13, the REKEY flag drop (bit 2), the radio request
`RADIO_OTAR_DROP_PREV` (`radio_aes.c`: the previous keyset ended at once, its key erased), `ui_svc_wipe_all_start`
(`ui_svc_zeroize.c`: keys and codeplug whatever Wipe what says) and the settings byte `otar_sil`
([settings-store.md](settings-store.md)).

Found on the bench (four DM-32UVs, 2026-11-27): radio silence on and off from net control 1 to a member, and Wipe the
radio (the member came back on the built-in channels, out of the net), then the radio joined again by key fill. Two
fixes came of it: a silent revoke right after a key fill, which had emptied the pool, waited for randomness without
asking for the receiver's noise (`pool_wanted`), so it stayed "sending"; and a radio joined again still showed what it
answered before ("Radio wipe: wiped"): a member added by key fill now clears those lines (`ui_svc_net_member_added`).

Tests: `otarEngineTest` (513 checks) adds WIPE refused and taken (the whole radio wiped after its ACK, not Clear all
keys) and sent as WIPE; SILENCE on answered before silence starts, no answer while silent, off ending only the net
control's silence and never the user's own, a silence the user ended becoming theirs, Remote silence off refused and
set on again at a join, and the net control's tries, answers and "no answer"; a REKEY flagged drop changing over and
erasing the old key at once (and without drop keeping the overlap); a silent revoke's throwaway key (to the member
alone, above the net's number, a key ID the net doesn't use, never stored), the member revoked with no ROSTER to it,
nothing else allowed meanwhile, revoked all the same after three tries with no answer, the noise asked for while the
pool is short, and a radio joined again shown without its old answers.
