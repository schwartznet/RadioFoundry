<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 The RadioFoundry Authors -->

# Key fill between radios

One radio sends a stored key to another radio over DMR data. The radios agree on a fresh secret with X25519, the
users compare a six-digit code on both screens to rule out a radio in the middle, and the key goes encrypted and
authenticated under that secret. Both radios then show the key's check value ([key-check.md](key-check.md)) as a last
check. Status: built and host-tested end to end with two simulated radios (`keyFillTest`, the UI flow tests);
untested on a radio and on air.

Sources: RFC 7748 (X25519), RFC 5869 (HKDF), RFC 2104 (HMAC), FIPS 180-4 (SHA-256), ETSI TS 102 361-3 (packet data,
the UDP/IP bearer). The commitment before the exchange follows the hash commitment of short authentication string
protocols (as in RFC 6189, ZRTP 4.4.1). The message format and the key schedule are ours.

## 1. Switches and files

| Item | Where |
|---|---|
| Switch | `CONFIG_KEY_FILL`, on by default where DMR and `CONFIG_KEY_CHECK` are built ([build-config.md](../build-config.md)). It also builds the TX queue (`CONFIG_DMR_AIR_QUEUE`) |
| Protocol engine | `core/keyfill/keyfill.c` (`keyfill.h`): the messages, the key schedule, the states. No RTOS, no allocation: the session is the caller's |
| Transport | `core/keyfill/keyfill_svc.c` (`keyfill_api.h`): the UDP port, the air queue, one received message held for the UI |
| Randomness | `core/support/entropy.c` (`entropy.h`): the pool the private keys and the session ID come from (6) |
| Crypto | `core/support/x25519.c`, `hkdf.c`, `sha256.c`, `kcv.c` |
| Storing a key | `core/codeplug/key_store.c` (`key_store_put`), as a storage job |
| UI | `core/ui/ui_svc_keyfill.c` (the session on the RTOS heap, the steps), the Key fill screen in `core/ui/ui_menus.c` |

## 2. Roles and the flow

The **sender** (S) holds the key. The **receiver** (R) is a radio set to receive. Both are on the same DMR channel: side by
side in direct mode (radio to radio), or through a repeater when the radios are apart. Key fill doesn't start on a
channel that isn't DMR.

### 2.1 Low power

On a direct mode channel, from the start of a session to its end, every transmission goes at the board's lowest power level
(level 0: `board_t` lists its levels lowest first; a board whose lowest level is a reduced drive gives that). The radio
core holds the override (`radio_req_tx_low`, `radio_view_t.tx_low`); it is never saved, so the user's level is back on
every way out: done, Back, a time-out, a failure, leaving the screen, and a restart or a power loss (RAM only). The key
fill screen says "Low power" while it holds.

Through a repeater the radios transmit at the user's own level: the repeater sends the exchange on at its power
anyway, and the radios may be far apart. They should be apart: the repeater sends each message on its output while the
sender is still transmitting on the input, so a receiver next to the sender is overloaded by it (desense) and decodes
nothing. It sends no acknowledgement, and the sender times out. Seen on air, 2026-11-21: two radios side by side
through a UHF repeater (5 MHz split) failed every try; with one in another room the fill completed. Radios side by side
use a direct channel.

This is defense in depth, not the security boundary. The X25519 exchange and the matching codes keep the key safe
from anyone who hears the exchange (7); low power only makes fewer receivers hear it.

| Step | Sender | Receiver |
|---|---|---|
| 1 | | Tools > Key fill > Receive a key. The screen shows the radio's DMR ID and waits |
| 2 | Tools > Key fill > Send a key (the stored keys), OK on a key, then the receiver's DMR ID and OK | |
| 3 | Both radios ask for random key presses until the randomness pool is full (6) | |
| 4 | COMMIT | |
| 5 | | RPUB |
| 6 | SPUB | |
| 7 | Both screens show the same six-digit code (for example `482 913`) and the other radio's ID. Each user checks the other screen | |
| 8 | | OK if the codes match: READY. Back: ABORT |
| 9 | OK if the codes match. After READY: KEY. Back: ABORT | |
| 10 | | Checks and stores the key: DONE with the result and the check value |
| 11 | Shows "Key sent" and the check value | Shows "Key stored" and the check value |

The users compare the check values once more: the same six hex digits on both screens. The sender's user must also
press OK before the key goes: nothing leaves the sender without both users' word.

## 3. Transport

- UDP, source and destination port **4101**, over the data service's IP bearer ([dmr-data.md](dmr-data.md) 11). Port
  4101 is outside 4000-4099, so the UDP header is compressed on auto (SAP 3), as zone sharing's 4100.
- In the clear on every channel, an AES channel's too ([dmr-data.md](dmr-data.md) 13.5): the radio getting a key, or
  joining a net that has rekeyed, may not hold the channel's key, and the exchange below protects itself.
- Individual packets to the other radio's DMR ID, confirmed ([dmr-data.md](dmr-data.md) 12): the link layer repeats a
  lost packet. Each message is one IP packet of at most 72 octets.
- Through the TX queue ([dmr-data.md](dmr-data.md) 12.6), one message at a time. A message the data service doesn't
  take within 10 s fails the session.
- A datagram to port 4101 is taken only while a session waits for one: from anyone in step 1, then only from the other
  radio of the session. One message is held for the UI task; another arriving before it is read is dropped (the
  sender's confirmed data repeats it).

## 4. Messages

Every message starts with the version (2), the type and the session ID (4 octets, chosen by the sender). Multi-octet
fields are big-endian unless a field says otherwise.

| Type | Name | From | Octets | After the header |
|---|---|---|---|---|
| 1 | COMMIT | S | 38 | H = SHA-256("RFKF2 commit" \| S's public key \| S's nonce (16)) |
| 2 | RPUB | R | 38 | R's public key (32) |
| 3 | SPUB | S | 54 | S's public key (32), S's nonce (16) |
| 4 | READY | R | 22 | tag (16) |
| 5 | KEY | S | 23 + n | length n (1), the encrypted payload (n), tag (16) |
| 6 | DONE | R | 26 | result (1), check value (3), tag (16) |
| 7 | ABORT | either | 7 | reason (1) |

A message that doesn't parse, comes from another radio, carries another session ID or isn't the one the state waits
for is dropped and counted; it doesn't end the session. The one exception is ABORT, below.

### 4.1 Key schedule

**Why the nonce (version 2).** A commitment to the public key alone keeps a radio in the middle from steering the code
only while that key is new: it has to answer COMMIT before it sees the key. Joining an OTAR net uses each radio's
long-lived key pair ([otar.md](otar.md) 6), already heard in earlier fills and on the roster, so a radio in the middle
knew S's key in advance and could search about a million keys of its own, offline, for one whose code toward S matched
its code toward R. The sender's fresh nonce is committed in COMMIT and only shown in SPUB, after R (or the radio in the
middle) has answered with its key, and it goes into T: the code toward S stays unpredictable until then, so the radio
in the middle matches by chance only, 1 in a million. Found by an independent review, 2026-11-24.

```
shared = X25519(own private key, other's public key)       all zeros: refused (RFC 7748 6.1)
T      = SHA-256("RFKF2 transcript" | session ID | S's DMR ID (3) | R's DMR ID (3) | S's public key | R's public key |
                 S's nonce)
PRK    = HKDF-Extract(salt = T, IKM = shared)
OKM    = HKDF-Expand(PRK, "RFKF1 keys", 68) = k_mac (32) | k_enc (32) | c (4)
code   = (c as a big-endian 32-bit number) mod 1,000,000, shown as two groups of three digits
```

The labels are ASCII without a terminator. The DMR IDs are the ones each radio uses on the air: a radio in the middle
that changes them changes T and so the code.

### 4.2 Tags and the payload's encryption

| Message | Tag: the first 16 octets of |
|---|---|
| READY | HMAC-SHA-256(k_mac, the message's header (6) \| T) |
| KEY | HMAC-SHA-256(k_mac, the message's header (6) \| n \| the encrypted payload \| T) |
| DONE | HMAC-SHA-256(k_mac, the message's header (6) \| result \| check value \| T) |

The payload is encrypted by XOR with `HKDF-Expand(k_enc, "RFKF1 payload", n)`. Each session derives k_enc once and
encrypts one payload with it, so the stream is never reused. Encrypt then MAC: a receiver checks the tag before it
decrypts. Tags are compared in constant time. HKDF as the stream cipher keeps the code to the SHA-256 already in every
image; a build with AES may replace it in a version 2.

### 4.3 The payload

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Class: 1 a privacy key slot, 2 a traffic key ([key-check.md](key-check.md) 2), 3 joining an OTAR net ([otar.md](otar.md) 18) |

Class 1, 7 octets:

| Offset | Size | Field |
|---|---|---|
| 1 | 1 | Type (`dmrPrivacyType_t`) |
| 2 | 1 | Slot, 1 to 4 ([settings-store.md](settings-store.md) 3.1) |
| 3 | 4 | Value |

Class 2, 8 + L + K octets:

| Offset | Size | Field |
|---|---|---|
| 1 | 1 | System type |
| 2 | 1 | Algorithm id |
| 3 | 2 | Key ID, little endian, as the record holds it |
| 5 | 1 | Flags, as the record holds them |
| 6 | 1 | Identity length L, 0 to 8: the first L octets of the system's block ([channel-modes.md](channel-modes.md) 7.1) |
| 7 | L | The system's identity |
| 7 + L | 1 | Key length K, 1 to 32 |
| 8 + L | K | The key |

The receiver doesn't take a payload whose length or fields don't agree.

### 4.4 Results (DONE) and reasons (ABORT)

| Code | DONE: result | ABORT: reason |
|---|---|---|
| 0 | Stored | |
| 1 | No system of that type and identity here | The user canceled |
| 2 | More than one system matches an empty identity | The codes didn't match (the user said so) |
| 3 | This build doesn't have that kind of key | A step timed out |
| 4 | The payload doesn't parse | A message failed its check (tag, commitment, shared secret) |
| 5 | The key couldn't be written | The radio is busy (another session) |

DONE carries the check value the receiver computed from the stored key, or zeros when it stored nothing.

## 5. States and times

| State | Who | Waits for | Times out after |
|---|---|---|---|
| Listening | R | COMMIT from anyone | 5 min |
| Sent COMMIT | S | RPUB | 30 s |
| Sent RPUB | R | SPUB | 30 s |
| Compare | both | the user's OK or Back | 2 min |
| Confirmed, waiting | S | READY | 2 min from Compare |
| Sent READY | R | KEY | 30 s |
| Sent KEY | S | DONE | 30 s |
| Storing | R | the storage job | none: a job always ends |
| Done, Failed | both | Back | |

- A time-out, Back, or a failed check sends ABORT with its reason (except to nobody: in Listening) and wipes the
  session. ABORT from the other radio ends the session at once and the screen says why. ABORT carries no tag: anyone
  on the channel can end a session. That only stops a fill; it can never make a radio store a key.
- Only one session at a time. A COMMIT from a third radio during a session gets ABORT "busy".
- The session ID, the private key and every derived secret are in the session, which lives on the RTOS heap while the
  Key fill screen is open and is wiped (`crypto_wipe`) before it is freed, on every way out. The engine wipes each
  intermediate secret when it is done with it.
- An emergency wipe ([zeroize.md](zeroize.md) 4.2, `CONFIG_ZEROIZE`) clears a running session: its RAM step
  (`zeroize_ram_hook`, in `core/ui/ui_svc_keyfill.c`) wipes the session in place, the transport's held message and the
  randomness pool (`entropy_wipe`), closes the port and gives the power level back (2.1). The session is then over:
  nothing more is sent, its screen closes, the UI task frees the wiped block, and a receiver's store job not yet run
  stores nothing.
- The sender's key octets are read from the store only when KEY is built, and wiped right after. KEY carries the
  stored entry that still matches the one picked (its class, slot or record, and check value); if none does, the
  session fails (ABORT, canceled) rather than send another key.

## 6. Randomness

The radios have no hardware random number generator. `entropy.c` keeps a 32-octet pool, stirred with SHA-256 by:

| Source | Credited |
|---|---|
| Every key press anywhere in the UI since start-up: the microsecond clock (`hal_micros`) and the key | 4 bits |
| A key a host injected over the debug link (`input_event_t.host`) | 0: mixed in, not counted. Found on the bench: scripted menu presses filled the pool and the screen never asked for presses |
| Each UI tick on the Key fill screen: the microsecond clock, the RSSI and the battery voltage | 0 |
| The radio's unique ID and DMR ID, at the start of a session | 0 |

A key press is credited 4 bits: the clock at a human's press varies over hundreds of milliseconds against a
microsecond clock and the input task's scan. The other sources are mixed in but not counted. A session starts only
when the pool holds 128 credited bits; until then the screen asks for random key presses and counts down. Taking
32 octets (`entropy_take`) hashes the pool with a counter and a different label, then replaces the pool by a hash of
itself, so a later read of RAM doesn't give back an earlier private key, and clears the credit.

The private key is 32 octets from the pool, the session ID 4 more and the sender's nonce 16. Both radios need good randomness: with either
private key guessable, a listener could work out the shared secret. The code (2) protects against a radio in the
middle, not against weak randomness. A hardware noise source (the receiver's baseband samples) can replace the
key presses; that is open.

**The receiver's noise, measured (2026-11-24).** On one radio with the FM receive copy ([feature-matrix.md](../feature-matrix.md)), that copy (the discriminator's output,
`modem-hrc7000.md` 10.1, 8000 samples a second, through the debug link's air tap in a `CONFIG_AIR_RAW` bench build),
with first estimates after NIST SP 800-90B 6.3 (most common value, collision, Markov, t-tuple; `RadioFoundry-drafts`
`noise/estimate.py`, not the NIST tool and not a certification), in bits of min-entropy per sample:

| Case | Spread (sd, counts) | Low 4 bits | Low 2 bits | Low bit |
|---|---|---|---|---|
| Quiet channel | 8457 | 3.68 | 1.87 | 0.87 |
| A DMR over from a radio 1 m away | 9219 | 3.78 | 1.83 | 0.80 |
| An unmodulated FM carrier from 1 m (the worst case: the carrier quiets the discriminator) | 773 (down to 258) | 3.71 | 1.84 | 0.76 |

The low bits barely correlate from one sample to the next (under 0.01) in every case, and even the quieted noise spans
hundreds of counts, against 16 for the low 4 bits. Crediting one bit per sample, a key's 128 bits take 16 ms. Still open: a longer capture on more radios
with NIST's own estimators.

### 6.1 The receiver's noise in the pool (as built)

On a board with the FM receive copy (`board.baseband`, `CONFIG_AIR`), while a session or an OTAR rekey or Start a net
waits for the pool:

| Part | What it does |
|---|---|
| Asking | The UI task asks the radio task for a grab (`radio_req_noise`, `RREQ_NOISE`) at once and then every 2 s while the pool is short (`ui_svc_noise_want`) |
| The grab | The radio task takes the modem as the debug link's air bench does (`radio_sm_noise_hold`: the DMR stack stopped, receiving in DMR on the channel's frequency; not while transmitting, a hotspot or the bench), reads 512 samples of the receive copy (64 ms, polled every 10 ms), and gives the channel back. Reception stops for about 70 ms |
| Health tests | SP 800-90B 4.4 on each sample's low 4 bits, for a claimed 2 bits of min-entropy per sample (3.7 measured) at a false alarm rate of 2^-20: the repetition count fails at 11 equal symbols in a row, the adaptive proportion at 177 of the window's first symbol in its 512; and a spread of 64 counts at least (a receiver that isn't running). A short read fails too |
| Into the pool | SHA-256 over a label and the samples, posted to the UI task (`noise_post`, `noise_take`: the pool is the UI task's alone). Stirred in always; credited 128 bits (one per 4 samples, a quarter of the worst case measured) when the grab passed, nothing when it failed |
| Key presses | Counted as before (6): a radio whose grabs fail, or a board without the copy, still fills the pool from the presses |
| Counters | Debug link `noise.grabs`, `noise.passed`, `noise.short`, `noise.rct`, `noise.apt`, `noise.flat`, `noise.taken` |

Tests: `noiseTest` (each health test at its cutoff and one below, a flat receiver, a short read, the mailbox once per
grab and credited only when it passed).

On air 2026-11-24, two radios on this build, no key pressed: Receive a key opened on a radio just restarted showed
"Ready" within 3 s (`noise.grabs=1 passed=1 taken=1`; presses over the debug link count nothing, 6); on the net
control, Rekey now made its key from one grab and the run reached all three members ("Key 83: 3 of 3 have it"), so the
radio receives and sends DMR as before after the grab.

## 7. Security

| Threat | What stops it |
|---|---|
| A listener on the channel | X25519: the key goes encrypted under a secret only the two radios have. Low power in direct mode (2.1) makes the exchange reach fewer listeners |
| A radio in the middle, answering both | The six-digit code: S commits to its public key before it sees R's, so a radio in the middle can't choose its keys to make the two codes agree; it wins once in a million tries, and each try costs it a user's attention |
| A changed or replayed message | Tags under k_mac, bound to T; a fresh session ID and fresh keys each time, so an old KEY never checks |
| A different key arriving than the one sent | The check value on both screens at the end |
| Sending to the wrong radio | The receiver's ID is typed; the code and the other radio's ID are on both screens |
| Ending a fill | Anyone can send ABORT (5); a fill can be repeated |

The users compare the codes over a path a radio in the middle doesn't also control. Side by side: each looks at the
other radio's screen. Apart (through a repeater): read the codes to each other on a phone call with a voice you know,
or meet. A code read out on the same radio channel, or on any radio channel, proves nothing: whoever sits in the
middle of the fill can answer on it too. When in doubt, press Back and fill the radios side by side.

What key fill doesn't do: it doesn't wipe or change keys on another radio, it doesn't keep keys secret in the radio's
flash ([settings-store.md](settings-store.md) 3.1), and it doesn't authenticate who the other radio's owner is.

## 8. Storing

| Class | Where it goes |
|---|---|
| 1 | Privacy slot of the payload's number. While that slot is the one in use and privacy is on, the radio core takes the new key at once |
| 2 | The receiver's system of the same type and identity (2: exactly one of that type when the identity is empty). A record of that system with the same algorithm and key ID is replaced; else the first free record of the family (0x1900-0x1CFF) |

The write runs as a storage job on the housekeeping task. A codeplug of another firmware (`codeplug_foreign`) is not
written: result 5.

## 9. Radio UI

Key fill is an operation, so it is a tool ([information-architecture.md](../ux/information-architecture.md) P1): Tools >
Key fill, the last tool. It comes after the zone offer's 0, so it has no digit: Up from the first tool reaches it (the
list wraps), `SELECT`, `6`, Up, `SELECT`. The key's setup stays in Settings > Privacy (Key type, Key, Key check, Stored
keys).

| Screen | Shows | Keys |
|---|---|---|
| Tools > Key fill | 1 Receive a key, 2 Send a key | Digits or OK, Back |
| Receive a key | "Ready. This radio: 9991234", then the steps | Back cancels |
| Send a key (Stored keys; also Settings > Privacy > Stored keys) | Each key and its check value | OK on a key: Send this key |
| Send this key | The key and its check value, "To ID:" and the digits typed | Digits, OK starts, Back |
| Randomness | "Press keys at random: 12" | Any key counts |
| Compare | "Code 482 913", "Other radio 9991234", "Same on both? OK yes, Back no" | OK, Back |
| Done | "Key stored" / "Key sent", "Check 9507A7" | Back |
| Failed | Why (4.4) | Back |

The screen keeps the backlight on. Leaving it (Back, a long Back to Home) cancels the session.

## 10. Limits

| Limit | Value |
|---|---|
| Key | 32 octets (AES-256); privacy slots and traffic keys of any type this build stores |
| RAM | the session on the RTOS heap while the screen is open (about 1.1 KB); static: the received message held for the UI and the entropy pool (about 150 B) |
| Time | X25519 twice on each radio (a public key, the shared secret); see the flash and RAM costs in [feature-matrix.md](../feature-matrix.md) |

## 11. Tests

- `tests/host/keyCryptoTest.c`: X25519 on RFC 7748's vectors and its low-order refusal; HMAC and HKDF.
- `tests/host/keyFillTest.c`: two engines end to end for each class of key, a radio in the middle (the codes
  differ), every changed message, replays from an earlier session, every time-out, ABORT both ways, a third radio's
  COMMIT, the receiver's refusals, the wipe of every secret, and a fuzz loop over received messages. With the UI glue
  (`ui_svc_keyfill.c`) and a faked transport, heap and scheduler: an emergency wipe (`zeroize_ram_hook`) of no session,
  of a listening receiver and of one whose store job hasn't run (every octet of the session zeroed, nothing sent after,
  the block freed by the next tick, nothing stored), and the pool after `entropy_wipe` as at power on.
- `tests/host/uiFlowTest.c`: the screens of 9 open, and Back from each; in direct mode low power on while a session runs and off after; through a repeater the user's level all along.
- `tests/host/radioCoreTest.c` (`test_power`): with the override every transmission goes at level 0, the user's level
  is kept and used again after it, and a restarted radio core has no override.
