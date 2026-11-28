<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 The RadioFoundry Authors -->

# Key PIN

The key PIN is an optional 4 to 8 digit PIN the radio asks for before it opens its key management: Settings > Privacy
(the stored keys, the key's settings, Clear all keys, the wipe code's settings) and Tools > Key fill (sending and
receiving a key, Generate, the group key, Net keys, Net and everything a net control does from it). Commercial radios
guard key management with a password in the same way. Someone holding a radio without the PIN can still use it (talk,
listen, change channel) but can't send the net's keys to another radio, look at the stored keys or manage the net.
Status: built and host-tested (`keypinTest`, the UI flow tests); untested on a radio. Switch: `CONFIG_KEY_PIN`.

The radio never shows a key's bytes, only check values ([key-check.md](key-check.md)): "seeing the keys" means these
screens, and what can be done from them.

## 1. Files

| Item | Where |
|---|---|
| The PIN's hash, set / check / clear, the back-off | `core/keypin/keypin.c` (`keypin.h`; the back-off's times are header only) |
| Stored | `settings_t.kp_*` (`core/settings/settings.h`, [settings-store.md](settings-store.md) 3) |
| For the UI | `core/ui/ui_svc_keypin.c` (`ui_svc_keypin_*`, `ui_svc.h`) |
| The gates, the unlock and its lifetime | `core/ui/ui_app.c` (`ui_push`, `kp_key`, `kp_open`) |
| Which screens are guarded, the PIN screen, the Privacy row | `core/ui/ui_menus.c` (`ui_kp_guarded`, `key_pin_screen`) |
| Debug link | `core/debuglink/debuglink_view.c` (the `link` section, 8); the refusals (10.3) in `debuglink.c` and `debuglink_cpkv.c` |
| Unlocked, for every task | `core/keypin/keypin_state.c` (`keypin_open`, `keypin_guard`; RAM only) |
| What the cable sees and writes | `core/codeplug/codeplug_kv.c` (`codeplug_kv_redact`, `codeplug_kv_commit`), `core/cps/cps_openfw.c` (area 1) |
| Codeplug Editor | `site/static/js/codeplug/channelmodes.js` (`keyHidden`), `site/static/js/editor/modesview.js` |

## 2. The PIN and its hash

4 to 8 digits, set in Settings > Privacy > Key PIN: typed twice, the same both times. The radio keeps a salted hash,
never the PIN:

```
hash = first 16 octets of SHA-256( "RFKP1" | UID | salt | length | PIN )
```

| Field | Octets | Value |
|---|---|---|
| Label | 5 | ASCII `RFKP1` |
| UID | 12 | The MCU's 96-bit unique ID (`hal_system_t.chip`, `uid[0]` first, each word little endian); 12 zero octets on a board without one |
| Salt | 4 | Little endian, chosen when the PIN is set: the uptime in ms mixed with the previous salt (the HAL has no random source) |
| Length | 1 | The number of digits, 4 to 8, so `1234` and `12340000` can't share a hash |
| PIN | 4-8 | The digits in ASCII |

The compare is constant time, and the PIN typed and the hashes are zeroed on the stack after use. It is the
emergency wipe's construction ([zeroize.md](zeroize.md) 2) with its own label, built on its own: the key PIN doesn't
need `CONFIG_ZEROIZE`.

**Where.** In the settings store, not the codeplug, for the reason the wipe code is ([zeroize.md](zeroize.md) 2): a
codeplug is copied to other radios, a PIN in it would travel with it.

## 3. Unlocked, and for how long

The radio is locked at start-up. Typing the right PIN unlocks it; it locks again at the first of:

- the Home screen shown (Back to Home, long Back, or anything else that goes Home);
- the key lock engaging (long `*`, a side key, auto lock);
- 5 minutes without a key press;
- a restart.

The unlock is in RAM only (`keypin_state.c`), never stored. It is one byte, and so is the RAM copy of "a PIN is set":
each is written whole, which is atomic on every MCU built for, so the host paths on other tasks read them without a
lock (10). A Clear all keys confirmation left open when the PIN locks again asks for the PIN at the next key like any
other key screen (6), Back still cancelling.

## 4. The back-off

The first 3 wrong PINs in a row cost nothing. After them each further try waits, from the last wrong one: 30 s, then
1, 2, 4, 8 minutes, then 15 minutes for every one after. While a wait runs, OK doesn't try the PIN at all (not even the
right one) and says how long is left; the PIN screen says it too. The right PIN starts the count again.

The count of wrong PINs is stored (`kp_flags` bits 4-7, saturating at 15) and saved at the next settings poll after
each wrong try (`settings_end_soon`), so switching the radio off and on doesn't reset it; after a restart the wait
counts from start-up. The debug link can inject key presses ([debuglink.md](debuglink.md) 3.4), so this back-off is
what limits guessing through it: at 15 minutes a try, 10,000 four-digit PINs take over three months.

## 5. Stored

| Field | Octets | Value |
|---|---|---|
| `kp_flags` | 1 | Bit 0 a PIN is set; bits 1-3 reserved (0); bits 4-7 consecutive wrong PINs (4), saturating at 15 |
| `kp_reserved` | 3 | 0 |
| `kp_salt` | 4 | The salt (2) |
| `kp_hash` | 16 | The hash (2) |

Appended at offsets 608-631 ([settings-store.md](settings-store.md) 3): a record from before reads 0, no PIN. A factory
reset clears it, and so does the emergency wipe of keys and codeplug (`settings_defaults`). The keys-only wipe and
Clear all keys keep it: the radio's owner still chose it.

## 6. The gates

While a PIN is set and the radio is locked:

| Way in | What happens |
|---|---|
| Settings > Privacy (the Settings list, the Privacy row or its digit) | The PIN screen, then Privacy |
| Find, a Privacy setting by name (`ui_open_setting`) | The PIN screen, then Privacy on that setting's row |
| Tools > Key fill | The PIN screen, then Key fill |
| A key screen already open when the PIN locked again (5 minutes, the key lock) | Back works as ever, so the user can always leave; any other key asks for the PIN first, does nothing else, and the right PIN goes back to the same screen |

One central check does it, in `ui_push`: a push of a guarded screen from a screen that isn't one opens the PIN screen
instead, and the screen asked for follows the right PIN with its argument (and, for Find, its focused row). The guarded
screens (`ui_kp_guarded`) are Settings > Privacy and every screen it or Key fill opens: Stored keys, Send this key, the
key fill session, the group key and Generate, Net keys, Net, Members, Net status, a member and its location, Roll call,
the Wipe Code screen, Clear all keys and the Key PIN screen when it sets or changes the PIN. A push from one guarded
screen to another isn't asked again: inside them every key but Back already went through the PIN (the last row above).

Not gated:

- **The emergency wipe.** Its code and `#` on Home or while locked ([zeroize.md](zeroize.md) 3) open its own screen,
  which is not a key screen: a wipe never waits for a PIN, and a radio about to be lost is wiped as before.
- **Anything arriving over the air.** No incoming key fill, group key or OTAR message opens a screen: receiving a key
  needs the user to open Receive a key or Receive group key first (behind the PIN), and a net control's OTAR messages
  (rekey, roster, wipe, silence, location) are handled by the OTAR service without the UI, under the net's own keys and
  each radio's Remote controls ([otar.md](otar.md) 7). They expose nothing on the screen and stay as they are.
- **Using the keys.** An AES channel talks and listens with its key as before: the PIN guards managing keys, not
  using them.

## 7. Setting it

Settings > Privacy > **Key PIN** shows Off or On (the row before Radio silence). Opening it:

- **Off:** New PIN: 4 to 8 digits, OK, then the same again ("Again"), OK. The same twice: "Key PIN set", back to
  Privacy, and the radio is unlocked (its owner is already past the gate). Different: "Not the same: type the PIN
  again", from the start.
- **On:** Change PIN (a new PIN, typed twice, as above) or Turn off ("Key PIN off"). Both need no PIN typed again:
  the screen is behind the gate already.

On the PIN screen digits are shown as `*`, Back takes the last one back and with none typed leaves (the screen asked
for stays shut), OK takes them; fewer than 4 says "The PIN has 4 to 8 digits" and isn't a try. A wrong PIN says "Wrong
PIN", and once the back-off runs "Wrong PIN. Wait 30 s". The row is dimmed on a radio without digit keys.

## 8. Debug link

The `link` section of GET_VIEW ([debuglink.md](debuglink.md) 3.7) has `keypin.set` (1 a PIN is set),
`keypin.unlocked` (1 while the right PIN has been typed and it hasn't locked again) and `keypin.wrong` (the
consecutive wrong PINs). Never the PIN or its hash.

## 9. What it doesn't protect

- **A cable while the radio is unlocked.** Once the right PIN is typed on the radio, every cable path sees and loads
  keys as without a PIN (10): that is how the owner backs keys up or loads them on purpose. It locks again as in 3.
- **A flash dump with a debugger** (SWD, or the chip desoldered): the keys are in the flash in plain text
  ([settings-store.md](settings-store.md) 3.1), whatever the PIN.
- **Brute force from a flash dump.** Whoever has the flash has the salt, the UID and the hash, and tries every PIN
  offline in a moment: 10,000 for four digits, 100 million for eight. The back-off (4) only limits tries made through
  the radio's keys or the debug link. The hash keeps the PIN from being read at a glance, nothing more; a longer PIN is
  better.
- **Someone who watched the PIN typed**, or a radio left unlocked on a key screen for less than 5 minutes.

## 10. The cable

While a PIN is set **and** the radio is locked (`keypin_guard`), no host path hands out key material or takes new keys.
With no PIN set, or once the right PIN is typed on the radio (until it locks again, 3), every path works as before, so
the owner can back up and load keys on purpose. Secrets are the system secrets (keys 0x0300-0x03FF) and the traffic
keys (0x1900-0x1CFF) of the codeplug settings area ([codeplug-settings.md](codeplug-settings.md) 3,
[channel-modes.md](channel-modes.md) 8). The basic privacy keys are in the settings store, which no cable path reads as
a codeplug; its raw reads are refused (10.3).

### 10.1 What a codeplug read sees

One function shapes the area's bytes for every host path, `codeplug_kv_redact`, called where each path reads its
image bytes from the flash (next to the live VFO's overlay): the CPS shim's area 1 and 2 reads, the fast codeplug
protocol's READ and SUMS (also over the debug link's CODEPLUG command, 0x1C) and TFTP's `codeplug.bin`.

| Bytes | As the cable sees them |
|---|---|
| A system secret's value | Every octet 0 |
| A traffic key's value | Octets 0-4 kept (system, algorithm, key ID, flags: which key it is), the key's octets 0 |
| The header's data CRC (offset 8) | The CRC of the data as shown, so the area still checks and parses |
| Past the data, to the sector's end | 0xFF |
| Everything else | As stored: the layout, every other key, the lengths |
| An area that isn't valid (damaged, a later version) | The whole sector 0xFF: its secrets can't be told apart |

The pattern is all zeros: a real key of all zero octets is no key anyone uses, and the Codeplug Editor shows such a
value as **Hidden (radio key PIN)**. Reads of any size and offset see the same bytes (the CPS shim reads 32 at a time).
A key's check value can't be shown for a hidden key (it is computed from the key); the radio's own Stored keys list
still shows it.

### 10.2 What a codeplug write does

Every path commits the area's sector through `codeplug_kv_commit`, which merges first while locked, in the sector the
path already holds (no buffer of its own):

| The file's area has | Kept |
|---|---|
| A secret the radio holds, hidden (all 0) | The radio's value: a read, edit and write while locked loses no key |
| A secret the radio holds, with another value | The radio's value: loading keys needs the PIN |
| A secret the radio doesn't hold | Not added |
| No entry for a secret the radio holds (deleted) | The radio's, appended to the area |
| Every other key | As the file has it, as without a PIN |

The rest of the transfer rule is as before ([codeplug-settings.md](codeplug-settings.md) 6): a file without a valid
area never erases the radio's, a later version's area is never written. A merge that doesn't fit the sector fails the
write (the path reports its usual flash error).

A fast CPS or TFTP commit cut by a power loss is finished at the next start-up after the settings are read and the
PIN state set (`keypin_init`, locked): it merges like any locked write, so a power cut can't load or delete keys. This
fails closed: keys staged by an owner who had typed the PIN are not loaded by the resumed commit, and are loaded again
with the PIN typed.

### 10.3 What is refused

| Path | While locked |
|---|---|
| CPS shim area 1 (raw flash) | Served only inside the EEPROM image or the flash image and clear of the settings store, the journal, the staging and native areas (the keys in the image read hidden, 10.1); any other read refused (`-`). qdmr's and the open-firmware CPS's reads stay inside the images |
| Debug link STORAGE READ | `DL_ST_REFUSED` |
| Debug link READ_MEM | `DL_ST_REFUSED`: RAM and the program flash may hold keys |
| Debug link CPKV SET and REMOVE of a secret | `DL_ST_REFUSED` (GET of a secret is refused always) |
| Debug link RADIO op 19 (`DL_OP_DMR_PRIVACY`, a basic privacy key in RAM) | `DL_ST_REFUSED` |

Not covered: a debugger on SWD or a flash chip read off the board (9).
