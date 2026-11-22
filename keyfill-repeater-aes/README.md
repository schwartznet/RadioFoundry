# Key fill over an AES-256 channel through a repeater (2026-11-21)

First on-air key fill between two DM-32UVs running RadioFoundry with key fill and data on AES channels
(`docs/spec/key-fill.md`, `docs/spec/dmr-data.md` 13.4).

## Setup

| Item | Value |
|---|---|
| Radios | Radio A, DMR ID 4670501 (receiver); radio B, DMR ID 4670502 (sender) |
| Channel | A UHF repeater, 5 MHz split, DMR CC1 TS1, an AES-256 channel with key ID 1 |
| Key sent | A throwaway test key |
| Capture | RTL-SDR Blog V4 and SDR++ on the repeater's input (both radios' transmissions, MS sync), its network sink into DSD-FME: `dsd-fme -fs -i tcp:<host>:7355 -o null -Z -6 keyfill1_raw.wav`. DSD-FME had no key |

## Files

| File | What | SHA-256 |
|---|---|---|
| `keyfill1_raw.wav` | Raw discriminator audio, 48 kHz mono, 342.8 s | `b28bf95708f5e3ffe1bb4cb71b2a57a7ffb70bec3547f06b72877e1b869fc8f4` |
| `keyfill1_live_plain.log` | DSD-FME's log (colour codes removed) | `f06a59d9678e8f8f50a13a2f984d4f0acb59a76a618cb7732792c9988ed89f6d` |

Replay the WAV with `dsd-fme -fs -i keyfill1_raw.wav -o null -Z`.

## What it shows

Every key fill message is one confirmed, individual UDP packet with the compressed header (SAP 3), carrying a DMRA
privacy header that DSD-FME decodes as `MFID 10; ENC 1; Key ID 01; ALG 05; AES256; MI(32) ...`. The payload shows only
as an encrypted PDU: the UDP port and contents never appear on air.

| Time | From → to | MI | Key fill message (key-fill.md 4) |
|---|---|---|---|
| 12:52:00, :05, :10, :15 | 02 → 01 | 01A9F7F6 | COMMIT: the first try and 3 retries, all with the same MI; not acknowledged (below) |
| 12:54:52 | 02 → 01 | 33283F4E | COMMIT, a new session |
| 12:54:56 | 01 → 02 | F9E9A31E | RPUB |
| 12:54:59, 12:55:04 | 02 → 01 | 191C0438 | SPUB, and one retry under the same MI |
| 12:55:25 | 01 → 02 | A45CA164 | READY, after the users compared the code (about 21 s) |
| 12:55:28 | 02 → 01 | 57665C5C | KEY |
| 12:55:32 | 01 → 02 | A8A19905 | DONE |

The second session took 40 s from COMMIT to DONE, the code compare included. Both radios showed the same check value.

**Message indicators.** Radio B's MIs 01A9F7F6, 33283F4E, 191C0438 and 57665C5C are consecutive words of the DMRA
LFSR: DSD-FME's own 128-bit expansion of 01A9F7F6 is `01A9F7F6 33283F4E 191C0438 57665C5C`. Each packet used exactly
one position of the radio's MI sequence, and each confirmed retry reused its first try's MI, as dmr-data.md 13.4
specifies. Radio A's MIs come from its own sequence.

## Notes

- **The first attempt (12:52) was not acknowledged: receiver desense.** The radios were side by side. Through a
  repeater the sender transmits on the input at full power while the receiver decodes the output 5 MHz away; at a few
  centimetres that overloads the receiver's front end (it showed RX but decoded nothing). With radio A in another
  room the next session worked at once. key-fill.md and the user guide now say to keep radios apart through a
  repeater, or use a direct channel side by side.
- The repeater's output was not recorded; the completed fill shows it forwarded the packets.
- A stock radio's view of this AES data was not tested.
