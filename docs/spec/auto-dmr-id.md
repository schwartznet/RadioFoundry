# Auto DMR ID

Tools > Auto DMR ID sets the radio's own DMR ID from its chip's unique ID (UID), with no PC. Every radio of a fleet
gets its own ID, the same one each time, for example after an emergency wipe erased the codeplug. Meant for a fleet's
own range off the networks: the IDs aren't registered anywhere. Status: built and host-tested; not yet tried on a
radio.

Code: `core/support/auto_dmr_id.{h,c}` (the formula and the UID), `core/ui/ui_menus.c` (the tool),
`tools/dmrid_from_uid.py` (the same on a PC).

## 1. Switch and range

| Build value | Default | Meaning |
|---|---|---|
| `CONFIG_AUTO_DMR_ID` | n | The tool. Needs DMR |
| `CONFIG_AUTO_DMR_ID_BASE` | 4670000 | The first ID of the range |
| `CONFIG_AUTO_DMR_ID_SPAN` | 10000 | How many IDs: BASE to BASE + SPAN - 1 |

The build refuses a range outside 1 to 16776415 (the last private ID). The radio and the PC helper must use the same
BASE and SPAN (`--base`, `--span`). Flash and RAM: [feature-matrix.md](../feature-matrix.md).

## 2. The formula

The UID is the chip's 96-bit unique ID, as the debug link's INFO_CHIP returns it ([debuglink.md](debuglink.md)): three
32-bit words, taken high word first, each big endian. That is the 24 hex digits `rfoundry_debug.py chip` prints after
`uid`, read as 12 octets. Candidate k (0 to 255):

| k | ID |
|---|---|
| 0 | BASE + (SHA-256(UID) octets 0-3, big endian) % SPAN |
| 1-255 | BASE + (SHA-256(UID followed by one octet k) octets 0-3, big endian) % SPAN |

Example: UID `401065E42855394B68455CAF` gives 4678512 (candidate 0) and 4676328 (candidate 1) with the default range.
`tests/vectors/auto-dmr-id.txt` holds these and more, computed with Python's hashlib; the firmware's host test and
`tools/dmrid_from_uid.py --self-test` both check them.

Two radios of a fleet land on the same candidate 0 with a chance of about n²/(2 x SPAN): for 10 radios in 10000 IDs,
about 0.5 %. Check a fleet before deploying (section 4); a collision is resolved by using the next candidate on one
radio.

## 3. On the radio

Tools > Auto DMR ID is the last tool. It comes after the zone offer's 0, so it has no digit: open Tools and press Up.

| Row | Shows |
|---|---|
| This radio | The DMR ID in the codeplug now, or "Not set" |
| Auto ID | The ID of the candidate shown |

Above the rows: "From this radio's chip ID" and "Candidate k". OK saves the Auto ID as Settings > My Radio > DMR ID
does (`UI_SET_DMR_ID`, a codeplug write); "DMR ID saved" says it went, or "That is this radio's ID already". `#` shows
the next candidate (255 wraps to 0). Back leaves without saving. A radio whose board can't read a UID (no
`board.system` chip hook, or a UID of all zeros) says "This radio has no chip ID to use" and doesn't open the tool.

## 4. On a PC

`tools/dmrid_from_uid.py`:

| Command | Does |
|---|---|
| `dmrid_from_uid.py 401065E42855394B68455CAF` | The ID and the next candidates |
| `dmrid_from_uid.py --port COM60` | Reads the UID over the debug link first |
| `dmrid_from_uid.py --check UID1 UID2 ...` or `--check --file uids.txt` | A fleet: each radio's ID; a collision says which candidate the later radio should use. A UID listed twice is skipped |
| `dmrid_from_uid.py --self-test` | The formula against the shared vectors |

## 5. Tests

| Test | What |
|---|---|
| `autoDmrIdTest` | The vectors file; a real radio's UID gives 4678512; all 256 candidates in range; the next candidate differs |
| `uiFlowTest` (built with the tool) | The last tool; no chip ID refused; the ID and candidate shown; `#`; OK saves it as the DMR ID; Back |
| `dmrid_from_uid.py --self-test` | The same vectors on the PC |
