# Evidence for key check, key fill, group key fill, the emergency wipe and data on AES channels

Test records for the RadioFoundry feature request and pull requests from `schwartznet/RadioFoundry`. This branch holds
no code and is not meant to be merged: the recordings stay out of the pull requests' diffs, as the PR template asks.

| Folder | What |
|---|---|
| `keyfill-repeater-aes/` | Key fill between two DM-32UVs through a UHF repeater on an AES-256 channel, 2026-11-21: the raw SDR recording (48 kHz discriminator audio), DSD-FME's log and a README that walks through every message, its privacy header and MI |
| `tests/` | The local test run on each pull request branch, 2026-11-22: the DM-32UV build (zero warnings, flash and RAM), the stack check, every host test, the site tests, `i18n.py --check`, `boards.py check`, `license_grep.sh`, `check_generic.py`. The runs were on the same trees as the pushed branches, before the commits were signed (`git diff` between them is empty) |

Group key fill was tested on air between the same two radios on the same AES channel: radio B broadcast a stored
AES-256 key, radio A received it, showed the sender and check value and saved it, and both radios then showed the same
check value. That run was not recorded.

No key is in this branch: the test keys used on air are throwaway keys and are not published.
