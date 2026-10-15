# Version 5 T169 offline facility foundation — 2026-10-15

T169 adds only the bounded service source, service normalization, persistence
parsers and the seven requested test files. The source modules are private to
the native crate. They are not yet wired into the standalone worker; T171 owns
that wiring and T172 owns native facility happy-path acceptance. No bus, host
service, journal or startup location was read by this campaign.

| Inherited task | Files and executed evidence | Result |
| --- | --- | --- |
| T082/T089/T090 services | `native/linux/tests/services.rs`, `src/sources/systemd.rs`, `src/collectors/services.rs` | Fixed ListUnits/ListUnitFiles/Properties.Get routes, system-bus Unix socket, NO_AUTO_START, 8-message main queue and 2-second per-call limit. Injected success, denial, timeout, oversize, forged-path, non-systemd and partial-property cases passed. No bus method mutates or activates units. |
| T083/T091/T092 persistence | `native/linux/tests/persistence.rs`, `src/collectors/persistence/{systemd,cron,autostart}.rs` | Owned confined startup path, symlink escape, malformed input, 64-KiB bound, changed source, denied read and inert target-reference cases passed. Systemd unit/timer, numeric cron and desktop-entry formats remain distinct. Parsers do not follow or run declared targets. |
| T084 journal | `native/linux/tests/journal.rs` | Half-open time and unavailable-field contract passed; optional safe `OpenFilesOptions::open_files` API type-check passed under `journal`. One injected reader/snapshot test remains ignored until T170 implements that adapter. |
| T085 text events | `native/linux/tests/text_events.rs` | Time/source contract vector passed; one injected RFC5424 reader test remains ignored until T170. It specifies offset, unknown-zone, yearless, empty, missing, denied, rotation and size cases. |
| T086 drivers | `native/linux/tests/drivers.rs` | Typed module fields and excluded address/path fields passed; one proc/sys join test remains ignored until T170. It specifies malformed names, missing version and size limits. |
| T087 indicators | `forensic-lib/tests/indicators.rs` | Four-kind case-bound admission/normalization and wildcard/IDNA/CIDR/zone/duplicate negatives passed. One exact-match/provenance/unevaluated test remains ignored until T171 adds the pure matcher. |
| T088 mixed facilities | `native/linux/tests/facilities.rs` | Selected system capability, source authority and complete/denied/partial result rules passed without native source access. |

All four ignored tests contain explicit expected outcomes and currently return
`NotImplemented` from test-only pending functions. They are **not** backend
passes. T170/T171 must replace those functions with actual adapters, enable
the assertions and demonstrate their real permitted happy paths. T169 does not
claim OP-01/05/06 native facility acceptance.

## Commands and measurements

```sh
cargo fmt --all --check
cargo check -p jocky-native-linux -p jocky-forensic --locked --offline
cargo test -p jocky-forensic -p jocky-native-linux --locked --offline -q
cargo test -p jocky-native-linux --features journal --locked --offline -q
git diff --check
```

The final default focused run passed **1,167 tests across 62 suites**, with
**four** explicitly ignored future-adapter contracts (`target/t169-final-focused.log`).
The optional-journal native run passed **1,057 tests across 44 suites**, with
**three** ignored future-adapter contracts (`target/t169-journal.log`). After
the final route and reference assertions, the affected service/persistence and
seven-file targeted suites passed. Formatting, `cargo check` and diff checks
passed. The installed Clippy driver reports Rust 1.98.0 while these packages
require 1.98.1; it stops before linting, so no Clippy pass is claimed. Cargo
metadata's offline full-graph read also lacked cached `memoffset 0.9.1`; the
native-boundary script was not counted as a pass. No dependencies were fetched.

The existing T165 Debian checkpoint and T168 native fault results are unchanged.
