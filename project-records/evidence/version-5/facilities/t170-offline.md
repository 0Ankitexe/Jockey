# Version 5 T170 offline facility adapters — 2026-10-15

T170/T093–T096 is implemented offline. This record supersedes the earlier
[T170 checkpoint](t170-progress.md). It is not native backend acceptance.
No workstation or VM evidence source was read in these tests.

| Inherited clause | Implementation and test evidence |
| --- | --- |
| T093 | `sources/journal_snapshot.rs` pins only an admitted `JournalFile` path through `ConfinedRoot`, checks stable source identity before/through/after copying, and copies exact bytes into an anonymous worker-owned memfd. The policy's 16 MiB per-file cap and shared 64 MiB source-byte counter bound cumulative copies; staging writes charge the staging counter. The memfd has no filesystem residue after worker death. Owned synthetic source, rotation, short-copy, scope and cap tests pass. |
| T094 | Optional `journal` feature calls the real safe `OpenFilesOptions::open_files` on the staged descriptor's `/proc/self/fd/N` path. It does not discover host journals or call an unavailable fd API. Field expansion is bounded at 4096 bytes per message and charged through the caller; snapshot plus expansion is capped at 64 MiB. Entry count is bounded at 10,000, with a per-entry renewal hook. Event normalization retains microsecond UTC time and applies a half-open window. Default feature returns typed `Unsupported`. Injected facts and malformed staged data pass offline; a genuine journal happy path belongs to T172. |
| T095 | `sources/text_log.rs` reads only the selected path through admitted `ConfinedRoot` with a 65,536-byte cap and after-read identity check. Explicit Syslog/Auth roles have no fallback. `collectors/events/text.rs` accepts RFC5424 version 1 with UTC or numeric offset, preserves fractional precision, bounds lines and window, and rejects yearless/zoneless and unsupported structured-data forms. Empty, missing, denied, rotated and oversize inputs remain distinct. Owned scoped syslog/auth fixtures and negative tests pass. |
| T096 | `collectors/drivers.rs` reads only the fixed admitted `/proc/modules` and `/sys/module/{name}/{version,srcversion}` facts, emits typed missing or denied version fields, and never records the kernel address, loads a module, or invokes a package manager. Malformed names, oversized data and stop-budget propagation tests pass. |

Commands run after implementation:

```sh
cargo fmt --all --check
cargo test -p jocky-native-linux --locked --offline -q
cargo test -p jocky-native-linux --features journal --locked --offline -q
git diff --check
```

The full default native run passed 1,338 tests across 44 suites with zero
ignored; the journal feature passed 1,340 tests across 44 suites with zero
ignored (`target/t170-final-{core,journal}.log`). A final exact-size journal
copy adjustment passed its targeted journal suite after those full runs. No
native facility success, OP-01 or broad Linux support is claimed. T171 must
wire these private adapters into worker dispatch and evidence reports; T172
must test real Debian journal, text and module facts.
