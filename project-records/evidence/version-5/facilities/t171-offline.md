# Version 5 T171 offline nine-collector integration — 2026-10-15

T171/T097–T103/T106 is offline implementation evidence. It does not close the
real Debian backend gate in T172 or the 11-run acceptance campaign.

| Inherited clause | Implemented result |
| --- | --- |
| T097 | Pure bounded exact SHA-256, path, IP-family and domain matching over eligible typed records only; absent/incomplete families remain unevaluated. The native adapter emits supplied-set digest, rules version and prior-record link, then verifies in a canonical report. No DNS, pattern matching or generic detection claim. |
| T098 | Nine collectors are dispatched: four core workers plus service, persistence, events and drivers workers; pure indicators are adapted after accepted prior records are renumbered. Separate versioned native adapter and runtime facility descriptors do not alter the unavailable-only fixture language catalogue. Missing and denied facilities retain typed per-source outcomes. |
| T099 | Four retained distribution trees carry synthetic service, four distinct startup formats, ten RFC5424 markers each and loaded-module facts. `family_matrix.rs` runs actual parsers and negative missing, malformed, denied, unsupported and changed-source cases. These trees are not native distribution proofs. |
| T100 | `tests/lab/linux/facilities.py` prepares only ledger-owned unit, timer, cron, desktop and syslog/auth samples after explicit scenario actions; each text backend has ten unique markers. It hands ten journal markers to a caller-supplied approved emitter. Unit/integration/negative tests verify action denial and cleanup. No test changes security logs or service state. |
| T101 | `facility_reports.rs` runs real service, persistence, text-event and module adapters over synthetic facts through canonical report/schema verification. Complete, denied-partial and all-failed outcomes, category, informational severity, input provenance, accepted-record counts and available fields are checked. The indicator report test checks set digest and linked record. |
| T102 | [Collector guide](../../../../docs/reference/linux-collectors.md) and [support matrix](../../../../docs/reference/linux-support-matrix.md) state explicit source/privilege requirements, optional journal build, and separate offline/native verdicts. |
| T103 | Both native configurations, four-family synthetic cases, pure indicator tests and Python harness tests passed with zero ignored native tests. See commands below. |
| T106 | [Evidence index](../index.md) reconciles all nine categories and names each missing native happy path without upgrading synthetic evidence. |

Verification commands from the repository root:

```sh
cargo fmt --all --check
cargo test -p jocky-forensic --test indicators --locked --offline -q
cargo test -p jocky-native-linux --locked --offline -q
cargo test -p jocky-native-linux --features journal --locked --offline -q
cargo test -p jocky-native-linux --test family_matrix --locked --offline -q
controller/.venv/bin/python -m pytest tests/lab/linux/test_facilities.py -q
controller/.venv/bin/python -m ruff format --check --config controller/pyproject.toml tests/lab/linux/facilities.py tests/lab/linux/test_facilities.py
controller/.venv/bin/python -m ruff check --config controller/pyproject.toml tests/lab/linux/facilities.py tests/lab/linux/test_facilities.py
git diff --check
```

The final full default native run passed **1,460 tests in 46 suites**; the
`journal` feature run passed **1,462 tests in 46 suites**. Both had zero failed
and zero ignored tests (`/tmp/jocky-t171-{core,journal}-final2.log` in the local
workspace session). The later family-matrix fault assertion was run separately.
Pure indicators passed 3/3 and facility harness tests passed 3/3.

The Debian T165 core checkpoint and T168 faults remain separate native
evidence. T172 still needs independently expected systemd service, every
startup format, real journal, selected RFC5424 syslog/auth and loaded-module
facts with typed native negative cases. Their cells remain unverified.
