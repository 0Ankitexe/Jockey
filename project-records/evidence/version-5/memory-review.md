# V5 schema-validation memory review

Date: **2026-10-09**. Scope: the user-approved memory-design revision, not V5
completion. **PASS for the early dependency probe; full T041 and live gates open.**
The [original failed measurement](resource-adoption.md) remains recorded.
[ADR-0019](../../decisions.md#adr-0019-validate-embedded-schema-definitions-at-build-time)
records the retained design. No native collection, VM or service was used.

## Cause, experiments and retained fix

The locked jsonschema 0.33.0 direct-root constructor checks definitions against
its recursive meta-schema and retains that validation state. The original core
release probe reached 105517056 virtual bytes after report verification; it
aborted during request initialization at the 67108864-byte supervisor limit.
Reducing regex caches and sharing only the registry did not resolve it.

This review first tried sharing the engine's own compiled pattern validators.
Its three unit/differential tests passed, but the supervisor still aborted. The
trial implementation/tests were removed; ADR-0018 preserves that failed choice.
A reference entry into the identical resources then passed initial admission,
but the expanded all-schema/hostile-scalar debug test exposed another allocation
failure. Combining reference entries with one shared immutable registry passes
the expanded checks. No failed experiment is counted as acceptance.

The mandatory Cargo build guard validates all thirteen complete definitions,
expected/unique IDs and references, including unused definitions, using the
unmodified engine and a deny retriever. The build and runtime share one embedded
inventory. Build failure is mandatory, not an optional CI convention. New nested
IDs or dynamic/recursive-reference mechanisms fail closed pending review.
At runtime the same engine compiles every validator and executes full input
rules, format checks and the unchanged strict JSON/typed/admission checks.
Nothing is prewarmed or transferred into the measured process. No schema bytes,
versions, dependency versions, legacy artifact or memory ceiling changed.

## What the probe tests

- Owned child only, fixed self executable, cleared environment, 15-second timeout;
  address-space limits are applied before any schema initialization.
- Synthetic expired authority with injected 2020 clock; no live authority or I/O.
- Admission, failure-envelope initialization and synthetic report verification.
- All thirteen document validators in one process, every document's exact byte
  ceiling/+1 (padding tests wire length, not maximum retained evidence).
- 256 path entries/+1, 1000 unique hash indicators/+1, and complete admission
  of all five input roles totaling 786432 bytes/+1 with 1000 indicators.
- A 10 MiB malformed scalar, excessive nodes/depth and sixteen repeated passes
  over all document kinds. Rejections assert typed reasons.
- Worker-only current-thread Tokio and zbus on an owned Unix socket pair;
  journal feature initializes real libsystemd against an owned invalid file.
- Own-process memory counters only: `statm`, `status` VmPeak/VmHWM, not endpoint
  evidence. No system bus, ambient journal, network connection or source scan.

## Recorded final release measurements

Exact Rust 1.98.1, x86_64 Linux development runner (not a designated VM), locked
offline dependencies and release builds. HEAD
`0f9049f6b8ad6a72fcbf36efd43425e9b553f94f` plus the uncommitted foundation/revision.
Each table row is a fresh owned process. Units are bytes; these are reported
process high-water marks, not a measured production process tree or LAB-SMALL.

| Build           | Role             | Enforced address-space limit | Reported peak virtual | Reported peak RSS | Exit |
| --------------- | ---------------- | ---------------------------: | --------------------: | ----------------: | ---: |
| Core release    | Supervisor probe |                     67108864 |              50810880 |          46424064 |    0 |
| Core release    | Worker probe     |                    201326592 |              50810880 |          46682112 |    0 |
| Journal release | Supervisor probe |                     67108864 |              52133888 |          46825472 |    0 |
| Journal release | Worker probe     |                    201326592 |              52137984 |          46780416 |    0 |
| Journal debug   | Supervisor probe |                     67108864 |              62345216 |          54919168 |    0 |
| Journal debug   | Worker probe     |                    201326592 |              62345216 |          55029760 |    0 |

The final core-debug rerun, including aggregate admission, also passed both
roles: each reported peak virtual memory 60952576 bytes; supervisor peak RSS
54333440 bytes, worker 54181888 bytes. Its log is `target/v5-memory-core-debug.log`.

Release core post-report virtual memory is now 22966272 bytes; journal is
24293376 bytes. Debug has less headroom; neither result promises that future
workers or maximum evidence sets fit. A new failure must again block adoption.
The unchanged aggregate acceptance ceiling is 268435456 bytes. These separately
run probes do not replace the eventual parent-plus-worker measurement.

Raw final command output is generated locally at `target/v5-memory-core-release.log`,
`target/v5-memory-journal-release.log`, `target/v5-memory-journal.log` and
`target/v5-memory-workspace.log`; logs are ignored build artifacts, not bundled
evidence. The metrics above and identities below retain the relevant observations.

## Reproduction

Use the installed repository-local toolchain/cache, or an equivalent configured
Rust 1.98.1 environment. The exports below identify this runner, not portable
installation requirements. All commands run from the repository root.

```sh
export PATH=/home/zer0/main/projects/jockey/target/v5-rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/home/zer0/main/projects/jockey/target/v5-cargo-home
cargo test -p jocky-shared --test collection_schema_build --locked --offline
cargo test -p jocky-shared --lib collection::schema::tests --locked --offline
cargo test -p jocky-native-linux --test resource_adoption --locked --offline
cargo test -p jocky-native-linux --features journal --locked --offline
cargo test -p jocky-native-linux --release --test resource_adoption --locked --offline
cargo test -p jocky-native-linux --release --test resource_adoption --features journal --locked --offline
```

Journal checks require already installed libsystemd development files; none were
installed for this revision. The probe deletes only its own temporary malformed
journal. No evidence or user file was deleted, and no Git commit was made.

## Reproduction identities (SHA-256)

| Artifact                                         | Digest                                                             |
| ------------------------------------------------ | ------------------------------------------------------------------ |
| `Cargo.lock` (unchanged)                         | `304f814361c7b378a5dd70061e2ec9d290fbc89e857c9163aea0f2d5faae29e2` |
| `shared/build.rs`                                | `4e6142961ea911ad385de42a0c339d22dbfef6759775d4be50d98cc746558089` |
| `shared/schema_build.rs`                         | `462c468d86faa5439da4f528d0733bb017ac7f568ec1638364e72ce18a55f762` |
| `shared/src/collection/schema.rs`                | `c07947fdb3a5ed5beb24114952cb4190e4e82277bf4ce86771c73035a36c7306` |
| `shared/src/collection/schema/resources.rs`      | `7233d2e47319366d3ac2268e0540ba0c154e8d87074e31733020974b9e47e1ec` |
| `native/linux/tests/resource_adoption.rs`        | `d2e3c5f40270a64efb330f1a96a688fd2630bdd5d35382d98bc8a0ad428126a0` |
| `native/linux/tests/resource_adoption/inputs.rs` | `77a3a80707743a51e854a8325c55de4816ccca017bd210f231e3712bc020a0c6` |
| Core release probe binary                        | `9ee5b0f5a65e603cec3928c47d1cfcda2b00631ff81ffe1264586765a66c63de` |
| Journal release probe binary                     | `8bcdb36b7cdee0af110fe4ceb4aa9f0fe30d0144de4ba139fa22d694e0944032` |

Local binary names: `target/release/deps/resource_adoption-d4e8638eacc8915c`
and `target/release/deps/resource_adoption-7f3fee06f5c15189`. Names are not stable
across toolchains. Fixture hashes remain as recorded in the original report;
all 362 protected legacy hashes match their baseline.

## Remaining acceptance

Five new tests cover the build guard and at least 2000 direct-root/reference-entry
fixture/mutation comparisons. Existing Rust and independent Python contract
tests remain required. Full regression results and the A–G hand-off are in
[the verification ledger](../../version-5-verification.md).

T023/T024 remain partial. Full supervisor/worker adoption, source confinement,
publication, core/facility collectors, usable CLI, portable compiler migration
and the five authorized VM campaigns remain open. No OP live gate, native
support matrix or V5 completion is claimed. Continue V5 only; V6 is a separate
request after genuine V5 closure.
