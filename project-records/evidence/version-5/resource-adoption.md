# V5 resource-adoption finding

Historical failure retained unchanged below. The user-authorized follow-up
[memory review](memory-review.md) resolves this initialization finding under
the original limits; it does not close full T041 or native VM acceptance.

Date: **2026-10-09 UTC**. Verdict: **FAIL — required design review**.
This is an owned offline dependency probe, not endpoint evidence or an OP live
gate. T041 remains unchecked. See [ADR-0017](../../decisions.md#adr-0017-resource-adoption-failure-requires-design-review).

## Environment and scope

Repository HEAD: `0f9049f6b8ad6a72fcbf36efd43425e9b553f94f`, with the uncommitted
V5 foundation changes. Exact Rust 1.98.1, locked offline dependencies; development
runner, **not a designated endpoint**. No VM image/authorisation or native support
claim applies. Test-only logical time is `2020-01-01T00:00:10Z`; all authority
fixtures are deliberately expired in real time and labelled synthetic.

The harness launches only its own test executable, sequentially, with cleared
environment and null stdin; it retains the child handle and enforces a 15-second
probe timeout. Child limits apply before schema admission. It reads only its own
`/proc/self/statm` counters, creates an unnamed owned Unix socket pair, and, for
the optional feature, creates/removes an owned malformed journal under `target/`.
It never contacts a system bus, opens default journals or reads endpoint evidence.
Crash dumps are disabled only for the owned allocation-failure probe; no global
kernel/security setting is changed. The application itself remains unavailable.

The probe is harness-free to avoid libtest's background-thread allocator arenas.
Both debug and release builds fail. The release failure rules out a debug-only
binary-overhead explanation. The passing worker initialization is not proof of
maximum-input safety, live backend functionality or the full worker supervisor.

## Commands and result

Run from the repository root; the local verification toolchain is repository-owned:

```sh
export PATH=/home/zer0/main/projects/jockey/target/v5-rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/home/zer0/main/projects/jockey/target/v5-cargo-home
cargo test -p jocky-native-linux --test resource_adoption --locked --offline
cargo test -p jocky-native-linux --release --test resource_adoption --locked --offline
cargo test -p jocky-native-linux --release --test resource_adoption --features journal --locked --offline
cargo test -p jocky-native-linux --features journal --no-fail-fast --locked --offline --quiet
```

Each adoption invocation exits **101**, not success. Within each harness run the
64 MiB parent probe aborts (SIGABRT) during request-schema initialization; the
192 MiB worker probe exits 0. The optional-feature suite passes its 22 ordinary
tests but fails the adoption target. No test is ignored to conceal this failure.

The final release journal-enabled output includes:

```text
--parent-probe: signal: 6 (SIGABRT)
ProbeMemory:before-limit:virtual_bytes=13336576:rss_bytes=4165632
AddressSpaceLimitApplied:67108864
Initializing:endpoint-designation
ProbeMemory:endpoint-designation:virtual_bytes=31289344:rss_bytes=25636864
Initializing:authorisation
ProbeMemory:authorisation:virtual_bytes=32841728:rss_bytes=27250688
Initializing:policy
ProbeMemory:policy:virtual_bytes=33988608:rss_bytes=28659712
Initializing:request
memory allocation of 320000 bytes failed

--worker-probe: exit status: 0
ProbeMemory:before-limit:virtual_bytes=13336576:rss_bytes=4349952
AddressSpaceLimitApplied:201326592
Initializing:endpoint-designation
ProbeMemory:endpoint-designation:virtual_bytes=31289344:rss_bytes=25583616
Initializing:authorisation
ProbeMemory:authorisation:virtual_bytes=32845824:rss_bytes=27201536
Initializing:policy
ProbeMemory:policy:virtual_bytes=33988608:rss_bytes=28557312
Initializing:request
ProbeMemory:request:virtual_bytes=72704000:rss_bytes=67276800
AdmissionAndSchemaInitializationPassed
ProbeMemory:after-admission:virtual_bytes=106164224:rss_bytes=101085184
SyntheticReportVerificationPassed
ProbeMemory:after-report:virtual_bytes=106840064:rss_bytes=101859328
TokioAndZbusInitializedOnOwnedSocketPair
LibsystemdInitializedAndRejectedOwnedMalformedFile
ProbePassed
```

The final core-only release probe also aborts during request initialization
(`memory allocation of 632 bytes failed`). Its 192 MiB worker reaches
71,380,992 virtual bytes after request validation, 104,841,216 after admission
and 105,517,056 after report verification, then passes Tokio/zbus initialization.
Those are **instantaneous virtual/RSS readings**, not peak-RSS measurements or
the required native LAB-SMALL workload. They must not be added to the live matrix.

## Alternatives investigated

1. Reduce the locked validator's regex DFA cache to 65,536 bytes: same parent
   failure; worker virtual memory remains about 106 MiB after report verification.
2. Reuse one offline schema registry across validators: reduces the worker's
   post-report virtual memory to 104,599,552 bytes, but request validation alone
   still reaches 69,828,608 bytes and the 64 MiB parent still aborts.

Neither experiment changes schema validity or authority. Neither resolves the
gate; both were removed. The current validator retains its original offline
resolution and strict validation behavior. All 362 protected legacy hashes match.

## Reproduction identities

SHA-256 values observed after the retained edits:

| Artifact                                  | SHA-256                                                            |
| ----------------------------------------- | ------------------------------------------------------------------ |
| `Cargo.lock`                              | `304f814361c7b378a5dd70061e2ec9d290fbc89e857c9163aea0f2d5faae29e2` |
| `shared/src/collection/schema.rs`         | `882fb79f5cd42622ab3f9a484ab090525311532b94362319ea4562f67646243e` |
| `shared/src/collection/serialization.rs`  | `02f47cf60d1dadae45b6d26257cf3a0399fffb939bb913f4f336fdd47116a196` |
| `native/linux/tests/resource_adoption.rs` | `2c92dd6bfeb1b2dc3eac1eeabf53792b17e0a9122f73d730193499e11636df6c` |
| Core release probe binary                 | `30c371d116498052d1d07807af44f4a3a6697eda6c4c0d52b1edc9f2453686bf` |
| Journal release probe binary              | `d0cfd994690fd91fed6ea8cdc79387b8a99524b94bb0f6cc6bbda469bee6954a` |
| Synthetic designation fixture             | `8b96626c723f0c0c4301e574fc6cddf5446e0b591766f9929117d29a9553b738` |
| Synthetic authorisation fixture           | `4c4efd9ee20f65d2a9b225fa9a3512ebd0530b02250eb689309187c522cfe4ee` |
| Synthetic policy fixture                  | `33fa08ae1fddaf67f117252a47672a9d9720fe6257b7030ce569a2d723980e4b` |
| Synthetic request fixture                 | `610f93504075636e856385da3b172fade6de5ccb7c021b1841f05fc48df94466` |
| Synthetic report fixture                  | `0f04731c4be8f0471763d18a08f220ff63986cfe3301e3d58221057d2f766e0d` |

Fixture paths are under `fixtures/valid/collection/`; test-binary paths are
`target/release/deps/resource_adoption-ab04dd865b3543a7` (core) and
`target/release/deps/resource_adoption-202b6b8c63e63aa3` (journal). Binaries are
local build outputs, not bundled evidence or stable names across other builds.

## Required next decision

Review the validator/supervisor architecture before resuming collector work.
Retain the **256 MiB aggregate acceptance ceiling**, strict schemas and all
authority checks. Any changed process split or validation-worker role needs an
explicit safety-contract/ADR review before code. Then repeat the real default
and journal worker pipeline at maximum bounded inputs, including failures.
Do not prewarm outside accounting, remove the failed test, waive limits or
advance to V6. Native VM and complete OP-01/02/05/06 evidence remain unverified.
