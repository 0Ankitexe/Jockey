# Continuous integration

## Linux-first scheduling

The Linux-first roadmap preserves regression jobs.
Keep existing Windows/Ubuntu compiler/fixture regressions; they do not require
manual Windows work or establish real collector support. Revised Version 5 must
add exact Linux distribution/release/architecture/facility evidence. Native VM
ground truth is distinct from container/userspace checks. Windows artifact,
collector and agent work is outside the active roadmap (ADR-0023), not reported as passed.

GitHub Actions jobs live in `.github/workflows/ci.yml`. The Ubuntu and Windows
Rust jobs fetch locked dependencies, then run formatting, offline Clippy and
workspace tests. The Windows job excludes the Linux-only native collector crate;
the Linux adapter matrix tests it separately. The portable workspace checks include
the complete Version 0–3 suites and actual
`jockyc` binary tests on both newline/path platforms. The dedicated robustness
target uses a fixed seed and standard-library generation, so it is repeatable
without a fuzzing service.

Python jobs retain the Version 0 controller Ruff, mypy, and pytest gates and
explicitly check repository helpers with Ruff and pytest.
TypeScript jobs retain dashboard formatting, ESLint, type checking, Vitest, and
build gates. Compose validation checks configuration only and does not enable a
lab or endpoint adapter.

After dependencies are cached, all parser and fixture tests run offline. The
language core accepts caller-supplied text and performs no file, environment,
OS, network, runtime, forensic, or platform operation. Only the tested CLI
adapter reads the explicit input path and writes standard streams. Windows and
Ubuntu use the same grammar and AST contracts; there is no platform-specific
parser behavior.

## Legacy AST schema

Rust tests load `shared/compiler-contracts/ast-v1.schema.json` directly. This
tracked contract is available in a clean checkout; no schema preparation step
or planning directory is needed.

New compiler-contract tests use deployed schemas directly; they do not depend
on planning artifacts. Test temporary directories stay under `target/`.
Version 3 adds verified IR and fixture-only interpretation, not collection,
code generation, transport or endpoint execution.
Configured hosted jobs are not evidence of a hosted run; consult the release
verification record for checks actually executed.

## Version 3 gates

Both Rust jobs explicitly repeat deployed schema/report/safety tests and the
actual fixture/file-adapter integrations after the full regression suite. The
portable workspace suite includes 20 IR goldens, 36 verifier-negative artifacts, ten-run
library/CLI determinism, resource boundaries and three fixed-seed 10,000-case IR
campaigns. Each campaign has a five-minute harness budget; jobs have a 20-minute
ceiling. No fuzzing service, native collector or live endpoint is used.

Windows runs its junction/reparse/device/ADS and retained-parent cases; Ubuntu
runs Unix symlink/FIFO/socket cases. Shared path-rule/unsupported-adapter tests
are not a substitute for executing the native platform tests. Only dependencies
are fetched before tests; test commands use `--locked --offline`.

Historically the Version 3 `rust-version = "1.85"` declaration conflicted with
locked ICU/idna dependencies; that release did not claim an MSRV pass. V5 setup
narrows the minimum to the locally tested 1.98.1 instead of downgrading working
dependencies. See [Version 3 verification](../project-records/version-3-verification.md) and
[current implementation evidence](../project-records/version-5-verification.md).

## Version 5 offline setup gates

The additional Linux matrix checks exact Rust 1.98.1 and current stable, each
with core and optional journal builds. Journal setup installs libsystemd development
files in the ephemeral CI runner, not a collection endpoint. It does not enable
an adapter, collect a journal, modify security settings or establish live VM
support. All test commands remain locked and offline after dependency fetching.
Separate existing Ubuntu and Windows regression jobs remain present.

The standard-library-only dependency guard consumes Cargo metadata, checks its
completeness and rejects even transitive/renamed native dependencies from shared,
forensic contracts, IR, language, codegen and transforms. Malformed input exits 2;
a forbidden edge exits 1; a valid graph exits 0. It reads only supplied metadata.

```sh
cargo metadata --locked --offline --format-version 1 | python3.12 ci/check_native_boundary.py
controller/.venv/bin/python -m pytest tests/test_native_boundary.py
```

Native tests must remain data-only/injected by default. Future explicitly gated
VM scenarios are not run in this CI matrix. Hosted execution is **configured,
not observed**; no minimum-version Windows or live distro claim follows from a
local Linux build.

The [Version 5 regression record](../project-records/evidence/version-5/regression/)
lists exact local Rust, Python, dashboard and Compose commands and observed
results. The [Linux collector guide](../docs/reference/linux-collectors.md) gives the
separate, explicit, owner-approved VM command. A CI configuration check never
dispatches that live command. Source-to-typed-IR and standalone collection
remain separate; V6's source-to-native package path is a future binding.
