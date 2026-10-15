# Version 5 ordinary-file confinement evidence

Date: 2026-10-09. Constitution 1.1.0; ADR-0021. **Offline evidence only**.
T026/T031 are complete; the ledger has **28/155 checked tasks**. Version 3 is
still the latest completed release. No live collector, endpoint observation,
portable compiler profile or Version 6 feature was enabled.

## Scope and test isolation

The new public `ValidatedCollectionContext::path_scope` method returns inert
metadata for an already admitted path-bearing target. It does not open anything,
mint authority or replace the future native lab gate. Native code stays in a
Linux-gated private module; compiler/shared modules import no native operations.

The integration seam compiles that private module directly into its test binary.
All content targets, FIFO/socket paths, aliases and replacements are test-owned
objects in temporary directories under repository `target/`. Tests clean only
those objects; they do not scan or collect the developer workstation. Resolving
the test path checks ancestor metadata; owned-FD reopening uses only this test
process's descriptor through verified procfs. The synthetic input timestamps and
injected clock are test data, not permission for live host collection.

No mounts, devices, privilege changes, service calls or network endpoints were
created. Mount/filesystem/device faults use injected statx values or errno maps.
These tests cannot certify native mount behavior on the five planned VM images.

## Coverage

| Behavior                                                                                                                          | Tests                                                                                                   | Limit of the evidence                                                               |
| --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Only admitted file/journal/log/startup paths get ordinary-root metadata                                                           | `forensic-lib/tests/collection_api.rs`                                                                  | Not a native admission or trust gate                                                |
| Traversal, absolute/NUL/malformed/oversized paths and depth limits                                                                | `native/linux/tests/confinement.rs`, `tests/support/confinement_scope.rs`, `src/sources/paths/tests.rs` | No directory enumerator yet; non-UTF-8 discovery belongs to T032 and later adapters |
| Symlink/magic-link/parent-link, hard-link, FIFO, socket and directory rejection                                                   | `native/linux/tests/confinement.rs`                                                                     | Tests own the objects; no host evidence is read                                     |
| Root retention, replacement before reopen, inode exclusions, mode denial                                                          | `tests/support/confinement_races.rs`, `tests/confinement.rs`                                            | Config/output exclusion inventory still belongs to T030                             |
| Missing statx flags, unsupported filesystems, same-device different-mount substitution, owner/device/link/type/mtime/ctime checks | `src/sources/metadata/tests.rs`, `src/sources/mod.rs`                                                   | Injected negative cases, not privileged/live mount tests                            |
| Read-only/CLOEXEC handles and post-open mutation                                                                                  | `tests/confinement.rs`                                                                                  | No hashing, bounded content reader or collector yet                                 |
| Before/after operation cutoff, cancellation/expiry, sticky limit failure and charged missing entries                              | `src/sources/operation/tests.rs`, `tests/support/confinement_races.rs`                                  | A wrapper cannot interrupt a kernel-blocked call                                    |

There are **22 distinct new test cases**: one pure API case, nine private native
guard cases and twelve native integration/race cases. The nine private unit
cases also run through the direct-module integration seam, giving **31 additional
workspace test executions**. The focused native library/confinement run has
36 passing executions including six pre-existing native library tests.

Tests exercise both the count boundary and next attempted operation; prior entry
charges are retained in a typed synthetic failure report. A missing path still
costs an attempted entry. Failure/cancellation after a syscall discards its result
and prevents subsequent calls; a fresh operation permit cannot revive a stopped
context. I/O permission errors remain typed, not silently empty results.

## Descriptor and filesystem rules

Each root ancestor is pinned before descent, requires trusted ownership and no
group/other write permission, and must have recognized local filesystem metadata.
Root ancestry can cross a trusted local mount; descendants cannot cross mounts.
The final root cannot be `/`, proc/sys/dev scope or a mount root. Required statx
mount/automount information cannot be replaced by a guessed device-only check.

The file object is pinned without content access before type/link/alias checks.
Only the retained own descriptor is reopened; never the evidence pathname.
Identity and mutation fields are checked before/after reopening and after future
reads. A renamed root still denotes its original retained directory. Changes can
yield SourceChanged; on filesystems with coarse timestamps, a renamed file may
still yield the unchanged original object, but never its replacement. Incidental
atime changes are deliberately not treated as content mutation.

The allowlist uses ext-family/XFS/Btrfs magic; the shared ext2/3/4 value is not an
ext4-version proof. No new distribution support claim is made. The read path
requires openat2, statx mount identity and verified own procfs. Missing facilities
fail closed; there is no ordinary-open fallback. Unsupported container/overlay
roots remain unsupported, not silently accepted for convenience.

## Test-first and verification record

Before editing, the existing Rust baseline passed **450 executions**, controller
checks passed **91 tests**, and dashboard checks/build passed **18 tests**.
The initial confinement suite failed compilation because the source module did
not exist (`target/v5-confinement-red.log`). Implementation made the first seven
cases pass; further adversarial/metadata/clock cases expanded coverage.
Clippy then detected a duplicate test-support module import. Moving shared test
support to the crate root resolved it without suppressing the lint. No old test,
schema, golden or fixture expectation was relaxed.

Reproduction commands and complete regression results are in the
[A–G hand-off](../../version-5-verification.md#confinement-a-g-hand-off--2026-10-09).
Local raw logs use `target/v5-confinement-*.log`. The implementation skill guided
prerequisite/checklist inspection, tests before implementation, task tracking and
verification. Its optional Git hooks were offered, not executed. No staging,
commit, push or dependency installation occurred.

## Remaining limitations

T023 end-to-end accounting, T030 complete source/output capability inventory,
T032 charged/interruptible reads, workers/protocol/resource enforcement,
publication and actual collectors remain open. The helper cannot independently
interrupt a stalled kernel call, prove snapshot immutability or authenticate the
local declaration. Full T041 adoption is not satisfied by the passing early
dependency probes. The native CLI still returns NotImplemented/Unsupported.

No VM designation or scenario approval was supplied. OP-01/05, the V5 OP-02/06
obligations, LAB-SMALL and the full pinned Linux matrix remain unverified. Fixtures
cannot close those gates. Next work remains Version 5; Version 6 requires genuine
V5 closure and a separate implementation request.
