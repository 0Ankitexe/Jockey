# Version 5 launch-control and owned-process evidence

Date: 2026-10-12. Constitution 1.2.0, ADR-0025. **Offline component evidence only**;
no endpoint collection, report publication or mandatory live gate has passed.

## Contract and isolation

Separate launch-control 1.1.0 is embedded beside the 13 unchanged original
resources. Its strict schema/decoder validates shape, versions, UUIDs/UTC,
unsigned OS numbers, monotonic clocks, global/reserved quotas, ordinal bases,
FD/config identity uniqueness and output-only publication separation. Fixtures
are explicitly synthetic; their PID/UID/inode values are not genuine observations.
Rust/Python cases agree and original worker v1 rejects the new document. The
decoder does not grant authority, verify actual objects or start a process.

Native in-memory launch framing caps the JSON document at 65536 bytes, delivers
one document, preserves a coalesced v1 tail and rejects malformed/truncated/replayed
input. Session binding checks the exact canonical first Start digest/job, original
admission clocks, report-wide bases and narrowed progress/record/error ceilings.
Worker-local budget narrowing keeps previous charges, global wire limits and
input provenance, rejects widening and does not renew a stopped lifetime. Zero
allowance means no work. Parent reservation/crash accounting is still pending.

## Owned-process test scope

`worker_ownership` is a harness-free **test executable**, not an enabled product
worker. It starts only itself, with fixed private modes, a cleared environment,
controlled stdio and an owned Unix socket pair. It checks actual kernel peer
credentials against parent/UID/start metadata and rejects wrong PID/UID/start
claims or pipes. The start-tick reader accesses only this process or its already
kernel-verified parent, with verified procfs and a bounded numeric stat path.
It never enumerates workstation processes, reads memory/environ/credentials,
opens a bus/journal/network endpoint or produces forensic evidence.

A test-owned interruptible sleeper is captured by an owned Child and pidfd,
terminated through that retained kernel process handle and bounded-poll reaped.
Post-reap signalling is rejected. No caller-supplied PID or process name is
signalled. Capture failures preserve the Child and return typed permission,
unsupported/resource/worker failures. Tests never fill a disk, alter security
settings, manufacture uninterruptible kernel work or signal unrelated processes.

StopSchedule tests use pure time/fault doubles. They preserve the original whole
deadline, at most two seconds cooperative stop plus one second reap and three
seconds finalization. Late stops receive no fresh windows; rollback and unreaped
work cannot become success. A selected action is not proof that a real worker
stopped. Signal-handler integration and actual resource supervision remain open.

## Test-first observations

Shared decoder, reservation API, native launch binding/framing, peer and stop
tests first failed on missing modules/methods. Their implementations made these
tests pass. The harness-free direct-module seam initially exposed an unused test
import; moving it inside the test fixed the lint. Clippy subsequently required a
collapsed early-exit capture condition; fixed without a lint suppression.
Neither historical expected results nor completed task rows were relaxed.

The shared Budget API is pure. Unit-style boundary cases and common-layer
integration/negative tests cover all eight narrowed counters, zero, previous
charges, widening, too-small ceilings, active-borrow conflicts and cancellation.
FD/PID claims still need actual binding at the future installed-worker entry.

## Resource and release status

Cold default/journal dependency probes include launch decoding and exact byte
boundary/+1 under the unchanged 64/192 MiB per-process design. They do not cover
the still-unimplemented supervisor/source/publisher pipeline or LAB-SMALL.
See the [A–G ledger](../../version-5-verification.md#launchowned-process-continuation--2026-10-12)
for actual commands/results. All 28 completed task rows remain unchanged;
T156/T157 and other unfinished V5 packages are still open. No authorised VM was
provided. This evidence cannot close OP-01/05, V5 OP-02/06 or a Linux support cell.
