# Operational workflow and acceptance gates

## Numbering and scope amendment — 2026-10-11

ADR-0023 and constitution 1.2.0 group all Linux gates into current Versions 5–9.
**All Vn / Version n labels in the retained contract below are ORIGINAL scope
IDs Ln**, not new milestone numbers. L06 is current V6; L07/L08 are current V7;
L09/L10 are current V8; L11–L15 are current V9. V5 was unchanged by that
2026-10-11 numbering amendment; ADR-0028/constitution 2.0.0 later narrow its
native matrix to four VMs and 44 raw samples. The
[roadmap ownership table](../docs/reference/linux-first-roadmap.md#operational-acceptance-ownership)
maps every OP gate to its current owner. All Linux requirements, numeric profiles,
fault outcomes and native/live-service proof remain mandatory. Original Windows
scopes L04/L16 are outside the active plan; no Windows milestone is scheduled.
Internal component and connected gates remain distinct inside current V7.

Current ADR-0029 / constitution 3.0.0 further narrows required V5 native testing to Debian and Fedora, 22 raw runs total; Ubuntu and Arch VM campaigns are withdrawn, not passed. Per-run and security gates remain unchanged.

Current ADR-0030 / constitution 4.0.0 supersedes that V5 matrix: pinned
Debian alone requires one cold plus ten warm runs and at least 11 raw samples.
Fedora is withdrawn, not passed. Per-run, trust, backend, fault and security
gates remain unchanged; later milestones retain their own acceptance.

## Retained Linux acceptance contract (original scope numbering)

Accepted **2026-09-27**, [ADR-0014](decisions.md#adr-0014-operational-workflow-and-live-acceptance-gates).
This is the retained Linux acceptance specification for original scopes V5–15, not implementation evidence.
It refines constitution 1.1.0 and the [Linux-first roadmap](../docs/reference/linux-first-roadmap.md);
its Linux security and technical requirements remain unchanged by ADR-0023; completed Version 0–3 contracts are preserved.
Each future specification, plan and task list must map applicable gate IDs below
to implementation tasks, positive/negative tests and evidence paths. The matching
version prompt must be read together with this document, not in isolation.

## Before implementing each milestone

The feature plan must freeze the current milestone's interfaces/schema versions,
compatibility migration, threat assumptions, error/state semantics, dependency
direction, test oracles, workload thresholds and evidence locations before task
generation. Resolve implementation-affecting choices there, not by inventing
incompatible contracts mid-implementation. Include a gate-to-task checklist with
unit, integration, negative and lab cases; retain unresolved infrastructure as
an explicit blocker to the affected live gate, never a waived criterion.

Before any live run, record exact VM images and authorisation, isolated service
addresses, test-owned paths/processes, resource quotas and cleanup/restore plan.
Pin and verify the actual supported toolchain; the existing Rust minimum-version
conflict must be resolved before claiming minimum-toolchain compatibility.
Only Linux operational work is in the active scope. This readiness work does not require building
later versions early or collecting from the development workstation.

## Intended workflow and current position

```text
Operator authorises case, endpoints, scope and limits
    -> JOCKY source -> parser/type checker -> verified IR
    -> trusted target package
    -> controller assigns an authorised task
    -> authenticated endpoint runs bounded read-only collectors
    -> controller validates and durably stores attributable evidence
    -> dashboard shows results, omissions and failures -> verified export
```

JOCKY is a custom domain-specific programming language, implemented using Rust
and Pest. Its frontend, typed IR, verifier and fixture interpreter exist today.
The real catalogue remains unavailable; all four fixture providers, including
indicator correlation, return authored data. V5 collector foundations are partially implemented; working native collectors,
packages, agents, tasking, durable remote evidence and an investigation UI remain
unavailable. See current-state.md for incremental evidence. Current tests
validate compiler/fixture properties, not live forensic accuracy or deployment.

## Gate ownership and dependency order

| Gate  | Owner                                                        | Required outcome; all are currently unverified                                                                            |
| ----- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| OP-01 | V5                                                           | Authorised standalone collection on named Linux VMs, independently checked ground truth, policy/permission/limit failures |
| OP-02 | V5 design/contracts; V6 execution                            | A real `.jky` program drives scoped collectors through a verified native package; no fixture fallback                     |
| OP-03 | V6 package trust; V7 protocol and agent; V8 connected gate   | Trusted packages and authenticated, authorised tasking before network-triggered collection                                |
| OP-04 | V7 local recovery; V8 durable base; V10 full matrix          | Explicit task transitions, durable acknowledgement, bounded retry and no duplicate accepted evidence                      |
| OP-05 | V5 local provenance; V8 storage/export; V9 UI; V10 streaming | Case-attributable evidence with integrity-checked export, visible partial failures and access control                     |
| OP-06 | V5–10 incrementally; V15 release                             | Fixed workloads, resource limits, repeatable measurements and fault/soak evidence                                         |
| OP-07 | V8 API; V9 browser; V10 two families; V15 release            | Real source-to-Linux-endpoints-to-dashboard workflow, not a simulator-only demonstration                                  |
| OP-08 | V11–14 Linux regression (current V9)                         | Later protection/research/adapters preserve the live Linux path                                                           |

Version 7 owns a versioned agent protocol, shared request/response schemas and
an agent-facing OpenAPI contract before client implementation. Its TLS test peer
is explicitly a test double. Native supervision must run on a designated VM,
but V7 closure is **component acceptance**, not connected deployment acceptance.
Version 8 implements the actual controller against that protocol and closes the
connected gate with real PostgreSQL, Redis and at least one native Linux agent.
Version 8 includes a minimal working build/dispatch/result/export path; V10 adds
fairness, concurrent multi-family execution and the full failure matrix. V9 may
therefore demonstrate the real browser workflow without waiting for V10.

ADR-0023 authorises delivery grouping only, not early implementation. The original
V7 component checkpoint must list the original V8 connected gate as pending;
current V7 cannot close until both are satisfied. Missing mandatory live evidence in any other
milestone remains failed/unverified; it cannot become a completed live milestone.

## OP-01 / OP-02: scoped language-to-collector execution

- V5 defines versioned typed collection inputs alongside `CollectorPolicy`:
  approved roots, requested paths, UTC event window, explicit indicator set,
  capabilities and time/record/byte limits. Unknown fields and excessive nesting,
  sizes, invalid windows and unsupported versions reject with typed errors.
- Effective scope is the intersection of operator/case authority, task request
  and endpoint-local policy; limits use the most restrictive value. Source code,
  configuration and privilege metadata cannot broaden that authority. V5's local
  authorisation is an operator-controlled lab declaration, not remote identity
  proof; V7–8 add authenticated origin. Document who controls each trust input.
- V5 records a binding design for opaque JOCKY types (`path`, `timestamp`, etc.)
  and registry signatures. Do not pretend strings implicitly convert to domain
  types. Prefer versioned typed context/accessor contracts over unrelated syntax
  expansion; preserve old source and fixtures. V6 implements the chosen binding,
  including any minimal explicitly versioned compiler changes it requires.
- V6 supplies runnable `.jky` examples that use approved paths, a time window
  and supplied indicators. Tests trace source hash, entry, IR/instruction identity,
  contract versions, native adapter and returned evidence. The program selects
  the calls; a standalone hard-coded collector script does not satisfy OP-02.
- Invalid inputs reject before collection. Test scope widening, path traversal,
  symlink replacement, denied facilities, expiry and cancellation during work.
  Recheck validity at dispatch/start and during bounded execution; an expired or
  revoked authority stops further collection when observed, with partial evidence
  labelled. Long blocking operations need bounded workers/deadlines and cleanup.
- Keep `parse`, `check`, `build-ir`, `verify-ir` and `run-fixture` non-collecting.
  Real execution is a separate package/runtime boundary. IR verification is not
  an OS sandbox; do not execute arbitrary uploaded binaries or shell commands.

## OP-03: trust before first connected execution

V6 must authenticate a canonical, versioned package manifest with a maintained
standard signing library and a locally configured trusted build public key.
The signed manifest binds artifact/component digests and lengths, source/IR,
build/package IDs, target/ABI, entry, capabilities and configuration schema.
Private keys are generated outside version control; no embedded development
private key, custom cryptography or trust in a public key supplied by the package.
Verify before execution, bind the task to the verified digest, and prevent file
replacement between verification and launch. Test changed artifact AND changed
manifest/digest, unknown/revoked signer, wrong target and version downgrade.
Signing authenticates origin, not safety: only the approved compiler/build path
may create executable packages; collectors still enforce endpoint policy.

V7 defines and tests, and V8 implements end to end:

- Direct HTTPS with hostname/chain/expiry validation and an explicitly installed
  lab CA; no insecure-skip-verification or HTTP fallback in execution mode.
- Single-use enrollment tokens, endpoint-bound and expiring within 15 minutes;
  subsequent per-endpoint credentials, protected local storage and revocation.
  Choose and freeze mTLS or scoped short-lived tokens in the protocol ADR. Record
  issuance, renewal, rotation and compromise recovery without logging secrets.
- Operator authentication with case-scoped viewer/investigator/admin permissions;
  agents access only their own assignments/uploads, never operator APIs. Test
  cross-case reads, launches, exports and cancellations, not just unauthenticated
  requests. Cover browser session/CSRF/CORS behavior for the chosen auth design.
- Execution grants bound to case, task, target, package digest, policy and expiry;
  maximum grant lifetime five minutes, refreshed for longer approved tasks. Offline
  agents cannot start new tasks on expired grants. Revoke immediately at controller
  boundaries and stop an isolated agent by grant expiry; measure this bound.
- Durable replay/idempotency keys, bounded clock skew (at most 30 seconds), and
  rejection of unknown endpoints, stale/revoked credentials, wrong-target tasks,
  expired grants, malformed/oversized data and unsupported algorithms/versions.

Publish a threat model and enrollment/renewal/revocation runbook before enabling
connected execution. V11 adds payload envelopes; V13 extends transport adapters.
Neither is permission to postpone TLS, identity, authorisation or package trust.
Do not claim safety against a compromised root user, build signer or lab CA.

## OP-04: authoritative state and failure recovery

Keep the existing task states exactly: `queued`, `assigned`, `delivered`, `running`,
`completed`, `failed`, `cancelled`, `expired`. A partial evidence summary is NOT a
ninth task state. Version the summary and reason codes separately. Per-target
transitions and parent-task aggregation must be documented and concurrency-tested.

Normal path: queued -> assigned -> delivered -> running -> completed/failed.
Cancellation/expiry may terminate a nonterminal task; terminal states never reopen.
`delivered` means durably accepted by the agent, not merely written to a socket.
`completed` requires durable validated evidence and its final summary at the
controller. Partial collector results must carry explicit omissions/errors and a
partial summary even if execution terminates normally. A crash/interruption is
failed with its reason, not successful empty collection. Immutable terminal races
use transactional compare-and-set rules; duplicate requests return the recorded
outcome, and conflicting replays reject. Preserve late evidence as explicitly
attributed partial evidence where authorised, without rewriting terminal history.

PostgreSQL is authoritative; Redis is a notification/cache layer. Use transactional
outbox/reconciliation or an equivalent tested atomic hand-off. Agent acceptance
and pending uploads need a bounded durable local journal/spool. No exactly-once
execution claim: an uncertain interrupted collection is reported as such and is
not blindly rerun. A new collection requires a separately authorised task ID.

| Injected failure                                            | Required observable outcome                                                                                          | First owner / full gate |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| Controller restart after DB commit, before publish/ack      | Reconcile assignment; retry returns same identity; no lost committed task                                            | V8 / V10                |
| Redis unavailable or loses queue data                       | DB tasks remain; bounded degraded delivery; rebuild notifications without duplicate execution                        | V8 / V10                |
| PostgreSQL unavailable                                      | Readiness fails; no new durable-acceptance claim; typed retryable errors and bounded agent spool                     | V8 / V10                |
| Agent restart before/after spawn                            | Journal reconciles; interrupted execution fails explicitly; owned child is stopped/reaped; no blind rerun            | V7 / V10                |
| Disconnect or interrupted upload                            | Preserve bounded spool; resume/retry by stable batch IDs/digests; acknowledge only durable verified bytes            | V8 / V10                |
| Duplicate task/status/result, including concurrent requests | One accepted assignment/evidence identity; identical retry returns prior outcome; conflicting payload rejects        | V7–8 / V10              |
| Agent or controller evidence volume full                    | Stop/deny additional work; no overwrite, false completion or unbounded memory retry; retain recoverable partial data | V7–8 / V10              |
| Cancel, expire or revoke during collection                  | Stop within the documented bound; terminate only owned workers; label partial evidence; reject late starts           | V7–8 / V10              |
| Result object written but DB commit/ack fails               | Reconcile staging/orphans and digest; no visible uncommitted evidence; retry cannot duplicate accepted records       | V8 / V10                |

Fault tests run only against isolated test services/volumes/owned processes, never
by filling the host disk or terminating unrelated processes. Include failures
immediately before and after durable boundaries, recovery/restart, asserted
task history, spool cleanup and independent stored/exported record counts.

## OP-05: evidence lifecycle

Record case/operator authority, endpoint identity, observed UTC time and time
uncertainty, task/target where applicable, source/build/package/collector versions,
policy digest, indicator-set/rule version, record IDs, provenance and typed
omissions. A local V5 report must not invent remote task IDs. Design versioned
schemas/relationships instead of silently widening existing messages.

V8 provides protected storage and a minimal manifest-plus-records export; V9
exposes it in the UI and V10 extends it for streams/files. Verify sizes, schema
versions and SHA-256 at ingestion and export; test altered, missing and truncated
files. Audit collection, upload, access and export without evidence in logs.
Do not claim tamper-proof custody or legal admissibility from hashes alone.

Set and document retention, explicit authorised deletion and bounded spool/staging
cleanup. No automatic deletion of evidence by test/demo reset scripts. V8 tests
backup/restore of both PostgreSQL and evidence objects into a separate lab
instance and reconciles manifests; V15 repeats it in the release rehearsal.
Stored lab evidence remains access-controlled before V11; V11 adds its documented
cryptographic envelope protection without relabelling earlier plaintext storage.

## OP-06: measurable acceptance profiles

These are initial **required test targets**, not measurements or current support
claims. Freeze them in each feature plan before implementation. If a target is
infeasible, report the failing measurement and propose a reviewed ADR/profile
revision; never silently raise a threshold, omit slow samples or call it passed.
ADR-0030 narrows the current V5 native configuration matrix to pinned Debian.
LAB-SMALL still requires 1 cold + 10 warm runs on that VM (11 raw samples);
every per-run ceiling below is unchanged.
Rocky/RHEL-compatible support is not claimed or tested by this matrix.

Record VM image hash/release, kernel, libc, architecture, CPU model/allocated vCPU,
RAM, storage, init/log facilities, security policy, network latency, toolchains,
lockfiles and build profile. Use release binaries. Report cold and warm results
separately, raw samples, median, nearest-rank p95, maximum, failures, peak RSS
(including owned workers), output bytes and accepted/omitted record counts.
Resource limits and deadline/cancellation tests apply even on failed runs.

| Profile              | Workload and repetitions                                                                                                                                                                                                                         | Passing target                                                                                                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LAB-SMALL, V5–6      | Each claimed x86_64/glibc VM: 2 vCPU, 4 GiB RAM; five owned benign processes, five loopback TCP connections, twenty 64-KiB known files, 1,000 supplied indicators; ten controlled events where a log backend is supported; 1 cold + 10 warm runs | Each run <=60 s, aggregate peak collector/package RSS <=256 MiB, report <=10 MiB and <=10,000 records; all seeded in-scope facts verified; no silent truncation                                                   |
| LAB-CONNECTED, V8–10 | Controller 2 vCPU/4 GiB plus recorded PostgreSQL/Redis resources; two LAB-SMALL VMs from different families on an isolated LAN; 10 tasks targeting both, then 60-minute soak with one task/minute targeting both                                 | Healthy dispatch-to-start p95 <=5 s; end-to-durable-result p95 <=90 s; all authorised healthy runs reach correct terminal results; zero duplicate accepted evidence or lost acknowledged records                  |
| LAB-CONTROL, V7–10   | Ten cancel/expiry/retry trials; inject each applicable OP-04 fault at least three times at recorded boundaries; limits at boundary and boundary+1                                                                                                | Cancel stops owned work <=5 s after receipt, cleanup <=5 s more; expiry/revocation obey grant + skew bound; after service restore, pending delivery/upload reconciles <=60 s; no scope escape or false completion |

V8 may run LAB-CONNECTED on one VM for its minimal integration gate; the full
two-family profile is mandatory at V10 and V15. V7 measures local receipt-to-stop
with its peer; V8 adds actual network/auth enforcement. Define per-service memory,
CPU, queue and disk quotas numerically in V8 planning before implementation; show
usage remains within them during the soak. Simulators supplement scale testing
but cannot replace the native agents. Hard record/byte caps must reject/stop with
typed partial/limit results, not hide evidence to hit performance targets.

The harness owns ground truth: record spawned PIDs/start identities, bound socket
endpoints, seeded file bytes/independent hashes and log markers before invoking
JOCKY. A second call to the collector is not an independent oracle. Assert stable
seeded facts, not equality of changing system-wide snapshots. For indicators,
include known positives and negatives and record TP/FP/TN/FN on that controlled
dataset only; do not market the result as general malware-detection accuracy.

## OP-07 / OP-08: release proof, not a staged mock demo

Offline tests remain mandatory and default. Explicit integration/lab runs require
authorised endpoint IDs, case, operator, validity interval and isolated service
inventory before any live I/O. Native VM kernel/permission evidence cannot be
replaced by containers; real PostgreSQL/Redis service integration may use Compose.

V9's browser test must launch a real source-derived package and show independently
checked evidence and denied/partial results through the real V8 stack. Mock UI
tests remain separate. V10/V15 use two different Linux families; V15 additionally
rehearses clean-clone setup, backup/restore, trust rotation/revocation and the full
failure/performance matrix. Fix or explicitly narrow the advertised Rust minimum
with actual toolchain evidence; configured hosted CI is not an observed pass.

V11/13 require real end-to-end reruns for envelope/transport changes. V12's fixture
equivalence corpus and V14's harmless simulations remain valid research evidence,
not replacements for native acceptance. Keep them optional in the operational
demo and prove the ordinary read-only workflow still works with them disabled.
No prohibited adapter becomes permissible to make the project look realistic.

Each gate report must identify commit/tree digest, scenario/profile version, exact
commands, timestamps, VM/service inventory, non-secret authorisation reference,
expected independent facts, observed outputs/digests, raw metrics, audit/status
correlation and pass/fail/unverified per assertion. Store only benign/sanitised lab
evidence in Git; keep secrets and private evidence outside it. A screenshot alone
is not proof. Never pre-seed successful task rows or evidence for the live demo.

There are two distinct demos: a labelled offline fixture demo and the live lab
demo. Missing live infrastructure means **live acceptance unverified**, not a
fallback pass. A complete Linux release requires OP-01–OP-07 and applicable
OP-08 Linux regressions. Additional operating-system work is outside the active plan. This is readiness
for the documented authorised lab profile, not general production certification.
