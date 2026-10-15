# Local collection result model

This document describes the Version 5 wire contract. The native collection
command has accepted pinned Debian checkpoint, backend and 11-run LAB-SMALL
evidence, with partial reports and independently matched controlled facts.
A schema-valid
fixture or report verifier result is not evidence of a completed Linux
collection. The deployed schemas under
`shared/schemas/collection/` are authoritative for encoded shapes. The
Version 5 encoded contract is detailed in the versioned schemas under
`shared/schemas/collection/` and their [inventory](../../shared/schemas/collection/README.md).

## Identity and version boundaries

The local context has one collection, case, operator, endpoint, designation,
authorisation and policy UUID. Every record, manifest and report repeats that
same context. The designation is an owner-supplied assertion for an isolated
VM, not an enrolled agent identity or a machine fingerprint. The report kind
distinguishes `live_lab` from `synthetic_test`; synthetic evidence cannot be
relabeled as a native result.

Collection inputs, status and worker frames use their separately declared
`1.0.0` schemas. `ForensicRecord` and `EvidenceManifest` use `2.0.0`. The
additive worker launch control document uses `1.1.0`; it does not widen the
worker frame schema. These numbers are wire versions, not product milestone
numbers. Historical Windows and Ubuntu contracts retain their original meaning.

## Observed facts and outcomes

An `EndpointObservation` states `os_family`, architecture, distribution and
release, kernel, ABI and current namespace from observed fields. A requested
distribution is never copied into an observed field. A missing or denied
facility is an explicit typed state. `Field<T>` distinguishes an observed value
from absent, denied, unsupported or changed data; an empty successful result is
different from failed collection.

Each `ForensicRecord` is a typed category/record-type payload with one source
ID, admitted scope and observed interval. File stability and process PID/start
identity are local observations, not claims that the disk or process table was
frozen. Record sequence is contiguous across the whole report. Manifest
entries address the embedded canonical record bytes and SHA-256 digests;
report verification checks structure and integrity, not legal provenance or
authenticity of a remote sender.

Collector outcomes and report summary preserve complete, partial, failed,
unsupported and not-requested distinctions. Accepted observations remain in a
partial report after a later source fault or cancellation. An item error does
not create a fictitious successful record. One bounded omission summary can
explain an exhausted error budget. A failed report remains a non-success even
if its JSON was published successfully.

The local status is a separate bounded diagnostic. It contains IDs only after
validation and a report digest only after exclusive publication. It never
contains evidence payloads, credentials or raw library stderr.

## Scope and source claims

Effective collection scope is the intersection of the owner designation,
case authorisation, local policy and explicit request. A request can narrow
capabilities, source IDs, root paths, time window and numeric limits; it cannot
add a source or extend expiry. Authority and policy root IDs must refer to the
same exact base path. The minimum applicable limit wins. The sealed admitted
context grants a fresh operation permit only while the original whole-run and
authority clocks still allow evidence work.

Ordinary files use explicit local ext4/XFS/Btrfs root handles and confined
relative paths. `/proc` and `/sys` are separate fixed, typed facility groups;
their names are selected by code, not by a requested path or distribution
label. The only process link reads are bounded metadata for a numeric PID's
`exe`, `fd/N` and namespace link. The implementation may reopen an already
owned file descriptor through its own verified `/proc/self/fd/N` entry; that
exception never turns a discovered process link into a content source. No
memory, environment, credential or arbitrary proc path is a collection input.

## Resource envelope

The maximum whole invocation is 60 seconds. Evidence stops at the earlier of
the original deadline minus six seconds and the earliest authority expiry.
Each source operation gets at most two seconds and cannot renew that cutoff.
The last six seconds reserve up to two seconds for cooperative stop, one second
for owned-worker kill/reap and three seconds for report publication. Clock
rollback stops new evidence reads. Finalization may use already admitted
observations after evidence authority expires, within the original deadline.

Parent and sequential worker address-space ceilings are 64 MiB and 192 MiB;
the aggregate acceptance ceiling is 256 MiB. Per-request limits may only
narrow these values. Maximums include 10,000 records, 10 MiB report, 64 MiB
source bytes, 16 MiB per regular file, 64 KiB per item/chunk, 20,000 entries,
depth 16, 10 million indicator comparisons, 1,000 item errors plus one
summary, and 80 MiB owned staging (64 MiB snapshots plus 16 MiB report).
An IPC frame is at most 131,072 bytes and a canonical record at most 98,304
bytes. The deployed input schemas are under `shared/schemas/collection/`; a successful result
must pass both the requested and hard caps.

The worker's source allowance is reserved before launch. A crash consumes
unacknowledged allowance; an observed valid `Done` can release only proven
unused quota. Reads, rejected entries, errors, retries, comparisons, retained
allocations, serialization and staging attempts are charged without refund.
The terminal failure envelope is reserved before ordinary report serialization.

## Local trust and effects

The owner supplies explicit local authority and policy files, mode 0600 under
owner-controlled parents. The request cannot choose a worker executable, bus
address or fallback source. A private child accepts only the fixed self image,
owned Unix channel, verified parent and transferred descriptor bindings.
This protects against accidental misuse under the local account model; it is
not a defense against compromised root, kernel or replacement installed code.

Collector source adapters read admitted content and do not intentionally alter
it. Ordinary reads can still change atime or trigger host audit/access effects;
there is no immutable disk snapshot guarantee. The supervisor creates and
reaps only its own worker processes. The output-only publisher creates private
staging and a new report; the separately authorised lab harness may create
benign test objects and cleans only its own objects. These operational effects
are distinct from read-only source collection. No collector changes system
protection, escalates privilege or executes discovered content.

## Fault outcomes and evidence strength

An admission denial has no evidence read and no new report. `SourceChanged`,
`SourceDisappeared` and `PermissionDenied` name distinct source outcomes;
observed bytes and errors are charged even if no record is accepted. A
cancelled or expired permit cannot yield another source read. `ResourceLimit`
at a counter boundary may lead to a typed partial or failed report, never an
unmarked prefix. `WorkerFailed` consumes the unacknowledged reservation;
`CleanupIncomplete` takes precedence when an owned child or staging object
cannot be safely removed. `PublicationFailed`/`OutputExists` never overwrite
an earlier report, and a publisher crash cannot be called a successful
publication merely because a staging file exists.

The [offline boundary campaign](../../project-records/evidence/version-5/faults/offline.md) checks
these rules with injected failures and owned temporary paths. The [T165 Debian
checkpoint](../../project-records/evidence/version-5/checkpoint/debian/README.md) covers the first
four collectors; [T168](../../project-records/evidence/version-5/faults/native.md) records native
stop/cleanup, scope, disappearance, permission and limit faults; and
[T178](../../project-records/evidence/version-5/debian/README.md) retains 11 real LAB-SMALL reports.
A kernel-blocked cleanup
or exceeded 60-second/256-MiB/10-MiB/10,000-record ceiling fails the relevant
gate, even if a partial report is valid. No backend-specific journal or
systemd permission claim follows from generic offline tests.

The negative suite can be replayed without live collection:

```sh
cargo test -p jocky-forensic --test collection_limits --locked --offline
cargo test -p jocky-native-linux --test stop_faults --locked --offline
cargo test -p jocky-native-linux --test publication_faults --locked --offline
python -m pytest tests/lab/linux/test_faults.py -q
```

## V6-only source binding design

V5's portable compiler profile describes unavailable source calls and does not execute the native collector. V6 must bind a minimally versioned immutable investigation context to each selected endpoint invocation after validating authority, policy, typed approved paths, bounded event windows and supplied indicators. Accessors return opaque `path`, `timestamp` and future `indicator_set` values; source text cannot invent them from strings. A new `forensic.indicator.match` signature would consume the supplied indicator set, while legacy `correlate` remains Windows/Ubuntu-only and is not widened. The proposed language 3.1.0, vocabulary/registry 2.1.0 and IR 2.1.0 tuple requires a separate reviewed migration. Until then, no native dispatcher, package execution or fixture fallback exists in the compiler path. Local collection reports retain their independent case/operator/endpoint context and must not acquire fabricated task, package or runtime IDs.
