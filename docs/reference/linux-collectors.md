# Linux collector operation and trust

Version 5 is complete at its pinned Debian scope. `validate-inputs` and `verify-report` are local,
non-collecting commands. The explicit `collect --allow-live-lab` command now
joins owned collector children, canonical report finalization and a separate
output-only publisher. Complete, partial, failed, unsupported and no-output
paths have offline synthetic coverage; no such fixture demonstrates support
for a Linux distribution. The pinned Debian T165 checkpoint, T168 fault
campaign, T172 backend campaign and T178 one-cold/ten-warm LAB-SMALL campaign
have passed their scoped native gates. The active
test matrix is pinned Debian on one x86_64/glibc VM under ADR-0030;
Rocky, Ubuntu, Arch and Fedora V5 campaigns are withdrawn, not passed.
Debian evidence does not establish support for other Linux configurations.

## Inputs and admission

An owner prepares five explicit roles: endpoint designation, case
authorisation, collector policy, collection request and optional indicator
set. The first three are current-UID-owned regular files, mode 0600, under
trusted parents. Every path is supplied on the command line; there is no
default search, environment opt-in, stdout evidence or automatic permission
repair. The owner supplies a separate new output filename in a trusted local
directory. A collection request names a real case, operator and designated
isolated VM with a validity window. Example fixture IDs and expired dates
are for parser tests only.

Command shape and bounded input reads precede cross-document identity,
profile, validity, scope, indicator and output checks. A valid document is not
itself a reusable source permit. Native source metadata is opened only after
the sealed context is admitted. The effective scope is the intersection of
authorisation, policy and request; source IDs, path roots, time windows and
limits can only narrow. A denied preflight must make zero evidence-source
calls. The exact contract and current CLI shape are in
the versioned [collection schemas](../../shared/schemas/collection/README.md)
and the [native CLI guide](../../native/linux/README.md).

## Source boundaries

The [support matrix](linux-support-matrix.md) lists every Version 5 collector,
its implemented adapter, facility requirement and evidence status. Native
adapter metadata and per-run facility observations use separate versioned
descriptors; neither changes the legacy fixture language catalogue, whose
source-callable implementations remain unavailable. A compiled collector does
not grant authority or imply a present facility.

Service inventory queries the fixed systemd bus as the ordinary guest user;
it never starts or changes units. Persistence reads only explicitly selected
startup directories and parses systemd units, timers, cron and desktop entries
as inert text. RFC5424 syslog/auth reads require explicit selected readable
files and a caller-provided time window; there is no `/var/log` fallback.
Loaded modules come from the selected proc/sys facilities; the kernel address
and module-loading operations are excluded. Exact indicator matching compares
only admitted typed record fields against the supplied, case-bound set; absent
or incomplete candidate families remain unevaluated.

The optional `journal` Cargo feature needs the pinned `systemd` crate and
development `libsystemd` at build time. A run must still select a readable
journal file. The collector snapshots it into a bounded private `.journal`
file under `TMPDIR`, uses `OpenFilesOptions::open_files` on that owned copy,
then unlinks the copy as soon as libsystemd has opened it. For live collection,
set `TMPDIR` to an approved, owner-private scratch directory. A build without the
feature returns typed `Unsupported` for journal selection before reading it.
Journal group membership or other ordinary read permission may be necessary
in a guest; the collector does not repair permissions.

Ordinary evidence roots must be explicit local ext4/XFS/Btrfs directories.
Retained directory descriptors, `openat2` confinement, no-follow rules,
mount identity and inode checks prevent pathname replacement, traversal,
cross-mount reads and hard-link aliases. Configuration/output inodes and
overlapping source/output roots are excluded. Bounded enumeration includes
rejected entries in its budget; no whole-drive recursion or implicit home
discovery occurs.

Fixed kernel, process, network and module facilities use admitted source
kinds with code-owned `/proc` or `/sys` names. A selected systemd bus may use
only `/run/dbus/system_bus_socket`. Journal and text logs require explicit
path sources. Missing, denied and unsupported facilities have separate typed
results; a distribution name does not grant permission. Process collection
reads numeric PID metadata and verifies PID/start identity. Only `exe`,
`fd/N` and namespace link text are permitted metadata-link exceptions.
Reading an owned descriptor through verified `/proc/self/fd/N` is a narrow
content-reopen mechanism, not authority to follow another process's link.
Memory, `environ`, credentials, arbitrary proc entries and discovered
executables are outside scope.

Each evidence read is checked before and after, split into at most 64 KiB
chunks and charged even when a later failure discards the bytes. File metadata
is compared across the observed interval; mutation returns `SourceChanged`
instead of a complete prefix digest. The source boundary is described above.

## Time, workers and publication

The invocation clock starts before configuration reading. Evidence cutoff is
the earlier of the original deadline minus six seconds and the earliest
designation/grant/policy expiry. A source operation is bounded by two seconds
or the remaining evidence time. The reserved interval allows two seconds to
ask the single owned worker to stop, one second to kill/reap through its
retained process handle and three seconds to validate and publish an
incomplete report. A blocked kernel call may fail cleanup; the result must be
`CleanupIncomplete`, not a claimed successful stop. SIGINT/SIGTERM and clock
rollback stop new reads.

Only a fixed installed self image can be a worker. It has an empty inherited
environment, private Unix IPC and authenticated parent/descriptor bindings.
One worker is outstanding at a time. The publisher is a separate bounded,
output-only worker; it can create a private 0700 staging directory and 0600
new file, sync them and atomically install without replacing an existing
report. A failed write, sync, rename or cleanup is non-success and any owned
residue must be disclosed. Existing reports are never overwritten.

The hard ceilings are 64 MiB parent and 192 MiB worker address space, 256 MiB
aggregate peak RSS, 60 seconds whole run, 10,000 records, 10 MiB report,
64 MiB source bytes, 16 MiB per regular file, 64 KiB item and IPC chunk,
20,000 entries, depth 16, 10 million indicator comparisons, 1,000 errors
plus one omission summary, 80 MiB owned staging and up to 64 KiB reserved failure
report space. A frame is at most 131,072 bytes and an encoded record at most
98,304 bytes. Smaller authorised limits take precedence. See the exact
numeric limits above and the output rules in
[the local result model](cross-platform-result-model.md).

## What read-only means

The collector does not intentionally modify admitted evidence sources. A
normal read may update atime or produce audit/access records; it does not
promise an immutable disk snapshot or eliminate races with a privileged
writer. The supervisor's owned child processes and the publisher's owned
output/staging are operational effects outside source collection. The lab
harness may create benign test processes, loopback sockets and sample files
only within a separately authorised VM scenario, then clean its own objects.
None of these operations authorises changing protections or collecting from
the developer workstation.

## Testing and result interpretation

Offline fixtures and fault doubles prove parser, confinement, budget and
worker transition behavior. Native VM acceptance additionally requires an
independent ground truth for every requested category and the pinned
LAB-SMALL campaign: one cold plus ten warm runs on pinned Debian,
at least 11 raw samples. Each run must meet the 60-second, 256-MiB,
10-MiB-report and 10,000-record limits. Failed samples remain visible.
The pinned Debian campaign now satisfies these per-run gates; the
[raw evidence](../../project-records/evidence/version-5/debian/README.md) retains partial status and
typed unrelated permission omissions. The [Version 5 verification record](../../project-records/version-5-verification.md) records implementation and gate
status; [saved evidence](../../project-records/evidence/version-5/index.md) holds measured results. A valid local
report proves only that its bytes satisfy the schema/integrity checks; it
does not authenticate who collected it or substitute for native oracle data.

## First Debian checkpoint: preparation and commands

This procedure describes how the original **T165 live gate** was prepared.
The T165, T172 and T178 campaigns have now passed on the designated Debian VM;
their saved reports can be shown without collecting again. `.jky` source driving a
trusted native package is Version 6 work. Run these commands only inside the
owner-designated Debian guest after its separate current approval is recorded.
The development workstation and an unapproved guest are not substitutes.

1. The lab owner verifies the pinned Debian ISO/signature, VM snapshot,
   installed release/architecture/toolchain and collector executable digest,
   then records the VM inventory and product UUID. The harness inventory JSON
   has exactly `inventory_id`, `endpoint_id`, `vm_product_uuid`, `machine_id`,
   `vm_name`, `disk_image_path`, `disk_sha256_before_boot`,
   `kind: "isolated_vm"`, `distribution_id: "debian"` and
   `architecture: "x86_64"`. On the shut-off owner host,
   `tests.lab.linux.host_preflight` checks the libvirt UUID, pinned disk digest
   and absent NIC, then creates a one-hour record. The guest matches its
   readable `/etc/machine-id` to that inventory and record; readable DMI UUID
   must also match. Record the real case,
   operator and endpoint UUIDs, approval reference, UTC start/end and approved
   source/output roots. The guest account must already have ordinary read
   permissions; this procedure uses no sudo or permission repair.
2. The owner creates the four current JSON collection documents in a separate
   trusted configuration directory. Their schemas are
   `shared/schemas/collection/v1/{endpoint-designation,authorisation,policy,request}.schema.json`;
   field meanings and cross-document constraints are in
   the versioned [collection schemas](../../shared/schemas/collection/README.md). The designation
   must name the `isolated_vm` endpoint and approved operator. Authorisation
   and policy must both grant the exact scratch root with a shared `root_id`
   and `files` purpose, plus source groups `kernel_profile`, `proc_processes`
   and `proc_net`. Policy sources need approved IDs for those three kinds.
   The request selects those IDs and the ordered collectors `system`,
   `processes`, `connections`, `files`, with matching capabilities `system`,
   `processes`, `network`, `files`. All windows must be current and the limits
   must remain within the fixed contract. The harness adds only its own
   `PathRef` to a fresh request copy; it never widens authority or policy.
3. The owner separately supplies a `lab-scenario` 1.0.0 document matching
   `shared/schemas/collection/v1/lab-scenario.schema.json`. For the first
   checkpoint, `scenario` is `checkpoint` and `allowed_actions` contains
   exactly `create_benign_processes`, `bind_loopback_tcp`,
   `create_sample_files`, `cleanup_owned_objects`. Its approval, inventory,
   designation, authorisation, endpoint, case and operator UUIDs must link to
   the inventory and collection documents. Set `collector_sha256` to the
   actual pinned executable digest, `valid_from`/`valid_until` to the short
   owner-approved UTC window, and `owned_scratch_root`/`output_root` to distinct,
   owner-controlled, mode-0700 directories outside configuration and existing
   evidence. Include the recorded `cold_preparation_reference`. The expired
   `fixtures/valid/collection/lab-scenario.json` is a **parser fixture only**:
   its 2020 window and zero digest cannot authorize a run.
   Likewise, the collection document fixtures in that directory have the
   expired `2020-01-01T00:00:00Z` to `2020-01-01T01:00:00Z` window. Copying
   either fixture into a live command must produce a denial, not evidence.
4. Use absolute paths for every input, executable and new report. The
   executable and JSON inputs, including inventory, must be current-user-owned
   regular files without group/other write permission. The harness opens and
   hashes the executable,
   then executes that pinned inode for all three collector commands. Keep the
   guest product UUID from the verified host inventory; the harness compares
   the guest machine ID and checks DMI UUID when readable. A fresh report filename must be
   directly inside the approved output root.

The guest needs a verified copy of this repository and its pinned Python 3.13
test dependencies (`jsonschema`, `referencing`, and the controller test oracle)
installed in `controller/.venv`; check that environment before the approved
window. This is local harness tooling, not controller service deployment.
While the VM is shut off, run this on the owner host with a fresh output name:

```sh
controller/.venv/bin/python -m tests.lab.linux.host_preflight \
  --inventory <absolute-vm-inventory.json> \
  --output <absolute-new-host-preflight.json>
```

Retain that output and transfer its mode-0600 JSON to the guest with the
approved configuration. The host preflight is valid for one hour; after it
expires, shut off the guest, inspect the disk state and create a fresh record
before another run.
From the repository root **inside the approved guest**, first inspect the
non-collecting CLI and prepare the approved document paths. The values in
angle brackets below are owner-supplied and are not example authorisations:

```sh
<absolute-binary> validate-inputs --designation <absolute-designation.json> \
  --authorisation <absolute-authorisation.json> --policy <absolute-policy.json> \
  --request <absolute-request.json>

controller/.venv/bin/python -m tests.lab.linux.run_scenario \
  --allow-live-lab --scenario <absolute-lab-scenario.json> \
  --inventory <absolute-vm-inventory.json> \
  --host-preflight <absolute-host-preflight.json> \
  --binary <absolute-binary> --vm-endpoint-id <approved-endpoint-uuid> \
  --vm-product-uuid <verified-guest-product-uuid> \
  --inventory-id <approved-inventory-uuid> \
  --endpoint-designation <absolute-designation.json> \
  --authorisation <absolute-authorisation.json> --policy <absolute-policy.json> \
  --request <absolute-request.json> --report <absolute-new-report.json>
```

The first command checks logical document validity only. The second command
requires the separate scenario and `--allow-live-lab`, validates all inputs,
creates one short-lived benign process, one held loopback TCP connection and
one known sample file, invokes the collector's `validate-inputs`, `collect`
and `verify-report` commands, then cleans only verified owned objects. The
report remains in the approved output directory. On success, harness stdout
is a JSON summary with approval ID, independent process/socket/file facts,
report path, SHA-256, collector exit and report summary. Preserve that output,
the exact report bytes and digest under the T165 evidence directory. The
collector itself emits a bounded status JSON; it never prints report contents.

The collector exits 0 for complete and 2 for partial published reports. A
partial report is acceptable only when **all three seeded facts** still match
the independent oracle and omissions are visible. Setup/expiry/output
collision exits 3; wholly unsupported without evidence exits 4; failed
collection/publication/cleanup exits 5; local SIGINT exits 130. The harness
returns 0 only when the report is canonical, schema-valid, integrity-valid,
context-bound, independently matched and collector-verified; otherwise it
returns 1 and leaves any already-published report for inspection. An expired
`valid_until`, wrong VM UUID, wrong binary digest, missing opt-in, overlapping
roots or existing report must reject **before** scenario objects are created.
For a denial or collision demonstration, use a separately approved run with
the same safety gates; do not edit an approved document to make it pass.

## T165 Debian demonstration

The first real Debian checkpoint passed on 2026-10-15. Its complete
[approval, expected/observed facts, report and negative outcomes](../../project-records/evidence/version-5/checkpoint/debian/README.md)
are retained. The accepted report is partial because inaccessible process
ownership fields are reported as `PermissionDenied`; the three seeded facts
were still independently matched and cleanup completed.

To show the existing result without collecting again, start the shutoff VM
from the host and use its ordinary `jockylab` account:

```sh
virsh -c qemu:///session start jocky-v5-debian-13-7
virsh -c qemu:///session console jocky-v5-debian-13-7
# After guest login:
~/jocky-lab/bin/jocky-collect-linux-final verify-report \
  ~/jocky-output/t165-accepted-report.json
sha256sum ~/jocky-output/t165-accepted-report.json
python3 -c 'import json; from pathlib import Path; r=json.loads(Path.home().joinpath("jocky-output/t165-accepted-report.json").read_text()); print(r["summary"])'
```

The displayed SHA-256 should be
`87d4e779f5aa032baa53b954e55263ebe12084359d62d452d1c7c064a6e98c69`.
The repository copy can be viewed without starting the VM. A **new** live
collection needs a current approval window and a new shutoff host preflight;
the retained T165 documents expire and should not be reused as fresh
authorisation.

## T178 Debian LAB-SMALL replay

For a fresh approved run, build the collector with
`cargo build --release --locked --offline -p jocky-native-linux --features journal`
and pin its SHA-256 in a new scenario. Use `--profile lab-small-v1` with the
dispatcher command above, a `scenario: "lab-small"` approval, all six selected
collectors, the approved journal source and the exact
`lab-small-template-only` request path. Shut off and hash the VM disk, record
a new host preflight, then boot once and run the dispatcher as the ordinary
guest user. It creates five benign processes, five loopback socket pairs,
twenty sample files, ten journal markers and 1,000 frozen indicators; it
records one cold plus ten warm samples in `samples.jsonl`. A failed row stays
in that file and makes the campaign return nonzero. Report exit 2 is expected
when unrelated process/socket-owner fields are denied, but every seeded fact,
all per-run limits and complete worker cleanup must still pass. The exact
[accepted 2026-10-16 campaign](../../project-records/evidence/version-5/debian/README.md) can be
shown without another collection.

## US2 fault guarantees and repeatable negative checks

The [T166 offline fault ledger](../../project-records/evidence/version-5/faults/offline.md) maps each
limit, authority, confinement, stop, worker, publisher and privacy boundary to
unit/integration/negative tests. Run these from the repository root; they use
fixtures and test-owned temporary objects, with no VM collection:

```sh
cargo test -p jocky-forensic --test collection_limits --locked --offline
cargo test -p jocky-forensic --test authority_adversarial --locked --offline
cargo test -p jocky-native-linux --test path_races --locked --offline
cargo test -p jocky-native-linux --test worker_faults --locked --offline
cargo test -p jocky-native-linux --test publication_faults --locked --offline
cargo test -p jocky-native-linux --test worker_product_binary \
  parent_supervisor_drives_output_only_publisher_and_reaps_it --locked --offline
python -m pytest tests/lab/linux/test_faults.py -q
```

The last command needs the project's Python test environment with `pytest`.
These tests assert zero native source reads on denied permits and preflight,
nonrefunded charges for bytes already returned, terminal malformed IPC,
exclusive output and private publisher-stage cleanup. An unrecognized,
replaced or unremovable stage yields `CleanupIncomplete`; an owned worker
that cannot be reaped also fails the gate. A failed report is still a failed
collection even when its bytes are published. Each configured cap can narrow
the hard limits, never raise them. The collection schemas are
[documented here](../../shared/schemas/collection/README.md).

An exploratory Debian write fault exposed staging residue in an older binary.
The T166 correction passed a synthetic crashed-child regression; the corrected
release image then passed the [T168 native fault campaign](../../project-records/evidence/version-5/faults/native.md),
including an isolated publication fault with no new residue. The campaign did
not demonstrate filesystem-wide space exhaustion, a forced mid-read authority
expiry or interruption of kernel-uninterruptible I/O. See the
[T167 lifetime audit](../../project-records/version-5-verification.md#version-5-t167-us2-lifetime-audit--2026-10-15)
for the original fault analysis.
