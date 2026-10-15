# Version 5 evidence index

Current status: **Version 5 complete at pinned Debian scope; T165, T168, T172 and T178 native gates passed, T179 reconciled and release regressions passed**.
ADR-0030 and constitution 4.0.0 require only pinned Debian for current V5
native acceptance. Original Fedora, Ubuntu, Arch and Rocky VM campaigns are
withdrawn, not passes. Later release closure remains separate from the
accepted 11-run campaign.

| Operational obligation | V5 verdict and scope |
| --- | --- |
| OP-01 | Pass for standalone collector slice: [core checkpoint](checkpoint/debian/README.md), [all backend happy paths](facilities/t172-native-results.json), [11-run ground truth](debian/README.md) |
| OP-02 | Pass for V5 typed standalone inputs, portable compiler migration and documented future binding; V6 package execution is unverified in V5. See [verification](../../version-5-verification.md#us5-native-reconciliation--2026-10-16). |
| OP-05 | Pass for local identity, canonical provenance, typed omissions and exclusive publication; [native collision/faults](faults/native.md). No controller custody claim. |
| OP-06 | Pass for pinned Debian numeric LAB-SMALL and retained faults; forced native mid-read expiry and filesystem-wide ENOSPC remain [unverified](limits-and-recovery.md). |

The [approved template inputs, authority, image verification, binary and source
manifest](debian/README.md) identify the exact tested scope. The guest cleaned
generated per-run inputs; digest-checked reconstructions are explicitly
labelled in that record. [Raw samples](debian/samples.jsonl), [independent
indicator oracle](indicator-evaluation.md), [SHA-256 manifest](debian/sha256-manifest.json)
and [privacy review](debian/README.md#privacy-review) make the current results
auditable. The full FR/SC/OP verdict is in the [verification log](../../version-5-verification.md#us5-native-reconciliation--2026-10-16).

| Gate | Evidence available | Verdict |
| --- | --- | --- |
| Foundation admission, confinement, workers and publication | [Confinement](confinement.md), [worker reads](worker-read-foundation.md), [launch control](launch-control.md), [report foundation](report-foundation.md), [resource adoption](resource-adoption.md) | Offline checks only |
| US1 core system/process/connection/file collector and standalone CLI | [T161 offline closure](../../version-5-verification.md#t161-offline-collector-closure--2026-10-14), [T162 offline CLI closure](../../version-5-verification.md#t162-offline-cli-closure--2026-10-15), [native checkpoint](checkpoint/debian/README.md) | Offline and first Debian core checkpoint passed |
| First designated-VM checkpoint (T165) | [Approval, host/guest inventory, original report, independent expected/observed facts, denial, partial result and collision](checkpoint/debian/README.md) | Passed on pinned Debian VM |
| Debian native campaign (T135/T178) | [Approval, inventory, 11 raw samples, reports, summary and hashes](debian/README.md) | Passed on pinned Debian, one cold plus ten warm |
| Fedora native campaign (T137) | Withdrawn by ADR-0030; historical VM inventory only | Not required; not passed |
| LAB-SMALL 11 raw Debian samples, each within unchanged 60 s / 256 MiB / 10 MiB / 10,000-record ceilings (T179) | [Per-sample limits and fault reconciliation](limits-and-recovery.md), [indicator evaluation](indicator-evaluation.md) | Passed for pinned Debian; explicit remaining fault limits in linked note |
| Full nine-category backend, indicator, portable-language and regression gates | T169–T171 offline integration, [T172 native facility results](facilities/services-persistence.md), [T176 compiler verification](../../version-5-verification.md#version-5-t174t176-portable-compiler-implementation--2026-10-15), [T178 indicators](indicator-evaluation.md), [release regressions](regression/) | Passed for V5 scope; hosted CI unobserved |
| T166/T167/T168 fault work | [Offline fault coverage](faults/offline.md), [native Debian measurements](faults/native.md) | See linked gate-specific results |

## Nine collector categories and backend-specific evidence

| Category | Offline implementation evidence | Current pinned Debian native evidence |
| --- | --- | --- |
| System | [T165 core checkpoint](checkpoint/debian/README.md), [T169 source foundation](facilities/t169-offline.md) | T165 and 11 T178 system profiles passed |
| Processes | [T165 core checkpoint](checkpoint/debian/README.md), [T169 source foundation](facilities/t169-offline.md) | T165 and T178 owned PIDs matched; unrelated permission omissions partial |
| Services | [T169 source foundation](facilities/t169-offline.md); T171 dispatch/report tests | [T172](facilities/services-persistence.md): 92 records, independent `dbus.service` match; partial optional omissions |
| Connections | [T165 core checkpoint](checkpoint/debian/README.md), [T169 source foundation](facilities/t169-offline.md) | T165 and T178 owned loopback facts matched; unrelated owner omissions partial |
| Persistence | [T169 source foundation](facilities/t169-offline.md); T171 four-format synthetic parser/report tests | [T172](facilities/services-persistence.md): four native formats, missing and denied distinctions |
| Files | [T165 core checkpoint](checkpoint/debian/README.md), [T169 source foundation](facilities/t169-offline.md) | T165 and T178 twenty owned file hashes matched |
| Events | [T170 journal and RFC5424 adapters](facilities/t170-offline.md); T171 synthetic integration | [T172](facilities/events-modules.md): real journal plus ten markers per text backend, denied/empty distinctions |
| Drivers | [T170 loaded-module adapter](facilities/t170-offline.md); T171 synthetic integration | [T172](facilities/events-modules.md): all 73 loaded module tuples match; optional sysfs omissions partial |
| Indicators | T171 pure four-kind matching and synthetic report-link test | T178: 51/0/949/0 in each of 11 native reports |

The per-facility [support matrix](../../../docs/reference/linux-support-matrix.md) names ordinary
access and optional build requirements. A synthetic passed cell is never used
as a native happy-path verdict. T172's nine raw reports and SHA-256 values are
listed in [machine-readable results](facilities/t172-native-results.json).

No fixture, host probe, image verification, VM boot or pre-collection inventory
is counted as a native collector sample. T165 is a separate real checkpoint;
T178 has its own fresh approval, inventory, cold boot and 11 measured reports.

## Historical pre-checkpoint notes

On 2026-10-15 the Debian VM was booted only for read-only prerequisite checks.
Its ordinary `jockylab` account could not read the root-only DMI product UUID
required by the T163 harness; the harness fails closed. The guest was shut down
without a JOCKY collection run. No T165/T168 evidence was generated.

ADR-0030 (2026-10-15) supersedes the older two-VM rows above for current V5
acceptance. Only pinned Debian is required; Fedora is withdrawn, not passed.
The required LAB-SMALL count is 11 raw Debian runs (one cold, ten warm).
No native collection has occurred and all live verdicts remain unverified.

# T163 checkpoint harness status — 2026-10-15

T163 offline harness and 13 Python U/I/N checks passed. It has not been run on a
native VM. No live report, ground truth, collision case or Debian acceptance
sample is recorded here; T165 remains pending separate owner designation and
scenario approval.

## T164 offline MVP verdict — 2026-10-15

T163 was audited and hardened; its focused harness suite now passes 16 tests.
T164 documentation and offline regressions passed, as detailed in the
[verification log](../../version-5-verification.md#t163-audit-and-t164-offline-mvp-review--2026-10-15).
This is an **offline MVP implementation verdict**, not a demonstrated native
checkpoint. No T165 VM report, independent live oracle, denial/collision
observation or LAB-SMALL sample exists. The next live prerequisites are the
separate owner designation, verified Debian image/inventory, current
authorisation and scenario, pinned binary, approved roots and cleanup plan.
