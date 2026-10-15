# T179 native limits and recovery reconciliation

The pinned Debian [campaign](debian/README.md) retained one cold and ten warm
raw rows, with no failed accepted row or outlier removal. Each elapsed time
was 2,108–2,222 ms, aggregate peak RSS 67,862,528–78,225,408 bytes, report
size 681,396–686,177 bytes, accepted records 300–302 and source bytes
10,032,959–10,037,004. These are each below the unchanged 60,000 ms,
268,435,456-byte, 10,485,760-byte, 10,000-record and 67,108,864-source-byte
ceilings. All reports had complete owned-worker cleanup, seven distinct
sequential worker traces, known typed omissions and no unknown omission.

The separate [native T168 fault campaign](faults/native.md) passed traversal,
owned-source denial/disappearance/replacement, pre-admission expiry, two
SIGINT cancellations, the exact 10,000/+1 record boundary, exclusive output
collision and isolated publication failure. The original failed observations
are retained privately and are never relabelled as passes. The offline
[fault suite](faults/offline.md) covers mid-read expiry, clock rollback,
resource exhaustion and more boundary/+1 cases. Filesystem-wide ENOSPC and
forced native mid-read expiry remain **unverified**, as stated in the T168
record; no native result is invented for them.

The retained [raw samples](debian/samples.jsonl), [summary](debian/summary.json),
[reports and hashes](debian/sha256-manifest.json), T168 measurements and T172
backend reports are the audit trail. Earlier T178 diagnostic runs failed
resource reservations, a missing optional journal build or the harness's
fixed worker-count check; their separate private outputs are preserved and
excluded from the accepted campaign.
