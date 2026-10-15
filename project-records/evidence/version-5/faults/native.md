# Version 5 T168 native Debian fault campaign

The live cases ran on the pinned, network-isolated Debian 13.7 VM `jocky-v5-debian-13-7` as unprivileged guest `jockylab`. This is the sole V5 native OS campaign under ADR-0030. The current user delegated approval in chat for this VM and its owned objects. The records were admitted inside the guest at `2026-10-15T07:43:04Z` before the first fault. Approval ID `f8847f9c-2ed4-4b7e-8254-f9120db531f3`, inventory ID `6bba2b7c-c3f4-4fcc-8dbb-826a648d2967`, collector SHA-256 `df837e13e70ace469a17f9dc9c76a351d5dbd92171c2cafd59e6013774a174b6`. Four closed fault plans were admitted. The host preflight had verified the shutoff VM image, no NIC, storage identity and no stale reservation; the guest checked machine ID, product UUID, approval time, binary digest, document identity and owned roots before collection.

The original guest observations and input records are retained under private local `~/.local/share/jocky-v5-vms/debian-t168-faults/`; the shareable, data-minimised measurements are in [native-measurements.json](native-measurements.json). The prior T165 checkpoint evidence remains separate. This file reports actual native results, not offline stand-ins.

| Case | Native observed result | Verdict |
| --- | --- | --- |
| Scope traversal | `../escape` rejected `InvalidInput`, exit 3, 12 ms, before evidence read | PASS |
| Owned source denial | Mode `000` owned file: `PermissionDenied`, source bytes 0, failed report, cleanup complete, 110 ms | PASS |
| Owned source disappearance | Removed owned file: `NotFound`, source bytes 0, failed report, cleanup complete, 114 ms | PASS |
| Path replacement race | 8 runs, 4,192–4,483 owned path switches/run; `NotFound`, `SourceDisappeared`, or `SourceChanged`; zero source bytes and no out-of-scope sentinel in every report; cleanup complete, 153–174 ms | PASS |
| Expired authority | Derived policy with `valid_until` one second before invocation: `AuthorisationExpired`, exit 3, no report or worker, 11 ms | PASS |
| SIGINT cancellation | Four owned 16 MiB files; signals at 35 and 60 ms; both `Cancelled`, exit 130, stop reason `Cancelled`, cleanup complete, final report present, 148 and 133 ms | PASS |
| Limit exact / +1 | `max_records=10000` validated, exit 0, 17 ms; `10001` rejected `InvalidInput`, exit 3, 11 ms | PASS |
| Exclusive output collision | Existing T165 report preserved byte-identically at SHA-256 `87d4e779f5aa032baa53b954e55263ebe12084359d62d452d1c7c064a6e98c69`; `OutputExists`, exit 3, 16 ms | PASS |
| Isolated publication failure | `RLIMIT_FSIZE=1024` applied only to the owned collector process; `WorkerFailed`, exit 5, 503 ms, no final report, no new stage/output entry, no remaining worker PID | PASS |

The isolated publication fault used a kernel file-size limit on the owned collector process, without filling a shared disk. It reproduced the earlier publisher crash condition. The exploratory run with the previous binary left a private stage; that failed observation is retained privately and was not counted as a pass. The corrected binary produced no new residue. The accepted campaign did not assert a filesystem-wide ENOSPC result; that specific fault remains unverified. A mid-read expiry was also not forced in the VM; the native expiry result is the pre-admission denial, while the mid-read behavior has offline tests in `native/linux/tests/stop_faults.rs`.

Two exploratory variants were excluded from the accepted cancellation/expiry claims: a request event window ending in the past was a valid event filter and did not expire collection authority; a 20 ms SIGINT arrived before the signal watcher and terminated the process directly. A 90 ms SIGINT lost a race to the 64 MiB source-byte ceiling and reported `ResourceLimit`. Their original measurements remain in the private guest observation files. No accepted verdict depends on those variants.

The VM was not used for Ubuntu, Arch, Fedora or Rocky campaigns. Guest reports contain only owned lab paths and metadata. No endpoint or host policy was altered. The result does not claim an actual volume exhaustion or a mid-read clock-expiry demonstration.

## Reproduction and custody

The owner-approved records, ISO manifest, VM inventory, guest observations and exact test scripts are held in the private local `debian-t168-faults` directory and `/tmp/jocky_us2_{fault_run,remaining,finalcases,expiry}.py`. The guest binary and every transferred record were SHA-256 checked after mounting the ISO. `native-measurements.json` was generated from those observations with assertions that each accepted code, exit status, byte count, cleanup result and report-collision hash matches the expected outcome. The original private files must be kept if independent reanalysis is needed; `/tmp` driver copies are transient and the test sequence can be reconstructed from the cases above.
