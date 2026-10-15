# T172 Debian native events and loaded modules — 2026-10-15

This evidence uses the same approved pinned Debian VM, inventory, binary and
private report custody as [services and persistence](services-persistence.md).
The [machine-readable results](t172-native-results.json) identify the original
report paths and SHA-256 values. Raw journal reports contain unrelated user
journal messages; only counts and approved marker results are published here.

| Inherited assertion | Independent expected fact | Native report result |
| --- | --- | --- |
| RFC5424 syslog | Ten unique markers were written to an owned selected sample log before collection. | Each marker appeared exactly once in a complete report. |
| RFC5424 auth | Ten different markers were written to another owned selected sample log. | Each appeared exactly once in the same complete report; 20 event records total, zero errors. |
| Real journal | Ten markers were emitted by ordinary-user `systemd-cat` to the guest journal. The explicitly selected, readable `user-1001.journal` was independently opened by `journalctl --file`. | Each marker appeared exactly once; 781 journal event records in a complete report, zero errors. The collector used the optional `journal` build, a private bounded `.journal` copy in the approved scratch root, and unlinked that copy after opening it. |
| Loaded modules | A pre-run `/proc/modules` read recorded the first five tuples; an independent post-run read recorded all 73 name, size and reference-count tuples (file SHA-256 `f0872f5377411e735efde095f81a647e5189f340e247d7d9c6b0ddc9a69f532f`). | All 73 loaded-module records matched the full set; the pre-run five also matched. Optional sysfs version fields absent on some modules stayed `NotFound`; the driver source and report were partial with one visible omission error. No kernel address was retained. |
| Denied selected text log | The owned auth sample was temporarily mode `000`, then restored to `0600`. | `PermissionDenied` on that source; ten syslog events retained; partial report. |
| Empty selected text log | The owned auth sample was temporarily empty, then restored byte-for-byte. | No auth events or errors, ten syslog events; complete report. Empty is distinct from denied. |

The private originals are `reports/{text,journal,modules,text_denied,text_empty}-report.json`
under `/home/zer0/.local/share/jocky-v5-vms/debian-t172-facilities/`.
Nine final reports (five positive/backend cases and four negatives) passed the
independent Python strict report decoder and SHA-256 check. The service,
persistence, marker and module facts above were reconciled from the decoded
reports against separate guest observations; the native collector's own
`PublishedComplete`/`PublishedPartial` status alone was not used as the oracle.
The post-run scratch check found no `jocky-journal-*.journal` file; owned sample
permissions were restored.

The journal file was selected explicitly; the run did not search `/var/log` or
modify security logs. The sample text logs and startup objects remain in the
owned private scratch root for the user's later demonstration; the VM was
shut off after evidence capture. A later demo
needs a fresh validity window, host preflight and binary digest check before
another live collection.
