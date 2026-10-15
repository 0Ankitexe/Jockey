# T179 independent native indicator reconciliation

The frozen LAB-SMALL owner dataset contains 1,000 predeclared indicators:
250 each for SHA-256, approved path, loopback IP address and the real
owner-provisioned `.invalid` hostname. Its labels contain 51 positives and
949 controls. The labels were built before the collector was invoked from
five owned processes, five loopback socket pairs, twenty 65,536-byte files,
ten journal markers and the VM hostname. No control was removed after seeing
the report.

The [11 raw Debian samples](debian/samples.jsonl) each have
`{"tp":51,"fp":0,"tn":949,"fn":0,"unevaluated":0}`. The independent oracle
checked every match ID against the frozen input set, the matched source
record and its actual field value. Every report also passed canonical
integrity, provenance and seeded process/socket/file/journal checks. Thus
SC-005 passes **for this controlled corpus on the pinned Debian VM**. This
does not estimate accuracy on other endpoint populations or OS configurations.

The underlying [reports and digests](debian/README.md) are retained. All
eleven indicator outcomes are partial because the unprivileged process and
connection collectors have typed `PermissionDenied` omissions; the controls
and all 51 seeded positives were still evaluated, with no unevaluated label.
