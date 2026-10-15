# Version 5 Linux support matrix

This matrix distinguishes installed code, a facility observed at collection
time, and native acceptance. Version 5 is complete at its pinned Debian scope. ADR-0030 requires
only the pinned Debian 13.7 VM for native acceptance. Ubuntu, Fedora, Arch and
Rocky are not current VM campaigns. Their retained trees are parser fixtures.

| Collector | Standalone native adapter | Runtime dependency and ordinary access | Offline result | Pinned Debian native result |
| --- | --- | --- | --- | --- |
| System | Kernel profile | Selected proc mount and OS release | Passed synthetic U/I/N | T165 and all 11 T178 reports complete; real hostname/OS facts matched |
| Processes | Proc process metadata | Selected proc mount; readable process entries | Passed synthetic U/I/N | T165 and all 11 T178 reports partial for typed `PermissionDenied`; all five owned PIDs/start identities matched |
| Services | Systemd bus | Read access to fixed system bus; systemd running | Passed injected bus and report tests | T172: 92 real service records, partial for optional `NotFound` and one malformed row; independent `dbus.service` values matched |
| Connections | Proc network tables | Selected proc mount; readable tables | Passed synthetic U/I/N | T165 and all 11 T178 reports partial for typed owner `PermissionDenied`; all five owned loopback pairs matched |
| Persistence | Selected startup directory | Explicit local root with readable unit, timer, cron or desktop files | Passed all four format parsers and synthetic report tests | T172: all four native formats and typed missing/denied cases passed |
| Files | Selected ordinary root | Explicit local root and readable selected file | Passed synthetic U/I/N | T165 and all 11 T178 reports complete; 20 owned 65,536-byte files and hashes matched |
| Events: RFC5424 syslog/auth | Selected text files | Explicit readable log paths; no implicit `/var/log` discovery | Passed synthetic UTC/window/denial tests | T172: ten markers per backend, typed denied/empty cases passed |
| Events: journal | Optional `journal` build | `libsystemd` at build time; readable explicitly selected journal file and approved private `TMPDIR` at run time | Passed staged journal and feature tests | T172 and all 11 T178 reports complete; ten unique approved markers matched per run |
| Drivers | Proc module list plus sys metadata | Selected proc and optional sys mount; readable module metadata | Passed synthetic module/parser/report tests | T172: all 73 loaded tuples matched; partial for absent optional version fields |
| Indicators | Pure exact matcher | Supplied, admitted indicator set and prior typed records | Passed four-kind pure and report-link tests | T178: all 11 partial outcomes preserve source omissions; independent four-kind TP 51, FP 0, TN 949, FN 0, unevaluated 0 per report |

The **tested support cell** is Debian 13.7 x86_64, glibc 2.41, systemd with
a readable selected user journal on the pinned isolated VM, running the
`journal`-enabled binary. Other Debian releases/architectures, Ubuntu,
Fedora, Arch, Rocky, musl, containers, non-systemd init/log facilities and
Windows are **unverified native configurations** for this V5 campaign.
Missing or denied facilities retain typed partial/unsupported outcomes;
fixture coverage for four Linux families does not extend this native cell.

| Configuration | Native V5 verdict | Basis |
| --- | --- | --- |
| Debian 13.7 x86_64/glibc 2.41, systemd and approved journal | Tested; per-collector complete or partial as above | T165, T172, T178 |
| Other Debian releases or architectures | Unverified | No pinned native run |
| Ubuntu, Fedora, Arch, Rocky | Unverified; VM campaigns withdrawn | ADR-0028/0029/0030; offline fixtures only |
| musl, containers, non-systemd init or other log facilities | Unverified | No native acceptance configuration |
| Native Windows collection | Unverified/outside active roadmap | No V5 implementation or run |

The native adapter inventory is versioned separately from the unavailable-only
fixture language catalogue. Runtime coverage is another versioned observation:
`supported`, `partial`, `unsupported`, `permission_denied` or `unavailable`
belongs to an admitted source in one run. A compiled adapter cannot establish
facility presence, source authority or distribution support. A missing journal
build reports `Unsupported`; a denied selected source reports
`PermissionDenied`; an empty readable source is a supported empty observation.

The [evidence index](../../project-records/evidence/version-5/index.md) links native proof. The
[collector guide](linux-collectors.md) describes source selection, limits and
the Debian procedure. [T178](../../project-records/evidence/version-5/debian/README.md) supplies
the 11-run campaign; T172 separately covers the implemented service,
persistence, text-event and driver backends.
