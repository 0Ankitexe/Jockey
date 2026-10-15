# T172 Debian native services and persistence — 2026-10-15

The pinned, isolated Debian 13.7 VM `jocky-v5-debian-13-7` ran the standalone
journal-enabled binary as ordinary `jockylab`, with no NIC. The shutoff disk
hash/VM XML passed `tests.lab.linux.host_preflight` before boot. The sealed
scenario, owner designation, authorisation, policy, approval record and binary
SHA-256 were checked in the guest before sample preparation and collection.
The final inventory ID was `8ad1b881-5df7-4b33-8103-13b23bc29994`; the
binary SHA-256 was
`7acce507f27ae2072436e356f5609809fcfa9d873040f9fb0dbadad8d514de13`.
The original owner records and unredacted reports are in the private
`/home/zer0/.local/share/jocky-v5-vms/debian-t172-facilities/` directory.
[Machine-readable results](t172-native-results.json) give each report's local
path, byte count, SHA-256 and status. Those private reports include observed
system descriptions and remain outside the repository.

| Inherited assertion | Independent expected fact | Native report result |
| --- | --- | --- |
| Systemd service inventory | `systemctl show` observed `Id=dbus.service`, `LoadState=loaded`, `ActiveState=active` before collection. No unit was started or changed. | 92 service records; `dbus.service` had the same three values. The overall report was `partial`: absent optional unit-file fields were `NotFound`, and one malformed bus row was omitted as `MalformedSource`, with two visible errors. The service source coverage was partial, not an empty success. |
| Systemd unit | Owned `units/jocky-demo.service` bytes and SHA-256 were recorded before collection. | One matching `systemd_units` record and content digest. |
| Systemd timer | Owned `timers/jocky-demo.timer` bytes and digest were recorded. | One matching `systemd_timers` record and content digest. |
| Cron | Owned `cron/jocky-demo.cron` bytes and digest were recorded. | One matching `cron` record and content digest. |
| Desktop autostart | Owned `autostart/jocky-demo.desktop` bytes and digest were recorded. | One matching `autostart` record and content digest. |
| Missing startup directory | The owned timer file and empty timer directory were removed only for this negative run, then restored. | Three other startup records; `NotFound` error for the selected timer source; `partial` report. |
| Denied startup directory | The owned cron directory was temporarily mode `000`, then restored to `0700`. | Three other startup records; `PermissionDenied` error for the selected cron source; `partial` report. |

All four startup formats passed in one complete report: four persistence
records, zero errors, four supported source coverages. The SHA-256 of every
reported startup object equalled the independently recorded pre-run digest.
The denied and missing runs used new collection IDs and output paths. Their
raw reports are `reports/persistence_denied-report.json` and
`reports/persistence_missing-report.json` under the private evidence directory;
the happy-path files are `reports/service-report.json` and
`reports/persistence-report.json`. The original report SHA-256 values are in
the linked results JSON.

The injected bus tests in `native/linux/tests/services.rs` also retain typed
`PermissionDenied`, timeout, malformed-row and unsupported cases. A native
system-bus denial was not forced by changing the VM's global socket or service
state. The native service report instead preserves its real optional-field and
malformed-row partial outcomes; neither is presented as a fully complete bus
inventory.
