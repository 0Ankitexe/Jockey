# T165 Debian native checkpoint — 2026-10-15

**Verdict:** passed on the isolated Debian 13.7 x86_64 VM. This is one real
core checkpoint for US1, not the T178/T179 11-run acceptance campaign or
Version 5 release closure.

## Identity and authority

- Domain: `jocky-v5-debian-13-7` on `qemu:///session`, with no guest NIC;
  product UUID `296bba74-2e38-458e-827e-56b7cd858997`; guest machine ID
  `8eda7802cadd47b48437c16e12730bea`.
- Debian 13.7 installer ISO SHA-256:
  `a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355`.
  The [signed checksum files and verification output](image-verification.txt)
  were retained. The ISO checksum was checked against Debian's signed SHA256SUMS, using
  signing fingerprint `DF9B9C49EAA9298432589D76DA87E80D6294BE9B`.
  The guest's Debian/kernel identity is in [observed.json](observed.json).
- The shutoff VM disk was hashed as
  `4d993364937e366cf98767a22340ab05cc3821c86048effe79b4fe258dd95d2d`;
  [inventory.json](inventory.json) and [host-preflight.json](host-preflight.json)
  bind the domain name, UUID, disk path/hash, endpoint and guest machine ID.
  Host preflight was recorded at `2026-10-15T06:45:16Z`, before this boot.
- The separately recorded [approval](approval-record.json) and
  [scenario](lab-scenario.json) cover case
  `2c1f188c-eef1-46d8-9be5-95f1c1c64218`, operator
  `41689e0d-82d2-4857-82af-f56d8d128c4f`, endpoint
  `77dad005-1930-4c68-b499-f8cd4dc058b4`, only the owned scratch/output
  roots and loopback/benign sample actions. The final release binary SHA-256
  was `934f25754c902fa68d4e9d992dfef021aca93f8f28b511a2c922db453b65ae28`.
  The approval window was `2026-10-15T06:39:49Z` through
  `2026-10-15T09:44:49Z`. The original collection documents are retained
  beside this note.

## Expected and observed facts

The harness recorded [expected.json](expected.json) **before** invoking the
binary. The separately decoded [observed.json](observed.json) and full raw
[report.json](report.json) show the matching process PID 1606/boot ID/start
ticks, loopback socket tuple/inode, and 34-byte scoped sample file with SHA-256
`974ce96b482433df8e92096aab1662a2ada4299ed38d2783ab21ea144e0eade1`.
The [oracle output](oracle.json) records the live collector exit 2 and report
SHA-256 `87d4e779f5aa032baa53b954e55263ebe12084359d62d452d1c7c064a6e98c69`.
Host verification reran the independent schema, canonical integrity, context,
and seeded-fact oracle on the exact 284,952 report bytes. The binary's own
`verify-report` command also succeeded inside the VM.

The report contains 118 accepted records, 110 item errors, 190,809 source
bytes, and `worker_cleanup=complete`. Status is **partial**, with
`PermissionDenied` visible for inaccessible process/connection ownership
facts. This is not presented as a complete report.

## Denial and collision

[negative.json](negative.json) retains native guest observations. Omitting
`--allow-live-lab` exited 3 at argument admission and created no output.
Reusing the accepted report path with opt-in exited 3 with `OutputExists` at
admission. The report's SHA-256 before and after collision was identical; the
pre-existing scratch file remained.

[sha256-manifest.json](sha256-manifest.json) hashes the retained original
inputs, report, oracle and negative observations. No VM report was fabricated
from a fixture. The diagnostic attempts that exposed proc read-budget,
`/proc/net` symlink and socket ordering defects were excluded from the
accepted sample; the final build has those fixes and passes the independent
oracle.
