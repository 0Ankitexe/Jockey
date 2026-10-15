# Linux native boundary

This crate is under construction. The `jocky-collect-linux` binary has an
explicit Linux `collect --allow-live-lab` command that revalidates local
authority, runs fixed-self owned workers and publishes a verified report.
It has offline synthetic tests for complete, partial, failed, unsupported and
no-output paths. Debian VM native acceptance remains open.

Implemented library groundwork includes explicit configuration-file reading and
logical validation. It accepts no default paths and does not discover endpoints.
Logical validation returns case/endpoint/collection identifiers, not a reusable
native execution permit. Authority files must be caller-owned, regular,
single-linked, mode 0600, under owner-controlled non-writable-by-others parents.
Requests/indicators are also bounded regular no-follow inputs. Unsupported
filesystem/confinement facilities produce typed errors, not fallback reads.

Configuration traversal and descriptor pinning are documented in
[ADR-0016](../../project-records/decisions.md#adr-0016-pin-explicit-configuration-files-before-opening-their-contents).
Only Linux ext-family, XFS and Btrfs filesystem classes are currently admitted;
actual deployment support requires the later VM matrix. Ordinary offline tests
create their own input objects under the repository's ignored `target/` directory.
They do not scan endpoint procfs, open a system bus or collect host evidence.
Owned-descriptor reopening is input plumbing, not a procfs collector.

Run from the repository root after dependency setup:

```sh
cargo test -p jocky-native-linux --locked --offline
cargo clippy -p jocky-native-linux --all-targets --locked --offline -- -D warnings
```

With libsystemd development files already installed, the optional `journal`
feature can be built/tested offline using `--features journal`. It does not
provide a working journal collector. The new resource-adoption test initializes
the real dependencies using synthetic inputs, an owned Unix socket pair and an
owned malformed journal file. It reads only its own `/proc/self/statm` and
`/proc/self/status` memory
counters and limits only its owned child; it never opens default journals.
No test requires sudo or a security-control change.

The original schema-initialization failure is resolved by ADR-0019. Cold core
and journal probes now fit the unchanged 64 MiB parent / 192 MiB worker limits.
They check all thirteen schemas, input byte/count boundaries, hostile input and
repeat validation. They are dependency tests, not the complete T041 pipeline or
native lab acceptance. Reproduce:

```sh
cargo test -p jocky-native-linux --release --test resource_adoption --locked --offline
cargo test -p jocky-native-linux --release --test resource_adoption --features journal --locked --offline
```

See [the memory review and measurements](../../project-records/evidence/version-5/memory-review.md)
and the retained [original failure](../../project-records/evidence/version-5/resource-adoption.md).
Schema definitions are checked by a mandatory build guard; incoming documents
still undergo full runtime validation inside accounting. No limit was raised.

Remaining backend coverage, fault campaigns and the authorised Debian VM
checkpoint are blocking unfinished work. The fixture interpreter remains
separate and has no native fallback. Current
commands, test counts and task status are in the
[verification ledger](../../project-records/version-5-verification.md).
