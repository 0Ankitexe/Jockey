# Version 5 T170 progress — 2026-10-15

T170 remains unchecked. This is an offline implementation checkpoint, not a
native facility acceptance result. No host or VM log, journal or module source
was read in these tests.

Implemented private pieces:

- `sources/journal_snapshot.rs`: bounded exact copy with source identity
  before/after and injectable source/staging byte charges; the actual confined
  source and worker-private staging handles are not yet bound.
- `sources/journal.rs`: feature-gated `OpenFilesOptions::open_files` reader of a
  caller-supplied staged filename; default feature returns `Unsupported`.
  The reader is not yet invoked from the worker and needs a bounded staging
  lifetime and charged event conversion in that path.
- `collectors/events/{journal,text}.rs` and `sources/text_log.rs`: half-open
  event window conversion, RFC5424 offset/UTC parsing, explicit syslog/auth
  source roles, and typed missing/denied/rotation/format outcomes. Structured
  data other than `-` is explicitly `UnsupportedFormat` at this checkpoint.
- `collectors/drivers.rs`: detection-only `/proc/modules` parser and fixed
  `/sys/module/{name}/{version,srcversion}` admitted query path. The kernel
  address is validated as a field but not retained.
- Enabled the formerly ignored text and module integration vectors. The
  journal snapshot/reader integration vector remains ignored pending actual
  confined staging and safe reader invocation.

Verification: `cargo fmt --all --check`, default and `journal` feature native
Cargo checks, targeted journal/text/module integration tests, and `git diff
--check` passed. Before the last targeted changes, full default native tests
passed 1,159 tests across 44 suites with three ignored; the optional journal
feature passed 1,161 across 44 suites with three ignored. Those counts are not
claimed as final after the later text/module test updates. All source inputs
in the completed tests were supplied in memory or owned temporary objects.

Open inherited clauses: T093 actual scoped source-to-private-stage binding;
T094 charged/cancelable staged reader integration; T095 admitted source-handle
binding; T096 worker report integration. T171 all-collector dispatch and T172
Debian native happy-path and negatives remain open. No task row is checked by
this checkpoint.
