# Checked worker/read foundation

Date: 2026-10-12. Constitution 1.2.0; ADR-0024. Offline development evidence,
not a native OP gate or completed V5 work package. T156/T157 remain partial.

## Isolation and coverage

No product worker, collector or publisher is connected. The CLI remains explicitly
NotImplemented/Unsupported. Tests use frozen synthetic clock pairs, expired JSON
fixtures and test-owned temporary directories beneath repository `target/`.
They never inventory the workstation, contact endpoint services or designate a VM.
Descriptor reopening touches only each test's own retained file. Ancestor checks
inspect filesystem metadata; these are not forensic collection or VM support proof.

| Behavior                                                                                                                          | Evidence                                                                               | Outstanding integration                                                                         |
| --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Immutable eight-counter snapshots, remaining quota, policy item bounds, sticky stops                                              | `forensic-lib/tests/collection_accounting.rs`                                          | Complete parent/worker reservation and allocation accounting                                    |
| Original invocation timeout; current authority, expiry and rollback checks                                                        | `forensic-lib/tests/collection_invocation.rs`                                          | System clock adapter and versioned cross-process launch binding                                 |
| Normalized complete input fingerprints; malformed/changed metadata rejects                                                        | `forensic-lib/tests/collection_fingerprints.rs`, `native/linux/tests/worker_inputs.rs` | Trusted local config ownership and native endpoint confirmation in orchestration                |
| Directional job order, cancellation, early failure but never early success                                                        | `native/linux/tests/worker_order.rs`                                                   | Actual owned-worker lifetime                                                                    |
| All cumulative usage fields, exact cap/+1, rollback and final error floor                                                         | `native/linux/tests/worker_progress.rs`                                                | Reserve before launch; no refund on a crashed worker                                            |
| Current admission before Ready, input context/fingerprints, record UUID/digest/ordinal/singleton, exact terminal counts and usage | `native/linux/tests/worker_session.rs`                                                 | Native truth, full provenance attribution and supervisor resource accounting                    |
| Canonical report verification before a report receipt; exact publication acknowledgement                                          | `native/linux/tests/worker_session.rs`                                                 | Physical exclusive publication, fsync, identity and residue handling                            |
| Regular-file short reads, empty/exact sizes, mutation, early EOF, cancellation, expiry and charged failed work                    | `native/linux/tests/reads.rs`, `native/linux/src/sources/reads/tests.rs`               | Actual collector/hash integration and external bound on stalled kernel calls                    |
| EOF-proven streaming exact 65536/+1, item/memory denial, expiry, failure without retries or prefix success                        | `native/linux/src/sources/reads/tests.rs`                                              | Scoped proc/sys native adapters and retained mount identity                                     |
| Trusted output pin, collisions/aliases/unsafe modes, config inode exclusions, root ancestry and replacement                       | `native/linux/tests/capabilities.rs`, private inventory/metadata tests                 | Fixed source kinds, descriptor transfer, publisher and complete inventory allocation accounting |

Internal source tests also run through several direct-module integration seams;
test-execution totals are not distinct behavioral test counts. A Session receipt
is checked data, not a native permit, authenticated peer, finished job or published
evidence. Source/report integrity is not proof of factual truth or legal custody.

## Failure observations and corrections

Test-first module imports failed before order/progress/session/read/capability
implementation. Ordering initially accepted a commit with no preceding chunk;
the regression required a preceding transfer chunk. Integrated Ready initially
accepted integrity alone; the new test failed until current matching admission
became mandatory. Admission/preflight failures could not terminate before Ready;
new tests failed and the ordering guard was corrected without enabling early
success. A test attempted a publisher error outside the existing v1 enum; it was
corrected to PublicationFailed, not accommodated by widening the schema.

Clippy identified a large receipt enum; input receipts now box their bounded
verified bundle. A private streaming re-export initially had insufficient
visibility; the module boundary was corrected. Adding charged root ancestry
changed the new read-accounting test's expected cost; it now asserts the exact
root storage plus buffer/data cost, rather than dropping that charge. Subsequent
checks pass. No historical golden expectation, schema or completed row changed.

## Accounting and limits

Read buffers are at most 65536 bytes. Regular reads require complete stable
descriptor size, capped by admitted file bytes; streaming reads require EOF and
an admitted item cap no greater than 65536. One extra returned byte detects an
oversized stream; it is charged and never returned as successful evidence.
If no source quota remains for EOF proof, return ResourceLimit rather than guess.
No automatic retry or refund occurs. Retained storage is reserved before read
allocation. Time/identity checks occur around operations and each chunk; actual
bytes remain charged even when the post-read check fails.

Output admission creates no directory/file. It cannot guarantee future no-replace
publication or stop a blocked syscall. The alias ledger caps 128 ordinary roots,
five config identities and 257 ancestry entries per root. Retained ordinary-root
ancestry is charged; inventory copies and other native retention remain T038
work. Publisher preparation must account for its own deliberate directory changes
without treating arbitrary changes as trusted. No deadline/memory limit is relaxed.

ADR-0024 records the missing original clock/quota/ordinal fields in worker v1.
A versioned launch-control contract is required before actual spawning. Existing
v1 wire bytes remain valid and all schema changes are deferred to explicit
compatibility work. The passing dependency probes still do not close T159/T041.

See the [A–G command/results ledger](../../version-5-verification.md#checked-workerread-foundation--2026-10-12).
