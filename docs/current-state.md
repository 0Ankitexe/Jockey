# Current project state

**Completed through Version 5, as of 2026-10-16.** Start with the
[Project and Viva Guide](PROJECT_GUIDE.md) for the complete explanation.

## Implemented

- Versions 0–2: repository foundations, JOCKY parsing, source diagnostics,
  types, semantic analysis and versioned module contracts.
- Version 3: verified intermediate representation and bounded fixture-only
  execution. Existing Windows/Ubuntu sample contracts remain compatible.
- Version 5: standalone read-only Linux collector, scoped authorisation and
  policy, nine observation categories, exact indicator matching, local JSON
  reports and an explicit portable Linux compiler migration.
- Controller and dashboard foundations: `/health`, `/version` and a status page.

The compiler/fixture path and standalone native collector are separate.
Generated native execution from JOCKY source is the next milestone.

## Tested scope

Native acceptance covers the pinned Debian 13.7 x86_64/glibc 2.41 VM:
core demonstration, implemented facility backends, applicable fault cases,
and one cold plus ten warm LAB-SMALL runs. Every seeded fact and numeric gate
passed. Partial reports preserve typed permission omissions. Other Linux
configurations and native Windows collection remain unverified.

Local Rust, Python, dashboard and Compose configuration gates passed. Hosted
CI is configured but was not observed in the recorded local campaign.
Forced native mid-read expiry and filesystem-wide ENOSPC remain unverified;
the available offline and isolated native fault results are documented.

## Where to find detail

- [Architecture](reference/architecture.md), [collector operation](reference/linux-collectors.md)
  and [support matrix](reference/linux-support-matrix.md).
- [Architecture decisions](../project-records/decisions.md),
  [all 24 SIH requirement mappings](../project-records/traceability.md) and
  [operational acceptance requirements](../project-records/operational-acceptance.md).
- [Original Version 5 verification](../project-records/version-5-verification.md)
  and [native evidence](../project-records/evidence/version-5/index.md).

Original evidence is kept outside `docs/` to keep this folder focused on
understanding and operating the project. Test records have not been rewritten
as new results.

## Next milestone

**Version 6 — Linux-First Code Generation and Function Packages**, after a
separate explicit request. V7 covers connected agent/controller work, V8
dashboard/multiple-endpoint operations, and V9 later Linux integration.
No later implementation starts as part of documentation cleanup.
