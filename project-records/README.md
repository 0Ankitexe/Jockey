# Project records: decisions and proof

For a simple explanation or demo, start with the
[Project and Viva Guide](../docs/PROJECT_GUIDE.md). For the latest status, use
[current-state.md](../docs/current-state.md). This folder contains the dated
decisions, requirements, checks and original evidence behind those summaries.

## Decisions and project rules

| File                                                                             | Read it for                                                                                                 |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [decisions.md](decisions.md)                                                     | Architecture Decision Records (ADRs): what was chosen, why and when a later choice superseded it.           |
| [traceability.md](traceability.md)                                               | Which code, version and test support each numbered project requirement. Dated progress rows are historical. |
| [operational-acceptance.md](operational-acceptance.md)                           | The approval, trust, numeric and failure gates for live work and later connected versions.                  |
| [constitution-audit.md](constitution-audit.md)                                   | The original adoption of the project rules and review of V0/V1.                                             |
| [linux-first-governance-verification.md](linux-first-governance-verification.md) | The documentation check for the earlier Linux-first roadmap change.                                         |
| [operational-readiness-verification.md](operational-readiness-verification.md)   | The documentation check for planned authorisation and connected-system gates.                               |
| [planning-consolidation-verification.md](planning-consolidation-verification.md) | How original Linux task IDs were regrouped into the current V5–V9 plan.                                     |

## Version records

| File                                                                     | Meaning                                                                                             |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| [version-2-verification.md](version-2-verification.md)                   | V2 final checker evidence plus earlier partial checkpoints.                                         |
| [version-3-phases-4-5-checkpoint.md](version-3-phases-4-5-checkpoint.md) | **Intermediate V3 checkpoint:** T046–T074, when the full release was still unfinished.              |
| [version-3-verification.md](version-3-verification.md)                   | **Final V3 release:** all 100 tasks, final tests and limits, with older checkpoints retained below. |
| [version-5-verification.md](version-5-verification.md)                   | **V5 release:** standalone Linux collectors, Debian VM acceptance and dated task hand-offs.         |

The V3 checkpoint has detailed test and file-change notes unique to that
intermediate request. The V3 release record refers to it but gives the later
final verdict. The V5 record covers a different version and real collection.
Read the top final section of a release record for its latest verdict; later
sections deliberately preserve what was known earlier.

## Raw Version 5 evidence

The [evidence index](evidence/version-5/index.md) is the starting point.
`evidence/version-5/checkpoint/debian/` holds the first native checkpoint;
`facilities/` holds backend checks; `faults/` holds failure tests;
`debian/` holds 11 final native runs; `regression/` holds local test results.
The other files at the evidence root record setup, resource and security
checks. The [Project and Viva Guide](../docs/PROJECT_GUIDE.md)
explains the main file types in plain English. Keep separate per-run reports
and even empty `stderr` files because their manifests account for each run.

The [retained-file checksum list](archive-manifest.json) detects accidental
changes to the records. A few links were adjusted after moving documentation;
the underlying test results were not rewritten. The nested evidence manifests
check the retained test bytes. Old path names and pending-status statements
inside dated sections describe their original time, not today's status.
