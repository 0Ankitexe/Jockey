# JOCKY: Project and Viva Guide

This guide covers the complete project from its foundation through **Version 5**.
It is intended for understanding the project, explaining it to a teacher and
running a short demonstration. Commands assume Bash and the repository root.

## 1. What is this project?

**JOCKY is a typed programming framework for authorised digital forensic work.**
It combines a small investigation language, a compiler, a safe sample-data
runner and a separate read-only Linux collector.

Digital forensics means collecting and examining computer information to
understand what happened. For example, an investigator may need to know which
processes were running, which network connections existed, or whether a file
matches a known SHA-256 hash.

An easy introduction for the viva:

> “Our project makes forensic work more structured and repeatable. We can
> check investigation programs before running them, test their logic using
> sample data, and collect authorised Linux observations into a consistent
> JSON report. Through Version 5, the language path and the live collector
> work separately. Connecting source programs to generated native packages
> is the next milestone.”

## 2. Why are we building it?

Investigations often combine commands, scripts and different output formats.
That makes mistakes, inconsistent records and repeated manual work possible.
JOCKY explores whether a small typed language and shared data rules can make
this work easier to check, explain and reproduce.

The goals are to catch program mistakes early, reuse collector components,
record where observations came from, enforce approved scope and resource
limits, and show failures honestly. Existing forensic tools can still be
useful; this project studies the framework around investigation logic and
controlled collection.

## 3. What was built in each version?

| Version                  | What it added                                                                                                         | Simple explanation                                                              |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| 0: Foundation            | Repository layout, shared data contracts, CI, controller and dashboard foundations                                    | Set up the parts and the rules they share.                                      |
| 1: Language frontend     | Grammar, parser, syntax tree and source-located errors                                                                | Understand whether a `.jky` program is written correctly.                       |
| 2: Semantic checking     | Names, types, function contracts and platform rules                                                                   | Check whether a correctly written program makes sense.                          |
| 3: IR and fixture runner | Intermediate representation, verification and bounded sample-data execution                                           | Turn a program into a checked plan and run it against supplied test data.       |
| 5: Linux collectors      | Read-only collection, scoped inputs, consistent reports, exact indicator matching and portable Linux compiler support | Collect real authorised observations and validate the implementation on Debian. |

Version 4 was an earlier Windows milestone and is outside the active Linux
roadmap. The numbering gap does not mean that part of the current Linux demo
is missing. Product versions and data-format version numbers are separate.

## 4. Architecture and how it works

There are two working execution paths through Version 5:

```text
LANGUAGE AND SAMPLE-DATA PATH
.jky source -> parser -> type checker -> verified IR
                                      -> fixture runner -> JSON sample result

STANDALONE LINUX COLLECTION PATH
Approved identity, authority, policy and request files
    -> validate scope and limits -> Linux collector workers
    -> observations from the approved VM -> verified local JSON report
```

The parser builds an **AST**, a tree describing the source program. The type
checker checks names, arguments, return values and target restrictions. The
compiler then produces **IR**, a simpler instruction format that is verified
before the fixture runner uses it.

The fixture runner reads supplied sample data. It does not inspect the
developer's machine. The new portable Linux language route can parse, check,
build and verify IR; native execution from that source is future work.

The standalone collector first checks five kinds of input:

| Input                         | What it means                                                     |
| ----------------------------- | ----------------------------------------------------------------- |
| Endpoint designation          | Identifies the approved VM.                                       |
| Authorisation                 | Records the case, operator, permitted work and time window.       |
| Local policy                  | Sets allowed sources, paths and resource limits.                  |
| Collection request            | Selects the approved observations wanted for this run.            |
| Indicator set, when requested | Supplies known hashes, paths, IP addresses or domains to compare. |

The collector applies the most restrictive allowed scope. Small worker
processes read approved sources, and a separate publisher writes a new report
without overwriting an existing one. The report includes observations,
source references, errors, identities and integrity hashes.

The controller and dashboard form a third foundation: the controller exposes
health and version information, and the dashboard displays it. Investigation
assignment, connected endpoint agents and collected-result views are planned.

## 5. Technologies and why we use them

| Technology                                | Role and reason                                                                                                                                |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust and Cargo                            | Language, IR, shared library and native collector. Rust provides strong types and memory-safety checks; Cargo manages builds and dependencies. |
| Pest                                      | Defines and parses the JOCKY grammar.                                                                                                          |
| Serde and JSON                            | Convert typed Rust data into readable, structured files and back.                                                                              |
| JSON Schema                               | Defines valid input and output shapes so Rust and Python agree.                                                                                |
| Tokio, zbus and optional libsystemd       | Support bounded asynchronous work, read-only systemd queries and journal access.                                                               |
| Python 3.12, FastAPI and Pydantic         | Controller API foundation, validated configuration and test tooling.                                                                           |
| React, TypeScript and Vite                | Dashboard interface with type checking and development/build tools.                                                                            |
| PostgreSQL, Redis, SQLAlchemy and Alembic | Prepared stack for future stored management data, queues and database changes; current health routes do not use it.                            |
| Cargo tests, Pytest and Vitest            | Test Rust, Python and interface behavior, including rejected inputs.                                                                           |
| GitHub Actions and Docker Compose         | Define automated checks and local service configuration. Local passes do not imply a hosted CI run.                                            |
| Debian VM with QEMU/libvirt               | Provides the isolated, repeatable Linux environment used for native collector testing.                                                         |

## 6. What can the Linux collector observe?

| Category    | Information collected when approved and readable                                         |
| ----------- | ---------------------------------------------------------------------------------------- |
| System      | OS, kernel, architecture, distribution and hostname.                                     |
| Processes   | Running process IDs, ownership and available command/start metadata.                     |
| Services    | Existing systemd services and their observed states.                                     |
| Connections | Current socket addresses and ports, with process ownership where readable.               |
| Persistence | Approved startup entries such as systemd units/timers, cron and desktop autostart files. |
| Files       | Approved regular-file metadata and complete SHA-256 hashes.                              |
| Events      | Selected journal or supported RFC5424 text log entries within a time window.             |
| Drivers     | Loaded Linux kernel module information.                                                  |
| Indicators  | Exact comparisons against supplied hashes, paths, IP addresses and domains.              |

Read-only means the collector does not intentionally change the evidence
sources. Ordinary reads can still cause access-time or audit updates. It does
not promise an immutable disk snapshot. It does not elevate privileges or
turn an exact indicator match into a claim that malware was detected.

## 7. Important folders

| Folder                                    | Purpose                                                               |
| ----------------------------------------- | --------------------------------------------------------------------- |
| `language/`, `ir/`                        | Source language, checking, intermediate format and fixture execution. |
| `forensic-lib/`, `native/linux/`          | Shared collection rules and Linux-specific source access.             |
| `shared/`                                 | Data schemas and shared types.                                        |
| `controller/`, `dashboard/`               | Current API and interface foundations.                                |
| `examples/`, `fixtures/`, `tests/`, `ci/` | Example programs, sample data, tests and automated checks.            |
| `docs/`                                   | This guide and useful project references.                             |
| `project-records/`                        | Decisions, release checks and original test evidence.                 |

`codegen/`, `runtime/`, `transforms/` and `transport/` contain boundaries for
later milestones; their presence does not mean those workflows are delivered.

### How to read `docs/`

`docs/` explains the project **as it stands now**. Start with this guide;
open a reference only when you want the exact design or rules for one part.
These files have different jobs:

| File                                                                                 | What it tells you in simple terms                                                   |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| [README.md](README.md)                                                               | A short menu of the documentation.                                                  |
| [PROJECT_GUIDE.md](PROJECT_GUIDE.md)                                                 | The overall story, setup, demo, results and viva answers.                           |
| [current-state.md](current-state.md)                                                 | What is complete today, what was tested and what is next.                           |
| [reference/architecture.md](reference/architecture.md)                               | The parts of the system and how they fit together.                                  |
| [reference/language-reference.md](reference/language-reference.md)                   | How to write a `.jky` program.                                                      |
| [reference/diagnostics.md](reference/diagnostics.md)                                 | What compiler errors and exit codes mean.                                           |
| [reference/module-contracts.md](reference/module-contracts.md)                       | Which investigation functions the language knows and whether they can actually run. |
| [reference/platform-capabilities.md](reference/platform-capabilities.md)             | Which source targets and platform features a program may name.                      |
| [reference/ir-specification.md](reference/ir-specification.md)                       | The checked instruction format made from source code.                               |
| [reference/reference-interpreter.md](reference/reference-interpreter.md)             | How the Version 3 runner uses supplied sample data.                                 |
| [reference/cross-platform-result-model.md](reference/cross-platform-result-model.md) | How identities, observations, reports and errors are represented.                   |
| [reference/linux-collectors.md](reference/linux-collectors.md)                       | Version 5 collector inputs, safety rules, VM procedure and report handling.         |
| [reference/linux-support-matrix.md](reference/linux-support-matrix.md)               | Exactly which Linux setup and collector facilities have native evidence.            |
| [reference/security-boundary.md](reference/security-boundary.md)                     | What collection is allowed and what the project forbids.                            |
| [reference/linux-first-roadmap.md](reference/linux-first-roadmap.md)                 | Which features are planned for V6–V9; it is a plan, not a test result.              |

### How to read `project-records/`

`project-records/` holds **why decisions were made and proof of past work**.
It is for checking a claim, not for learning commands from start to finish.
Many records contain dated intermediate statements such as “still pending.”
Use [current-state.md](current-state.md) for the latest status, then the final
section at the top of a release record for its final verdict.

| File                                                                                                | What it tells you in simple terms                                                                                             |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [README.md](../project-records/README.md)                                                           | Menu and explanation of the records.                                                                                          |
| [decisions.md](../project-records/decisions.md)                                                     | Dated architecture decisions, called ADRs, and why choices changed.                                                           |
| [traceability.md](../project-records/traceability.md)                                               | Where each numbered project requirement is implemented and tested.                                                            |
| [operational-acceptance.md](../project-records/operational-acceptance.md)                           | The rules for deciding whether live and future connected features pass.                                                       |
| [constitution-audit.md](../project-records/constitution-audit.md)                                   | The review that adopted the project rules and checked earlier V0/V1 work.                                                     |
| [linux-first-governance-verification.md](../project-records/linux-first-governance-verification.md) | Proof that the Linux-first roadmap change was reflected in project guidance; it is not a collector test.                      |
| [operational-readiness-verification.md](../project-records/operational-readiness-verification.md)   | Review of planned approval, trust and connected-system acceptance rules.                                                      |
| [planning-consolidation-verification.md](../project-records/planning-consolidation-verification.md) | How original Linux tasks were regrouped into the current V5–V9 plan.                                                          |
| [version-2-verification.md](../project-records/version-2-verification.md)                           | Version 2 checker test results, with older partial checkpoints below the final result.                                        |
| [version-3-phases-4-5-checkpoint.md](../project-records/version-3-phases-4-5-checkpoint.md)         | A **mid-build** V3 record: IR verification and sample-data execution reached T074; V3 was still unfinished _at that date_.    |
| [version-3-verification.md](../project-records/version-3-verification.md)                           | The **final V3 release** record: all 100 tasks, final tests and limitations. Its later sections preserve earlier checkpoints. |
| [version-5-verification.md](../project-records/version-5-verification.md)                           | The **V5 release** record: standalone Linux collection, Debian VM gates, final test results and historical task hand-offs.    |
| [archive-manifest.json](../project-records/archive-manifest.json)                                   | SHA-256 fingerprints for retained record files, used to notice accidental changes.                                            |

The two Version 3 files are **not the same result**: the checkpoint explains
how part of V3 was built; the V3 release file gives the later final verdict.
The V5 file concerns a different product version and real Debian collection.
They repeat some background so each dated hand-off makes sense on its own.
There is no second copy of these files in `docs/`.

### What is inside `project-records/evidence/version-5/`?

Start at the [evidence index](../project-records/evidence/version-5/index.md).
The following files answer different questions:

| File or group                                                                                                                                                                                                                                                  | What it proves or records                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [baseline.json](../project-records/evidence/version-5/baseline.json)                                                                                                                                                                                           | The test baseline before V5 changes.                                                                                         |
| [memory-review.md](../project-records/evidence/version-5/memory-review.md), [resource-adoption.md](../project-records/evidence/version-5/resource-adoption.md), [confinement.md](../project-records/evidence/version-5/confinement.md)                         | Memory limits, an earlier resource problem and rules that keep reads inside approved paths.                                  |
| [report-foundation.md](../project-records/evidence/version-5/report-foundation.md), [worker-read-foundation.md](../project-records/evidence/version-5/worker-read-foundation.md), [launch-control.md](../project-records/evidence/version-5/launch-control.md) | How reports, bounded reading and child-process launches were checked.                                                        |
| [limits-and-recovery.md](../project-records/evidence/version-5/limits-and-recovery.md), [indicator-evaluation.md](../project-records/evidence/version-5/indicator-evaluation.md)                                                                               | Numeric limits, failure handling and exact indicator-match results.                                                          |
| [checkpoint/debian/](../project-records/evidence/version-5/checkpoint/debian/README.md)                                                                                                                                                                        | The first real four-category Debian check: approval, known test facts, original report, denials and hashes.                  |
| [facilities/](../project-records/evidence/version-5/facilities/services-persistence.md)                                                                                                                                                                        | Separate offline and real-VM results for services, persistence, events and modules, including machine-readable T172 results. |
| [faults/](../project-records/evidence/version-5/faults/native.md)                                                                                                                                                                                              | Offline fault checks and the separate real Debian fault campaign.                                                            |
| [debian/](../project-records/evidence/version-5/debian/README.md)                                                                                                                                                                                              | The final Debian campaign: one cold and ten warm reports, measurements, original inputs and checksums.                       |
| [regression/](../project-records/evidence/version-5/regression/rust.md)                                                                                                                                                                                        | Final local Rust, Python, dashboard and Compose check results.                                                               |

Within `checkpoint/debian/` and `debian/`, `approval-record`, `authorisation`,
`policy`, `request` and `lab-scenario` files state **who/what/when was approved**.
`inventory`, `host-preflight` and image files identify the VM and its starting
state. `expected`, `observed`, `oracle` and `negative` files compare known test
facts with results and denials. `report.json` or `lab-small-00.json` through
`lab-small-10.json` are the actual outputs. `samples.jsonl` and `summary.json`
summarise runs; `stdout` and `stderr` files preserve each command's output;
SHA-256 manifests check retained bytes. The repeated empty `stderr` files are
separate per-run evidence, not extra project documents.

## 8. How to set up and run the project

The compiler demo needs Rust **1.98.1 or newer** and a C compiler/linker.
The optional controller/dashboard needs Python **3.12** and Node **22.20+ on the 22.x line**.
Docker and a VM are not needed for the sample-data demo.

```bash
cd /path/to/JOCKEY
bash scripts/setup.sh --demo
```

On another computer, use its repository location in the first command.
Dependency fetching needs internet access once; cached builds can run offline.
The script checks prerequisites, fetches locked dependencies and builds the
workspace. The optional `journal` collector build additionally
needs libsystemd development files; see the [collector guide](reference/linux-collectors.md).

For the optional controller/dashboard demonstration, run `bash scripts/setup.sh --full`
instead of `--demo`. It also installs the Python and Node project dependencies.
The equivalent manual commands are:

```bash
python3.12 -m venv controller/.venv
controller/.venv/bin/python -m pip install -e './controller[dev]'
(cd dashboard && npm ci)
```

Start these in two separate terminals from the repository root:

```bash
# Terminal 1
(cd controller && .venv/bin/python -m uvicorn jocky_controller.main:app --host 127.0.0.1 --port 8000)

# Terminal 2
(cd dashboard && npm run dev -- --host localhost --port 5173 --strictPort)
```

Open `http://localhost:5173`. The page shows controller health and version.
`http://127.0.0.1:8000/health` returns `{"status":"ok"}`. Stop the servers
with `Ctrl+C` when finished.

### What every part of the dashboard means

The dashboard is a small **service health page** built in the Version 0
foundation. It does not display the Version 5 Debian report. The page checks
the controller's `/health` and `/version` routes when it loads.

| On-screen part                       | What it tells you                                                                                                                                                     |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `JOCKY` heading and description      | The name and purpose of the project.                                                                                                                                  |
| `Dashboard` card: `Ready`            | The React page loaded in your browser. This does **not** mean the collector, controller or VM is running.                                                             |
| `Version 0 status interface`         | This page began as a foundation feature. The overall project is complete through Version 5.                                                                           |
| `Controller`: `Checking controller…` | The browser is waiting for the controller's two API responses.                                                                                                        |
| `Controller`: `Online`               | Both API responses were valid. `Service` is the API name (`JOCKY Controller`); `Version` is its package version (`0.0.0`), **not** the project's Version 5 milestone. |
| `Controller`: `Unavailable`          | The API could not be reached or returned an error or unexpected data. The line below says what went wrong.                                                            |
| `Version 0 scope` note               | The page reports service health only; endpoint lists, tasks and forensic results are future dashboard work.                                                           |

There are no investigation buttons or report views yet. The check happens on
page load; refresh the browser to check again. For a simple failure demo, stop
the controller, refresh and show `Unavailable`, then restart it and refresh to
show `Online`. The dashboard's own `Ready` card stays visible in both cases.

## 9. A short demonstration for the teacher

Use this order to show **the actual progress through Version 5**: checked
source, a sample-data run, a saved real Debian collector report, and the
separate dashboard foundation. The VM display is optional for the short demo.

**First, check a program and execute sample-data logic:**

```bash
target/debug/jockyc parse examples/triage.jky
target/debug/jockyc check examples/triage.jky
target/debug/jockyc run-fixture examples/triage.jky --fixture examples/fixtures/triage/ubuntu
```

Explain that parsing checks syntax, checking checks meaning, and execution
uses the supplied fixture. A clean `check` can be silent with exit code 0.
The result says `mode: "fixture"`, has a successful outcome and includes the
sample hostname `fixture-ubuntu`. This is the language demonstration.

**Next, show generic Linux source checking:**

```bash
target/debug/jockyc check examples/linux/triage.jky --language-version 3.0.0
```

This demonstrates the explicit portable compiler route. The language version
flag selects the new syntax/contracts; it does not launch collection.

**Then, verify a saved report from the real Debian campaign:**

```bash
target/debug/jocky-collect-linux verify-report \
  /home/zer0/main/jockey/project-records/evidence/version-5/debian/lab-small-00.json
```

Show its short summary without printing the whole report:

```bash
python3.12 - <<'PY'
import json
from pathlib import Path
p = Path('project-records/evidence/version-5/debian/lab-small-00.json')
r = json.loads(p.read_text())
print('Report kind:', r['report_kind'])
print('Collected at:', r['started_at'])
print('Records:', len(r['records']))
print('Summary:', r['summary'])
PY
```

State clearly that this verifies an existing real VM result. It does not
collect fresh information. Report verification checks format and content
integrity; a hash alone does not prove who produced a report.

The prepared VM is `jocky-v5-debian-13-7`. To show the installed guest:

```bash
virsh -c qemu:///session start jocky-v5-debian-13-7
virt-manager --connect qemu:///session
```

Open that VM in Virtual Machine Manager. The VM is a separate computer
simulated on the host, used to make collection isolated and repeatable.
Only Debian is required for the current native demonstration.

**Finally, show the controller and dashboard:** use the two terminal commands
in Section 8, open `http://localhost:5173`, and point out `Dashboard: Ready`,
`Controller: Online`, `Service` and `Version`. Explain that the controller
status is live, but the Debian report is shown through the collector command
above because report views are planned for Version 8. If you want to show a
failure state, stop the controller and refresh the page; it should say
`Unavailable`. Restart the controller and refresh to restore `Online`.
The `0.0.0` value is the controller package version, not evidence that the
whole JOCKY project is only at Version 0.

For a **fresh live collection**, prepare current approval/policy/request
files and a fresh VM preflight, then follow the exact command in the
[collector guide](reference/linux-collectors.md#first-debian-checkpoint-preparation-and-commands).
The saved campaign inputs have expired and are historical records. The
ordinary developer workstation is not the designated collection endpoint.

## 10. What results can we honestly show?

The native campaign used Debian 13.7, 2 virtual CPUs and 4 GiB RAM, with no
network adapter. It checked five known processes, five loopback connection
pairs, twenty known 64 KiB files, ten journal markers and 1,000 indicators.
One cold run means the first collection after boot; ten warm runs followed.

| Measurement                      | Actual recorded result                     | Limit                                  |
| -------------------------------- | ------------------------------------------ | -------------------------------------- |
| Native runs                      | 11, all seeded facts checked               | One cold plus ten warm                 |
| Slowest elapsed time             | 2.222 seconds                              | 60 seconds per run                     |
| Highest aggregate peak memory    | About 74.6 MiB                             | 256 MiB                                |
| Largest report                   | About 670 KiB                              | 10 MiB                                 |
| Highest accepted record count    | 302                                        | 10,000                                 |
| Exact indicator corpus, each run | 51 correct matches; 949 correct nonmatches | No unexpected or missed seeded matches |

Reports are **partial** because the ordinary VM user could not read some
unrelated process/socket-owner fields. Those denials are visible; every known
lab fact still matched. Complete, partial and failed are different outcomes.
Native collector exit codes include 0 for complete and 2 for partial reports.

Rust workspace and journal-feature checks, 185 Python tests, 18 dashboard
tests and Compose configuration passed locally. Full records are preserved in
[the test archive](../project-records/evidence/version-5/index.md).
Other distributions and hosted CI are not claimed as verified native runs.

## 11. Common viva questions

**Is this a new operating system or a normal scripting language?**
It is a small domain-specific language and a forensic framework. It runs on
an existing operating system and focuses on typed investigation workflows.

**Why use types?**
Types catch mistakes such as passing an integer where a process list is
expected. Checks happen before the fixture program executes.

**Why build an IR?**
IR gives the compiler a simpler, checkable instruction format. It supports
verification and keeps parsing separate from execution and future backends.

**Does compiling a `.jky` file collect real data?**
Through Version 5, compilation checks/builds a plan and fixture execution
uses sample data. Real collection is an explicitly invoked separate command.

**Why use a VM?**
It gives us a known OS and permissions, separates test objects from personal
host data and lets us repeat controlled tests for a demonstration.

**Does SHA-256 prove that a file is safe?**
It is a content fingerprint. Matching a supplied hash identifies matching
bytes; it does not by itself establish safety or maliciousness.

**Why can a partial result still be useful?**
Some facts are readable and some are denied. The report keeps valid facts
and states the omissions instead of inventing missing information.

**What is still planned?**
V6: generated Linux packages and source-selected native calls. V7: connected
agent/controller work. V8: investigation dashboard and multiple endpoints.
V9: protection, transport, research and integrated Linux delivery.

## 12. Short glossary

| Term                               | Simple meaning                                                                            |
| ---------------------------------- | ----------------------------------------------------------------------------------------- |
| DSL                                | A language designed for one area of work; here, forensic investigation.                   |
| Compiler                           | Software that checks source and converts it into another representation.                  |
| Parser / grammar                   | The parser recognises source structure using the language's writing rules.                |
| AST                                | Abstract Syntax Tree: a structured tree of the written program.                           |
| Semantic checking                  | Checking meaning: names, types, calls and platform rules.                                 |
| IR                                 | Intermediate Representation: the compiler's simpler instruction plan.                     |
| Fixture                            | Supplied sample data used for repeatable tests.                                           |
| Collector / adapter                | Code that reads an approved information source; an adapter handles OS-specific details.   |
| Endpoint / operator / case         | The examined computer, the person running the work, and the investigation reference.      |
| Policy / scope                     | The rules and exact sources/actions permitted for a run.                                  |
| Schema / JSON                      | A schema defines the allowed structure; JSON is the structured text format used for data. |
| Hash / integrity                   | A content fingerprint / checking whether recorded content remains consistent.             |
| Indicator                          | A supplied value to compare, such as a known hash, path, IP address or domain.            |
| Provenance                         | Information about where an observation came from and its collection context.              |
| VM / host / guest                  | A virtual computer / the real machine running it / the OS inside it.                      |
| Loopback                           | A connection within the same computer, using addresses such as `127.0.0.1`.               |
| Kernel / module / systemd          | The OS core / a loaded kernel component / a Linux service manager.                        |
| API / controller / dashboard       | A software interface / the management service / its user interface.                       |
| Unit / integration / negative test | Tests one part / connected parts / expected rejection or failure.                         |
| CI                                 | Continuous Integration: automated checks configured for code changes.                     |
