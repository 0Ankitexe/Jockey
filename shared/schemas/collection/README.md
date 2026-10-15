# Local collection contract inventory

Collection schemas use Draft 2020-12 and are additive to the unchanged operational
v1 schemas in the parent directory. They do not enable native execution.
[ADR-0015](../../../project-records/decisions.md#adr-0015-local-collection-contracts-authority-and-bounded-native-boundary)
records compatibility, trust and resource decisions.

## Additive worker launch control — 1.1.0

[ADR-0025](../../../project-records/decisions.md#adr-0025-add-separate-launch-control-without-widening-worker-v1)
adds `v1_1/worker-launch.schema.json`. It is decoded separately through
`shared::collection::launch::decode_launch`, not through the 13 existing
DocumentKind variants. Worker frames stay 1.0.0; other resources and their fixture
corpus below are unchanged. The embedded definition/reference inventory now has
14 resources. `fixtures/worker-launch-cases.json` registers the additional
synthetic valid/invalid corpus; Rust/Python tests and cold resource probes cover it.

Launch carries original clocks, reserved quota, ordinal bases and claimed owned
process/descriptor bindings. Native entry must verify actual peer/objects and
current committed authority. Decoding metadata never launches a process, renews
authority or proves ownership. Existing v1 worker decoders reject launch documents;
there is no automatic upgrade. Scope and resource thresholds are not weakened.

Every original `v1/` collection resource has an explicit `schema_version: "1.0.0"` root.
Its exact `$id` is `https://jocky.dev/schemas/collection/v1/` plus the filename
below. These are identifiers, never runtime fetch locations. Validators must
resolve only bundled resources and refuse remote retrieval.

| File                               | Contract                                                 |
| ---------------------------------- | -------------------------------------------------------- |
| `types.schema.json`                | Bounded common definitions; not a collection request     |
| `endpoint-designation.schema.json` | Owner assertion of an isolated lab VM                    |
| `authorisation.schema.json`        | Operator/case grant and limits                           |
| `policy.schema.json`               | Independently controlled endpoint scope/source policy    |
| `request.schema.json`              | One investigation's narrowing request                    |
| `indicator-set.schema.json`        | Explicit supplied exact-match criteria                   |
| `endpoint-observation.schema.json` | Actual observed platform/facility facts                  |
| `report.schema.json`               | Attributable local report; synthetic/live labels         |
| `status.schema.json`               | Bounded evidence-free command status                     |
| `worker.schema.json`               | Private closed supervisor/worker protocol                |
| `lab-scenario.schema.json`         | Separate test-harness approval, not collection authority |

Evidence resources have `schema_version: "2.0.0"` and exact IDs
`https://jocky.dev/schemas/v2/forensic-record.schema.json` and
`https://jocky.dev/schemas/v2/evidence-manifest.schema.json`. Their sole context
variant is `local_lab`: collection, case, operator, endpoint, designation,
authorisation and policy UUIDs. No fabricated remote task/runtime/package IDs.
There is no EndpointIdentity, TaskEnvelope or BuildManifest v2 in this change.

Schema validation is only one layer: strict JSON rejects duplicate keys, BOM,
excessive depth/bytes and unsupported numbers. Typed checks enforce real UTC
dates, UUIDs, byte lengths, cross-document references, scope/time/limit inclusion,
canonical bytes, ordering, counts and digests. Examples carry expired authority;
even valid fixtures never designate the developer workstation.

Versioned source/compiler migration is separate: old `ubuntu` and `windows`
source and artifacts stay valid. A future selected `linux` profile does not
inherit Ubuntu-only availability or make catalogue entries executable. Native
MVP work does not implement that later compiler story or V6 source execution.

Deployment/testing status is recorded in
[Version 5 verification](../../../project-records/version-5-verification.md); this inventory
alone is not evidence that all listed schemas, validators or collectors exist.

## Decoder and implementation boundaries

All thirteen schema resources are deployed with a 104-case shared corpus and
independent Rust/Python compatibility checks. Besides schema byte/cardinality
bounds, strict decoders limit retained JSON values plus object keys to 131,072
nodes. This is an additional fail-closed memory guard, not a promise that every
combination of individual maxima fits one report. No network resolver is used.

`Coverage` distinguishes source facility state and a typed reason; `Field<T>`
distinguishes available values from unavailable requested facts. Unknown omitted
counts use null plus a reason, never an invented zero. Complete-empty is distinct
from all-unsupported/all-denied. The pure report verifier checks canonical bytes,
digest/manifest/identity/count/order consistency. It cannot establish that a
record is true, that a local declaration is authentic, or that a VM was tested.

Normalization compares IP addresses by parsed address bits and decimal inode/
start counters numerically; input arrays use explicit canonical ordering.
Report finalization cannot repair contradictory outcomes. Native budget charging,
full worker sequencing and publication are still pending. Current worker wire
shapes are not a functioning IPC protocol or evidence of resource enforcement.

## Definition checks and runtime validation

The shared crate's mandatory Cargo build guard validates all fourteen immutable
definitions, expected/unique IDs and local references (including unused `$defs`).
Malformed definitions and unknown references stop the build. The guard currently
accepts this inventory's flat resource IDs and ordinary `$ref`, not nested IDs or
dynamic/recursive-reference extensions. It uses the same locked Draft 2020-12
engine; no schema URI is fetched.

At runtime, small `$ref` entry points compile against a shared embedded registry.
All input constraints and format checks still execute, followed by strict typed
cross-field validation. No runtime-supplied schema is accepted. This avoids
retaining deep definition/meta-schema validation state in the limited supervisor;
it does not bypass incoming-document checks or initialize outside the measured
process. See [ADR-0019](../../../project-records/decisions.md#adr-0019-validate-embedded-schema-definitions-at-build-time).
Schema bytes/IDs/versions and the 64/192 MiB process limits remain unchanged.
