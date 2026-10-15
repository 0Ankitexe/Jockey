use super::identity::{TimeObservation, Uuid};
use super::inputs::{CollectionVersion, EvidenceVersion};
use super::outcomes::{Code, CollectorOutcome, ItemError, WorkUsed};
use super::records::{EndpointObservation, ForensicRecord, LocalContext};

wire!(ManifestEntry {
    record_id: Uuid,
    sequence: u64,
    byte_length: u64,
    sha256: String
});
wire!(EvidenceManifest {
    schema_version: EvidenceVersion, manifest_id: Uuid, context: LocalContext,
    created_at: TimeObservation, entries: Vec<ManifestEntry>, content_sha256: String
});
wire!(InputProvenance {
    id: Uuid,
    schema_version: CollectionVersion,
    sha256: String
});
wire!(Inputs {
    designation: InputProvenance, authorisation: InputProvenance, policy: InputProvenance,
    request: InputProvenance, indicators: Option<InputProvenance>
});
vocabulary!(ReportKind { LiveLab => "live_lab", SyntheticTest => "synthetic_test" });
vocabulary!(SummaryStatus { Complete => "complete", Partial => "partial", Failed => "failed" });
vocabulary!(WorkerCleanup { Complete => "complete", Incomplete => "incomplete", NotStarted => "not_started" });
wire!(Summary {
    status: SummaryStatus, stop_reason: Option<Code>, accepted_records: u64, errors: u64,
    omitted_known: u64, omitted_unknown: bool, source_bytes: u64, report_bytes: u64,
    work_used: WorkUsed, worker_cleanup: WorkerCleanup
});
wire!(CollectionReport {
    schema_version: CollectionVersion, report_kind: ReportKind, context: LocalContext,
    started_at: TimeObservation, finished_at: TimeObservation, endpoint: Option<EndpointObservation>,
    inputs: Inputs, collectors: Vec<CollectorOutcome>, records: Vec<ForensicRecord>,
    errors: Vec<ItemError>, summary: Summary, manifest: EvidenceManifest, content_sha256: String
});
vocabulary!(SuccessCode {
    Help => "Help", Version => "Version", InputsValid => "InputsValid", ReportValid => "ReportValid",
    PublishedComplete => "PublishedComplete", PublishedPartial => "PublishedPartial", PublishedFailed => "PublishedFailed"
});
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum StatusCode {
    Error(Code),
    Success(SuccessCode),
}
vocabulary!(Stage {
    Arguments => "arguments", Configuration => "configuration", Validation => "validation",
    Admission => "admission", Collection => "collection", Finalization => "finalization",
    Publication => "publication", Verification => "verification", Build => "build"
});

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub schema_version: CollectionVersion,
    pub code: StatusCode,
    pub stage: Stage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residue_ordinal: Option<u64>,
}
