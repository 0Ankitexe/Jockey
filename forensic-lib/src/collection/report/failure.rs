use crate::collection::{
    ValidatedCollectionContext,
    identity::{IdentityKind, derive_id},
    outcome,
};
use jocky_shared::collection::{
    Code,
    identity::TimeObservation,
    inputs::{CollectionVersion, EvidenceVersion},
    outcomes::{CollectorOutcome, CollectorStatus},
    report::*,
};

/// Build an explicit no-observation failure envelope, not a replacement for an
/// investigation that already accepted records. Callers must retain those records.
pub fn failure(
    context: &ValidatedCollectionContext,
    kind: ReportKind,
    finished_at: TimeObservation,
    reason: Code,
    cleanup: WorkerCleanup,
) -> Result<CollectionReport, Code> {
    if reason == Code::NotRequested {
        return Err(Code::InvalidInput);
    }
    let usage = context.empty_report_usage()?;
    let collectors: Vec<_> = context
        .input
        .request
        .collectors
        .iter()
        .map(|c| CollectorOutcome {
            collector: *c,
            status: CollectorStatus::Failed,
            coverage: Vec::new(),
            accepted_records: 0,
            omitted_records: None,
            omitted_reason: Some(reason),
            errors: 0,
            stop_reason: Some(reason),
        })
        .collect();
    let summary = outcome::summarize(&collectors, Some(reason), cleanup)?;
    Ok(CollectionReport {
        schema_version: CollectionVersion::V1,
        report_kind: kind,
        context: context.identity().clone(),
        started_at: context.started_at().clone(),
        finished_at: finished_at.clone(),
        endpoint: None,
        inputs: context.input_provenance().clone(),
        collectors,
        records: Vec::new(),
        errors: Vec::new(),
        summary: Summary {
            status: summary.status,
            stop_reason: summary.stop_reason,
            accepted_records: 0,
            errors: 0,
            omitted_known: 0,
            omitted_unknown: true,
            source_bytes: usage.source_bytes,
            report_bytes: 0,
            work_used: usage,
            worker_cleanup: cleanup,
        },
        manifest: EvidenceManifest {
            schema_version: EvidenceVersion::V2,
            manifest_id: derive_id(IdentityKind::Manifest, &context.identity().collection_id, 0)?,
            context: context.identity().clone(),
            created_at: finished_at,
            entries: Vec::new(),
            content_sha256: "0".repeat(64),
        },
        content_sha256: "0".repeat(64),
    })
}
