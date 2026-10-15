//! Synthetic report assembly only; no source access and no live authority.
use jocky_forensic::collection::{
    identity::{IdentityKind, derive_id},
    outcome,
};
use jocky_shared::collection::{
    Code,
    inputs::CollectionVersion,
    outcomes::{CollectorStatus, Coverage, FacilityState, ItemError},
    records::{ForensicRecord, SourceScope},
    report::{CollectionReport, InputProvenance},
};

pub fn base() -> CollectionReport {
    serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/report.json"
    ))
    .unwrap()
}

pub fn observation(text: &str) -> CollectionReport {
    let mut report = base();
    let mut record: ForensicRecord = serde_json::from_str(text).unwrap();
    record.provenance.policy_sha256 = report.inputs.policy.sha256.clone();
    record.provenance.authorisation_sha256 = report.inputs.authorisation.sha256.clone();
    record.provenance.request_sha256 = report.inputs.request.sha256.clone();
    report.collectors[0].collector = record.collector.name;
    report.records = vec![record];
    report
}

pub fn partial(report: &mut CollectionReport, code: Code) {
    let outcome = &mut report.collectors[0];
    outcome.status = CollectorStatus::Partial;
    outcome.stop_reason = Some(code);
    outcome.omitted_reason = Some(code);
    reconcile(report);
}

pub fn reconcile(report: &mut CollectionReport) {
    let summary =
        outcome::summarize(&report.collectors, None, report.summary.worker_cleanup).unwrap();
    report.summary.status = summary.status;
    report.summary.stop_reason = summary.stop_reason;
    report.summary.accepted_records = summary.accepted_records;
    report.summary.errors = summary.errors;
    report.summary.work_used.errors = summary.errors;
    report.summary.omitted_known = summary.omitted_known;
    report.summary.omitted_unknown = summary.omitted_unknown;
}

pub fn with_error() -> CollectionReport {
    let mut report = base();
    report.errors.push(ItemError {
        error_id: derive_id(IdentityKind::Error, &report.context.collection_id, 0).unwrap(),
        collector: report.collectors[0].collector,
        source_id: Some(report.collectors[0].coverage[0].source_id.clone()),
        item_ref: 17,
        field_path: Some("/payload/hostname".into()),
        code: Code::PermissionDenied,
        retryable: false,
        counted_omission: true,
    });
    report.collectors[0].errors = 1;
    partial(&mut report, Code::PermissionDenied);
    report
}

pub fn with_match(mut report: CollectionReport, field: &str, kind: &str) -> CollectionReport {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/forensic-record--match.json"
    ))
    .unwrap();
    value["payload"]["field_path"] = field.into();
    value["payload"]["kind"] = kind.into();
    value["payload"]["matched_record_id"] = report.records[0].record_id.as_str().into();
    let mut record: ForensicRecord = serde_json::from_value(value).unwrap();
    record.sequence = 1;
    record.record_id = derive_id(IdentityKind::Record, &report.context.collection_id, 1).unwrap();
    let set_id = report.context.collection_id.clone();
    if let jocky_shared::collection::records::Payload::Indicator(value) = &mut record.payload {
        value.indicator_set_id = set_id.clone();
    }
    record.provenance.source_id = set_id.clone();
    record.provenance.source_scope = SourceScope::Indicators {
        indicator_set_id: set_id.clone(),
    };
    record.provenance.policy_sha256 = report.inputs.policy.sha256.clone();
    record.provenance.authorisation_sha256 = report.inputs.authorisation.sha256.clone();
    record.provenance.request_sha256 = report.inputs.request.sha256.clone();
    report.inputs.indicators = Some(InputProvenance {
        id: set_id.clone(),
        schema_version: CollectionVersion::V1,
        sha256: "0".repeat(64),
    });
    let mut outcome = base().collectors.remove(0);
    outcome.collector = record.collector.name;
    outcome.coverage = vec![Coverage {
        source_id: set_id,
        state: FacilityState::Supported,
        reason: None,
    }];
    report.records.push(record);
    report.collectors.push(outcome);
    reconcile(&mut report);
    report
}
