//! Synthetic-only orchestration checks. No source path or endpoint is opened.
#![cfg(target_os = "linux")]
#[path = "../src/cli/mod.rs"]
#[allow(dead_code)]
mod cli;
#[path = "../src/collection.rs"]
#[allow(dead_code)]
mod collection;
#[path = "../src/collectors/mod.rs"]
#[allow(dead_code)]
mod collectors;
#[path = "../src/sources/mod.rs"]
#[allow(dead_code)]
mod sources;
#[path = "support/confinement.rs"]
#[allow(dead_code)]
mod support;
#[path = "../src/worker/mod.rs"]
#[allow(dead_code)]
mod worker;

use collection::Collected;
use jocky_forensic::collection::{ClockReading, InputSet, admit, outcome};
use jocky_shared::collection::{
    Code,
    identity::UtcTime,
    outcomes::CollectorStatus,
    report::{CollectionReport, SummaryStatus},
};

struct Frozen(ClockReading);
impl jocky_forensic::collection::clock::Clock for Frozen {
    fn read(&mut self) -> Result<ClockReading, Code> {
        Ok(self.0.clone())
    }
}

fn admitted() -> (
    jocky_forensic::collection::ValidatedCollectionContext,
    Frozen,
) {
    let now = ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        monotonic_ms: 0,
    };
    let context = admit(
        InputSet {
            designation: include_bytes!(
                "../../../fixtures/valid/collection/endpoint-designation.json"
            ),
            authorisation: Some(include_bytes!(
                "../../../fixtures/valid/collection/authorisation.json"
            )),
            policy: include_bytes!("../../../fixtures/valid/collection/policy.json"),
            request: include_bytes!("../../../fixtures/valid/collection/request.json"),
            indicators: None,
        },
        now.clone(),
    )
    .unwrap();
    (context, Frozen(now))
}

fn model() -> CollectionReport {
    serde_json::from_slice(include_bytes!(
        "../../../fixtures/valid/collection/report.json"
    ))
    .unwrap()
}

#[test]
fn admitted_domain_match_survives_report_assembly_and_verification() {
    use jocky_shared::collection::{
        outcomes::Collector,
        records::{Adapter, Category, ProvenanceKind},
    };
    use serde_json::json;
    let mut input = [
        include_str!("../../../fixtures/valid/collection/endpoint-designation.json"),
        include_str!("../../../fixtures/valid/collection/authorisation.json"),
        include_str!("../../../fixtures/valid/collection/policy.json"),
        include_str!("../../../fixtures/valid/collection/request.json"),
        include_str!("../../../fixtures/valid/collection/indicator-set.json"),
    ]
    .map(|value| serde_json::from_str::<serde_json::Value>(value).unwrap());
    for index in [1, 2] {
        input[index]["scope"]["capabilities"] = json!(["system", "indicators"]);
    }
    input[3]["capabilities"] = json!(["system", "indicators"]);
    input[3]["collectors"] = json!(["system", "indicators"]);
    input[3]["indicator_set_id"] = input[4]["indicator_set_id"].clone();
    input[4]["indicators"] = json!([{
        "indicator_id":"10000000-0000-4000-8000-000000000020",
        "kind":"domain", "value":"synthetic.invalid"
    }]);
    let raw = input
        .each_ref()
        .map(|value| serde_json::to_vec(value).unwrap());
    let now = ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        monotonic_ms: 0,
    };
    let context = admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: Some(&raw[4]),
        },
        now.clone(),
    )
    .unwrap();
    let model = model();
    let source_id = model.records[0].provenance.source_id.clone();
    let system = collectors::record::make(
        &context,
        Collector::System,
        Adapter::KernelProfile,
        Category::System,
        ProvenanceKind::KernelProfile,
        source_id.clone(),
        collectors::record::facility_scope(source_id),
        model.records[0].payload.clone(),
        0,
        model.started_at.clone(),
    )
    .unwrap();
    let part = Collected {
        outcome: model.collectors[0].clone(),
        usage: model.summary.work_used.clone(),
        records: vec![system],
        errors: Vec::new(),
    };
    let empty = Collected {
        outcome: outcome::unsupported(Collector::Indicators),
        usage: jocky_shared::collection::outcomes::WorkUsed {
            entries: 0,
            indicator_comparisons: 0,
            errors: 0,
            source_bytes: 0,
            staging_bytes: 0,
            retained_bytes: 0,
        },
        records: Vec::new(),
        errors: Vec::new(),
    };
    let encoded = collection::assemble(
        &context,
        vec![part, empty],
        model.endpoint,
        model.finished_at,
        &mut Frozen(now),
    )
    .unwrap();
    let verified = jocky_forensic::collection::verify::verify_report(&encoded).unwrap();
    assert_eq!(verified.records.len(), 2);
    assert!(matches!(
        verified.records[1].payload,
        jocky_shared::collection::records::Payload::Indicator(_)
    ));
    assert_eq!(verified.summary.work_used.indicator_comparisons, 1);
}

#[test]
fn fake_complete_partial_and_all_failed_keep_their_real_summary_states() {
    let model = model();
    for expected in [
        SummaryStatus::Complete,
        SummaryStatus::Partial,
        SummaryStatus::Failed,
    ] {
        let (context, mut clock) = admitted();
        let mut part = Collected {
            outcome: model.collectors[0].clone(),
            usage: model.summary.work_used.clone(),
            records: model.records.clone(),
            errors: Vec::new(),
        };
        let endpoint = if expected == SummaryStatus::Failed {
            part = Collected {
                outcome: outcome::unsupported(part.outcome.collector),
                usage: jocky_shared::collection::outcomes::WorkUsed {
                    entries: 0,
                    indicator_comparisons: 0,
                    errors: 0,
                    source_bytes: 0,
                    staging_bytes: 0,
                    retained_bytes: 0,
                },
                records: Vec::new(),
                errors: Vec::new(),
            };
            None
        } else {
            if expected == SummaryStatus::Partial {
                part.outcome.status = CollectorStatus::Partial;
                part.outcome.omitted_records = None;
                part.outcome.omitted_reason = Some(Code::PermissionDenied);
                part.outcome.stop_reason = Some(Code::PermissionDenied);
            }
            model.endpoint.clone()
        };
        let raw = collection::assemble(
            &context,
            vec![part],
            endpoint,
            model.finished_at.clone(),
            &mut clock,
        )
        .unwrap();
        let verified = jocky_forensic::collection::verify::verify_report(&raw).unwrap();
        assert_eq!(verified.summary.status, expected);
        assert_eq!(
            verified.records.is_empty(),
            expected == SummaryStatus::Failed
        );
    }
}

#[test]
fn genuine_profile_record_supplies_endpoint_fields_without_distro_inference() {
    let (context, _) = admitted();
    let model = model();
    let part = Collected {
        outcome: model.collectors[0].clone(),
        usage: model.summary.work_used,
        records: model.records,
        errors: Vec::new(),
    };
    let endpoint = collection::endpoint_from_parts(&context, &[part])
        .unwrap()
        .unwrap();
    assert_eq!(endpoint.endpoint_id, context.identity().endpoint_id);
    assert_eq!(
        endpoint.distribution.id,
        model.endpoint.unwrap().distribution.id
    );
    assert!(
        matches!(endpoint.abi, jocky_shared::collection::outcomes::Field::Available { ref value } if value == "gnu")
    );
}

#[test]
fn admitted_profile_record_envelope_survives_canonical_report_verification() {
    use jocky_shared::collection::records::{Adapter, Category, ProvenanceKind};
    let (context, mut clock) = admitted();
    let model = model();
    let source_id = model.records[0].provenance.source_id.clone();
    let payload = model.records[0].payload.clone();
    let record = collectors::record::make(
        &context,
        jocky_shared::collection::outcomes::Collector::System,
        Adapter::KernelProfile,
        Category::System,
        ProvenanceKind::KernelProfile,
        source_id.clone(),
        collectors::record::facility_scope(source_id),
        payload,
        0,
        model.started_at.clone(),
    )
    .unwrap();
    let part = Collected {
        outcome: model.collectors[0].clone(),
        usage: model.summary.work_used,
        records: vec![record],
        errors: Vec::new(),
    };
    let raw = collection::assemble(
        &context,
        vec![part],
        model.endpoint,
        model.finished_at,
        &mut clock,
    )
    .unwrap();
    assert_eq!(
        jocky_forensic::collection::verify::verify_report(&raw)
            .unwrap()
            .records
            .len(),
        1
    );
}

#[test]
fn preflight_rejects_missing_or_forged_worker_results_before_finalization() {
    let (context, mut clock) = admitted();
    assert_eq!(
        collection::assemble(
            &context,
            Vec::new(),
            None,
            context.started_at().clone(),
            &mut clock
        ),
        Err(Code::WorkerProtocol)
    );
    let model = model();
    let mut part = Collected {
        outcome: model.collectors[0].clone(),
        usage: model.summary.work_used,
        records: Vec::new(),
        errors: Vec::new(),
    };
    assert_eq!(
        collection::assemble(
            &context,
            vec![part],
            None,
            model.finished_at.clone(),
            &mut clock
        ),
        Err(Code::WorkerProtocol)
    );
    part = Collected {
        outcome: outcome::unsupported(model.collectors[0].collector),
        usage: jocky_shared::collection::outcomes::WorkUsed {
            entries: 0,
            indicator_comparisons: 0,
            errors: 0,
            source_bytes: 0,
            staging_bytes: 0,
            retained_bytes: 0,
        },
        records: Vec::new(),
        errors: Vec::new(),
    };
    let raw =
        collection::assemble(&context, vec![part], None, model.finished_at, &mut clock).unwrap();
    assert_eq!(
        jocky_forensic::collection::verify::verify_report(&raw)
            .unwrap()
            .summary
            .status,
        SummaryStatus::Failed
    );
}

#[test]
fn denied_pipeline_never_dispatches_a_source_or_publisher_worker() {
    use jocky_forensic::collection::context::OperationTarget;
    use sources::capabilities::OutputDirectory;
    use std::{cell::Cell, fs};
    let owned = support::scratch();
    let source = owned.path().join("source");
    let output_path = owned.path().join("output");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&output_path).unwrap();
    let context = support::context(&support::values(source.to_str().unwrap(), "selected"));
    let selected = support::path("selected");
    let mut clock = support::Frozen::default();
    let output = OutputDirectory::open(
        &context,
        OperationTarget::File(&selected),
        output_path.join("report.json").to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    let launch = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    let source_calls = Cell::new(0);
    let publisher_calls = Cell::new(0);
    let result = collection::run_with(
        &context,
        &[],
        &output,
        launch,
        &mut clock,
        || false,
        |_, _, _, _, _| {
            source_calls.set(source_calls.get() + 1);
            Err(Code::WorkerFailed)
        },
        |_, _, _, _, _, _| {
            publisher_calls.set(publisher_calls.get() + 1);
            Err(Code::WorkerFailed)
        },
    );
    assert!(matches!(result, Err(Code::WorkerProtocol)));
    assert_eq!(source_calls.get(), 0);
    assert_eq!(publisher_calls.get(), 0);
    assert!(fs::read_dir(&output_path).unwrap().next().is_none());
}
