//! Synthetic adapter output through the canonical report verifier; no host reads.
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

use jocky_forensic::collection::{InputSet, admit, outcome, report};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    inputs::{PathRef, UtcWindow},
    outcomes::{Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState},
    records::{Adapter, Category, Payload, ProvenanceKind, SourceScope},
    report::{CollectionReport, SummaryStatus, WorkerCleanup},
};
use std::collections::BTreeMap;

fn source(id: &str) -> Uuid {
    Uuid::parse(id).unwrap()
}
fn complete(collector: Collector, source_id: Uuid) -> CollectorOutcome {
    CollectorOutcome {
        collector,
        status: CollectorStatus::Complete,
        coverage: vec![Coverage {
            source_id,
            state: FacilityState::Supported,
            reason: None,
        }],
        accepted_records: 1,
        omitted_records: Some(0),
        omitted_reason: None,
        errors: 0,
        stop_reason: None,
    }
}
fn synthetic_report() -> CollectionReport {
    let mut model: CollectionReport = serde_json::from_slice(include_bytes!(
        "../../../fixtures/valid/collection/report.json"
    ))
    .unwrap();
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
        support::Frozen::default().0,
    )
    .unwrap();
    let at = model.started_at.clone();
    let service_id = source("10000000-0000-4000-8000-000000000021");
    let persistence_id = source("10000000-0000-4000-8000-000000000022");
    let event_id = source("10000000-0000-4000-8000-000000000023");
    let driver_id = source("10000000-0000-4000-8000-000000000024");
    let service_name = "jocky-synthetic.service".to_owned();
    let service = collectors::services::normalize(sources::systemd::Snapshot {
        units: vec![sources::systemd::UnitFact {
            name: service_name.clone(),
            description: "Synthetic service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            object_path: "/org/freedesktop/systemd1/unit/jocky_2dsynthetic_2eservice".into(),
        }],
        files: vec![sources::systemd::UnitFileFact {
            name: service_name,
            state: "enabled".into(),
        }],
        properties: BTreeMap::new(),
    })
    .unwrap()
    .remove(0);
    let root = source("10000000-0000-4000-8000-000000000090");
    let startup_path = PathRef {
        root_id: root.clone(),
        relative_path: "jocky-synthetic.service".into(),
    };
    let persistence = collectors::persistence::systemd::parse_unit(
        b"[Unit]\nDescription=Synthetic\n[Service]\nExecStart=/usr/bin/true\n",
        startup_path.clone(),
    )
    .unwrap();
    let log_path = PathRef {
        root_id: root,
        relative_path: "jocky-synthetic.log".into(),
    };
    let window = UtcWindow {
        start: jocky_shared::collection::identity::UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        end: jocky_shared::collection::identity::UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
    };
    let event = collectors::events::text::parse(
        b"<14>1 2020-01-01T00:00:00Z lab app 1 ID47 - synthetic marker\n",
        event_id.clone(),
        &window,
    )
    .unwrap()
    .remove(0);
    let driver = collectors::drivers::parse_loaded(
        b"jocky_synthetic 4096 1 - Live 0xffff000000000000\n",
        |_, _| Ok(b"1.0\n".to_vec()),
    )
    .unwrap()
    .remove(0);
    for (collector, adapter, category, kind, id, scope, payload) in [
        (
            Collector::Services,
            Adapter::Systemd,
            Category::System,
            ProvenanceKind::SystemdBus,
            service_id.clone(),
            collectors::record::facility_scope(service_id.clone()),
            Payload::Service(service),
        ),
        (
            Collector::Persistence,
            Adapter::Startup,
            Category::Persistence,
            ProvenanceKind::StartupDirectory,
            persistence_id.clone(),
            SourceScope::Path { path: startup_path },
            Payload::Persistence(persistence),
        ),
        (
            Collector::Events,
            Adapter::TextLog,
            Category::Event,
            ProvenanceKind::TextLog,
            event_id.clone(),
            SourceScope::Path { path: log_path },
            Payload::Event(event),
        ),
        (
            Collector::Drivers,
            Adapter::Modules,
            Category::Driver,
            ProvenanceKind::SysModules,
            driver_id.clone(),
            collectors::record::facility_scope(driver_id.clone()),
            Payload::Driver(driver),
        ),
    ] {
        model.records.push(
            collectors::record::make(
                &context,
                collector,
                adapter,
                category,
                kind,
                id.clone(),
                scope,
                payload,
                model.records.len() as u64,
                at.clone(),
            )
            .unwrap(),
        );
        model.collectors.push(complete(collector, id));
    }
    model.summary.accepted_records = model.records.len() as u64;
    model.summary.work_used.entries = model.records.len() as u64;
    model
}
fn finalize(mut model: CollectionReport) -> CollectionReport {
    let summary = outcome::summarize(&model.collectors, None, WorkerCleanup::Complete).unwrap();
    model.summary.status = summary.status;
    model.summary.stop_reason = summary.stop_reason;
    model.summary.accepted_records = summary.accepted_records;
    model.summary.errors = summary.errors;
    model.summary.omitted_known = summary.omitted_known;
    model.summary.omitted_unknown = summary.omitted_unknown;
    let raw = report::finalize(model, 10_485_760).unwrap();
    jocky_forensic::collection::verify::verify_report(&raw).unwrap()
}

#[test]
fn native_assembly_canonicalizes_unordered_facility_records() {
    let mut model = synthetic_report();
    model.records.swap(3, 4);
    collection::canonicalize_records(&mut model.records, &model.context.collection_id).unwrap();
    let verified = finalize(model);
    assert_eq!(verified.records.len(), 5);
    assert!(jocky_forensic::collection::normalize::is_ordered(&verified.records).unwrap());
}

#[test]
fn real_facility_adapters_verify_complete_payloads_and_provenance() {
    let verified = finalize(synthetic_report());
    assert_eq!(verified.summary.status, SummaryStatus::Complete);
    assert_eq!(verified.records.len(), 5);
    for record in &verified.records {
        assert_eq!(
            record.severity,
            jocky_shared::collection::records::Severity::Informational
        );
        assert_eq!(
            record.provenance.policy_sha256,
            verified.inputs.policy.sha256
        );
    }
    assert_eq!(
        verified
            .collectors
            .iter()
            .map(|item| item.accepted_records)
            .sum::<u64>(),
        5
    );
}

#[test]
fn denied_backend_preserves_partial_and_all_failed_never_claims_success() {
    let mut partial = synthetic_report();
    partial
        .records
        .retain(|record| record.collector.name != Collector::Services);
    for (index, record) in partial.records.iter_mut().enumerate() {
        record.sequence = index as u64;
        record.record_id = jocky_forensic::collection::identity::derive_id(
            jocky_forensic::collection::identity::IdentityKind::Record,
            &partial.context.collection_id,
            index as u64,
        )
        .unwrap();
    }
    let service = partial
        .collectors
        .iter_mut()
        .find(|item| item.collector == Collector::Services)
        .unwrap();
    service.status = CollectorStatus::PermissionDenied;
    service.coverage[0].state = FacilityState::PermissionDenied;
    service.coverage[0].reason = Some(Code::PermissionDenied);
    service.accepted_records = 0;
    service.omitted_records = Some(1);
    service.omitted_reason = Some(Code::PermissionDenied);
    service.stop_reason = Some(Code::PermissionDenied);
    assert_eq!(finalize(partial).summary.status, SummaryStatus::Partial);

    let mut failed = synthetic_report();
    failed.records.clear();
    failed.endpoint = None;
    for item in &mut failed.collectors {
        *item = outcome::unsupported(item.collector);
    }
    assert_eq!(finalize(failed).summary.status, SummaryStatus::Failed);
}
