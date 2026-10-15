#[path = "support/reports.rs"]
mod reports;

use jocky_forensic::collection::{report::finalize, verify::verify_report};
use jocky_shared::collection::{
    Code,
    outcomes::{CollectorStatus, Field},
    records::{Payload, SourceScope},
    report::{CollectionReport, SummaryStatus},
};
use serde_json::json;

const MAX: usize = 10_485_760;

fn rejects_change(report: &CollectionReport, pointer: &str, replacement: serde_json::Value) {
    let mut value = serde_json::to_value(report).unwrap();
    *value.pointer_mut(pointer).unwrap() = replacement;
    assert_eq!(
        finalize(serde_json::from_value(value).unwrap(), MAX),
        Err(Code::InvalidInput),
        "{pointer}"
    );
}

fn file_report() -> CollectionReport {
    let mut report = reports::observation(include_str!(
        "../../fixtures/valid/collection/forensic-record--metadata.json"
    ));
    let record = &mut report.records[0];
    let Payload::File(file) = &mut record.payload else {
        unreachable!()
    };
    file.location.root_id = record.provenance.source_id.clone();
    record.provenance.source_scope = SourceScope::Path {
        path: file.location.clone(),
    };
    report
}

#[test]
fn attributed_errors_round_trip_but_unrelated_sources_and_fields_fail() {
    let report = reports::with_error();
    let bytes = finalize(report.clone(), MAX).unwrap();
    let checked = verify_report(&bytes).unwrap();
    assert_eq!(checked.errors[0].item_ref, 17); // A source ordinal, NOT a record sequence.
    assert_eq!(checked.summary.status, SummaryStatus::Partial);
    rejects_change(
        &report,
        "/errors/0/source_id",
        json!(report.context.collection_id),
    );
    rejects_change(&report, "/errors/0/field_path", json!("/payload/sha256"));
    rejects_change(&report, "/errors/0/code", json!("NotRequested"));
    rejects_change(&report, "/errors/0/code", json!("Timeout"));
    let mut timeout = report.clone();
    timeout.errors[0].code = Code::Timeout;
    timeout.summary.stop_reason = Some(Code::Timeout);
    assert!(finalize(timeout, MAX).is_ok());
    // Collector-wide failure may have neither source nor field.
    let mut wide = report;
    wide.errors[0].source_id = None;
    wide.errors[0].field_path = None;
    assert!(finalize(wide, MAX).is_ok());
}

#[test]
fn absent_endpoint_cannot_claim_success_without_a_failure_reason() {
    let report = reports::base();
    rejects_change(&report, "/endpoint", json!(null));
    rejects_change(
        &report,
        "/endpoint/architecture",
        json!({"state":"unavailable","reason":"PermissionDenied"}),
    );
    let mut partial = report.clone();
    partial.endpoint = None;
    reports::partial(&mut partial, Code::FacilityUnavailable);
    assert!(finalize(partial, MAX).is_ok());
    let mut optional = report;
    optional.endpoint.as_mut().unwrap().abi = Field::Unavailable {
        reason: Code::NotRequested,
    };
    assert!(finalize(optional, MAX).is_ok());
}

#[test]
fn not_requested_is_not_an_execution_or_omission_failure() {
    let report = reports::with_error();
    for pointer in [
        "/summary/stop_reason",
        "/collectors/0/stop_reason",
        "/collectors/0/omitted_reason",
    ] {
        rejects_change(&report, pointer, json!("NotRequested"));
    }
}

#[test]
fn file_hash_matches_require_the_observed_complete_hash_and_correct_kind() {
    let report = reports::with_match(file_report(), "/payload/sha256", "sha256");
    assert!(finalize(report.clone(), MAX).is_ok());
    for (field, kind) in [
        ("/payload/location", "sha256"),
        ("/payload/sha256", "path"),
        ("/payload/hostname", "domain"),
    ] {
        let mut bad = report.clone();
        let Payload::Indicator(value) = &mut bad.records[1].payload else {
            unreachable!()
        };
        value.field_path = field.into();
        value.kind = serde_json::from_value(json!(kind)).unwrap();
        assert_eq!(finalize(bad, MAX), Err(Code::InvalidInput));
    }
    let mut missing = file_report();
    let Payload::File(file) = &mut missing.records[0].payload else {
        unreachable!()
    };
    file.sha256 = Field::Unavailable {
        reason: Code::PermissionDenied,
    };
    reports::partial(&mut missing, Code::PermissionDenied);
    assert!(finalize(missing.clone(), MAX).is_ok());
    assert_eq!(
        finalize(
            reports::with_match(missing, "/payload/sha256", "sha256"),
            MAX
        ),
        Err(Code::InvalidInput)
    );
    assert!(
        finalize(
            reports::with_match(file_report(), "/payload/location", "path"),
            MAX
        )
        .is_ok()
    );
}

#[test]
fn domain_matches_require_an_explicit_available_fqdn_not_free_text() {
    let mut report = reports::base();
    let Payload::System(system) = &mut report.records[0].payload else {
        unreachable!()
    };
    system.hostname = Field::Available {
        value: "Host.Example.".into(),
    };
    let matched = reports::with_match(report, "/payload/hostname", "domain");
    assert!(finalize(matched.clone(), MAX).is_ok());
    for value in [
        "localhost",
        "127.0.0.1",
        "bad host.example",
        "a..example",
        "-a.example",
        "a-.example",
        "é.example",
        "*.example",
        "a.example..",
    ] {
        rejects_change(&matched, "/records/0/payload/hostname/value", json!(value));
    }
    let mut missing = reports::base();
    let Payload::System(system) = &mut missing.records[0].payload else {
        unreachable!()
    };
    system.hostname = Field::Unavailable {
        reason: Code::PermissionDenied,
    };
    reports::partial(&mut missing, Code::PermissionDenied);
    assert_eq!(
        finalize(
            reports::with_match(missing, "/payload/hostname", "domain"),
            MAX
        ),
        Err(Code::InvalidInput)
    );
}

#[test]
fn connection_owners_are_unique_and_matches_use_typed_addresses() {
    let mut report = reports::observation(include_str!(
        "../../fixtures/valid/collection/forensic-record--connection.json"
    ));
    let identity = serde_json::from_value(
        json!({"boot_id": report.context.collection_id, "pid":42, "start_ticks":"12"}),
    )
    .unwrap();
    let Payload::Connection(connection) = &mut report.records[0].payload else {
        unreachable!()
    };
    connection.owners = Field::Available {
        value: vec![identity],
    };
    for field in ["/payload/local_address", "/payload/remote_address"] {
        assert!(
            finalize(
                reports::with_match(report.clone(), field, "ip_address"),
                MAX
            )
            .is_ok()
        );
    }
    let Payload::Connection(connection) = &mut report.records[0].payload else {
        unreachable!()
    };
    let Field::Available { value } = &mut connection.owners else {
        unreachable!()
    };
    value.push(value[0].clone());
    assert_eq!(finalize(report, MAX), Err(Code::InvalidInput));
}

#[test]
fn persistence_locations_remain_inside_the_declared_source_path() {
    let mut report = reports::observation(include_str!(
        "../../fixtures/valid/collection/forensic-record--entry.json"
    ));
    let Payload::Persistence(entry) = &mut report.records[0].payload else {
        unreachable!()
    };
    entry.location.relative_path = "approved/entry.service".into();
    let mut directory = entry.location.clone();
    directory.relative_path = "approved".into();
    report.records[0].provenance.source_scope = SourceScope::Path { path: directory };
    assert!(finalize(report.clone(), MAX).is_ok());
    assert!(
        finalize(
            reports::with_match(report.clone(), "/payload/location", "path"),
            MAX
        )
        .is_ok()
    );
    for path in ["other/entry.service", "approved-neighbor/entry.service"] {
        rejects_change(
            &report,
            "/records/0/payload/location/relative_path",
            json!(path),
        );
    }
    rejects_change(
        &report,
        "/records/0/payload/location/root_id",
        json!(report.context.collection_id),
    );
    assert_eq!(
        finalize(
            reports::with_match(report, "/payload/content_sha256", "sha256"),
            MAX
        ),
        Err(Code::InvalidInput)
    );
}

#[test]
fn unavailable_endpoint_information_can_be_reported_as_partial() {
    let mut report = reports::base();
    report.endpoint.as_mut().unwrap().kernel_release = Field::Unavailable {
        reason: Code::PermissionDenied,
    };
    reports::partial(&mut report, Code::PermissionDenied);
    assert_eq!(report.collectors[0].status, CollectorStatus::Partial);
    assert!(finalize(report, MAX).is_ok());
}

#[test]
fn service_process_and_driver_observations_round_trip_without_indicator_shortcuts() {
    for text in [
        include_str!("../../fixtures/valid/collection/forensic-record--service.json"),
        include_str!("../../fixtures/valid/collection/forensic-record--process.json"),
        include_str!("../../fixtures/valid/collection/forensic-record--module.json"),
    ] {
        let report = reports::observation(text);
        let bytes = finalize(report.clone(), MAX).unwrap();
        assert_eq!(verify_report(&bytes).unwrap().records.len(), 1);
        assert_eq!(
            finalize(
                reports::with_match(report, "/payload/domain", "domain"),
                MAX
            )
            .map(|_| ()),
            Err(Code::InvalidInput)
        );
    }
}

#[test]
fn event_domains_are_typed_candidates_but_messages_cannot_supply_a_match() {
    use jocky_shared::collection::inputs::PathRef;
    let mut report = reports::observation(include_str!(
        "../../fixtures/valid/collection/forensic-record--log.json"
    ));
    report.records[0].provenance.source_scope = SourceScope::Path {
        path: PathRef::new(report.context.policy_id.clone(), "synthetic.log").unwrap(),
    };
    let source_id = report.records[0].provenance.source_id.clone();
    let Payload::Event(event) = &mut report.records[0].payload else {
        unreachable!()
    };
    event.domain = Field::Available {
        value: "event.example".into(),
    };
    event.source_id = source_id;
    event.message = "untrusted.example appears only in text".into();
    let matched = reports::with_match(report, "/payload/domain", "domain");
    assert!(finalize(matched.clone(), MAX).is_ok());
    rejects_change(
        &matched,
        "/records/0/payload/domain",
        json!({"state":"unavailable","reason":"NotRequested"}),
    );
    rejects_change(
        &matched,
        "/records/1/payload/field_path",
        json!("/payload/message"),
    );
    rejects_change(
        &matched,
        "/records/1/payload/matched_record_id",
        json!(matched.records[1].record_id),
    );
    rejects_change(
        &matched,
        "/records/1/payload/matched_record_id",
        json!(matched.context.collection_id),
    );
}

#[test]
fn system_profile_is_a_singleton_not_duplicate_success_records() {
    use jocky_forensic::collection::identity::{IdentityKind, derive_id};
    let mut report = reports::base();
    let mut second = report.records[0].clone();
    second.sequence = 1;
    second.record_id = derive_id(IdentityKind::Record, &report.context.collection_id, 1).unwrap();
    report.records.push(second);
    report.collectors[0].accepted_records = 2;
    reports::reconcile(&mut report);
    assert_eq!(finalize(report, MAX).map(|_| ()), Err(Code::InvalidInput));
}
