use jocky_forensic::collection::{
    canonical,
    identity::{IdentityKind, derive_id},
    verify::verify_report,
};
use jocky_shared::collection::{Code, identity::Uuid};

#[test]
fn canonical_encoding_is_sorted_exact_unicode_and_bounded() {
    let value = serde_json::json!({"z":"é/\n\u{1}","a":[true,null,-1]});
    assert_eq!(
        canonical::encode(&value, 100).unwrap(),
        "{\"a\":[true,null,-1],\"z\":\"é/\\n\\u0001\"}".as_bytes()
    );
    assert_eq!(
        canonical::encode(&serde_json::json!(true), 4).unwrap(),
        b"true"
    );
    assert_eq!(
        canonical::encode(&serde_json::json!(true), 3),
        Err(Code::ResourceLimit)
    );
    for bad in [
        serde_json::json!(1.5),
        serde_json::json!(9007199254740992u64),
        serde_json::json!({"é":1}),
    ] {
        assert_eq!(canonical::encode(&bad, 100), Err(Code::InvalidInput));
    }
}

#[test]
fn record_manifest_error_ids_are_deterministic_and_domain_separated() {
    let collection = Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap();
    let first = derive_id(IdentityKind::Record, &collection, 0).unwrap();
    assert_eq!(
        first,
        derive_id(IdentityKind::Record, &collection, 0).unwrap()
    );
    assert_ne!(
        first,
        derive_id(IdentityKind::Record, &collection, 1).unwrap()
    );
    assert_ne!(
        first,
        derive_id(IdentityKind::Manifest, &collection, 0).unwrap()
    );
    assert_ne!(
        first,
        derive_id(IdentityKind::Error, &collection, 0).unwrap()
    );
    assert_eq!(first.as_str().as_bytes()[14], b'8');
    assert!(b"89ab".contains(&first.as_str().as_bytes()[19]));
    assert_eq!(
        derive_id(IdentityKind::Manifest, &collection, 1),
        Err(Code::InvalidInput)
    );
}

#[test]
fn synthetic_report_verifies_without_opening_any_source_and_corruption_fails() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/valid/collection/report.json")).unwrap();
    let mut bytes = canonical::encode(&value, 10485759).unwrap();
    bytes.push(b'\n');
    let verified = verify_report(&bytes).unwrap();
    assert_eq!(verified.summary.accepted_records, 1);
    for pointer in [
        "/content_sha256",
        "/manifest/content_sha256",
        "/records/0/content_sha256",
        "/records/0/provenance/policy_sha256",
    ] {
        let mut corrupt = value.clone();
        *corrupt.pointer_mut(pointer).unwrap() = serde_json::json!("1".repeat(64));
        let mut bytes = canonical::encode(&corrupt, 10485759).unwrap();
        bytes.push(b'\n');
        assert_eq!(verify_report(&bytes).unwrap_err(), Code::InvalidInput);
    }
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert_eq!(verify_report(&pretty).unwrap_err(), Code::InvalidInput);
}

#[test]
fn finalization_is_deterministic_bounded_and_does_not_repair_false_success() {
    use jocky_forensic::collection::report::finalize;
    use jocky_shared::collection::report::CollectionReport;
    let report: CollectionReport =
        serde_json::from_str(include_str!("../../fixtures/valid/collection/report.json")).unwrap();
    let first = finalize(report.clone(), 10485760).unwrap();
    assert_eq!(first, finalize(report.clone(), 10485760).unwrap());
    assert_eq!(first, finalize(report.clone(), first.len()).unwrap());
    assert_eq!(
        finalize(report.clone(), first.len() - 1),
        Err(Code::ResourceLimit)
    );
    let mut bad = report.clone();
    bad.summary.accepted_records = 2;
    assert_eq!(finalize(bad, 10485760), Err(Code::InvalidInput));
    let mut bad = report.clone();
    bad.records[0].collector.adapter = jocky_shared::collection::records::Adapter::Processes;
    assert_eq!(finalize(bad, 10485760), Err(Code::InvalidInput));
    let mut bad = report;
    bad.collectors[0].coverage.clear();
    assert_eq!(finalize(bad, 10485760), Err(Code::InvalidInput));
}

#[test]
fn rehashed_contradictions_do_not_become_valid_evidence() {
    use jocky_forensic::collection::report::finalize;
    let base: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/valid/collection/report.json")).unwrap();
    for (pointer, replacement) in [
        (
            "/collectors/0/coverage/0/state",
            serde_json::json!("permission_denied"),
        ),
        (
            "/collectors/0/coverage/0/reason",
            serde_json::json!("PermissionDenied"),
        ),
        (
            "/collectors/0/omitted_reason",
            serde_json::json!("PermissionDenied"),
        ),
        ("/summary/stop_reason", serde_json::json!("Cancelled")),
        (
            "/manifest/created_at/value",
            serde_json::json!("2019-12-31T00:00:00Z"),
        ),
        (
            "/endpoint/observed_at/value",
            serde_json::json!("2020-01-02T00:00:00Z"),
        ),
        ("/endpoint/os_family", serde_json::json!("windows")),
        (
            "/records/0/provenance/observed_start/value",
            serde_json::json!("2019-12-31T00:00:00Z"),
        ),
        (
            "/records/0/provenance/observed_end/value",
            serde_json::json!("2020-01-02T00:00:00Z"),
        ),
        (
            "/records/0/provenance/source_scope",
            serde_json::json!({"kind":"path","path":{"root_id":"10000000-0000-4000-8000-000000000008","relative_path":"not-a-kernel-source"}}),
        ),
    ] {
        let mut value = base.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let result = finalize(serde_json::from_value(value).unwrap(), 10485760);
        assert_eq!(result, Err(Code::InvalidInput), "{pointer}");
    }
}

#[test]
fn complete_empty_partial_and_all_unsupported_remain_distinct() {
    use jocky_forensic::collection::{outcome, report::finalize};
    use jocky_shared::collection::{
        outcomes::{CollectorStatus, FacilityState, Field},
        records::Payload,
        report::{CollectionReport, SummaryStatus},
    };
    let base: CollectionReport =
        serde_json::from_str(include_str!("../../fixtures/valid/collection/report.json")).unwrap();
    let mut empty = base.clone();
    empty.records.clear();
    empty.summary.accepted_records = 0;
    empty.collectors[0].accepted_records = 0;
    assert_eq!(
        verify_report(&finalize(empty.clone(), 10485760).unwrap())
            .unwrap()
            .summary
            .status,
        SummaryStatus::Complete
    );

    let mut failed = empty;
    failed.collectors[0] = outcome::unsupported(failed.collectors[0].collector);
    failed.endpoint = None;
    failed.summary.status = SummaryStatus::Failed;
    failed.summary.stop_reason = Some(Code::Unsupported);
    failed.summary.omitted_unknown = true;
    assert_eq!(
        verify_report(&finalize(failed.clone(), 10485760).unwrap())
            .unwrap()
            .summary
            .status,
        SummaryStatus::Failed
    );
    failed.summary.status = SummaryStatus::Complete;
    assert_eq!(finalize(failed, 10485760), Err(Code::InvalidInput));

    let mut partial = base;
    let Payload::System(system) = &mut partial.records[0].payload else {
        panic!("fixture kind")
    };
    system.hostname = Field::Unavailable {
        reason: Code::PermissionDenied,
    };
    partial.collectors[0].status = CollectorStatus::Partial;
    partial.collectors[0].coverage[0].state = FacilityState::Partial;
    partial.collectors[0].coverage[0].reason = Some(Code::PermissionDenied);
    partial.collectors[0].omitted_reason = Some(Code::PermissionDenied);
    partial.collectors[0].stop_reason = Some(Code::PermissionDenied);
    partial.summary.status = SummaryStatus::Partial;
    partial.summary.stop_reason = Some(Code::PermissionDenied);
    assert_eq!(
        verify_report(&finalize(partial.clone(), 10485760).unwrap())
            .unwrap()
            .summary
            .status,
        SummaryStatus::Partial
    );
    partial.collectors[0].status = CollectorStatus::PermissionDenied;
    assert_eq!(finalize(partial, 10485760), Err(Code::InvalidInput));
}

#[test]
fn normalization_uses_numeric_addresses_inodes_and_start_ticks_not_text_order() {
    use jocky_forensic::collection::normalize;
    use jocky_shared::collection::records::{ForensicRecord, Payload};
    let mut one: ForensicRecord = serde_json::from_str(include_str!(
        "../../fixtures/valid/collection/forensic-record--connection.json"
    ))
    .unwrap();
    let mut two = one.clone();
    two.record_id = derive_id(IdentityKind::Record, &two.context.collection_id, 1).unwrap();
    two.sequence = 1;
    let Payload::Connection(a) = &mut one.payload else {
        panic!("kind")
    };
    a.local_address = "10.0.0.10".into();
    let Payload::Connection(b) = &mut two.payload else {
        panic!("kind")
    };
    b.local_address = "10.0.0.2".into();
    let mut records = vec![one, two];
    assert!(!normalize::is_ordered(&records).unwrap());
    normalize::records(&mut records).unwrap();
    assert_eq!(records[0].sequence, 1);
    assert!(normalize::is_ordered(&records).unwrap());
    let Payload::Connection(a) = &mut records[0].payload else {
        panic!("kind")
    };
    a.local_address = "10.0.0.10".into();
    a.socket_inode = "10".into();
    let Payload::Connection(b) = &mut records[1].payload else {
        panic!("kind")
    };
    b.socket_inode = "2".into();
    normalize::records(&mut records).unwrap();
    assert_eq!(records[0].sequence, 0);
    let Payload::Connection(a) = &mut records[0].payload else {
        panic!("kind")
    };
    a.local_address = "not-an-address".into();
    assert_eq!(normalize::records(&mut records), Err(Code::InvalidInput));
}

#[test]
fn canonical_depth_nodes_and_arbitrary_report_bytes_are_bounded() {
    let mut value = serde_json::json!(true);
    for _ in 0..16 {
        value = serde_json::json!([value]);
    }
    assert!(canonical::encode(&value, 1000).is_ok());
    value = serde_json::json!([value]);
    assert_eq!(canonical::encode(&value, 1000), Err(Code::ResourceLimit));
    let at = serde_json::Value::Array(vec![serde_json::Value::Null; 131071]);
    assert!(canonical::encode(&at, 10485760).is_ok());
    let over = serde_json::Value::Array(vec![serde_json::Value::Null; 131072]);
    assert_eq!(canonical::encode(&over, 10485760), Err(Code::ResourceLimit));
    let mut state = 0x324a1234u64;
    for length in 0..256 {
        let input: Vec<u8> = (0..length)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 32) as u8
            })
            .collect();
        assert!(verify_report(&input).is_err());
    }
}
