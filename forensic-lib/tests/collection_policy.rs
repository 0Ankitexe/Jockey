//! Pure authority tests use a frozen injected clock, never workstation identity/time.
use jocky_forensic::collection::{ClockReading, InputSet, admit};
use jocky_shared::collection::{Code, identity::UtcTime};
use serde_json::Value;

fn fixtures() -> [Value; 4] {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    ["endpoint-designation", "authorisation", "policy", "request"].map(|name| {
        serde_json::from_slice(
            &std::fs::read(root.join(format!("fixtures/valid/collection/{name}.json"))).unwrap(),
        )
        .unwrap()
    })
}
fn attempt(
    values: &[Value; 4],
    time: &str,
) -> Result<jocky_forensic::collection::ValidatedCollectionContext, Code> {
    let raw = values.each_ref().map(|v| serde_json::to_vec(v).unwrap());
    admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: None,
        },
        ClockReading {
            utc: UtcTime::parse(time).unwrap(),
            monotonic_ms: 1000,
        },
    )
}

#[test]
fn valid_intersection_retains_only_explicit_request_without_source_io() {
    let values = fixtures();
    let context = attempt(&values, "2020-01-01T00:00:10Z").unwrap();
    assert_eq!(
        context.identity().collection_id.as_str(),
        values[3]["collection_id"].as_str().unwrap()
    );
    assert_eq!(context.limits().max_records, 10000);
    assert_eq!(context.sources().len(), 1);
    assert!(context.paths().is_empty());
    // The API accepts bytes and an injected clock only, no source adapter.
    assert!(!format!("{context:?}").contains("absolute_path"));
}

#[test]
fn missing_and_expired_authority_are_typed_denials() {
    let values = fixtures();
    let raw = values.each_ref().map(|v| serde_json::to_vec(v).unwrap());
    let result = admit(
        InputSet {
            designation: &raw[0],
            authorisation: None,
            policy: &raw[2],
            request: &raw[3],
            indicators: None,
        },
        ClockReading {
            utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
            monotonic_ms: 0,
        },
    );
    assert_eq!(result.unwrap_err(), Code::MissingAuthorisation);
    assert_eq!(
        attempt(&values, "2020-01-01T01:00:00Z").unwrap_err(),
        Code::AuthorisationExpired
    );
    assert_eq!(
        attempt(&values, "2019-12-31T23:59:59Z").unwrap_err(),
        Code::AuthorisationDenied
    );
    assert_eq!(
        attempt(&values, "2020-01-01T00:59:55Z").unwrap_err(),
        Code::AuthorisationExpired
    );
}

#[test]
fn each_cross_document_identity_is_bound() {
    for (index, key) in [
        (1, "designation_id"),
        (1, "operator_id"),
        (1, "endpoint_id"),
        (2, "endpoint_id"),
        (3, "collection_id"),
        (3, "designation_id"),
        (3, "authorisation_id"),
        (3, "policy_id"),
        (3, "operator_id"),
        (3, "case_id"),
        (3, "endpoint_id"),
    ] {
        let mut values = fixtures();
        values[index][key] = serde_json::json!("10000000-0000-4000-8000-000000000099");
        // Collection identity is intentionally caller-assigned, not another document's ID.
        if key == "collection_id" {
            assert!(attempt(&values, "2020-01-01T00:00:10Z").is_ok());
        } else {
            assert_eq!(
                attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
                Code::AuthorisationDenied,
                "{index}/{key}"
            );
        }
    }
}

#[test]
fn request_cannot_widen_either_trusted_limit_or_scope() {
    for trusted in [1, 2] {
        let mut values = fixtures();
        values[trusted]["limits"]["max_records"] = serde_json::json!(9);
        assert_eq!(
            attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
            Code::ScopeDenied
        );
        values[3]["limits"]["max_records"] = serde_json::json!(9);
        assert_eq!(
            attempt(&values, "2020-01-01T00:00:10Z")
                .unwrap()
                .limits()
                .max_records,
            9
        );
        let mut values = fixtures();
        values[trusted]["scope"]["event_window"]["start"] =
            serde_json::json!("2020-01-01T00:00:01Z");
        assert_eq!(
            attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
            Code::ScopeDenied
        );
    }
    let mut values = fixtures();
    values[3]["capabilities"] = serde_json::json!(["system", "network"]);
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ScopeDenied
    );
    let mut values = fixtures();
    values[3]["source_ids"] = serde_json::json!([]);
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ScopeDenied
    );
}

#[test]
fn unknown_source_and_ungranted_path_fail_closed() {
    for key in ["source_ids", "paths"] {
        let mut values = fixtures();
        values[3][key] = if key == "paths" {
            serde_json::json!([{"root_id":"10000000-0000-4000-8000-000000000099","relative_path":"evidence.txt"}])
        } else {
            serde_json::json!(["10000000-0000-4000-8000-000000000099"])
        };
        assert_eq!(
            attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
            Code::ScopeDenied
        );
    }
}

#[test]
fn tampered_dtos_are_revalidated_and_fresh_ids_are_not_fabricated() {
    let mut values = fixtures();
    values[3]["unexpected"] = serde_json::json!(true);
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::InvalidInput
    );
    let mut values = fixtures();
    values[1]["valid_until"] = serde_json::json!("2020-01-01T02:00:00Z");
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::AuthorisationDenied
    );
}

#[test]
fn admitted_source_permits_are_exclusive_and_stop_after_cancel_or_exhaustion() {
    use jocky_forensic::collection::{budget::Counter, context::OperationTarget};
    let context = attempt(&fixtures(), "2020-01-01T00:00:10Z").unwrap();
    let id = context.sources()[0].definition().id();
    let now = ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        monotonic_ms: 1000,
    };
    let mut permit = context
        .permit(OperationTarget::Source(id), &now, false)
        .unwrap();
    assert!(matches!(
        context.permit(OperationTarget::Source(id), &now, false),
        Err(Code::ResourceLimit)
    ));
    assert_eq!(permit.renew(&now, true), Err(Code::Cancelled));
    assert_eq!(permit.charge(Counter::SourceBytes, 1), Err(Code::Cancelled));
    drop(permit);
    assert!(matches!(
        context.permit(OperationTarget::Source(id), &now, false),
        Err(Code::Cancelled)
    ));
    let context = attempt(&fixtures(), "2020-01-01T00:00:10Z").unwrap();
    let id = context.sources()[0].definition().id();
    let mut permit = context
        .permit(OperationTarget::Source(id), &now, false)
        .unwrap();
    permit.charge(Counter::Entries, 20000).unwrap();
    assert_eq!(permit.charge(Counter::Entries, 1), Err(Code::ResourceLimit));
    assert_eq!(permit.renew(&now, false), Err(Code::ResourceLimit));
}

#[test]
fn extra_sources_cannot_grant_an_unrequested_collector() {
    let mut values = fixtures();
    let extra = serde_json::json!("10000000-0000-4000-8000-000000000099");
    values[1]["scope"]["source_groups"] = serde_json::json!(["kernel_profile", "proc_processes"]);
    values[2]["scope"]["source_groups"] = values[1]["scope"]["source_groups"].clone();
    values[2]["sources"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"source_id":extra,"kind":"proc_processes"}));
    values[3]["source_ids"].as_array_mut().unwrap().push(extra);
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ScopeDenied
    );
}

#[test]
fn file_roots_must_match_both_grants_and_requested_capability() {
    let mut values = fixtures();
    let id = "10000000-0000-4000-8000-000000000020";
    for index in [1, 2] {
        values[index]["scope"]["capabilities"] = serde_json::json!(["system", "files"]);
        values[index]["scope"]["roots"] = serde_json::json!([{"root_id":id,"absolute_path":"/srv/approved","purposes":["files"]}]);
    }
    values[3]["capabilities"] = serde_json::json!(["system", "files"]);
    values[3]["collectors"] = serde_json::json!(["system", "files"]);
    values[3]["paths"] = serde_json::json!([{"root_id":id,"relative_path":"sample.txt"}]);
    let context = attempt(&values, "2020-01-01T00:00:10Z").unwrap();
    assert_eq!(context.paths()[0].root().absolute_path, "/srv/approved");
    assert_eq!(context.paths()[0].path().relative_path, "sample.txt");
    values[2]["scope"]["roots"][0]["absolute_path"] = serde_json::json!("/srv/different");
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ScopeDenied
    );
}

#[test]
fn report_budget_must_fit_a_failure_before_admission() {
    let mut values = fixtures();
    values[3]["limits"]["max_report_bytes"] = serde_json::json!(1);
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ResourceLimit
    );
    let context = attempt(&fixtures(), "2020-01-01T00:00:10Z").unwrap();
    let minimum = context.failure_report_reserve();
    assert!(minimum > 1 && minimum <= 65536);
    values[3]["limits"]["max_report_bytes"] = serde_json::json!(minimum);
    assert!(attempt(&values, "2020-01-01T00:00:10Z").is_ok());
    values[3]["limits"]["max_report_bytes"] = serde_json::json!(minimum - 1);
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ResourceLimit
    );
}

#[test]
fn request_depth_is_enforced_below_the_hard_maximum() {
    let mut values = fixtures();
    let id = "10000000-0000-4000-8000-000000000020";
    for index in [1, 2] {
        values[index]["scope"]["capabilities"] = serde_json::json!(["system", "files"]);
        values[index]["scope"]["roots"] = serde_json::json!([{"root_id":id,"absolute_path":"/srv/approved","purposes":["files"]}]);
    }
    values[3]["capabilities"] = serde_json::json!(["system", "files"]);
    values[3]["collectors"] = serde_json::json!(["system", "files"]);
    values[3]["limits"]["max_depth"] = serde_json::json!(2);
    values[3]["paths"] = serde_json::json!([{"root_id":id,"relative_path":"one/two"}]);
    assert!(attempt(&values, "2020-01-01T00:00:10Z").is_ok());
    values[3]["paths"][0]["relative_path"] = serde_json::json!("one/two/three");
    assert_eq!(
        attempt(&values, "2020-01-01T00:00:10Z").unwrap_err(),
        Code::ScopeDenied
    );
}
