//! Frozen, synthetic multi-document denials. No source adapter is constructed.
use jocky_forensic::collection::{ClockReading, InputSet, admit};
use jocky_shared::collection::{Code, identity::UtcTime};
use serde_json::{Value, json};

fn values() -> [Value; 4] {
    [
        include_str!("../../fixtures/valid/collection/endpoint-designation.json"),
        include_str!("../../fixtures/valid/collection/authorisation.json"),
        include_str!("../../fixtures/valid/collection/policy.json"),
        include_str!("../../fixtures/valid/collection/request.json"),
    ]
    .map(|s| serde_json::from_str(s).unwrap())
}

fn admit_values(
    values: &[Value; 4],
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
            utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
            monotonic_ms: 0,
        },
    )
}

#[test]
fn mismatched_id_profile_and_source_are_all_denied_before_any_source_adapter() {
    for (document, field) in [
        (1, "case_id"),
        (1, "endpoint_id"),
        (1, "operator_id"),
        (2, "endpoint_id"),
        (3, "case_id"),
        (3, "endpoint_id"),
        (3, "authorisation_id"),
        (3, "policy_id"),
    ] {
        let mut input = values();
        input[document][field] = json!("10000000-0000-4000-8000-000000000099");
        assert_eq!(
            admit_values(&input).unwrap_err(),
            Code::AuthorisationDenied,
            "{document}/{field}"
        );
    }
    let mut input = values();
    input[3]["profile"] = json!("other");
    assert!(admit_values(&input).is_err());
    let mut input = values();
    input[3]["source_ids"] = json!(["10000000-0000-4000-8000-000000000099"]);
    assert!(admit_values(&input).is_err());
}

#[test]
fn limits_and_event_windows_cannot_be_widened_by_the_request() {
    for trusted in [1, 2] {
        let mut input = values();
        input[trusted]["limits"]["max_records"] = json!(9);
        assert_eq!(admit_values(&input).unwrap_err(), Code::ScopeDenied);
        input[3]["limits"]["max_records"] = json!(9);
        assert_eq!(admit_values(&input).unwrap().limits().max_records, 9);
        let mut input = values();
        input[trusted]["scope"]["event_window"]["start"] = json!("2020-01-01T00:00:01Z");
        assert_eq!(admit_values(&input).unwrap_err(), Code::ScopeDenied);
    }
}

#[test]
fn lexical_path_normalization_is_not_an_authority_expansion() {
    for path in [
        "../escape",
        "./selected",
        "selected//child",
        "selected/",
        "/absolute",
        "selected/../other",
    ] {
        let mut input = values();
        input[3]["paths"] =
            json!([{"root_id":"10000000-0000-4000-8000-000000000090","relative_path":path}]);
        assert!(admit_values(&input).is_err(), "{path}");
    }
}

#[test]
fn source_and_profile_intersections_deny_each_untrusted_widening() {
    let foreign = "10000000-0000-4000-8000-000000000099";
    for (document, pointer, replacement) in [
        (1, "approved_profile", json!("foreign-profile")),
        (2, "approved_profile", json!("foreign-profile")),
        (
            2,
            "sources",
            json!([{"source_id": foreign, "kind": "kernel_profile"}]),
        ),
        (
            1,
            "scope",
            json!({"capabilities":["system"],"source_groups":[],"roots":[],"event_window":{"start":"2020-01-01T00:00:00Z","end":"2020-01-01T01:00:00Z"}}),
        ),
        (
            2,
            "scope",
            json!({"capabilities":["system"],"source_groups":[],"roots":[],"event_window":{"start":"2020-01-01T00:00:00Z","end":"2020-01-01T01:00:00Z"}}),
        ),
    ] {
        let mut input = values();
        input[document][pointer] = replacement;
        assert!(admit_values(&input).is_err(), "{document}/{pointer}");
    }
    for (document, timestamp) in [
        (0, "2020-01-01T00:00:09Z"),
        (1, "2020-01-01T00:00:09Z"),
        (2, "2020-01-01T00:00:09Z"),
    ] {
        let mut input = values();
        input[document]["valid_until"] = json!(timestamp);
        assert!(admit_values(&input).is_err(), "expired document {document}");
    }
}
