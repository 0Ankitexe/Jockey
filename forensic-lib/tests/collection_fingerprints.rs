use jocky_forensic::collection::{ClockReading, InputSet, admit};
use jocky_shared::collection::{Code, identity::UtcTime};
fn values() -> [serde_json::Value; 4] {
    [
        include_str!("../../fixtures/valid/collection/endpoint-designation.json"),
        include_str!("../../fixtures/valid/collection/authorisation.json"),
        include_str!("../../fixtures/valid/collection/policy.json"),
        include_str!("../../fixtures/valid/collection/request.json"),
    ]
    .map(|v| serde_json::from_str(v).unwrap())
}
fn raw(v: &[serde_json::Value; 4]) -> [Vec<u8>; 4] {
    v.each_ref().map(|v| serde_json::to_vec(v).unwrap())
}
fn input(v: &[Vec<u8>; 4]) -> InputSet<'_> {
    InputSet {
        designation: &v[0],
        authorisation: Some(&v[1]),
        policy: &v[2],
        request: &v[3],
        indicators: None,
    }
}

#[test]
fn normalized_fingerprint_matches_admitted_provenance_without_needing_current_authority() {
    let v = raw(&values());
    let fingerprint = input(&v).fingerprint().unwrap();
    let ctx = admit(
        input(&v),
        ClockReading {
            utc: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
            monotonic_ms: 0,
        },
    )
    .unwrap();
    assert_eq!(&fingerprint, ctx.input_provenance());
    assert!(matches!(
        admit(
            input(&v),
            ClockReading {
                utc: UtcTime::parse("2026-10-11T00:00:00Z").unwrap(),
                monotonic_ms: 0
            }
        ),
        Err(Code::AuthorisationExpired)
    ));
}

#[test]
fn reordered_keys_and_scope_arrays_have_the_same_normalized_fingerprint() {
    let mut v = values();
    // Add two permitted capabilities to both trusted scopes; request stays system.
    for index in [1, 2] {
        v[index]["scope"]["capabilities"] = serde_json::json!(["system", "files"]);
    }
    let first = input(&raw(&v)).fingerprint().unwrap();
    for index in [1, 2] {
        v[index]["scope"]["capabilities"] = serde_json::json!(["files", "system"]);
    }
    assert_eq!(input(&raw(&v)).fingerprint().unwrap(), first);
}

#[test]
fn changed_policy_with_identical_ids_changes_only_its_document_digest() {
    let mut v = values();
    let first = input(&raw(&v)).fingerprint().unwrap();
    v[2]["valid_until"] = serde_json::json!("2020-01-01T00:30:00Z");
    let second = input(&raw(&v)).fingerprint().unwrap();
    assert_eq!(first.policy.id, second.policy.id);
    assert_ne!(first.policy.sha256, second.policy.sha256);
    assert_eq!(first.request, second.request);
}

#[test]
fn missing_authority_duplicates_unknown_fields_and_oversize_fail_typed() {
    let v = raw(&values());
    let mut missing = input(&v);
    missing.authorisation = None;
    assert_eq!(missing.fingerprint(), Err(Code::MissingAuthorisation));
    let mut v = v;
    v[0] = br#"{"schema_version":"1.0.0","schema_version":"1.0.0"}"#.to_vec();
    assert!(input(&v).fingerprint().is_err());
    let mut v = values();
    v[2]["unknown"] = serde_json::json!(true);
    assert!(input(&raw(&v)).fingerprint().is_err());
    let mut v = raw(&values());
    v[0] = vec![b' '; 65537];
    assert_eq!(input(&v).fingerprint(), Err(Code::ResourceLimit));
}

#[test]
fn metadata_fingerprinting_cannot_authorize_widened_scope() {
    let mut v = values();
    v[3]["limits"]["max_source_bytes"] = serde_json::json!(100);
    v[1]["limits"]["max_source_bytes"] = serde_json::json!(99);
    let v = raw(&v);
    assert!(input(&v).fingerprint().is_ok());
    assert!(matches!(
        admit(
            input(&v),
            ClockReading {
                utc: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
                monotonic_ms: 0
            }
        ),
        Err(Code::ScopeDenied)
    ));
}
