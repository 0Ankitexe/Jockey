//! Shared golden vectors have an independent Python oracle; no collector runs.
use jocky_forensic::collection::{
    canonical,
    identity::{IdentityKind, derive_id, digest},
    report::finalize,
    verify::verify_report,
};
use jocky_shared::collection::{Code, identity::Uuid};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../fixtures/valid/collection/canonical-vectors.json"
    ))
    .unwrap()
}

#[test]
fn canonical_bytes_and_digests_match_cross_language_goldens() {
    let data = vectors();
    assert_eq!(data["format"], "JOCKY-CJSON-1");
    for vector in data["values"].as_array().unwrap() {
        let expected = vector["canonical"].as_str().unwrap().as_bytes();
        let actual = canonical::encode(&vector["value"], expected.len()).unwrap();
        assert_eq!(actual, expected, "{}", vector["name"]);
        assert_eq!(digest(&actual).unwrap(), vector["sha256"]);
        assert_eq!(
            canonical::encode(&vector["value"], expected.len() - 1),
            Err(Code::ResourceLimit)
        );
    }
    for vector in data["invalid_values"].as_array().unwrap() {
        assert_eq!(
            canonical::encode(&vector["value"], 1000),
            Err(Code::InvalidInput)
        );
    }
}

#[test]
fn all_report_outcomes_match_independent_lengths_and_digests() {
    for vector in vectors()["reports"].as_array().unwrap() {
        let mut report: Value =
            serde_json::from_str(include_str!("../../fixtures/valid/collection/report.json"))
                .unwrap();
        for change in vector["changes"].as_array().unwrap() {
            *report.pointer_mut(change[0].as_str().unwrap()).unwrap() = change[1].clone();
        }
        let bytes = finalize(serde_json::from_value(report).unwrap(), 10_485_760).unwrap();
        let report = verify_report(&bytes).unwrap();
        assert_eq!(
            bytes.len() as u64,
            vector["report_bytes"].as_u64().unwrap(),
            "{}",
            vector["name"]
        );
        assert_eq!(
            report.content_sha256, vector["sha256"],
            "{}",
            vector["name"]
        );
        assert_eq!(report.manifest.content_sha256, vector["manifest_sha256"]);
        assert_eq!(report.summary.status.as_str(), vector["status"]);
        assert_eq!(report.report_kind.as_str(), "synthetic_test");
        for suffix in [b"".as_slice(), b"\n\n", b" \n"] {
            let mut bad = bytes[..bytes.len() - 1].to_vec();
            bad.extend_from_slice(suffix);
            assert_eq!(verify_report(&bad).unwrap_err(), Code::InvalidInput);
        }
    }
}

#[test]
fn uuid_domains_have_cross_language_known_answers() {
    let data = vectors();
    let collection = Uuid::parse(data["collection_id"].as_str().unwrap()).unwrap();
    for (kind, name) in [
        (IdentityKind::Record, "record"),
        (IdentityKind::Error, "error"),
        (IdentityKind::Manifest, "manifest"),
    ] {
        assert_eq!(
            derive_id(kind, &collection, 0).unwrap().as_str(),
            data["ids"][name]
        );
    }
}
