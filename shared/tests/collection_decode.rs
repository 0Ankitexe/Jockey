//! Strict wire decoding never creates collection authority.
use jocky_shared::collection::{DecodeReason, DocumentKind, decode};

#[test]
fn every_manifest_case_is_checked_by_the_strict_decoder() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("fixtures/collection-cases.json")).unwrap(),
    )
    .unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        let name = case["schema"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .strip_suffix(".schema.json")
            .unwrap();
        let kind = DocumentKind::ALL
            .into_iter()
            .find(|k| k.name() == name)
            .unwrap();
        let file = case["file"].as_str().unwrap();
        let result = decode(kind, &std::fs::read(root.join(file)).unwrap());
        if case["valid"] == true {
            assert!(result.is_ok(), "{file}: {result:?}");
        } else {
            let error = result.expect_err(file);
            if case["stage"] == "decode" {
                assert_eq!(
                    format!("{:?}", error.reason),
                    case["reason"].as_str().unwrap(),
                    "{file}"
                );
            }
        }
    }
}

#[test]
fn deterministic_arbitrary_input_does_not_panic_or_admit_unknown_documents() {
    let mut seed = 0x9e37_79b9_u64;
    for length in 0..1024 {
        let mut bytes = Vec::new();
        for _ in 0..length {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            bytes.push(seed as u8);
        }
        for kind in DocumentKind::ALL {
            assert!(decode(kind, &bytes).is_err());
        }
    }
}

#[test]
fn all_valid_fixtures_decode_to_typed_documents_and_round_trip() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    for kind in DocumentKind::ALL {
        let bytes =
            std::fs::read(root.join(format!("fixtures/valid/collection/{}.json", kind.name())))
                .unwrap();
        let doc = decode(kind, &bytes).unwrap_or_else(|e| panic!("{}: {e:?}", kind.name()));
        assert_eq!(doc.kind(), kind);
        assert_eq!(
            doc.to_value().unwrap(),
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        );
    }
}

#[test]
fn strict_json_failures_are_typed_and_evidence_free() {
    for (bytes, reason) in [
        (
            br#"{"schema_version":"1.0.0","schema_version":"1.0.0"}"#.as_slice(),
            DecodeReason::DuplicateKey,
        ),
        (b"\xef\xbb\xbf{}", DecodeReason::Json),
        (b"{} {}", DecodeReason::Json),
        (b"\xff", DecodeReason::Json),
        (b"{\"x\":1.0}", DecodeReason::Number),
        (b"{\"x\":1e0}", DecodeReason::Number),
        (b"{\"x\":-0}", DecodeReason::Number),
        (b"{\"x\":9007199254740992}", DecodeReason::Number),
        (br#"{"schema_version":"99.0.0"}"#, DecodeReason::Version),
        (
            br#"{"schema_version":"1.0.0","secret-canary":"private"}"#,
            DecodeReason::Schema,
        ),
    ] {
        let error = decode(DocumentKind::Types, bytes).unwrap_err();
        assert_eq!(error.reason, reason);
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
        assert!(!format!("{error:?} {error}").contains("private"));
    }
}

#[test]
fn size_and_depth_fail_before_schema_or_unbounded_descent() {
    let bytes = vec![b' '; 65537];
    assert_eq!(
        decode(DocumentKind::Types, &bytes).unwrap_err().reason,
        DecodeReason::Size
    );
    let bytes = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    assert_eq!(
        decode(DocumentKind::Types, bytes.as_bytes())
            .unwrap_err()
            .reason,
        DecodeReason::Depth
    );
    let exact = format!("{}0{}", "[".repeat(16), "]".repeat(16));
    assert_eq!(
        decode(DocumentKind::Types, exact.as_bytes())
            .unwrap_err()
            .reason,
        DecodeReason::Schema
    );
}

#[test]
fn identity_calendar_and_relative_path_are_strict() {
    use jocky_shared::collection::identity::{UtcTime, Uuid};
    use jocky_shared::collection::inputs::PathRef;
    for text in [
        "00000000-0000-0000-0000-000000000000",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "endpoint-1",
    ] {
        assert!(Uuid::parse(text).is_err());
    }
    for text in [
        "2020-02-30T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "2020-01-01T00:00:60Z",
        "2020-01-01T00:00:00+00:00",
    ] {
        assert!(UtcTime::parse(text).is_err());
    }
    assert_eq!(
        UtcTime::parse("1970-01-01T00:00:00Z").unwrap().unix_nanos(),
        0
    );
    assert_eq!(
        UtcTime::parse("2000-02-29T00:00:00.100Z")
            .unwrap()
            .unix_nanos(),
        UtcTime::parse("2000-02-29T00:00:00.1Z")
            .unwrap()
            .unix_nanos()
    );
    let id = Uuid::parse("10000000-0000-4000-8000-000000000001").unwrap();
    for text in ["", "/absolute", "a//b", "a/../b", "a/./b", "a/", "a\0b"] {
        assert!(PathRef::new(id.clone(), text).is_err());
    }
    assert!(PathRef::new(id, "case/evidence.txt").is_ok());
}
