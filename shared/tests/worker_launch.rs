//! Pure launch metadata tests: decoding cannot start a worker or grant authority.
use jocky_shared::collection::{Code, DecodeReason, launch::decode_launch};
use serde_json::{Value, json};

fn value() -> Value {
    serde_json::from_str(include_str!(
        "../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap()
}

#[test]
fn deployed_fixtures_match_registered_expected_reasons() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let cases: Value =
        serde_json::from_str(include_str!("../../fixtures/worker-launch-cases.json")).unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let bytes = std::fs::read(root.join(case["file"].as_str().unwrap())).unwrap();
        let result = decode_launch(&bytes);
        if case["valid"] == true {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                format!("{:?}", result.unwrap_err().reason),
                case["reason"].as_str().unwrap()
            );
        }
    }
}
fn reject(v: &Value, reason: DecodeReason) {
    assert_eq!(
        decode_launch(&serde_json::to_vec(v).unwrap())
            .unwrap_err()
            .reason,
        reason
    );
}

#[test]
fn closed_launch_metadata_roundtrips_without_changing_v1_frames() {
    let raw = serde_json::to_vec(&value()).unwrap();
    let launch = decode_launch(&raw).unwrap();
    assert_eq!(launch.record_base, 0);
    assert_eq!(launch.error_base, 0);
    assert_eq!(launch.allowance.retained_bytes, 201326592);
    assert_eq!(
        decode_launch(&serde_json::to_vec(&launch).unwrap()).unwrap(),
        launch
    );
    assert!(
        jocky_shared::collection::decode(jocky_shared::collection::DocumentKind::Worker, &raw)
            .is_err()
    );
    assert_eq!(
        jocky_shared::collection::DocumentKind::Worker.version(),
        "1.0.0"
    );
}

#[test]
fn missing_unknown_version_fields_and_enums_are_rejected() {
    for key in value().as_object().unwrap().keys() {
        let mut v = value();
        v.as_object_mut().unwrap().remove(key);
        reject(&v, DecodeReason::Schema);
    }
    let mut v = value();
    v["unknown"] = json!(false);
    reject(&v, DecodeReason::Schema);
    let mut v = value();
    v["schema_version"] = json!("1.0.0");
    reject(&v, DecodeReason::Version);
    let mut v = value();
    v["job"] = json!("execute_command");
    reject(&v, DecodeReason::Schema);
    let mut v = value();
    v["clock_basis"] = json!("fresh_instant");
    reject(&v, DecodeReason::Schema);
}

#[test]
fn duplicate_json_keys_and_byte_limits_fail_before_unbounded_retention() {
    let raw = serde_json::to_string(&value()).unwrap();
    let duplicate = raw.replacen('{', r#"{"schema_version":"1.1.0","#, 1);
    assert_eq!(
        decode_launch(duplicate.as_bytes()).unwrap_err().reason,
        DecodeReason::DuplicateKey
    );
    assert_eq!(
        decode_launch(&vec![b' '; 65537]).unwrap_err().code,
        Code::ResourceLimit
    );
}

#[test]
fn hostile_encoding_depth_numbers_and_arbitrary_input_do_not_panic() {
    for (raw, reason) in [
        (
            format!("{}0{}", "[".repeat(17), "]".repeat(17)).into_bytes(),
            DecodeReason::Depth,
        ),
        (b"1.0".to_vec(), DecodeReason::Number),
        (b"-0".to_vec(), DecodeReason::Number),
        (vec![255], DecodeReason::Json),
        (br#""\ud800""#.to_vec(), DecodeReason::Json),
    ] {
        assert_eq!(decode_launch(&raw).unwrap_err().reason, reason);
    }
    let mut seed = 41u32;
    for length in 0..512 {
        let raw: Vec<_> = (0..length)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        assert!(std::panic::catch_unwind(|| decode_launch(&raw)).is_ok());
    }
}

#[test]
fn rollback_global_quota_and_ordinal_rebinding_fail_typed() {
    for mode in 0..7 {
        let mut v = value();
        match mode {
            0 => v["launch_observed"]["monotonic_ms"] = json!(999),
            1 => v["launch_observed"]["utc"] = json!("2019-12-31T23:59:59Z"),
            2 => v["record_base"] = json!(10000),
            3 => v["error_base"] = json!(1000),
            4 => v["allowance"]["source_bytes"] = json!(67108865),
            5 => v["global_limits"]["max_source_bytes"] = json!(1),
            _ => v["allowance"]["retained_bytes"] = json!(201326593),
        }
        reject(
            &v,
            if mode == 4 {
                DecodeReason::Schema
            } else {
                DecodeReason::Context
            },
        );
    }
}

#[test]
fn descriptor_and_config_aliases_or_unsigned_counter_overflow_reject() {
    for mode in 0..5 {
        let mut v = value();
        match mode {
            0 => {
                let binding = v["descriptors"][0].clone();
                v["descriptors"].as_array_mut().unwrap().push(binding);
            }
            1 => v["config_exclusions"][1] = v["config_exclusions"][0].clone(),
            2 => v["descriptors"][0]["object"]["inode"] = json!("18446744073709551616"),
            3 => v["descriptors"][0]["kind"] = json!("output_directory"),
            _ => v["descriptors"][0]["subject_id"] = Value::Null,
        }
        reject(
            &v,
            match mode {
                1 => DecodeReason::Schema,
                2 => DecodeReason::Number,
                _ => DecodeReason::Context,
            },
        );
    }
}

#[test]
fn publisher_can_receive_only_output_and_no_source_or_record_allowance() {
    let mut v = value();
    v["job"] = json!("publish");
    v["descriptors"][0]["kind"] = json!("output_directory");
    v["descriptors"][0]["subject_id"] = Value::Null;
    for key in [
        "records",
        "source_bytes",
        "indicator_comparisons",
        "entries",
        "errors",
    ] {
        v["allowance"][key] = json!(0);
    }
    assert!(decode_launch(&serde_json::to_vec(&v).unwrap()).is_ok());
    v["allowance"]["source_bytes"] = json!(1);
    reject(&v, DecodeReason::Context);
}
