//! Independent v2 verifier regression corpus alongside unchanged legacy goldens.
use jocky_forensic::contracts::v2::builtin_registry;
use jocky_ir::{DiagnosticCode as Code, v2};
use serde_json::{Value, json};
fn golden() -> Value {
    serde_json::from_str(include_str!("fixtures/valid/portable-minimal.ir.json")).unwrap()
}
fn reject(value: &Value) -> Code {
    let bytes = serde_json::to_vec(value).unwrap();
    match v2::decode_ir(&bytes) {
        Err(error) => error.code(),
        Ok(document) => v2::verify(document, builtin_registry().unwrap())
            .unwrap_err()
            .code(),
    }
}
#[test]
fn portable_golden_is_verified_and_byte_deterministic() {
    let bytes = include_bytes!("fixtures/valid/portable-minimal.ir.json");
    let first = v2::verify(v2::decode_ir(bytes).unwrap(), builtin_registry().unwrap()).unwrap();
    let output = first.to_json().unwrap();
    for _ in 0..3 {
        let checked =
            v2::verify(v2::decode_ir(&output).unwrap(), builtin_registry().unwrap()).unwrap();
        assert_eq!(checked.to_json().unwrap(), output);
    }
    assert_eq!(first.document().schema_version, "2.0.0");
    assert_eq!(first.document().language_version, "3.0.0");
    assert_eq!(first.document().registry.schema_version, "2.0.0");
}
#[test]
fn complete_legacy_invariant_categories_are_enforced_under_v2() {
    type Mutation = (Code, fn(&mut Value));
    let cases: [Mutation; 11] = [
        (Code::Version, |d| d["language_version"] = json!("2.0.0")),
        (Code::Schema, |d| d["native_provider"] = json!("host")),
        (Code::Identity, |d| {
            d["functions"][0]["regions"][0]["instructions"][0]["id"] =
                json!("00000000-0000-8000-8000-000000000000")
        }),
        (Code::Reference, |d| d["entry"] = json!(99)),
        (Code::Type, |d| {
            d["functions"][1]["slots"][1]["type"] = json!({"kind":"named","name":"bool"})
        }),
        (Code::Initialization, |d| {
            d["functions"][1]["parameters"] = json!([0, 1])
        }),
        (Code::Control, |d| {
            d["functions"][1]["regions"]
                .as_array_mut()
                .unwrap()
                .push(json!({"instructions":[]}))
        }),
        (Code::Return, |d| {
            d["functions"][1]["regions"][0]["instructions"]
                .as_array_mut()
                .unwrap()
                .pop();
        }),
        (Code::Contract, |d| {
            d["registry"]["fingerprint"] = json!("0".repeat(64))
        }),
        (Code::Metadata, |d| {
            d["entry_metadata"]["read_only"] = json!(false)
        }),
        (Code::Resource, |d| {
            d["source"]["label"] = json!("🙂".repeat(1025))
        }),
    ];
    for (expected, change) in cases {
        let mut value = golden();
        change(&mut value);
        if expected == Code::Contract {
            let mut document: v2::IrDocument = serde_json::from_value(value).unwrap();
            v2::identity::assign_instruction_ids(&mut document).unwrap();
            value = serde_json::to_value(document).unwrap();
        }
        assert_eq!(reject(&value), expected, "{expected:?}");
    }
    assert_eq!(v2::decode_ir(b"{").unwrap_err().code(), Code::Json);
    let legacy: Value =
        serde_json::from_str(include_str!("fixtures/invalid/verifier/manifest.json")).unwrap();
    let categories: std::collections::BTreeSet<_> = legacy
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["code"].as_str().unwrap())
        .collect();
    let covered: std::collections::BTreeSet<_> = [
        Code::Version,
        Code::Schema,
        Code::Identity,
        Code::Reference,
        Code::Type,
        Code::Initialization,
        Code::Control,
        Code::Return,
        Code::Contract,
        Code::Metadata,
        Code::Resource,
        Code::Json,
    ]
    .map(Code::as_str)
    .into_iter()
    .collect();
    assert_eq!(categories, covered);
}
#[test]
fn legacy_identity_and_unsupported_tuples_do_not_enter_v2() {
    let old: Value = serde_json::from_str(include_str!(
        "../../fixtures/valid/compiler-v2/ir-v2-structural.json"
    ))
    .unwrap();
    assert_ne!(reject(&old), Code::Json);
    for name in [
        "ir-v2-legacy-language",
        "ir-v2-legacy-registry",
        "ir-v2-bad-identity",
        "ir-v2-open-ir",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../fixtures/invalid/compiler-v2/{name}.json"));
        let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_ne!(reject(&value), Code::Json, "{name}");
    }
}
