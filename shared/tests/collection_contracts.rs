//! Offline schema cases share fixtures with an independent Python validator.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use jsonschema::{Resource, Retrieve, Uri, ValidationError, Validator};
use serde_json::Value;

const NAMES: [&str; 13] = [
    "collection/v1/types",
    "collection/v1/endpoint-designation",
    "collection/v1/authorisation",
    "collection/v1/policy",
    "collection/v1/request",
    "collection/v1/indicator-set",
    "collection/v1/endpoint-observation",
    "collection/v1/report",
    "collection/v1/status",
    "collection/v1/worker",
    "collection/v1/lab-scenario",
    "v2/forensic-record",
    "v2/evidence-manifest",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&std::fs::read(root().join(path)).unwrap()).unwrap()
}

struct Deny;
impl Retrieve for Deny {
    fn retrieve(&self, _: &Uri<String>) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("unknown local collection schema".into())
    }
}

fn validators() -> BTreeMap<String, Validator> {
    let resources: Vec<_> = NAMES
        .iter()
        .map(|name| json(format!("shared/schemas/{name}.schema.json")))
        .collect();
    resources
        .iter()
        .map(|schema| {
            let id = schema["$id"].as_str().unwrap().to_owned();
            let validator = jsonschema::draft202012::options()
                .with_retriever(Deny)
                .with_resources(resources.iter().map(|s| {
                    (
                        s["$id"].as_str().unwrap().to_owned(),
                        Resource::from_contents(s.clone()).unwrap(),
                    )
                }))
                .should_validate_formats(true)
                .build(schema)
                .unwrap();
            (id, validator)
        })
        .collect()
}

fn has_keyword(error: &ValidationError<'_>, keyword: &str) -> bool {
    if error
        .schema_path
        .to_string()
        .ends_with(&format!("/{keyword}"))
    {
        return true;
    }
    match &error.kind {
        jsonschema::error::ValidationErrorKind::AnyOf { context }
        | jsonschema::error::ValidationErrorKind::OneOfNotValid { context }
        | jsonschema::error::ValidationErrorKind::OneOfMultipleValid { context } => {
            context.iter().flatten().any(|e| has_keyword(e, keyword))
        }
        _ => false,
    }
}

#[test]
fn all_resources_have_positive_and_expected_reason_negative_cases() {
    let validators = validators();
    let manifest = json("fixtures/collection-cases.json");
    let mut valid_seen = BTreeSet::new();
    let mut invalid_seen = BTreeSet::new();
    for case in manifest["cases"].as_array().unwrap() {
        if case["stage"] != "schema" {
            continue; // Strict decoder cases are exercised by collection_decode.rs.
        }
        let name = case["schema"].as_str().unwrap();
        let file = case["file"].as_str().unwrap();
        let instance = json(file);
        let errors: Vec<_> = validators[name].iter_errors(&instance).collect();
        if case["valid"] == true {
            assert!(errors.is_empty(), "{file}: {errors:?}");
            valid_seen.insert(name.to_owned());
        } else {
            let keyword = case["keyword"].as_str().unwrap();
            assert!(
                errors.iter().any(|e| has_keyword(e, keyword)),
                "{file}: {errors:?}"
            );
            invalid_seen.insert(name.to_owned());
        }
    }
    assert_eq!(valid_seen, invalid_seen);
    assert_eq!(valid_seen, validators.keys().cloned().collect());
}

#[test]
fn remote_schema_retrieval_is_refused() {
    assert!(
        jsonschema::draft202012::options()
            .with_retriever(Deny)
            .build(&serde_json::json!({"$ref":"https://example.invalid/schema"}))
            .is_err()
    );
}

#[test]
fn local_and_legacy_task_bound_evidence_are_separate_contracts() {
    let validators = validators();
    for name in ["forensic-record", "evidence-manifest"] {
        let old = jsonschema::draft202012::options()
            .with_retriever(Deny)
            .should_validate_formats(true)
            .build(&json(format!("shared/schemas/{name}.schema.json")))
            .unwrap();
        let new = &validators[&format!("https://jocky.dev/schemas/v2/{name}.schema.json")];
        assert!(!old.is_valid(&json(format!("fixtures/valid/collection/{name}.json"))));
        assert!(!new.is_valid(&json(format!("fixtures/valid/{name}.json"))));
    }
}
