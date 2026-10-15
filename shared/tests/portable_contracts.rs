//! Offline portable compiler schemas share the Python fixture manifest.
use jsonschema::{Resource, Retrieve, Uri, Validator};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const NAMES: [&str; 12] = [
    "ast-v1",
    "profile-ast",
    "compiler-types",
    "module-registry",
    "check-report",
    "ir",
    "fixture-values",
    "portable-ast",
    "compiler-types-v2",
    "module-registry-v2",
    "check-report-v2",
    "ir-v2",
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
        Err("unregistered compiler schema".into())
    }
}
fn validators() -> BTreeMap<&'static str, Validator> {
    let resources: Vec<_> = NAMES
        .iter()
        .map(|n| json(format!("shared/compiler-contracts/{n}.schema.json")))
        .collect();
    NAMES
        .iter()
        .zip(resources.iter())
        .map(|(name, schema)| {
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
            (*name, validator)
        })
        .collect()
}

#[test]
fn portable_cases_and_strict_legacy_rejection() {
    let validators = validators();
    let manifest = json("fixtures/compiler-v2-cases.json");
    let cases = manifest["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let name = case["schema"].as_str().unwrap();
        let file = case["file"].as_str().unwrap();
        let value = json(file);
        let errors: Vec<_> = validators[name]
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        if case["valid"] == true {
            assert!(errors.is_empty(), "{file}: {errors:?}");
        } else {
            assert!(!errors.is_empty(), "{file}");
        }
    }
    for (new, old, file) in [
        ("portable-ast", "profile-ast", "portable-ast-linux"),
        (
            "module-registry-v2",
            "module-registry",
            "module-registry-v2-portable",
        ),
        ("check-report-v2", "check-report", "check-report-v2-valid"),
        ("ir-v2", "ir", "ir-v2-structural"),
    ] {
        let value = json(format!("fixtures/valid/compiler-v2/{file}.json"));
        assert!(validators[new].is_valid(&value));
        assert!(!validators[old].is_valid(&value));
    }
    for (old, fixture) in [
        (
            "profile-ast",
            "language/tests/fixtures/profile/valid.ast.json",
        ),
        (
            "module-registry",
            "forensic-lib/contracts/catalogue.v1.json",
        ),
        (
            "check-report",
            "language/tests/fixtures/reports/valid/valid.json",
        ),
        ("ir", "language/tests/fixtures/ir/golden/branches.ir.json"),
    ] {
        assert!(validators[old].is_valid(&json(fixture)), "{fixture}");
    }
}

#[test]
fn references_are_registered_and_never_fetched() {
    let resources: Vec<_> = NAMES
        .iter()
        .map(|n| json(format!("shared/compiler-contracts/{n}.schema.json")))
        .collect();
    let ids: std::collections::BTreeSet<_> = resources
        .iter()
        .map(|s| s["$id"].as_str().unwrap())
        .collect();
    fn walk(v: &Value, ids: &std::collections::BTreeSet<&str>) {
        match v {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str)
                    && !reference.starts_with('#')
                {
                    assert!(
                        ids.contains(reference.split('#').next().unwrap()),
                        "{reference}"
                    );
                }
                for child in map.values() {
                    walk(child, ids);
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child, ids);
                }
            }
            _ => (),
        }
    }
    for schema in &resources {
        walk(schema, &ids);
    }
}
