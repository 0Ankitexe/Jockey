//! Versioned registry tests, held until T174 publishes the catalogue and loader.
use serde_json::Value;
#[test]
fn portable_schema_is_additive_and_legacy_catalogue_does_not_claim_linux() {
    let old: Value = serde_json::from_str(include_str!("../contracts/catalogue.v1.json")).unwrap();
    assert_eq!(old["schema_version"], "1.0.0");
    for function in old["functions"].as_array().unwrap() {
        assert!(
            !function["supported_platforms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "linux")
        );
    }
}
#[test]
fn portable_catalogue_has_exact_selectors_unavailable_sources_and_closed_metadata() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/catalogue.v2.json");
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(value["schema_version"], "2.0.0");
    let functions = value["functions"].as_array().unwrap();
    assert_eq!(functions.len(), 11);
    for function in functions {
        assert_eq!(function["availability"], "unavailable");
        assert_eq!(function["read_only"], true);
        let name = format!(
            "{}.{}",
            function["module"].as_str().unwrap(),
            function["name"].as_str().unwrap()
        );
        if name == "forensic.event.ubuntu_journal" {
            assert_eq!(
                function["supported_platforms"],
                serde_json::json!(["ubuntu"])
            );
        }
        if name == "forensic.event.windows_log" {
            assert_eq!(
                function["supported_platforms"],
                serde_json::json!(["windows"])
            );
        }
        if name == "forensic.indicator.correlate" {
            assert!(
                !function["supported_platforms"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p == "linux")
            );
        }
    }
}

#[test]
fn portable_loader_rejects_versions_duplicates_unknown_fields_and_is_stable() {
    use jocky_forensic::contracts::v2::{Registry, RegistryErrorKind, builtin_registry};
    let registry = builtin_registry().unwrap();
    assert_eq!(registry.functions().len(), 11);
    assert!(std::ptr::eq(registry, builtin_registry().unwrap()));
    let mut value: Value =
        serde_json::from_str(include_str!("../contracts/catalogue.v2.json")).unwrap();
    value["schema_version"] = "1.0.0".into();
    assert_eq!(
        Registry::from_json(&value.to_string()).unwrap_err().kind,
        RegistryErrorKind::UnsupportedVersion
    );
    value["schema_version"] = "2.0.0".into();
    let duplicate = value["functions"][0].clone();
    value["functions"].as_array_mut().unwrap().push(duplicate);
    assert_eq!(
        Registry::from_json(&value.to_string()).unwrap_err().kind,
        RegistryErrorKind::DuplicateFunction
    );
    value["functions"].as_array_mut().unwrap().pop();
    value["functions"][0]["native_provider"] = "host".into();
    assert_eq!(
        Registry::from_json(&value.to_string()).unwrap_err().kind,
        RegistryErrorKind::SchemaViolation
    );
    assert_eq!(
        Registry::from_json(r#"{"schema_version":"2.0.0","schema_version":"2.0.0"}"#)
            .unwrap_err()
            .kind,
        RegistryErrorKind::DuplicateJsonKey
    );
}
