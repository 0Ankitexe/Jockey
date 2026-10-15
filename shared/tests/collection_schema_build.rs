//! The mandatory build guard fails for invalid immutable schema definitions.
#[path = "../schema_build.rs"]
mod guard;
#[path = "../src/collection/schema/resources.rs"]
mod resources;
use guard::{BuildFailure, check};

#[test]
fn exact_embedded_inventory_is_valid() {
    let sources: Vec<_> = resources::SCHEMAS
        .iter()
        .map(|s| (s.path, s.contents))
        .collect();
    assert_eq!(check(&sources), Ok(()));
}

#[test]
fn malformed_schema_or_identity_cannot_build() {
    let path = "schemas/collection/v1/test.schema.json";
    let valid =
        r#"{"$id":"https://jocky.dev/schemas/collection/v1/test.schema.json","type":"string"}"#;
    assert_eq!(check(&[(path, valid)]), Ok(()));
    assert_eq!(check(&[]), Err(BuildFailure::Identity));
    assert_eq!(check(&[(path, "{")]), Err(BuildFailure::Json));
    assert_eq!(check(&[(path, "{}")]), Err(BuildFailure::Identity));
    assert_eq!(
        check(&[("schemas/wrong.json", valid)]),
        Err(BuildFailure::Identity)
    );
    assert_eq!(
        check(&[(path, valid), (path, valid)]),
        Err(BuildFailure::Identity)
    );
    let invalid = valid.replace("\"string\"", "42");
    assert_eq!(check(&[(path, &invalid)]), Err(BuildFailure::Definition));
}

#[test]
fn missing_local_or_external_references_cannot_build() {
    let path = "schemas/collection/v1/test.schema.json";
    for reference in [
        "#/$defs/missing",
        "https://jocky.dev/schemas/missing.json",
        "https://example.invalid/schema",
        "file:///never-read-this.json",
    ] {
        let schema = serde_json::json!({
            "$id": format!("https://jocky.dev/{path}"), "$ref": reference
        })
        .to_string();
        assert_eq!(check(&[(path, &schema)]), Err(BuildFailure::Reference));
    }
}

#[test]
fn unused_definitions_and_unreviewed_reference_scopes_fail_closed() {
    let path = "schemas/collection/v1/test.schema.json";
    let id = format!("https://jocky.dev/{path}");
    for (definition, expected) in [
        (
            serde_json::json!({"$ref":"#/$defs/missing"}),
            BuildFailure::Reference,
        ),
        (serde_json::json!({"type":42}), BuildFailure::Definition),
        (
            serde_json::json!({"$id":"https://example.invalid/nested"}),
            BuildFailure::Definition,
        ),
        (
            serde_json::json!({"$dynamicRef":"#node"}),
            BuildFailure::Definition,
        ),
        (
            serde_json::json!({"$recursiveRef":"#"}),
            BuildFailure::Definition,
        ),
    ] {
        let schema = serde_json::json!({"$id":id, "$defs":{"unused":definition}}).to_string();
        assert_eq!(check(&[(path, &schema)]), Err(expected));
    }
    let schema =
        serde_json::json!({"$id":id, "$ref":"#/title", "title":"not a schema"}).to_string();
    assert_eq!(check(&[(path, &schema)]), Err(BuildFailure::Reference));
}
