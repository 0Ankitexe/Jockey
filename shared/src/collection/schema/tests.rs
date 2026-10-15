use super::*;
use serde_json::json;

#[test]
fn reference_entries_match_direct_roots_on_fixtures_and_mutations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("fixtures/collection-cases.json")).unwrap(),
    )
    .unwrap();
    let schemas: Vec<Value> = SCHEMAS
        .iter()
        .map(|s| serde_json::from_str(s.contents).unwrap())
        .collect();
    let mut compared = 0;
    for kind in DocumentKind::ALL {
        let schema = &schemas[kind as usize];
        assert!(
            SCHEMAS[kind as usize]
                .path
                .ends_with(&format!("/{}.schema.json", kind.name()))
        );
        let direct = jsonschema::draft202012::options()
            .with_retriever(Deny)
            .with_resources(schemas.iter().map(|s| {
                (
                    s["$id"].as_str().unwrap().to_owned(),
                    Resource::from_contents(s.clone()).unwrap(),
                )
            }))
            .should_validate_formats(true)
            .build(schema)
            .unwrap();
        let reference = build(kind).unwrap();
        let mut compare = |value: &Value| {
            compared += 1;
            assert_eq!(
                direct.is_valid(value),
                reference.is_valid(value),
                "{}",
                kind.name()
            );
        };
        for case in manifest["cases"].as_array().unwrap() {
            if case["schema"] != schema["$id"] {
                continue;
            }
            let raw = std::fs::read(root.join(case["file"].as_str().unwrap())).unwrap();
            // Raw duplicate-key/encoding/size failures remain decoder tests.
            let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
                continue;
            };
            compare(&value);
            if let Value::Object(fields) = &value {
                let mut extra = value.clone();
                extra["unknown_field"] = json!("not accepted");
                compare(&extra);
                for key in fields.keys() {
                    let mut missing = value.clone();
                    missing.as_object_mut().unwrap().remove(key);
                    compare(&missing);
                    let mut wrong_type = value.clone();
                    wrong_type[key] = Value::Null;
                    compare(&wrong_type);
                }
            }
        }
        for value in [
            json!(null),
            json!(false),
            json!(42),
            json!([]),
            json!({}),
            json!("é/汉/😀"),
        ] {
            compare(&value);
        }
    }
    assert!(
        compared >= 2000,
        "fixture/mutation coverage unexpectedly shrank: {compared}"
    );
}
