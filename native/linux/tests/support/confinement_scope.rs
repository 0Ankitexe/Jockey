use super::*;
use jocky_shared::collection::identity::Uuid;
use serde_json::json;

#[test]
fn startup_sources_allow_only_component_descendants_with_requested_depth() {
    let dir = scratch();
    for name in ["approved", "approved-extra", "approved/nested"] {
        fs::create_dir(dir.path().join(name)).unwrap();
        fs::write(dir.path().join(name).join("file"), b"test").unwrap();
    }
    let mut input = values(dir.path().to_str().unwrap(), "approved");
    let id = Uuid::parse("10000000-0000-4000-8000-000000000091").unwrap();
    for index in [1, 2] {
        input[index]["scope"]["capabilities"] = json!(["persistence"]);
        input[index]["scope"]["source_groups"] = json!(["startup_directory"]);
    }
    input[2]["sources"] = json!([{"source_id":id,"kind":"startup_directory","path":path("approved"),"format":"cron"}]);
    input[3]["collectors"] = json!(["persistence"]);
    input[3]["capabilities"] = json!(["persistence"]);
    input[3]["source_ids"] = json!([id]);
    input[3]["paths"] = json!([]);
    input[3]["limits"]["max_depth"] = json!(2);
    let ctx = context(&input);
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::Source(&id),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    root.pin_file("approved/file", &mut clock, &false).unwrap();
    for rejected in ["approved-extra/file", "sibling", "approved/nested/file"] {
        assert!(matches!(
            root.pin_file(rejected, &mut clock, &false),
            Err(Code::ScopeDenied)
        ));
    }
}

#[test]
fn raw_path_bytes_are_never_lossily_decoded_or_truncated() {
    let dir = scratch();
    let name = "測定-✓";
    fs::write(dir.path().join(name), b"test").unwrap();
    let reference = path(name);
    let ctx = context(&values(dir.path().to_str().unwrap(), name));
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::File(&reference),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    root.pin_file(name, &mut clock, &false).unwrap();
    for invalid in ["x".repeat(4097), "測".repeat(1366), "a/".repeat(17)] {
        assert!(matches!(
            root.pin_file(&invalid, &mut clock, &false),
            Err(Code::InvalidInput)
        ));
    }
}
