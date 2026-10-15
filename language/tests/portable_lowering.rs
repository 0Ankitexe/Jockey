//! Deterministic portable lowering from checked source, activated in T175.
#[path = "support/artifacts.rs"]
mod artifacts;
use artifacts::OwnedDir;
use std::process::Command;
fn build(source: &std::path::Path, output: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_jockyc"))
        .args([
            "build-ir",
            source.to_str().unwrap(),
            "--language-version",
            "3.0.0",
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}
#[test]
fn same_source_and_seed_are_byte_identical_and_versioned() {
    let dir = OwnedDir::new("portable-lowering");
    let source = dir.write("source.jky", "module demo\ntarget linux\nfn inspect(t: endpoint) -> forensic_result { return forensic.system.profile(t) }\nrun inspect on selected_endpoints\n");
    let first = dir.path("first.ir.json");
    let second = dir.path("second.ir.json");
    for output in [&first, &second] {
        let result = build(&source, output);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let a = std::fs::read(first).unwrap();
    let b = std::fs::read(second).unwrap();
    assert_eq!(a, b);
    let document: serde_json::Value = serde_json::from_slice(&a).unwrap();
    assert_eq!(document["schema_version"], "2.0.0");
    assert_eq!(document["language_version"], "3.0.0");
    assert_eq!(document["registry"]["schema_version"], "2.0.0");
    assert_eq!(document["targets"], serde_json::json!(["linux"]));
}
#[test]
fn failed_semantics_publish_no_ir_and_legacy_golden_remains_identical() {
    let dir = OwnedDir::new("portable-lowering-negative");
    let source = dir.write("source.jky", "module demo\ntarget linux\nfn inspect(t: endpoint) -> forensic_result { return forensic.event.ubuntu_journal(t) }\nrun inspect on selected_endpoints\n");
    let output = dir.path("bad.ir.json");
    let result = build(&source, &output);
    assert_ne!(result.status.code(), Some(0));
    assert!(!output.exists());
    let legacy = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ir/golden/branches.ir.json"),
    )
    .unwrap();
    assert_eq!(
        legacy,
        include_bytes!("fixtures/ir/golden/branches.ir.json")
    );
}
