//! Actual-binary profile routing, fixture isolation and dependency boundaries.
#[path = "support/artifacts.rs"]
mod artifacts;
use artifacts::OwnedDir;
use std::process::{Command, Output};
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_jockyc"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn compiler_dependency_graph_has_no_native_collector_edge() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    for name in ["language", "ir", "forensic-lib", "shared"] {
        let manifest = std::fs::read_to_string(root.join(name).join("Cargo.toml")).unwrap();
        assert!(
            !manifest.contains("jocky-native-linux"),
            "{name} must not depend on native collection"
        );
    }
}
#[test]
fn parse_check_modules_build_and_verify_are_explicit_and_offline() {
    let dir = OwnedDir::new("portable-cli");
    let source = dir.write("source.jky", "module demo\ntarget linux\nfn inspect(t: endpoint) -> forensic_result { return forensic.system.profile(t) }\nrun inspect on selected_endpoints\n");
    let path = source.to_str().unwrap();
    let parse = run(&[
        "parse",
        path,
        "--language-version",
        "3.0.0",
        "--emit-ast",
        "json",
    ]);
    assert_eq!(parse.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&parse.stdout).unwrap()["schema_version"],
        "3.0.0"
    );
    assert_eq!(
        run(&["check", path, "--language-version", "3.0.0"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run(&["modules", "list", "--registry-version", "2.0.0"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run(&[
            "modules",
            "describe",
            "forensic.system.profile",
            "--registry-version",
            "2.0.0"
        ])
        .status
        .code(),
        Some(0)
    );
    let output = dir.path("result.json");
    assert_eq!(
        run(&[
            "build-ir",
            path,
            "--language-version",
            "3.0.0",
            "--output",
            output.to_str().unwrap()
        ])
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run(&["verify-ir", output.to_str().unwrap()]).status.code(),
        Some(0)
    );
}
#[test]
fn unknown_duplicate_conflicting_and_fixture_options_fail_stably() {
    let dir = OwnedDir::new("portable-cli-negative");
    let source = dir.write("source.jky", "module demo\ntarget linux\nfn inspect(t: endpoint) -> forensic_result { return forensic.system.profile(t) }\nrun inspect on selected_endpoints\n");
    let path = source.to_str().unwrap();
    for args in [
        vec!["parse", path, "--language-version", "9.0.0"],
        vec![
            "parse",
            path,
            "--language-version",
            "3.0.0",
            "--language-version",
            "3.0.0",
        ],
        vec!["check", path, "--language-version", "3.0.0", "--unknown"],
        vec!["modules", "list", "--registry-version", "9.0.0"],
        vec!["run-fixture", path, "--language-version", "3.0.0"],
    ] {
        let first = run(&args);
        let second = run(&args);
        assert_ne!(first.status.code(), Some(0), "{args:?}");
        assert_eq!(first.stderr, second.stderr, "{args:?}");
        assert!(first.stdout.is_empty(), "{args:?}");
    }
    let fixture = run(&[
        "run-fixture",
        path,
        "--fixture",
        dir.path("fixtures").to_str().unwrap(),
        "--language-version",
        "3.0.0",
    ]);
    assert_eq!(fixture.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&fixture.stderr).contains("unsupported-version"),
        "{:?}",
        fixture.stderr
    );
    // A portable syntax error must not fall back to the old parser.
    let bad = dir.write("bad.jky", "module demo\ntarget linux | ubuntu\n");
    assert_ne!(
        run(&[
            "parse",
            bad.to_str().unwrap(),
            "--language-version",
            "3.0.0"
        ])
        .status
        .code(),
        Some(0)
    );
}
