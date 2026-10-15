//! Portable syntax acceptance cases. Unignore when the T174 v3 parser lands.
#[path = "support/artifacts.rs"]
mod artifacts;
use artifacts::OwnedDir;
use serde_json::Value;
use std::process::Command;

fn parse(text: &str) -> (std::process::Output, OwnedDir) {
    let dir = OwnedDir::new("portable-parser");
    let path = dir.write("source.jky", text);
    let out = Command::new(env!("CARGO_BIN_EXE_jockyc"))
        .args([
            "parse",
            path.to_str().unwrap(),
            "--language-version",
            "3.0.0",
            "--emit-ast",
            "json",
        ])
        .output()
        .unwrap();
    (out, dir)
}
fn source(targets: &str) -> String {
    format!(
        "module demo\ntarget {targets}\nfn inspect(t: endpoint) -> forensic_result {{ return forensic.system.profile(t) }}\nrun inspect on selected_endpoints\n"
    )
}

#[test]
fn contextual_linux_and_canonical_target_sets_keep_spans() {
    for target in [
        "linux",
        "windows | linux",
        "windows | ubuntu",
        "ubuntu | linux",
    ] {
        for text in [source(target), source(target).replace('\n', "\r\n")] {
            let (out, _dir) = parse(&text);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{target}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let ast: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(ast["schema_version"], "3.0.0");
            assert_eq!(ast["program"]["span"]["end"], text.len());
            assert_eq!(
                ast["program"]["target"]["platforms"]
                    .as_array()
                    .unwrap()
                    .len(),
                target.split(" | ").count()
            );
        }
    }
    let text = source("linux").replace("inspect", "linux");
    let (out, _dir) = parse(&text);
    assert_eq!(
        out.status.code(),
        Some(0),
        "linux remains an ordinary identifier outside target position"
    );
}

#[test]
fn duplicate_redundant_reversed_and_malformed_targets_fail_closed() {
    for target in [
        "linux | linux",
        "linux | ubuntu",
        "ubuntu | windows",
        "linux | windows",
        "windows | ubuntu | linux",
        "macos",
        "",
    ] {
        let (out, _dir) = parse(&source(target));
        assert_eq!(out.status.code(), Some(1), "{target}");
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }
    for text in ["module", "module demo\ntarget linux\nfn ("] {
        let (out, _dir) = parse(text);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn legacy_parser_still_rejects_generic_linux() {
    let dir = OwnedDir::new("legacy-linux-negative");
    let path = dir.write("legacy.jky", source("linux"));
    let out = Command::new(env!("CARGO_BIN_EXE_jockyc"))
        .args(["parse", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
