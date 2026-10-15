//! Public CLI status never repeats unvalidated evidence-like arguments.
#![cfg(target_os = "linux")]
use std::process::Command;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn argument_and_input_failures_emit_only_bounded_safe_status() {
    let canary = "secret-evidence-path-DO-NOT-LOG";
    for args in [
        vec!["collect", "--allow-live-lab", "--request", canary],
        vec!["verify-report", canary],
        vec!["validate-inputs", "--designation", canary],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(result.stderr.len() <= 16_384);
        assert!(
            !result
                .stderr
                .windows(canary.len())
                .any(|bytes| bytes == canary.as_bytes())
        );
        let status: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert!(status["code"].is_string());
        assert!(status["collection_id"].is_null());
        assert!(status["endpoint_id"].is_null());
    }
}

#[test]
fn owned_configuration_name_and_os_permission_details_never_reach_status() {
    let root = tempfile::Builder::new()
        .prefix("v5-privacy-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
        .unwrap();
    let canary = "private-case-credential-CANARY";
    let path = root.path().join(canary);
    fs::write(&path, b"private evidence CANARY").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .args(["validate-inputs", "--designation", path.to_str().unwrap()])
        .output()
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() <= 16_384);
    assert!(
        !output
            .stderr
            .windows(canary.len())
            .any(|bytes| bytes == canary.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(b"private evidence".len())
            .any(|bytes| bytes == b"private evidence")
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(status["code"].is_string());
}
