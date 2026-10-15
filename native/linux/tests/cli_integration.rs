//! Binary-level offline CLI checks use only a test-owned temporary source.
//! No VM or host inventory is designated by these documents.
#![cfg(target_os = "linux")]
#[path = "../src/cli/clock.rs"]
mod clock;
#[path = "support/confinement.rs"]
#[allow(dead_code)]
mod support;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

fn fixture(partial: bool) -> (tempfile::TempDir, [PathBuf; 4], PathBuf, PathBuf) {
    let dir = support::scratch();
    let source = dir.path().join("source");
    let config = dir.path().join("config");
    let output = dir.path().join("output");
    for path in [&source, &config, &output] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(source.join("selected"), b"bounded synthetic source\n").unwrap();
    let now = clock::read().unwrap().utc.unix_nanos() / 1_000_000_000;
    let before = clock::unix_utc((now - 3600) as i64).unwrap();
    let after = clock::unix_utc((now + 3600) as i64).unwrap();
    let mut values = support::values(source.to_str().unwrap(), "selected");
    for value in &mut values {
        if value.get("valid_from").is_some() {
            value["valid_from"] = before.as_str().into();
            value["valid_until"] = after.as_str().into();
        }
        if value.get("scope").is_some() {
            value["scope"]["event_window"]["start"] = before.as_str().into();
            value["scope"]["event_window"]["end"] = after.as_str().into();
        }
        if value.get("event_window").is_some() {
            value["event_window"]["start"] = before.as_str().into();
            value["event_window"]["end"] = after.as_str().into();
        }
    }
    values[3]["paths"] = if partial {
        serde_json::json!([support::path("selected"), support::path("missing")])
    } else {
        serde_json::json!([support::path("missing")])
    };
    let files = [
        "designation.json",
        "authorisation.json",
        "policy.json",
        "request.json",
    ]
    .map(|name| config.join(name));
    for (file, value) in files.iter().zip(values) {
        fs::write(file, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let report = output.join("report.json");
    (dir, files, output, report)
}

fn args(files: &[PathBuf; 4]) -> Vec<String> {
    ["--designation", "--authorisation", "--policy", "--request"]
        .into_iter()
        .zip(files)
        .flat_map(|(flag, path)| [flag.to_owned(), path.to_str().unwrap().to_owned()])
        .collect()
}

#[test]
fn binary_validates_inputs_and_publishes_partial_synthetic_report() {
    let (_dir, files, output, report) = fixture(true);
    let validate = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("validate-inputs")
        .args(args(&files))
        .output()
        .unwrap();
    assert_eq!(
        validate.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let valid: serde_json::Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(valid["code"], "InputsValid");

    let collected = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("collect")
        .arg("--allow-live-lab")
        .args(args(&files))
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(
        collected.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&collected.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&collected.stdout).unwrap();
    assert_eq!(status["code"], "PublishedPartial");
    let raw = fs::read(&report).unwrap();
    let verified = jocky_forensic::collection::verify::verify_report(&raw).unwrap();
    assert_eq!(
        verified.summary.status,
        jocky_shared::collection::report::SummaryStatus::Partial
    );
    assert_eq!(verified.records.len(), 1);
    assert_eq!(status["byte_length"], raw.len() as u64);

    let collision = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("collect")
        .arg("--allow-live-lab")
        .args(args(&files))
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(collision.status.code(), Some(3));
    assert!(collision.stdout.is_empty());
    let rejected: serde_json::Value = serde_json::from_slice(&collision.stderr).unwrap();
    assert_eq!(rejected["code"], "OutputExists");
    assert_eq!(fs::read_dir(output).unwrap().count(), 1);
}

#[test]
fn binary_publishes_failed_report_with_nonzero_exit() {
    let (_dir, files, _output, report) = fixture(false);
    let collected = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("collect")
        .arg("--allow-live-lab")
        .args(args(&files))
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(
        collected.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&collected.stderr)
    );
    assert!(collected.stdout.is_empty());
    let status: serde_json::Value = serde_json::from_slice(&collected.stderr).unwrap();
    assert_eq!(status["code"], "PublishedFailed");
    let raw = fs::read(&report).unwrap();
    let verified = jocky_forensic::collection::verify::verify_report(&raw).unwrap();
    assert_eq!(
        verified.summary.status,
        jocky_shared::collection::report::SummaryStatus::Failed
    );
    assert!(verified.records.is_empty());
}

#[test]
fn binary_reports_failed_when_selected_startup_directory_is_a_file() {
    let (dir, files, _output, report) = fixture(true);
    let source_id = "10000000-0000-4000-8000-000000000008";
    for index in [1, 2, 3] {
        let mut doc: serde_json::Value =
            serde_json::from_slice(&fs::read(&files[index]).unwrap()).unwrap();
        if index < 3 {
            doc["scope"]["capabilities"] = serde_json::json!(["persistence"]);
            doc["scope"]["source_groups"] = serde_json::json!(["startup_directory"]);
        }
        if index == 2 {
            doc["sources"] = serde_json::json!([{
                "source_id": source_id, "kind": "startup_directory",
                "path": support::path("selected"), "format": "systemd_units"
            }]);
        }
        if index == 3 {
            doc["capabilities"] = serde_json::json!(["persistence"]);
            doc["collectors"] = serde_json::json!(["persistence"]);
            doc["source_ids"] = serde_json::json!([source_id]);
            doc["paths"] = serde_json::json!([]);
        }
        fs::write(&files[index], serde_json::to_vec(&doc).unwrap()).unwrap();
    }
    assert!(dir.path().join("source").exists());
    let collected = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("collect")
        .arg("--allow-live-lab")
        .args(args(&files))
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(
        collected.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&collected.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&collected.stderr).unwrap();
    assert_eq!(status["code"], "PublishedFailed");
    let raw = fs::read(report).unwrap();
    let verified = jocky_forensic::collection::verify::verify_report(&raw).unwrap();
    assert!(verified.records.is_empty());
}

#[test]
fn binary_verifies_a_finalized_positive_report_without_source_access() {
    let model: jocky_shared::collection::report::CollectionReport = serde_json::from_slice(
        include_bytes!("../../../fixtures/valid/collection/report.json"),
    )
    .unwrap();
    let raw = jocky_forensic::collection::report::finalize(model, 10_485_760).unwrap();
    let root = support::scratch();
    let report = root.path().join("verified-report.json");
    fs::write(&report, &raw).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("verify-report")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let status: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["code"], "ReportValid");
    assert_eq!(status["byte_length"], raw.len() as u64);
}

#[test]
fn expired_authority_creates_no_output_or_staging_file() {
    let (_dir, files, output, report) = fixture(true);
    let mut authority: serde_json::Value =
        serde_json::from_slice(&fs::read(&files[1]).unwrap()).unwrap();
    let now = clock::read().unwrap().utc.unix_nanos() / 1_000_000_000;
    authority["valid_until"] = clock::unix_utc((now - 10) as i64).unwrap().as_str().into();
    fs::write(&files[1], serde_json::to_vec(&authority).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("collect")
        .arg("--allow-live-lab")
        .args(args(&files))
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stdout.is_empty());
    let status: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(status["code"], "AuthorisationExpired");
    assert_eq!(fs::read_dir(output).unwrap().count(), 0);
}
