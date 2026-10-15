#![cfg(target_os = "linux")]
use jocky_forensic::collection::report::finalize;
use jocky_shared::collection::report::CollectionReport;
use std::process::Command;
#[path = "../src/worker/peer.rs"]
#[allow(dead_code)]
mod peer;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn broken_status_delivery_never_returns_success_or_evidence() {
    use std::{fs::OpenOptions, process::Stdio};
    for args in [["--help"].as_slice(), ["unknown"].as_slice()] {
        let full = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
            .args(args)
            .stdout(Stdio::from(full.try_clone().unwrap()))
            .stderr(Stdio::from(full))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(5));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn pure_commands_return_typed_status_and_incomplete_collect_is_rejected() {
    for (args, code, exit) in [
        (vec!["--help"], "Help", 0),
        (vec!["--version"], "Version", 0),
        (vec!["collect", "--allow-live-lab"], "InvalidInput", 3),
        (vec!["__worker"], "NotImplemented", 4),
        (vec!["unknown"], "InvalidInput", 3),
    ] {
        let result = run(&args);
        assert_eq!(result.status.code(), Some(exit));
        let payload = if exit == 0 {
            &result.stdout
        } else {
            &result.stderr
        };
        let status: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(status["code"], code);
        assert!(status.get("collection_id").is_none());
        assert!(if exit == 0 {
            result.stderr.is_empty()
        } else {
            result.stdout.is_empty()
        });
    }
}

#[test]
fn report_command_accepts_only_finalized_integrity_checked_bytes() {
    let model: CollectionReport = serde_json::from_slice(include_bytes!(
        "../../../fixtures/valid/collection/report.json"
    ))
    .unwrap();
    let verified = finalize(model, 10_485_760).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()
        .unwrap();
    let mut report = tempfile::NamedTempFile::new_in(root).unwrap();
    std::io::Write::write_all(&mut report, &verified).unwrap();
    let result = run(&["verify-report", report.path().to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stderr.is_empty());
    let status: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["code"], "ReportValid");
    assert_eq!(status["byte_length"], verified.len() as u64);
    assert_eq!(
        status["collection_id"],
        "10000000-0000-4000-8000-000000000007"
    );

    let raw = run(&[
        "verify-report",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/valid/collection/report.json"
        ),
    ]);
    // The argument contains `..`; canonical fixture content is also not a
    // finalized digest. Either way it must not return ReportValid.
    assert_ne!(raw.status.code(), Some(0));
}

#[test]
fn missing_or_duplicate_input_flags_reject_before_any_configuration_read() {
    for args in [
        vec!["validate-inputs"],
        vec!["validate-inputs", "--designation", "/absent"],
        vec![
            "validate-inputs",
            "--designation",
            "/x",
            "--designation",
            "/y",
            "--policy",
            "/z",
            "--request",
            "/w",
        ],
    ] {
        let result = run(&args);
        assert_eq!(result.status.code(), Some(3));
        let status: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
        assert_eq!(status["code"], "InvalidInput");
    }
}

#[test]
fn owned_binary_worker_authenticates_launch_and_rejects_missing_commit() {
    use std::{
        io::{Read, Write},
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
    };
    let (mut parent, child) = UnixStream::pair().unwrap();
    let child_output = child.try_clone().unwrap();
    let mut launch = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.parent = peer::own_identity().unwrap();
    launch.descriptors.clear();
    let raw = serde_json::to_vec(&launch).unwrap();
    let mut owned = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("__worker")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    parent.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
    parent.write_all(&raw).unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    parent.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
    assert_eq!(owned.wait().unwrap().code(), Some(3));
}

#[test]
fn private_worker_rejects_inherited_environment_before_launch_read() {
    use std::{
        io::Read,
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
        time::Duration,
    };
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let child_output = child.try_clone().unwrap();
    let mut owned = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("__worker")
        .env_clear()
        .env("JOCKY_TEST_INHERITED", "1")
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reply = Vec::new();
    parent.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
    assert_eq!(owned.wait().unwrap().code(), Some(3));
    let mut diagnostic = String::new();
    owned
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut diagnostic)
        .unwrap();
    assert_eq!(diagnostic, "WorkerEntry:WorkerProtocol\n");
}
