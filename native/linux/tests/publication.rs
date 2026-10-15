//! Offline output tests use only owned temporary directories and synthetic data.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/publication/mod.rs"]
mod publication;
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;
#[allow(dead_code)]
#[path = "../src/worker/mod.rs"]
mod worker;

use jocky_forensic::collection::{context::OperationTarget, report};
use jocky_shared::collection::{
    Code,
    report::{ReportKind, WorkerCleanup},
};
use sources::capabilities::OutputDirectory;
use std::{
    fs,
    os::fd::AsFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use support::{Frozen, context, path, scratch, values};

#[test]
fn verified_failure_report_is_exclusive_and_private_on_disk() {
    let owned = scratch();
    let root = owned.path().join("source");
    let output_dir = owned.path().join("output");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&output_dir).unwrap();
    let destination = output_dir.join("report.json");
    let context = context(&values(root.to_str().unwrap(), "selected"));
    let selected = path("selected");
    let mut clock = Frozen::default();
    let output = OutputDirectory::open(
        &context,
        OperationTarget::File(&selected),
        destination.to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    let failed = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let bytes = report::finalize(failed, 65_536).unwrap();
    let digest = publication::install_verified(&output, &bytes, &mut clock).unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(fs::read(&destination).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        publication::install_verified(&output, &bytes, &mut clock),
        Err(Code::OutputExists)
    );
    assert_eq!(fs::read(&destination).unwrap(), bytes);
}

#[test]
fn tamper_and_unsafe_parent_never_create_an_output() {
    let owned = scratch();
    let root = owned.path().join("source");
    let output_dir = owned.path().join("output");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&output_dir).unwrap();
    let destination = output_dir.join("report.json");
    let context = context(&values(root.to_str().unwrap(), "selected"));
    let selected = path("selected");
    let mut clock = Frozen::default();
    let output = OutputDirectory::open(
        &context,
        OperationTarget::File(&selected),
        destination.to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    let failed = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let valid = report::finalize(failed, 65_536).unwrap();
    let mut bytes = valid.clone();
    bytes[0] ^= 1;
    assert!(publication::install_verified(&output, &bytes, &mut clock).is_err());
    assert!(!destination.exists());

    clock.0.monotonic_ms = 70_000;
    assert!(publication::install_verified(&output, &valid, &mut clock).is_err());
    assert!(!destination.exists());
    clock = Frozen::default();

    fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        OutputDirectory::open(
            &context,
            OperationTarget::File(&selected),
            destination.to_str().unwrap(),
            &mut clock,
            &false,
        )
        .is_err()
    );
    assert!(!destination.exists());
}

#[test]
fn transferred_output_capability_installs_only_matching_verified_report() {
    let owned = scratch();
    let root = owned.path().join("source");
    let output_dir = owned.path().join("output");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&output_dir).unwrap();
    let context = context(&values(root.to_str().unwrap(), "selected"));
    let report = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let valid = report::finalize(report, 65_536).unwrap();
    let output = fs::File::open(&output_dir).unwrap();
    let limits = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap()
    .global_limits;
    let mut quota = worker::accounting::PublicationQuota::new(&limits).unwrap();
    let destination = output_dir.join("report.json");

    let mut tampered = valid.clone();
    tampered[0] ^= 1;
    assert!(
        publication::install_transferred(
            output.as_fd(),
            "report.json",
            &tampered,
            context.identity(),
            &mut quota,
            || Ok(())
        )
        .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(quota.failure_charged(), 0);
    let synthetic = report::failure(
        &context,
        ReportKind::SyntheticTest,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let synthetic = report::finalize(synthetic, 65_536).unwrap();
    assert_eq!(
        publication::install_transferred(
            output.as_fd(),
            "report.json",
            &synthetic,
            context.identity(),
            &mut quota,
            || Ok(())
        ),
        Err(Code::ScopeDenied)
    );
    assert_eq!(quota.failure_charged(), 0);
    assert!(!destination.exists());
    assert_eq!(
        publication::install_transferred(
            output.as_fd(),
            "report.json",
            &valid,
            context.identity(),
            &mut quota,
            || Err(Code::Timeout)
        ),
        Err(Code::Timeout)
    );
    assert!(!destination.exists());

    let identity = publication::install_transferred(
        output.as_fd(),
        "report.json",
        &valid,
        context.identity(),
        &mut quota,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(quota.failure_charged(), valid.len() as u64);
    let metadata = fs::metadata(&destination).unwrap();
    assert_eq!(identity.inode, metadata.ino().to_string());
    assert_eq!(fs::read(&destination).unwrap(), valid);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        publication::install_transferred(
            output.as_fd(),
            "report.json",
            &valid,
            context.identity(),
            &mut quota,
            || Ok(())
        ),
        Err(Code::OutputExists)
    );
    assert_eq!(fs::read(&destination).unwrap(), valid);
}

#[test]
fn post_rename_fault_discloses_owned_file_identity_without_removing_it() {
    let owned = scratch();
    let root = owned.path().join("source");
    let output_dir = owned.path().join("output");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&output_dir).unwrap();
    let context = context(&values(root.to_str().unwrap(), "selected"));
    let failed = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let bytes = report::finalize(failed, 65_536).unwrap();
    let limits = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap()
    .global_limits;
    let output = fs::File::open(&output_dir).unwrap();
    let mut quota = worker::accounting::PublicationQuota::new(&limits).unwrap();
    let mut calls = 0;
    let failure = publication::install_transferred_detailed(
        output.as_fd(),
        "report.json",
        &bytes,
        context.identity(),
        &mut quota,
        || {
            calls += 1;
            if calls == 5 {
                Err(Code::Timeout)
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(failure.code, Code::Timeout);
    assert!(!failure.staging_residue);
    let destination = output_dir.join("report.json");
    assert_eq!(fs::read(&destination).unwrap(), bytes);
    assert_eq!(
        failure.created_identity.unwrap().inode,
        fs::metadata(&destination).unwrap().ino().to_string()
    );
    assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 1);
}

#[test]
fn cleanup_fault_preserves_only_invocation_owned_residue() {
    let owned = scratch();
    let root = owned.path().join("source");
    let output_dir = owned.path().join("output");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&output_dir).unwrap();
    let context = context(&values(root.to_str().unwrap(), "selected"));
    let failed = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let bytes = report::finalize(failed, 65_536).unwrap();
    let limits = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap()
    .global_limits;
    let output = fs::File::open(&output_dir).unwrap();
    let mut quota = worker::accounting::PublicationQuota::new(&limits).unwrap();
    let stage_name = format!(".jocky-{}.stage", context.identity().collection_id.as_str());
    let mut calls = 0;
    let failure = publication::install_transferred_detailed(
        output.as_fd(),
        "report.json",
        &bytes,
        context.identity(),
        &mut quota,
        || {
            calls += 1;
            if calls == 3 {
                fs::write(output_dir.join(&stage_name).join("unexpected"), b"owned").unwrap();
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(failure.code, Code::CleanupIncomplete);
    assert!(failure.staging_residue);
    assert!(failure.created_identity.is_some());
    assert!(output_dir.join("report.json").exists());
    assert_eq!(
        fs::read(output_dir.join(stage_name).join("unexpected")).unwrap(),
        b"owned"
    );
}
