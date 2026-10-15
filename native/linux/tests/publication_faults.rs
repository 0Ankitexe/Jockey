//! Exclusive publication faults on test-owned output only; no volume filling.
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
    os::unix::fs::{PermissionsExt, symlink},
};
use support::{Frozen, context, path, scratch, values};

#[test]
fn collision_and_symlink_faults_preserve_original_output() {
    for prior in ["regular", "symlink"] {
        let owned = scratch();
        let source = owned.path().join("source");
        let output = owned.path().join("output");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&output).unwrap();
        let destination = output.join("report.json");
        if prior == "regular" {
            fs::write(&destination, b"prior evidence").unwrap();
        } else {
            fs::write(owned.path().join("sentinel"), b"prior evidence").unwrap();
            symlink("../sentinel", &destination).unwrap();
        }
        let admitted = context(&values(source.to_str().unwrap(), "selected"));
        let reference = path("selected");
        let mut clock = Frozen::default();
        let opened = OutputDirectory::open(
            &admitted,
            OperationTarget::File(&reference),
            destination.to_str().unwrap(),
            &mut clock,
            &false,
        );
        if let Ok(capability) = opened {
            let failed = report::failure(
                &admitted,
                ReportKind::LiveLab,
                admitted.started_at().clone(),
                Code::Unsupported,
                WorkerCleanup::NotStarted,
            )
            .unwrap();
            let bytes = report::finalize(failed, 65_536).unwrap();
            assert!(publication::install_verified(&capability, &bytes, &mut clock).is_err());
        }
        assert_eq!(fs::read(&destination).unwrap(), b"prior evidence");
    }
}

#[test]
fn abandoned_publisher_stage_is_cleaned_only_when_new_and_private() {
    let owned = scratch();
    let parent = fs::File::open(owned.path()).unwrap();
    let id =
        jocky_shared::collection::identity::Uuid::parse("10000000-0000-4000-8000-000000000007")
            .unwrap();
    assert_eq!(
        worker::publisher_cleanup::abandoned_stage_absent(parent.as_fd(), &id),
        Ok(true)
    );
    let stage_path = owned.path().join(format!(".jocky-{}.stage", id.as_str()));
    fs::create_dir(&stage_path).unwrap();
    fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o700)).unwrap();
    let stage_file = stage_path.join("report.json");
    fs::write(&stage_file, b"incomplete report").unwrap();
    fs::set_permissions(&stage_file, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        worker::publisher_cleanup::abandoned_stage_absent(parent.as_fd(), &id),
        Ok(false)
    );
    // Inject an abrupt publisher exit before its ordinary cleanup.
    worker::publisher_cleanup::cleanup_abandoned_stage(parent.as_fd(), &id).unwrap();
    assert_eq!(
        worker::publisher_cleanup::abandoned_stage_absent(parent.as_fd(), &id),
        Ok(true)
    );

    let outside = owned.path().join("outside");
    fs::write(&outside, b"preserve").unwrap();
    symlink(
        "outside",
        owned.path().join(format!(".jocky-{}.stage", id.as_str())),
    )
    .unwrap();
    assert_eq!(
        worker::publisher_cleanup::cleanup_abandoned_stage(parent.as_fd(), &id),
        Err(Code::CleanupIncomplete)
    );
    assert_eq!(fs::read(outside).unwrap(), b"preserve");
}
