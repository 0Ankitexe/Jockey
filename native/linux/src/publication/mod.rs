//! Private output-only publication primitives. A caller must first obtain an
//! admitted output directory and independently validate the final report.
mod commit;
mod stage;

pub(crate) use stage::Stage;

use crate::{sources::capabilities::OutputDirectory, worker::accounting::PublicationQuota};
use jocky_forensic::collection::clock::Clock;
use jocky_shared::collection::{Code, report::SummaryStatus};
use jocky_shared::collection::{
    records::LocalContext, report::ReportKind, worker::CreatedIdentity,
};
use rustix::fd::BorrowedFd;

/// Final report installation primitive for a future separately supervised
/// publisher worker. A validated output capability, matching live-lab report,
/// current finalization clock and bounded quota are all required. This does
/// not launch a worker or make the collector CLI operational.
pub(crate) fn install_verified(
    output: &OutputDirectory<'_>,
    bytes: &[u8],
    clock: &mut dyn Clock,
) -> Result<String, Code> {
    let mut quota = PublicationQuota::new(output.limits())?;
    if bytes.len() as u64 > output.limits().max_report_bytes {
        return Err(Code::ResourceLimit);
    }
    let report = jocky_forensic::collection::verify::verify_report(bytes)?;
    output.check_report(&report)?;
    if report.summary.status == SummaryStatus::Failed && bytes.len() <= 65_536 {
        quota.charge_failure_report(bytes.len() as u64)?;
    } else {
        quota.charge_report(bytes.len() as u64)?;
    }
    output.check_for_publication(clock)?;
    let mut stage = Stage::create(output, &report.context.collection_id, clock)?;
    let result = stage
        .write(output, bytes, &mut quota, clock)
        .and_then(|()| commit::commit(output, &stage, output.name(), clock));
    let cleanup = commit::cleanup(output, &stage);
    match (result, cleanup) {
        (_, Err(_)) => Err(Code::CleanupIncomplete),
        (Err(code), Ok(())) => Err(code),
        (Ok(()), Ok(())) => Ok(report.content_sha256),
    }
}

/// A failed directory sync can leave the new final name visible. Preserve its
/// inode identity in the acknowledgement so the caller can disclose residue
/// without reading or deleting the file.
#[derive(Debug, PartialEq)]
pub(crate) struct PublishFailure {
    pub code: Code,
    pub created_identity: Option<CreatedIdentity>,
    pub staging_residue: bool,
}

/// Output-only commit path for a separately authenticated publisher worker.
/// The caller has already checked the transferred directory object, its
/// admitted purpose and the original whole-run deadline. Every callback check
/// must use that same deadline; it never grants a source read. This primitive
/// does not itself spawn the publisher.
pub(crate) fn install_transferred(
    output: BorrowedFd<'_>,
    name: &str,
    raw: &[u8],
    context: &LocalContext,
    quota: &mut PublicationQuota,
    check_deadline: impl FnMut() -> Result<(), Code>,
) -> Result<CreatedIdentity, Code> {
    install_transferred_detailed(output, name, raw, context, quota, check_deadline)
        .map_err(|failure| failure.code)
}

pub(crate) fn install_transferred_detailed(
    output: BorrowedFd<'_>,
    name: &str,
    raw: &[u8],
    context: &LocalContext,
    quota: &mut PublicationQuota,
    mut check_deadline: impl FnMut() -> Result<(), Code>,
) -> Result<CreatedIdentity, PublishFailure> {
    let failure = |code| PublishFailure {
        code,
        created_identity: None,
        staging_residue: false,
    };
    commit::valid_name(name).map_err(failure)?;
    check_deadline().map_err(failure)?;
    let report = jocky_forensic::collection::verify::verify_report(raw).map_err(failure)?;
    if report.context != *context || report.report_kind != ReportKind::LiveLab {
        return Err(failure(Code::ScopeDenied));
    }
    if report.summary.status == SummaryStatus::Failed
        && report.records.is_empty()
        && report.errors.is_empty()
    {
        quota
            .charge_failure_report(raw.len() as u64)
            .map_err(failure)?;
    } else {
        quota.charge_report(raw.len() as u64).map_err(failure)?;
    }
    check_deadline().map_err(failure)?;
    let mut stage =
        Stage::create_in(output, &report.context.collection_id).map_err(|code| PublishFailure {
            code,
            created_identity: None,
            staging_residue: code == Code::CleanupIncomplete,
        })?;
    let mut renamed = false;
    let result = (|| {
        for chunk in raw.chunks(65_536) {
            check_deadline()?;
            stage.write_in(chunk, quota)?;
            check_deadline()?;
        }
        let identity = stage.created_identity()?;
        commit::commit_in_tracked(output, output, &stage, name, &mut renamed)?;
        check_deadline()?;
        Ok(identity)
    })();
    let cleanup = commit::cleanup_in(output, output, &stage);
    match (result, cleanup) {
        (_, Err(_)) => Err(PublishFailure {
            code: Code::CleanupIncomplete,
            created_identity: if renamed {
                stage.created_identity().ok()
            } else {
                None
            },
            staging_residue: true,
        }),
        (Err(code), Ok(())) => Err(PublishFailure {
            code,
            created_identity: if renamed {
                stage.created_identity().ok()
            } else {
                None
            },
            staging_residue: false,
        }),
        (Ok(identity), Ok(())) => Ok(identity),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Stage,
        commit::{cleanup_in, commit_in},
        install_verified,
    };
    use crate::worker::accounting::PublicationQuota;
    use jocky_shared::collection::{Code, identity::Uuid};
    use rustix::fd::AsFd;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn id() -> Uuid {
        Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap()
    }

    fn quota() -> PublicationQuota {
        let launch = jocky_shared::collection::launch::decode_launch(include_bytes!(
            "../../../../fixtures/valid/collection/worker-launch.json"
        ))
        .unwrap();
        PublicationQuota::new(&launch.global_limits).unwrap()
    }

    #[test]
    fn admitted_live_report_is_installed_once_and_mismatched_reports_are_denied() {
        use crate::support;
        use jocky_forensic::collection::{context::OperationTarget, report};
        use jocky_shared::collection::report::{ReportKind, WorkerCleanup};

        let owned = support::scratch();
        fs::create_dir(owned.path().join("evidence")).unwrap();
        fs::create_dir(owned.path().join("output")).unwrap();
        let evidence = owned.path().join("evidence");
        let destination = owned.path().join("output/report.json");
        let ctx = support::context(&support::values(evidence.to_str().unwrap(), "selected"));
        let selected = support::path("selected");
        let mut clock = support::Frozen::default();
        let output = crate::sources::capabilities::OutputDirectory::open(
            &ctx,
            OperationTarget::File(&selected),
            destination.to_str().unwrap(),
            &mut clock,
            &false,
        )
        .unwrap();
        let report = report::failure(
            &ctx,
            ReportKind::LiveLab,
            ctx.started_at().clone(),
            Code::Unsupported,
            WorkerCleanup::NotStarted,
        )
        .unwrap();
        let bytes = report::finalize(report.clone(), 65536).unwrap();
        let mut synthetic = report;
        synthetic.report_kind = ReportKind::SyntheticTest;
        let synthetic = report::finalize(synthetic, 65536).unwrap();
        assert_eq!(
            install_verified(&output, &synthetic, &mut clock),
            Err(Code::ScopeDenied)
        );
        assert!(install_verified(&output, &bytes[..bytes.len() - 1], &mut clock).is_err());
        assert!(!destination.exists());
        let digest = install_verified(&output, &bytes, &mut clock).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(digest.len(), 64);
        assert_eq!(
            install_verified(&output, &bytes, &mut clock),
            Err(Code::OutputExists)
        );
        assert_eq!(fs::read(&destination).unwrap(), bytes);
    }

    #[test]
    fn stages_private_bytes_and_installs_without_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::File::open(temp.path()).unwrap();
        let mut stage = Stage::create_in(parent.as_fd(), &id()).unwrap();
        stage.write_in(b"forensic report", &mut quota()).unwrap();
        assert_eq!(stage.written(), 15);
        let staging = temp.path().join(stage.name());
        assert_eq!(
            fs::metadata(&staging).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(staging.join("report.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            Stage::create_in(parent.as_fd(), &id()).err(),
            Some(Code::OutputExists)
        );
        fs::write(temp.path().join("existing.json"), b"old").unwrap();
        assert_eq!(
            commit_in(parent.as_fd(), parent.as_fd(), &stage, "existing.json"),
            Err(Code::OutputExists)
        );
        assert_eq!(fs::read(temp.path().join("existing.json")).unwrap(), b"old");
        commit_in(parent.as_fd(), parent.as_fd(), &stage, "report.json").unwrap();
        assert_eq!(
            fs::read(temp.path().join("report.json")).unwrap(),
            b"forensic report"
        );
        cleanup_in(parent.as_fd(), parent.as_fd(), &stage).unwrap();
        assert!(!staging.exists());
    }

    #[test]
    fn preexisting_staging_symlink_is_never_followed_or_removed() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::File::open(temp.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let name = format!(".jocky-{}.stage", id().as_str());
        let link = temp.path().join(&name);
        symlink(outside.path(), &link).unwrap();
        assert_eq!(
            Stage::create_in(parent.as_fd(), &id()).err(),
            Some(Code::OutputExists)
        );
        assert_eq!(fs::read_link(&link).unwrap(), outside.path());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[test]
    fn bounds_and_invalid_destinations_fail_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::File::open(temp.path()).unwrap();
        let mut stage = Stage::create_in(parent.as_fd(), &id()).unwrap();
        let mut quota = quota();
        stage.write_in(b"1234", &mut quota).unwrap();
        assert_eq!(stage.written(), 4);
        assert_eq!(quota.charged().1, 4);
        assert_eq!(
            stage.write_in(&vec![0; 10_485_761], &mut quota),
            Err(Code::ResourceLimit)
        );
        assert_eq!(quota.charged().1, 4);
        for bad in ["", ".", "..", "../escape", "a/b"] {
            assert_eq!(
                commit_in(parent.as_fd(), parent.as_fd(), &stage, bad),
                Err(Code::InvalidInput)
            );
        }
        assert!(!temp.path().join("escape").exists());
        cleanup_in(parent.as_fd(), parent.as_fd(), &stage).unwrap();
    }

    #[test]
    fn unexpected_owned_staging_residue_is_reported_not_discarded() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::File::open(temp.path()).unwrap();
        let stage = Stage::create_in(parent.as_fd(), &id()).unwrap();
        let staging = temp.path().join(stage.name());
        fs::write(staging.join("unexpected"), b"owned residue").unwrap();
        assert_eq!(
            cleanup_in(parent.as_fd(), parent.as_fd(), &stage),
            Err(Code::CleanupIncomplete)
        );
        assert!(staging.join("unexpected").exists());
        fs::remove_file(staging.join("unexpected")).unwrap();
        cleanup_in(parent.as_fd(), parent.as_fd(), &stage).unwrap();
    }

    #[test]
    fn admitted_output_capability_can_publish_during_reserved_interval() {
        use super::commit::{cleanup, commit};
        use crate::{sources::capabilities::OutputDirectory, support};
        use jocky_forensic::collection::context::OperationTarget;
        use jocky_shared::collection::identity::UtcTime;

        let owned = support::scratch();
        fs::create_dir(owned.path().join("evidence")).unwrap();
        fs::create_dir(owned.path().join("output")).unwrap();
        let evidence = owned.path().join("evidence");
        let target = support::path("selected");
        let context = support::context(&support::values(evidence.to_str().unwrap(), "selected"));
        let destination = owned.path().join("output/report.json");
        let mut clock = support::Frozen::default();
        let output = OutputDirectory::open(
            &context,
            OperationTarget::File(&target),
            destination.to_str().unwrap(),
            &mut clock,
            &false,
        )
        .unwrap();
        clock.0.monotonic_ms = 55_000;
        clock.0.utc = UtcTime::parse("2020-01-01T00:01:05Z").unwrap();
        let mut stage = Stage::create(&output, &id(), &mut clock).unwrap();
        let mut quota = quota();
        stage
            .write(&output, b"bounded report", &mut quota, &mut clock)
            .unwrap();
        commit(&output, &stage, output.name(), &mut clock).unwrap();
        cleanup(&output, &stage).unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"bounded report");
        assert_eq!(quota.charged().1, 14);
    }
}
