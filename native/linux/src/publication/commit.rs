use super::Stage;
use crate::sources::capabilities::OutputDirectory;
use jocky_forensic::collection::clock::Clock;
use jocky_shared::collection::Code;
use rustix::{
    fd::BorrowedFd,
    fs::{self, AtFlags, RenameFlags},
};

/// Atomically install an already synced report without replacing a prior
/// report. The caller owns cleanup of the staging directory in all outcomes.
pub(crate) fn commit(
    output: &OutputDirectory<'_>,
    stage: &Stage,
    destination: &str,
    clock: &mut dyn Clock,
) -> Result<(), Code> {
    if destination != output.name() {
        return Err(Code::ScopeDenied);
    }
    output.check_for_publication(clock)?;
    commit_in(output.fd(), output.sync_fd(), stage, destination)
}

pub(super) fn commit_in(
    parent: BorrowedFd<'_>,
    sync_parent: BorrowedFd<'_>,
    stage: &Stage,
    destination: &str,
) -> Result<(), Code> {
    commit_in_tracked(parent, sync_parent, stage, destination, &mut false)
}

/// Records the point at which the final name becomes visible. A later sync
/// failure must not erase that fact from the publisher acknowledgement.
pub(super) fn commit_in_tracked(
    parent: BorrowedFd<'_>,
    sync_parent: BorrowedFd<'_>,
    stage: &Stage,
    destination: &str,
    renamed: &mut bool,
) -> Result<(), Code> {
    commit_steps(
        destination,
        || stage.sync(),
        || {
            fs::renameat_with(
                stage.directory(),
                "report.json",
                parent,
                destination,
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| match error {
                rustix::io::Errno::EXIST => Code::OutputExists,
                _ => Code::PublicationFailed,
            })?;
            *renamed = true;
            Ok(())
        },
        || stage.sync_directory(),
        || fs::fsync(sync_parent).map_err(|_| Code::PublicationFailed),
    )
}

fn commit_steps(
    destination: &str,
    mut sync_report: impl FnMut() -> Result<(), Code>,
    mut rename: impl FnMut() -> Result<(), Code>,
    mut sync_stage: impl FnMut() -> Result<(), Code>,
    mut sync_parent: impl FnMut() -> Result<(), Code>,
) -> Result<(), Code> {
    valid_name(destination)?;
    sync_report()?;
    rename()?;
    sync_stage()?;
    sync_parent()
}

pub(super) fn valid_name(destination: &str) -> Result<(), Code> {
    if destination.is_empty()
        || destination.len() > 255
        || destination.contains('/')
        || destination.contains('\0')
        || matches!(destination, "." | "..")
    {
        return Err(Code::InvalidInput);
    }
    Ok(())
}

/// Remove only the fixed, invocation-owned staging objects. A failed removal
/// is visible to the caller; it must not be converted to successful cleanup.
pub(crate) fn cleanup(output: &OutputDirectory<'_>, stage: &Stage) -> Result<(), Code> {
    cleanup_in(output.fd(), output.sync_fd(), stage)
}

pub(super) fn cleanup_in(
    parent: BorrowedFd<'_>,
    sync_parent: BorrowedFd<'_>,
    stage: &Stage,
) -> Result<(), Code> {
    match fs::unlinkat(stage.directory(), "report.json", AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(Code::CleanupIncomplete),
    }
    fs::unlinkat(parent, stage.name(), AtFlags::REMOVEDIR).map_err(|_| Code::CleanupIncomplete)?;
    fs::fsync(sync_parent).map_err(|_| Code::CleanupIncomplete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn sync_and_rename_faults_never_report_success_or_run_later_steps() {
        for failed in 0..4 {
            let step = Cell::new(0usize);
            let run = |position| {
                assert_eq!(step.get(), position);
                step.set(position + 1);
                if position == failed {
                    Err(Code::PublicationFailed)
                } else {
                    Ok(())
                }
            };
            assert_eq!(
                commit_steps("report.json", || run(0), || run(1), || run(2), || run(3)),
                Err(Code::PublicationFailed)
            );
            assert_eq!(step.get(), failed + 1);
        }
    }
}
