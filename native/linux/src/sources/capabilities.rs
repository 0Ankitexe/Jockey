//! Metadata-only output admission. Never creates, truncates, writes or publishes.
use super::{
    error,
    metadata::{self, Exclusions, ObjectId, Snapshot},
    operation::Operation,
    paths,
};
use jocky_forensic::collection::{
    ValidatedCollectionContext, cancellation::Cancellation, clock::Clock, context::OperationTarget,
};
use jocky_shared::collection::Code;
use jocky_shared::collection::report::{CollectionReport, ReportKind};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, FileType, Mode, OFlags, ResolveFlags},
};

pub(crate) struct OutputDirectory<'ctx> {
    context: &'ctx ValidatedCollectionContext,
    target: OperationTarget<'ctx>,
    fd: OwnedFd,
    sync_fd: OwnedFd,
    before: Snapshot,
    absolute: String,
    lineage: Vec<ObjectId>,
    name: String,
}
impl<'ctx> OutputDirectory<'ctx> {
    pub fn open(
        context: &'ctx ValidatedCollectionContext,
        target: OperationTarget<'ctx>,
        output: &str,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Self, Code> {
        let (parent, name) = split(output)?;
        // The sealed context and current permit precede even output metadata I/O.
        let permit = context.permit(target, &clock.read()?, cancel.cancelled())?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        let (fd, before, lineage) = paths::root(parent, &Exclusions::default(), &mut op)?;
        metadata::directory(&before, rustix::process::geteuid().as_raw(), true)?;
        if before.stat.stx_uid != rustix::process::geteuid().as_raw() {
            return Err(Code::PermissionDenied);
        }
        check_absent(&fd, name, &mut op)?;
        let sync_fd = op.run(|| {
            fs::openat2(
                &fd,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )
            .map_err(error)
        })?;
        let sync_identity = metadata::inspect(&sync_fd, &mut op)?;
        metadata::same_output_directory(&before, &sync_identity)?;
        op.permit.charge(
            jocky_forensic::collection::budget::Counter::RetainedBytes,
            output.len() as u64,
        )?;
        Ok(Self {
            context,
            target,
            fd,
            sync_fd,
            before,
            absolute: parent.into(),
            lineage,
            name: name.into(),
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn check_report(&self, report: &CollectionReport) -> Result<(), Code> {
        if report.report_kind != ReportKind::LiveLab
            || report.context != *self.context.identity()
            || report.inputs != *self.context.input_provenance()
        {
            return Err(Code::ScopeDenied);
        }
        Ok(())
    }
    pub(crate) fn limits(&self) -> &jocky_shared::collection::inputs::Limits {
        self.context.limits()
    }
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub fn sync_fd(&self) -> BorrowedFd<'_> {
        self.sync_fd.as_fd()
    }
    pub(super) fn identity(&self) -> (&str, &[ObjectId]) {
        (&self.absolute, &self.lineage)
    }
    pub fn check_unchanged(
        &self,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<(), Code> {
        let permit = self
            .context
            .permit(self.target, &clock.read()?, cancel.cancelled())?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        let current = metadata::inspect(&self.fd, &mut op)?;
        metadata::unchanged(&self.before, &current)?;
        metadata::directory(&current, rustix::process::geteuid().as_raw(), true)?;
        check_absent(&self.fd, &self.name, &mut op)
    }

    /// Recheck this retained output-only capability during local report
    /// finalization. Evidence authority may have expired; no source permit or
    /// source bytes are touched. Atomic NOREPLACE remains mandatory at commit.
    pub fn check_for_publication(&self, clock: &mut dyn Clock) -> Result<(), Code> {
        self.context.check_finalization(&clock.read()?)?;
        let current = metadata::inspect_output(&self.fd)?;
        self.context.check_finalization(&clock.read()?)?;
        metadata::same_output_directory(&self.before, &current)?;
        let sync_current = metadata::inspect_output(&self.sync_fd)?;
        metadata::same_output_directory(&self.before, &sync_current)?;
        metadata::directory(&current, rustix::process::geteuid().as_raw(), true)?;
        let existing = match fs::openat2(
            &self.fd,
            self.name.as_str(),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(_) => Err(Code::OutputExists),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(super::error(error)),
        };
        self.context.check_finalization(&clock.read()?)?;
        existing
    }
}
fn split(output: &str) -> Result<(&str, &str), Code> {
    if output.len() > 4096 || output.contains('\0') {
        return Err(Code::InvalidInput);
    }
    let (parent, name) = output.rsplit_once('/').ok_or(Code::InvalidInput)?;
    if !parent.starts_with('/') || name.is_empty() || name.len() > 255 || matches!(name, "." | "..")
    {
        return Err(Code::InvalidInput);
    }
    Ok((parent, name))
}
fn check_absent(fd: &OwnedFd, name: &str, op: &mut Operation<'_, '_>) -> Result<(), Code> {
    op.entry()?;
    let pin = op.run(|| {
        match fs::openat2(
            fd,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => Ok(Some(fd)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(error(e)),
        }
    })?;
    if let Some(pin) = pin {
        let stat = metadata::inspect(&pin, op)?;
        if FileType::from_raw_mode(u32::from(stat.stat.stx_mode)) == FileType::Symlink {
            Err(Code::AliasDenied)
        } else {
            Err(Code::OutputExists)
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_output_names_fail_before_authority_or_filesystem_access() {
        for bad in [
            "",
            "relative",
            "/report",
            "/owned/",
            "/owned/.",
            "/owned/..",
            "/owned/nul\0",
        ] {
            assert!(split(bad).is_err(), "{bad:?}");
        }
        assert!(split(&format!("/owned/{}", "a".repeat(256))).is_err());
        assert_eq!(split("/owned/report.json"), Ok(("/owned", "report.json")));
    }
}
