//! O_PATH pins reject special objects before a content-capable descriptor exists.
use super::{
    error,
    metadata::{self, Exclusions, Snapshot},
    operation::Operation,
};
use jocky_forensic::collection::{
    ValidatedCollectionContext, cancellation::Cancellation, clock::Clock, context::OperationTarget,
    inputs::ApprovedPath,
};
use jocky_shared::collection::{
    Code,
    inputs::{PathRef, SourceRef},
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, Mode, OFlags, ResolveFlags},
};

mod reopen;
const PIN: OFlags = OFlags::PATH.union(OFlags::CLOEXEC).union(OFlags::NOFOLLOW);
const NO_LINKS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const CONFINED: ResolveFlags = NO_LINKS.union(ResolveFlags::NO_XDEV);

pub(crate) struct ConfinedRoot<'ctx> {
    context: &'ctx ValidatedCollectionContext,
    target: OperationTarget<'ctx>,
    scope: ApprovedPath,
    descendants: bool,
    fd: OwnedFd,
    before: Snapshot,
    excluded: Exclusions,
    lineage: Vec<metadata::ObjectId>,
}
impl<'ctx> ConfinedRoot<'ctx> {
    /// Reconstitute an already authenticated parent pin after worker input
    /// commitment. This never resolves the request's root pathname again.
    pub(crate) fn inherited(
        context: &'ctx ValidatedCollectionContext,
        target: OperationTarget<'ctx>,
        fd: OwnedFd,
        excluded: Exclusions,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Self, Code> {
        let scope = context.path_scope(target)?;
        let permit = context.permit(target, &clock.read()?, cancel.cancelled())?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        let before = metadata::inspect(&fd, &mut op)?;
        metadata::directory(&before, rustix::process::geteuid().as_raw(), true)?;
        let descendants = match target {
            OperationTarget::Source(id) => context.sources().iter().any(|s| {
                s.definition().id() == id
                    && matches!(s.definition(), SourceRef::StartupDirectory { .. })
            }),
            _ => false,
        };
        Ok(Self {
            context,
            target,
            scope,
            descendants,
            fd,
            before,
            excluded,
            lineage: vec![before.id],
        })
    }

    pub fn open(
        context: &'ctx ValidatedCollectionContext,
        target: OperationTarget<'ctx>,
        excluded: Exclusions,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Self, Code> {
        let scope = context.path_scope(target)?;
        let descendants = match target {
            OperationTarget::Source(id) => context.sources().iter().any(|s| {
                s.definition().id() == id
                    && matches!(s.definition(), SourceRef::StartupDirectory { .. })
            }),
            _ => false,
        };
        let permit = context.permit(target, &clock.read()?, cancel.cancelled())?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        let (fd, before, lineage) = root(&scope.root().absolute_path, &excluded, &mut op)?;
        Ok(Self {
            context,
            target,
            scope,
            descendants,
            fd,
            before,
            excluded,
            lineage,
        })
    }
    pub(super) fn identity(&self) -> (&str, &[metadata::ObjectId]) {
        (&self.scope.root().absolute_path, &self.lineage)
    }
    pub(crate) fn root_id(&self) -> &jocky_shared::collection::identity::Uuid {
        &self.scope.root().root_id
    }
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
    fn operation<'a>(
        &'a self,
        clock: &'a mut dyn Clock,
        cancel: &'a dyn Cancellation,
    ) -> Result<Operation<'a, 'a>, Code> {
        let permit = self
            .context
            .permit(self.target, &clock.read()?, cancel.cancelled())?;
        Ok(Operation {
            permit,
            clock,
            cancel,
        })
    }
    fn scope(&self, relative: &str) -> Result<(), Code> {
        PathRef::new(self.scope.path().root_id.clone(), relative)
            .map_err(|_| Code::InvalidInput)?;
        if relative.split('/').count() as u64 > self.context.limits().max_depth {
            return Err(Code::ScopeDenied);
        }
        let base = &self.scope.path().relative_path;
        if relative == base
            || self.descendants
                && relative
                    .strip_prefix(base)
                    .is_some_and(|s| s.starts_with('/'))
        {
            Ok(())
        } else {
            Err(Code::ScopeDenied)
        }
    }
    /// Enumerate only direct children of the one approved startup directory.
    /// Every name consumes an entry budget before format-specific selection.
    pub(crate) fn list_children(
        &self,
        relative: &str,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Vec<String>, Code> {
        if !self.descendants {
            return Err(Code::ScopeDenied);
        }
        self.scope(relative)?;
        let mut op = self.operation(clock, cancel)?;
        let directory = op.run(|| {
            fs::openat2(
                &self.fd,
                relative,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                CONFINED,
            )
            .map_err(error)
        })?;
        let before = metadata::inspect(&directory, &mut op)?;
        metadata::directory(&before, rustix::process::geteuid().as_raw(), false)?;
        let mut iterator = op.run(|| fs::Dir::read_from(&directory).map_err(error))?;
        let mut names = Vec::new();
        loop {
            op.check()?;
            let entry = op.run(|| iterator.read().transpose().map_err(error))?;
            let Some(entry) = entry else {
                break;
            };
            op.entry()?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| Code::UnsupportedEncoding)?;
            if matches!(name, "." | "..") {
                continue;
            }
            if name.is_empty() || name.len() > 255 || name.contains('/') {
                return Err(Code::MalformedSource);
            }
            if names.len() >= 256 {
                return Err(Code::ResourceLimit);
            }
            names.push(name.to_owned());
        }
        metadata::unchanged(&before, &metadata::inspect(&directory, &mut op)?)?;
        names.sort();
        names.dedup();
        Ok(names)
    }

    pub fn pin_file<'root>(
        &'root self,
        relative: &str,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<PinnedFile<'root, 'ctx>, Code> {
        self.scope(relative)?;
        let mut op = self.operation(clock, cancel)?;
        op.entry()?;
        let current = metadata::inspect(&self.fd, &mut op)?;
        metadata::directory(&current, rustix::process::geteuid().as_raw(), true)?;
        if current.id != self.before.id || current.stat.stx_mnt_id != self.before.stat.stx_mnt_id {
            return Err(Code::SourceChanged);
        }
        let fd = op
            .run(|| fs::openat2(&self.fd, relative, PIN, Mode::empty(), CONFINED).map_err(error))?;
        let before = metadata::inspect(&fd, &mut op)?;
        metadata::regular(&before, self.before.stat.stx_mnt_id, &self.excluded)?;
        Ok(PinnedFile {
            root: self,
            fd,
            before,
        })
    }
}

pub(super) fn root(
    path: &str,
    excluded: &Exclusions,
    op: &mut Operation<'_, '_>,
) -> Result<(OwnedFd, Snapshot, Vec<metadata::ObjectId>), Code> {
    validate_root(path)?;
    op.permit.charge(
        jocky_forensic::collection::budget::Counter::RetainedBytes,
        ((path[1..].split('/').count() + 1) * std::mem::size_of::<metadata::ObjectId>()) as u64,
    )?;
    let mut lineage = Vec::with_capacity(path[1..].split('/').count() + 1);
    let uid = rustix::process::geteuid().as_raw();
    let mut fd = op.run(|| fs::open("/", PIN | OFlags::DIRECTORY, Mode::empty()).map_err(error))?;
    let mut before = metadata::inspect(&fd, op)?;
    metadata::directory(&before, uid, false)?;
    lineage.push(before.id);
    for part in path[1..].split('/') {
        op.entry()?;
        // Pin each component: never traverse an unchecked automount/remote FS.
        // Explicit root ancestry may cross a local mount (e.g. separate /home).
        fd = op.run(|| {
            fs::openat2(&fd, part, PIN | OFlags::DIRECTORY, Mode::empty(), NO_LINKS).map_err(error)
        })?;
        before = metadata::inspect(&fd, op)?;
        metadata::directory(&before, uid, false)?;
        excluded.check(before.id)?;
        lineage.push(before.id);
    }
    metadata::directory(&before, uid, true)?;
    Ok((fd, before, lineage))
}

fn validate_root(path: &str) -> Result<(), Code> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.contains('\0')
        || path[1..].split('/').any(|p| matches!(p, "" | "." | ".."))
        || path[1..].split('/').count() > 256
        || ["/proc", "/sys", "/dev"]
            .iter()
            .any(|p| path == *p || path.strip_prefix(p).is_some_and(|s| s.starts_with('/')))
    {
        Err(Code::ScopeDenied)
    } else {
        Ok(())
    }
}

pub(crate) struct PinnedFile<'root, 'ctx> {
    root: &'root ConfinedRoot<'ctx>,
    fd: OwnedFd,
    before: Snapshot,
}
impl<'root, 'ctx> PinnedFile<'root, 'ctx> {
    pub fn reopen(
        &self,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<ReadableFile<'root, 'ctx>, Code> {
        let mut op = self.root.operation(clock, cancel)?;
        let current = metadata::inspect(&self.fd, &mut op)?;
        metadata::unchanged(&self.before, &current)?;
        metadata::regular(
            &current,
            self.root.before.stat.stx_mnt_id,
            &self.root.excluded,
        )?;
        let fd = reopen::readable(&self.fd, &mut op)?;
        let after = metadata::inspect(&fd, &mut op)?;
        metadata::unchanged(&self.before, &after)?;
        metadata::regular(
            &after,
            self.root.before.stat.stx_mnt_id,
            &self.root.excluded,
        )?;
        Ok(ReadableFile {
            root: self.root,
            fd,
            before: after,
        })
    }
}
pub(crate) struct ReadableFile<'root, 'ctx> {
    root: &'root ConfinedRoot<'ctx>,
    fd: OwnedFd,
    before: Snapshot,
}
#[derive(Clone, Copy)]
pub(crate) struct FileFacts {
    pub size: u64,
    pub mode: u64,
    pub uid: u64,
    pub gid: u64,
    pub mtime_seconds: i64,
    pub ctime_seconds: i64,
}
impl ReadableFile<'_, '_> {
    pub(super) fn begin<'a>(
        &'a self,
        clock: &'a mut dyn Clock,
        cancel: &'a dyn Cancellation,
    ) -> Result<Operation<'a, 'a>, Code> {
        self.root.operation(clock, cancel)
    }
    pub(super) fn size(&self) -> u64 {
        self.before.stat.stx_size
    }
    pub(super) fn maximum_file_bytes(&self) -> u64 {
        self.root.context.limits().max_file_bytes
    }
    pub(super) fn verify(&self, op: &mut Operation<'_, '_>) -> Result<(), Code> {
        let current = metadata::inspect(&self.fd, op)?;
        metadata::unchanged(&self.before, &current)?;
        metadata::regular(
            &current,
            self.root.before.stat.stx_mnt_id,
            &self.root.excluded,
        )
    }
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub(crate) fn facts(&self) -> FileFacts {
        let value = &self.before.stat;
        FileFacts {
            size: value.stx_size,
            mode: u64::from(value.stx_mode),
            uid: u64::from(value.stx_uid),
            gid: u64::from(value.stx_gid),
            mtime_seconds: value.stx_mtime.tv_sec,
            ctime_seconds: value.stx_ctime.tv_sec,
        }
    }
    pub fn check_unchanged(
        &self,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<(), Code> {
        let mut op = self.root.operation(clock, cancel)?;
        self.verify(&mut op)
    }
}

#[cfg(test)]
mod tests;
