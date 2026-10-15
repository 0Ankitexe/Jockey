//! Closed proc/sys query set over an already inherited mount handle. This
//! private adapter cannot discover a mount, admit an endpoint or follow links.
use super::{
    error,
    operation::Operation,
    reads::{Reader, stream::bounded},
};
use jocky_forensic::collection::{
    ValidatedCollectionContext, budget::Counter, cancellation::Cancellation, clock::Clock,
    context::OperationTarget,
};
use jocky_shared::collection::{Code, identity::Uuid, inputs::SourceKind};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags, Statx, StatxAttributes, StatxFlags},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountKind {
    Proc,
    Sys,
}

pub(crate) mod links;

/// These variants are the entire text-content surface. No arbitrary path,
/// process memory/environment/credentials or namespace switching is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Query {
    KernelVersion,
    KernelRelease,
    KernelHostname,
    BootId,
    ProcessBootId,
    ConnectionBootId,
    KernelUptime,
    ProcessStat(u32),
    OwnerStat(u32),
    ProcessStatus(u32),
    ProcessCmdline(u32),
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Modules,
    ModuleVersion(String),
    ModuleSourceVersion(String),
}
impl Query {
    fn byte_limit(&self) -> u64 {
        match self {
            Self::ProcessStat(_) | Self::OwnerStat(_) => 4_096,
            Self::ProcessBootId | Self::ConnectionBootId | Self::BootId => 64,
            Self::ProcessStatus(_) => 8_192,
            _ => 65_536,
        }
    }

    fn source(&self) -> (MountKind, SourceKind) {
        match self {
            Self::KernelVersion
            | Self::KernelRelease
            | Self::KernelHostname
            | Self::BootId
            | Self::KernelUptime => (MountKind::Proc, SourceKind::KernelProfile),
            Self::ProcessBootId
            | Self::ProcessStat(_)
            | Self::ProcessStatus(_)
            | Self::ProcessCmdline(_) => (MountKind::Proc, SourceKind::ProcProcesses),
            Self::ConnectionBootId | Self::OwnerStat(_) => (MountKind::Proc, SourceKind::ProcNet),
            Self::Tcp | Self::Tcp6 | Self::Udp | Self::Udp6 => {
                (MountKind::Proc, SourceKind::ProcNet)
            }
            Self::Modules => (MountKind::Proc, SourceKind::SysModules),
            Self::ModuleVersion(_) | Self::ModuleSourceVersion(_) => {
                (MountKind::Sys, SourceKind::SysModules)
            }
        }
    }
    fn path(&self) -> Result<String, Code> {
        let name = match self {
            Self::KernelVersion => "version".into(),
            Self::KernelRelease => "sys/kernel/osrelease".into(),
            Self::KernelHostname => "sys/kernel/hostname".into(),
            Self::BootId => "sys/kernel/random/boot_id".into(),
            Self::ProcessBootId | Self::ConnectionBootId => "sys/kernel/random/boot_id".into(),
            Self::KernelUptime => "uptime".into(),
            Self::ProcessStat(pid) => format!("{}/stat", valid_pid(*pid)?),
            Self::OwnerStat(pid) => format!("{}/stat", valid_pid(*pid)?),
            Self::ProcessStatus(pid) => format!("{}/status", valid_pid(*pid)?),
            Self::ProcessCmdline(pid) => format!("{}/cmdline", valid_pid(*pid)?),
            Self::Tcp => format!("{}/net/tcp", std::process::id()),
            Self::Tcp6 => format!("{}/net/tcp6", std::process::id()),
            Self::Udp => format!("{}/net/udp", std::process::id()),
            Self::Udp6 => format!("{}/net/udp6", std::process::id()),
            Self::Modules => "modules".into(),
            Self::ModuleVersion(module) => format!("module/{}/version", valid_module(module)?),
            Self::ModuleSourceVersion(module) => {
                format!("module/{}/srcversion", valid_module(module)?)
            }
        };
        Ok(name)
    }
}
fn valid_pid(pid: u32) -> Result<u32, Code> {
    if pid == 0 {
        Err(Code::InvalidInput)
    } else {
        Ok(pid)
    }
}
fn valid_module(name: &str) -> Result<&str, Code> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        Err(Code::InvalidInput)
    } else {
        Ok(name)
    }
}

#[derive(Clone, Copy)]
struct Identity {
    inode: u64,
    device: u64,
    mount: u64,
    mode: u16,
    mount_root: bool,
}
fn inspect(fd: impl AsFd, op: &mut Operation<'_, '_>) -> Result<Identity, Code> {
    const REQUIRED: StatxFlags = StatxFlags::TYPE
        .union(StatxFlags::MODE)
        .union(StatxFlags::INO)
        .union(StatxFlags::MNT_ID);
    let stat: Statx = op.run(|| {
        fs::statx(
            &fd,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            REQUIRED,
        )
        .map_err(error)
    })?;
    if stat.stx_mask & REQUIRED.bits() != REQUIRED.bits() {
        return Err(Code::Unsupported);
    }
    if !stat
        .stx_attributes_mask
        .contains(StatxAttributes::MOUNT_ROOT | StatxAttributes::AUTOMOUNT)
        || stat.stx_attributes.contains(StatxAttributes::AUTOMOUNT)
    {
        return Err(Code::Unsupported);
    }
    Ok(Identity {
        inode: stat.stx_ino,
        device: fs::makedev(stat.stx_dev_major, stat.stx_dev_minor),
        mount: stat.stx_mnt_id,
        mode: stat.stx_mode,
        mount_root: stat.stx_attributes.contains(StatxAttributes::MOUNT_ROOT),
    })
}
fn same(a: Identity, b: Identity) -> Result<(), Code> {
    if a.inode == b.inode
        && a.device == b.device
        && a.mount == b.mount
        && a.mode == b.mode
        && a.mount_root == b.mount_root
    {
        Ok(())
    } else {
        Err(Code::SourceChanged)
    }
}

pub(crate) struct FixedMount<'ctx> {
    context: &'ctx ValidatedCollectionContext,
    source_id: &'ctx Uuid,
    source_kind: SourceKind,
    mount_kind: MountKind,
    fd: OwnedFd,
    before: Identity,
}

impl<'ctx> FixedMount<'ctx> {
    pub(crate) fn fd(&self) -> rustix::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
    /// Open one fixed kernel mount only after logical admission. The absolute
    /// path is selected by code, never by a request, environment or distro ID.
    /// The owned worker still supplies the external bound on blocked syscalls.
    pub fn open(
        context: &'ctx ValidatedCollectionContext,
        source_id: &'ctx Uuid,
        kind: MountKind,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Self, Code> {
        let source_kind = selected_kind(context, source_id, kind)?;
        let permit = context.permit(
            OperationTarget::Source(source_id),
            &clock.read()?,
            cancel.cancelled(),
        )?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        op.entry()?;
        let path = match kind {
            MountKind::Proc => "/proc",
            MountKind::Sys => "/sys",
        };
        let fd = op.run(|| {
            fs::open(
                path,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(error)
        })?;
        drop(op);
        debug_assert!(mount_matches(kind, source_kind));
        Self::inherited(context, source_id, kind, fd, clock, cancel)
    }

    /// The parent must already have transferred and authenticated this handle.
    /// This constructor checks actual mount type after current admission; it
    /// does not accept a path or open a host mount on its own.
    pub fn inherited(
        context: &'ctx ValidatedCollectionContext,
        source_id: &'ctx Uuid,
        kind: MountKind,
        fd: OwnedFd,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Self, Code> {
        let source_kind = selected_kind(context, source_id, kind)?;
        let permit = context.permit(
            OperationTarget::Source(source_id),
            &clock.read()?,
            cancel.cancelled(),
        )?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        op.entry()?;
        let fs_kind = op.run(|| fs::fstatfs(&fd).map_err(error))?.f_type;
        let expected = match kind {
            MountKind::Proc => fs::PROC_SUPER_MAGIC,
            MountKind::Sys => 0x6265_6572, // Linux SYSFS_MAGIC
        };
        if fs_kind != expected {
            return Err(Code::Unsupported);
        }
        let before = inspect(&fd, &mut op)?;
        if FileType::from_raw_mode(u32::from(before.mode)) != FileType::Directory
            || !before.mount_root
        {
            return Err(Code::AliasDenied);
        }
        Ok(Self {
            context,
            source_id,
            source_kind,
            mount_kind: kind,
            fd,
            before,
        })
    }

    pub fn read(
        &self,
        query: Query,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Vec<u8>, Code> {
        if query.source() != (self.mount_kind, self.source_kind) {
            return Err(Code::ScopeDenied);
        }
        let permit = self.context.permit(
            OperationTarget::Source(self.source_id),
            &clock.read()?,
            cancel.cancelled(),
        )?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        // Fixed query strings are <=96 bytes. Charge before allocating them.
        op.permit.charge(Counter::RetainedBytes, 96)?;
        let path = query.path()?;
        op.entry()?;
        same(self.before, inspect(&self.fd, &mut op)?)?;
        let fd = op.run(|| {
            fs::openat2(
                &self.fd,
                path.as_str(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )
            .map_err(error)
        })?;
        let before = inspect(&fd, &mut op)?;
        if before.mount != self.before.mount
            || FileType::from_raw_mode(u32::from(before.mode)) != FileType::RegularFile
        {
            return Err(Code::AliasDenied);
        }
        let mut reader = PseudoReader { fd, before };
        let result = bounded(
            &mut reader,
            self.context.limits().max_item_bytes.min(query.byte_limit()),
            &mut op,
        )?;
        same(self.before, inspect(&self.fd, &mut op)?)?;
        Ok(result)
    }

    /// Enumerate only numeric process entries beneath the already inherited
    /// proc mount. Every observed directory entry consumes the entry budget.
    pub fn list_pids(
        &self,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Vec<u32>, Code> {
        if self.mount_kind != MountKind::Proc
            || !matches!(
                self.source_kind,
                SourceKind::ProcProcesses | SourceKind::ProcNet
            )
        {
            return Err(Code::ScopeDenied);
        }
        let permit = self.context.permit(
            OperationTarget::Source(self.source_id),
            &clock.read()?,
            cancel.cancelled(),
        )?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        same(self.before, inspect(&self.fd, &mut op)?)?;
        let readable = op.run(|| {
            fs::openat2(
                &self.fd,
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
        let mut directory = op.run(|| fs::Dir::read_from(&readable).map_err(error))?;
        let mut pids = Vec::new();
        loop {
            op.check()?;
            let entry = op.run(|| directory.read().transpose().map_err(error))?;
            let Some(entry) = entry else { break };
            op.permit.charge(Counter::Entries, 1)?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name.is_empty() || name.len() > 10 || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(pid) = name.parse::<u32>()
                && pid != 0
            {
                pids.push(pid);
            }
        }
        same(self.before, inspect(&self.fd, &mut op)?)?;
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    /// Enumerate descriptor numbers only for a selected proc-net source.
    /// Link targets are read separately through the metadata-only exception.
    pub fn list_fds(
        &self,
        pid: u32,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Vec<u32>, Code> {
        if self.mount_kind != MountKind::Proc || self.source_kind != SourceKind::ProcNet {
            return Err(Code::ScopeDenied);
        }
        let pid = valid_pid(pid)?;
        let permit = self.context.permit(
            OperationTarget::Source(self.source_id),
            &clock.read()?,
            cancel.cancelled(),
        )?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        same(self.before, inspect(&self.fd, &mut op)?)?;
        let path = format!("{pid}/fd");
        let readable = op.run(|| {
            fs::openat2(
                &self.fd,
                path.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )
            .map_err(error)
        })?;
        let before = inspect(&readable, &mut op)?;
        if before.mount != self.before.mount
            || FileType::from_raw_mode(u32::from(before.mode)) != FileType::Directory
        {
            return Err(Code::AliasDenied);
        }
        let mut directory = op.run(|| fs::Dir::read_from(&readable).map_err(error))?;
        let mut fds = Vec::new();
        loop {
            op.check()?;
            let entry = op.run(|| directory.read().transpose().map_err(error))?;
            let Some(entry) = entry else { break };
            op.permit.charge(Counter::Entries, 1)?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name.is_empty() || name.len() > 10 || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(fd) = name.parse::<u32>()
                && fd <= 1_048_576
            {
                fds.push(fd);
            }
        }
        same(before, inspect(&readable, &mut op)?)?;
        same(self.before, inspect(&self.fd, &mut op)?)?;
        fds.sort_unstable();
        fds.dedup();
        Ok(fds)
    }
}

fn mount_matches(kind: MountKind, source: SourceKind) -> bool {
    matches!(
        (kind, source),
        (
            MountKind::Proc,
            SourceKind::KernelProfile
                | SourceKind::ProcProcesses
                | SourceKind::ProcNet
                | SourceKind::SysModules
        ) | (MountKind::Sys, SourceKind::SysModules)
    )
}

fn selected_kind(
    context: &ValidatedCollectionContext,
    source_id: &Uuid,
    kind: MountKind,
) -> Result<SourceKind, Code> {
    let source = context
        .sources()
        .iter()
        .find(|source| source.definition().id() == source_id)
        .ok_or(Code::ScopeDenied)?
        .definition()
        .kind();
    if mount_matches(kind, source) {
        Ok(source)
    } else {
        Err(Code::ScopeDenied)
    }
}

struct PseudoReader {
    fd: OwnedFd,
    before: Identity,
}
impl Reader for PseudoReader {
    fn verify(&mut self, op: &mut Operation<'_, '_>) -> Result<(), Code> {
        same(self.before, inspect(&self.fd, op)?)
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Code> {
        rustix::io::read(&self.fd, buffer).map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::links::LinkQuery;
    use super::*;
    #[test]
    fn selectors_exclude_arbitrary_paths_and_credential_sources() {
        for (query, expected) in [
            (Query::KernelVersion, "version"),
            (Query::KernelRelease, "sys/kernel/osrelease"),
            (Query::KernelHostname, "sys/kernel/hostname"),
            (Query::BootId, "sys/kernel/random/boot_id"),
            (Query::ProcessStat(42), "42/stat"),
            (Query::ProcessCmdline(42), "42/cmdline"),
            (Query::Tcp6, &format!("{}/net/tcp6", std::process::id())),
            (
                Query::ModuleSourceVersion("safe_module".into()),
                "module/safe_module/srcversion",
            ),
        ] {
            assert_eq!(query.path().unwrap(), expected);
        }
        for module in ["", "../x", "x/y", "x.y", "ü", "a very long module name"] {
            assert!(valid_module(module).is_err());
        }
        assert_eq!(Query::ProcessStat(0).path(), Err(Code::InvalidInput));
    }

    #[test]
    fn per_query_caps_keep_proc_inventory_within_the_worker_partition() {
        assert_eq!(Query::ProcessStat(42).byte_limit(), 4_096);
        assert_eq!(Query::OwnerStat(42).byte_limit(), 4_096);
        assert_eq!(Query::ProcessStatus(42).byte_limit(), 8_192);
        assert_eq!(Query::ProcessBootId.byte_limit(), 64);
        assert_eq!(Query::ConnectionBootId.byte_limit(), 64);
        assert_eq!(Query::Tcp.byte_limit(), 65_536);
        assert_eq!(Query::ProcessStatus(42).byte_limit().min(1_024), 1_024);
    }

    #[test]
    fn fixed_mount_capability_matrix_has_no_implicit_cross_source_access() {
        for source in [
            SourceKind::KernelProfile,
            SourceKind::ProcProcesses,
            SourceKind::ProcNet,
            SourceKind::SysModules,
        ] {
            assert!(mount_matches(MountKind::Proc, source));
        }
        assert!(mount_matches(MountKind::Sys, SourceKind::SysModules));
        for source in [
            SourceKind::KernelProfile,
            SourceKind::ProcProcesses,
            SourceKind::ProcNet,
            SourceKind::SystemdBus,
            SourceKind::JournalFile,
            SourceKind::TextLog,
            SourceKind::StartupDirectory,
        ] {
            assert!(!mount_matches(MountKind::Sys, source));
        }
        for source in [
            SourceKind::SystemdBus,
            SourceKind::JournalFile,
            SourceKind::TextLog,
            SourceKind::StartupDirectory,
        ] {
            assert!(!mount_matches(MountKind::Proc, source));
        }
        assert_eq!(
            Query::BootId.source(),
            (MountKind::Proc, SourceKind::KernelProfile)
        );
        assert_eq!(Query::Tcp.source(), (MountKind::Proc, SourceKind::ProcNet));
        assert_eq!(
            Query::ModuleVersion("safe".into()).source(),
            (MountKind::Sys, SourceKind::SysModules)
        );
    }

    #[test]
    fn link_selectors_are_closed_to_process_metadata_only() {
        assert_eq!(
            LinkQuery::Exe(42).parts(),
            Ok(("42".into(), None, "exe".into()))
        );
        assert_eq!(
            LinkQuery::Fd(42, 7).parts(),
            Ok(("42".into(), Some("fd"), "7".into()))
        );
        assert_eq!(
            LinkQuery::NetNamespace(42).parts(),
            Ok(("42".into(), Some("ns"), "net".into()))
        );
        assert_eq!(LinkQuery::Exe(0).parts(), Err(Code::InvalidInput));
        assert_eq!(
            LinkQuery::Fd(42, 1_048_577).parts(),
            Err(Code::InvalidInput)
        );
        assert_eq!(LinkQuery::Exe(42).source(), SourceKind::ProcProcesses);
        assert_eq!(LinkQuery::Fd(42, 7).source(), SourceKind::ProcNet);
        assert_eq!(LinkQuery::NetNamespace(42).source(), SourceKind::ProcNet);
    }
}
