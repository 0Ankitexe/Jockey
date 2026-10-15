//! Bounded one-shot descriptor transfer on the already authenticated Unix
//! control channel. Receiving an FD is not permission to use it: the caller
//! must verify its object identity, type and admitted source relationship.
use jocky_forensic::collection::ValidatedCollectionContext;
use jocky_shared::collection::{
    Code,
    inputs::SourceRef,
    launch::{DescriptorBinding, HandleKind, ObjectIdentity},
    worker::Job,
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, AtFlags, FileType, StatxAttributes, StatxFlags},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    },
};
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
};

const TOKEN: u8 = 0xa5;
const MAX_HANDLES: usize = 128;

/// Bind each transferred object's declared purpose to the committed case
/// context. Object identity checks alone cannot make an unselected source an
/// authorised input. Optional fixed alternatives may be absent, but a present
/// binding must name the exact selected source kind.
pub(crate) fn verify_scope(
    context: &ValidatedCollectionContext,
    job: Job,
    bindings: &[DescriptorBinding],
) -> Result<(), Code> {
    for binding in bindings {
        let selected = match binding.kind {
            HandleKind::OutputDirectory => job == Job::Publish && binding.subject_id.is_none(),
            HandleKind::OrdinaryRoot if job == Job::Collect => {
                binding.subject_id.as_ref().is_some_and(|id| {
                    context
                        .paths()
                        .iter()
                        .any(|path| &path.root().root_id == id)
                        || context.sources().iter().any(|source| {
                            matches!(
                                source.definition(),
                                SourceRef::JournalFile { path, .. }
                                    | SourceRef::TextLog { path, .. }
                                    | SourceRef::StartupDirectory { path, .. }
                                    if &path.root_id == id || source.definition().id() == id
                            )
                        })
                })
            }
            other if job == Job::Collect => binding.subject_id.as_ref().is_some_and(|id| {
                context.sources().iter().any(|source| {
                    source.definition().id() == id
                        && (matches!(
                            (other, source.definition()),
                            (
                                HandleKind::ProcMount,
                                SourceRef::KernelProfile { .. }
                                    | SourceRef::ProcProcesses { .. }
                                    | SourceRef::ProcNet { .. }
                                    | SourceRef::SysModules { .. }
                            ) | (HandleKind::SysMount, SourceRef::SysModules { .. })
                                | (
                                    HandleKind::OsRelease | HandleKind::OsReleaseFallback,
                                    SourceRef::KernelProfile { .. }
                                )
                        ) || matches!(
                            (other, source.definition()),
                            (HandleKind::SystemdSocket, SourceRef::SystemdBus { unix_path, .. })
                                if unix_path == "/run/dbus/system_bus_socket"
                        ))
                })
            }),
            _ => false,
        };
        if !selected {
            return Err(Code::ScopeDenied);
        }
    }
    Ok(())
}

fn claimed_number(value: &str) -> Result<u64, Code> {
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Code::WorkerProtocol);
    }
    value.parse().map_err(|_| Code::WorkerProtocol)
}

fn claimed_object(value: &ObjectIdentity) -> Result<(u64, u64, Option<u64>), Code> {
    Ok((
        claimed_number(&value.device_id)?,
        claimed_number(&value.inode)?,
        value
            .mount_id
            .as_ref()
            .map(|id| claimed_number(id))
            .transpose()?,
    ))
}

/// Check received kernel objects against the launch bindings before any use.
/// The sender and receiver must use the same descriptor order; the launch FD
/// numbers identify slots, never substitute for a received kernel handle.
pub(crate) fn verify_objects(
    bindings: &[DescriptorBinding],
    handles: &[OwnedFd],
    exclusions: &[ObjectIdentity],
) -> Result<(), Code> {
    if bindings.len() != handles.len() || bindings.len() > MAX_HANDLES {
        return Err(Code::WorkerProtocol);
    }
    let mut seen = std::collections::BTreeSet::new();
    let excluded = exclusions
        .iter()
        .map(claimed_object)
        .collect::<Result<Vec<_>, _>>()?;
    const REQUIRED: StatxFlags = StatxFlags::TYPE
        .union(StatxFlags::MODE)
        .union(StatxFlags::INO)
        .union(StatxFlags::MNT_ID)
        .union(StatxFlags::UID)
        .union(StatxFlags::NLINK);
    for (binding, handle) in bindings.iter().zip(handles) {
        let stat = fs::statx(
            handle,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            REQUIRED,
        )
        .map_err(|_| Code::WorkerProtocol)?;
        if stat.stx_mask & REQUIRED.bits() != REQUIRED.bits()
            || !stat
                .stx_attributes_mask
                .contains(StatxAttributes::AUTOMOUNT | StatxAttributes::MOUNT_ROOT)
            || stat.stx_attributes.contains(StatxAttributes::AUTOMOUNT)
        {
            return Err(Code::Unsupported);
        }
        let actual = (
            fs::makedev(stat.stx_dev_major, stat.stx_dev_minor),
            stat.stx_ino,
            Some(stat.stx_mnt_id),
        );
        let claimed = claimed_object(&binding.object)?;
        if actual.0 != claimed.0
            || actual.1 != claimed.1
            || binding.kind != HandleKind::SystemdSocket && claimed.2.is_none()
            || claimed.2.is_some_and(|mount| actual.2 != Some(mount))
            || !seen.insert((actual.0, actual.1))
            || excluded
                .iter()
                .any(|item| item.0 == actual.0 && item.1 == actual.1)
        {
            return Err(Code::WorkerProtocol);
        }
        let kind = FileType::from_raw_mode(u32::from(stat.stx_mode));
        let filesystem = fs::fstatfs(handle)
            .map_err(|_| Code::WorkerProtocol)?
            .f_type as u64;
        let mount_root = stat.stx_attributes.contains(StatxAttributes::MOUNT_ROOT);
        match binding.kind {
            HandleKind::OrdinaryRoot | HandleKind::OutputDirectory => {
                if !matches!(filesystem, 0xef53 | 0x5846_5342 | 0x9123_683e) {
                    return Err(Code::Unsupported);
                }
                if kind != FileType::Directory || mount_root || stat.stx_mode & 0o022 != 0 {
                    return Err(Code::WorkerProtocol);
                }
                if stat.stx_uid != 0 && stat.stx_uid != rustix::process::geteuid().as_raw() {
                    return Err(Code::PermissionDenied);
                }
                if binding.kind == HandleKind::OutputDirectory
                    && stat.stx_uid != rustix::process::geteuid().as_raw()
                {
                    return Err(Code::PermissionDenied);
                }
            }
            HandleKind::ProcMount | HandleKind::SysMount => {
                let expected = if binding.kind == HandleKind::ProcMount {
                    fs::PROC_SUPER_MAGIC as u64
                } else {
                    0x6265_6572
                };
                if filesystem != expected
                    || kind != FileType::Directory
                    || !mount_root
                    || stat.stx_uid != 0
                    || stat.stx_mode & 0o022 != 0
                {
                    return Err(Code::WorkerProtocol);
                }
            }
            HandleKind::OsRelease | HandleKind::OsReleaseFallback => {
                if !matches!(filesystem, 0xef53 | 0x5846_5342 | 0x9123_683e) {
                    return Err(Code::Unsupported);
                }
                if kind != FileType::RegularFile
                    || stat.stx_nlink != 1
                    || stat.stx_mode & 0o022 != 0
                    || stat.stx_uid != 0 && stat.stx_uid != rustix::process::geteuid().as_raw()
                {
                    return Err(Code::WorkerProtocol);
                }
            }
            HandleKind::SystemdSocket => {
                if kind != FileType::Socket {
                    return Err(Code::WorkerProtocol);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn send(channel: impl AsFd, descriptors: &[BorrowedFd<'_>]) -> Result<(), Code> {
    if descriptors.is_empty() || descriptors.len() > MAX_HANDLES {
        return Err(Code::WorkerProtocol);
    }
    let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_HANDLES))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(Code::ResourceLimit);
    }
    let sent = sendmsg(
        channel,
        &[IoSlice::new(&[TOKEN])],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|_| Code::WorkerFailed)?;
    if sent == 1 {
        Ok(())
    } else {
        Err(Code::WorkerProtocol)
    }
}

pub(crate) fn receive(channel: impl AsFd, expected: usize) -> Result<Vec<OwnedFd>, Code> {
    if expected == 0 || expected > MAX_HANDLES {
        return Err(Code::WorkerProtocol);
    }
    let mut byte = [0u8; 1];
    let mut buffers = [IoSliceMut::new(&mut byte)];
    let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_HANDLES))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        channel,
        &mut buffers,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| Code::WorkerFailed)?;
    if received.bytes != 1
        || received
            .flags
            .contains(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || byte[0] != TOKEN
    {
        return Err(Code::WorkerProtocol);
    }
    let mut handles = Vec::new();
    handles
        .try_reserve_exact(expected)
        .map_err(|_| Code::ResourceLimit)?;
    for message in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(fds) = message else {
            return Err(Code::WorkerProtocol);
        };
        for fd in fds {
            if handles.len() == expected {
                return Err(Code::WorkerProtocol);
            }
            handles.push(fd);
        }
    }
    if handles.len() == expected {
        Ok(handles)
    } else {
        Err(Code::WorkerProtocol)
    }
}
