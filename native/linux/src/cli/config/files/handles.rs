//! Pin input objects without opening devices/FIFOs; see ADR-0016.
use super::error;
use jocky_shared::collection::Code;
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, FileType, Mode, OFlags, ResolveFlags},
};

const PATH: OFlags = OFlags::PATH.union(OFlags::CLOEXEC).union(OFlags::NOFOLLOW);
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

fn local(fd: &OwnedFd) -> Result<(), Code> {
    // Linux UAPI magic numbers. Ext2/3/4 share a magic: this is no ext4-version claim.
    let kind = fs::fstatfs(fd).map_err(error)?.f_type as u64;
    local_kind(kind)
}
fn local_kind(kind: u64) -> Result<(), Code> {
    if matches!(kind, 0xef53 | 0x58465342 | 0x9123683e) {
        Ok(())
    } else {
        Err(Code::Unsupported)
    }
}
fn directory(fd: &OwnedFd, uid: u32, immediate: bool, authority: bool) -> Result<(), Code> {
    local(fd)?;
    let stat = fs::fstat(fd).map_err(error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(Code::AliasDenied);
    }
    if (stat.st_uid != uid && stat.st_uid != 0)
        || stat.st_mode & 0o022 != 0
        || (immediate && authority && stat.st_uid != uid)
    {
        Err(Code::PermissionDenied)
    } else {
        Ok(())
    }
}
pub(super) fn pin(path: &str, authority: bool, uid: u32) -> Result<OwnedFd, Code> {
    let mut dir = fs::open("/", PATH | OFlags::DIRECTORY, Mode::empty()).map_err(error)?;
    let parts: Vec<_> = path[1..].split('/').collect();
    directory(&dir, uid, parts.len() == 1, authority)?;
    for (index, part) in parts[..parts.len() - 1].iter().enumerate() {
        // One component means an untriggered automount can be rejected before descent.
        dir = fs::openat2(
            &dir,
            *part,
            PATH | OFlags::DIRECTORY,
            Mode::empty(),
            RESOLVE,
        )
        .map_err(error)?;
        directory(&dir, uid, index == parts.len() - 2, authority)?;
    }
    let pinned = fs::openat2(
        &dir,
        parts[parts.len() - 1],
        PATH,
        Mode::empty(),
        RESOLVE | ResolveFlags::NO_XDEV,
    )
    .map_err(error)?;
    local(&pinned)?;
    Ok(pinned)
}
pub(super) fn readable(pinned: &OwnedFd) -> Result<OwnedFd, Code> {
    // No user path, target PID, enumeration or readlink. Only this process's owned FD.
    let proc = fs::open("/proc", PATH | OFlags::DIRECTORY, Mode::empty()).map_err(error)?;
    if fs::fstatfs(&proc).map_err(error)?.f_type != fs::PROC_SUPER_MAGIC {
        return Err(Code::Unsupported);
    }
    let own = format!("{}/fd", rustix::process::getpid().as_raw_nonzero());
    let directory = fs::openat2(
        &proc,
        own.as_str(),
        PATH | OFlags::DIRECTORY,
        Mode::empty(),
        RESOLVE | ResolveFlags::NO_XDEV,
    )
    .map_err(error)?;
    let number = pinned.as_raw_fd().to_string();
    // Intentional owned-descriptor reopen, not input symlink resolution.
    let fd = fs::openat(
        &directory,
        number.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(error)?;
    local(&fd)?;
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::unix::fs::symlink};
    #[test]
    fn remote_automount_and_unverified_filesystems_fail_closed() {
        for kind in [0xef53, 0x58465342, 0x9123683e] {
            assert_eq!(local_kind(kind), Ok(()));
        }
        for kind in [
            0x6969, 0xff534d42, 0x65735546, 0x0187, 0x794c7630, 0x01021994, 0,
        ] {
            assert_eq!(local_kind(kind), Err(Code::Unsupported));
        }
    }
    #[test]
    fn renamed_input_never_reopens_a_replacement_symlink_or_fifo() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        for replacement in ["symlink", "fifo"] {
            let dir = tempfile::tempdir_in(&root).unwrap();
            let path = dir.path().join("input");
            std::fs::write(&path, b"original").unwrap();
            let pinned = pin(
                path.to_str().unwrap(),
                false,
                rustix::process::geteuid().as_raw(),
            )
            .unwrap();
            std::fs::rename(&path, dir.path().join("original")).unwrap();
            if replacement == "symlink" {
                symlink("unopened-target", &path).unwrap();
            } else {
                fs::mknodat(fs::CWD, &path, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
            }
            let mut file = std::fs::File::from(readable(&pinned).unwrap());
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"original");
        }
    }
}
