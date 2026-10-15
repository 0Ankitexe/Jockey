//! Bounded cleanup of an owned publisher child that exits before staging cleanup.
use jocky_shared::collection::{Code, identity::Uuid};
use rustix::{
    fd::BorrowedFd,
    fs::{self, AtFlags, Mode, OFlags, ResolveFlags},
};

/// The parent checks absence before launching the output-only child. A name
/// left by an earlier invocation is never adopted as this invocation's work.
pub(crate) fn abandoned_stage_absent(parent: BorrowedFd<'_>, id: &Uuid) -> Result<bool, Code> {
    let name = format!(".jocky-{}.stage", id.as_str());
    match fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(true),
        Ok(_) => Ok(false),
        Err(_) => Err(Code::PublicationFailed),
    }
}

/// After the owned publisher has been reaped, remove only its private, fixed
/// stage name. Any unexpected object leaves visible residue and fails cleanup.
pub(crate) fn cleanup_abandoned_stage(parent: BorrowedFd<'_>, id: &Uuid) -> Result<(), Code> {
    let name = format!(".jocky-{}.stage", id.as_str());
    let directory = match fs::openat2(
        parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(_) => return Err(Code::CleanupIncomplete),
    };
    let parent_stat = fs::fstat(parent).map_err(|_| Code::CleanupIncomplete)?;
    let directory_stat = fs::fstat(&directory).map_err(|_| Code::CleanupIncomplete)?;
    if directory_stat.st_uid != rustix::process::geteuid().as_raw()
        || directory_stat.st_dev != parent_stat.st_dev
        || directory_stat.st_mode & 0o077 != 0
    {
        return Err(Code::CleanupIncomplete);
    }
    match fs::statat(&directory, "report.json", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Ok(file)
            if file.st_uid == directory_stat.st_uid
                && file.st_dev == directory_stat.st_dev
                && file.st_mode & 0o170000 == 0o100000
                && file.st_mode & 0o077 == 0
                && file.st_nlink == 1
                && file.st_size <= 10_485_760 =>
        {
            fs::unlinkat(&directory, "report.json", AtFlags::empty())
                .map_err(|_| Code::CleanupIncomplete)?;
        }
        _ => return Err(Code::CleanupIncomplete),
    }
    fs::unlinkat(parent, &name, AtFlags::REMOVEDIR).map_err(|_| Code::CleanupIncomplete)?;
    fs::fsync(parent).map_err(|_| Code::CleanupIncomplete)
}
