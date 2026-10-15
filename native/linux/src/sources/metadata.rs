use super::{error, operation::Operation};
use jocky_shared::collection::Code;
use rustix::{
    fd::AsFd,
    fs::{self, AtFlags, FileType, Statx, StatxAttributes, StatxFlags},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectId {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Default)]
pub(crate) struct Exclusions(Vec<ObjectId>);
impl Exclusions {
    pub fn new(ids: &[ObjectId]) -> Result<Self, Code> {
        if ids.len() > 32 {
            return Err(Code::ResourceLimit);
        }
        Ok(Self(ids.to_vec()))
    }
    pub(super) fn check(&self, id: ObjectId) -> Result<(), Code> {
        if self.0.contains(&id) {
            Err(Code::AliasDenied)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    pub stat: Statx,
    pub id: ObjectId,
}
const REQUIRED: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::NLINK)
    .union(StatxFlags::UID)
    .union(StatxFlags::GID)
    .union(StatxFlags::MTIME)
    .union(StatxFlags::CTIME)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::MNT_ID);

pub(super) fn local_kind(kind: u64) -> Result<(), Code> {
    // Linux UAPI magic; ext2/3/4 share a value, not an ext4-version assertion.
    if matches!(kind, 0xef53 | 0x58465342 | 0x9123683e) {
        Ok(())
    } else {
        Err(Code::Unsupported)
    }
}
pub(super) fn inspect(fd: impl AsFd, op: &mut Operation<'_, '_>) -> Result<Snapshot, Code> {
    op.run(|| local_kind(fs::fstatfs(&fd).map_err(error)?.f_type as u64))?;
    let stat = op.run(|| {
        fs::statx(
            &fd,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            REQUIRED,
        )
        .map_err(error)
    })?;
    snapshot(stat)
}

/// Output-only metadata inspection during the reserved finalization interval.
/// The caller must bracket this with sealed-context monotonic deadline checks;
/// it does not read an evidence source or create an operation permit.
pub(super) fn inspect_output(fd: impl AsFd) -> Result<Snapshot, Code> {
    local_kind(fs::fstatfs(&fd).map_err(error)?.f_type as u64)?;
    let stat = fs::statx(
        &fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        REQUIRED,
    )
    .map_err(error)?;
    snapshot(stat)
}
fn snapshot(stat: Statx) -> Result<Snapshot, Code> {
    if stat.stx_mask & REQUIRED.bits() != REQUIRED.bits()
        || !stat
            .stx_attributes_mask
            .contains(StatxAttributes::AUTOMOUNT | StatxAttributes::MOUNT_ROOT)
        || stat.stx_attributes.contains(StatxAttributes::AUTOMOUNT)
    {
        return Err(Code::Unsupported);
    }
    Ok(Snapshot {
        id: ObjectId {
            device: fs::makedev(stat.stx_dev_major, stat.stx_dev_minor),
            inode: stat.stx_ino,
        },
        stat,
    })
}
pub(super) fn directory(value: &Snapshot, uid: u32, root: bool) -> Result<(), Code> {
    if FileType::from_raw_mode(u32::from(value.stat.stx_mode)) != FileType::Directory {
        return Err(Code::AliasDenied);
    }
    if value.stat.stx_nlink == 0 {
        return Err(Code::SourceDisappeared);
    }
    if value.stat.stx_uid != uid && value.stat.stx_uid != 0 || value.stat.stx_mode & 0o022 != 0 {
        return Err(Code::PermissionDenied);
    }
    if root
        && value
            .stat
            .stx_attributes
            .contains(StatxAttributes::MOUNT_ROOT)
    {
        return Err(Code::ScopeDenied); // Whole mounted volume is not a scoped root.
    }
    Ok(())
}
pub(super) fn regular(value: &Snapshot, mount: u64, excluded: &Exclusions) -> Result<(), Code> {
    excluded.check(value.id)?;
    if value.stat.stx_mnt_id != mount || value.stat.stx_nlink > 1 {
        return Err(Code::AliasDenied);
    }
    if value.stat.stx_nlink == 0 {
        return Err(Code::SourceDisappeared);
    }
    match FileType::from_raw_mode(u32::from(value.stat.stx_mode)) {
        FileType::RegularFile => Ok(()),
        FileType::Symlink => Err(Code::AliasDenied),
        _ => Err(Code::Unsupported),
    }
}
pub(super) fn unchanged(a: &Snapshot, b: &Snapshot) -> Result<(), Code> {
    let a_stat = &a.stat;
    let b_stat = &b.stat;
    if a.id == b.id
        && a_stat.stx_mnt_id == b_stat.stx_mnt_id
        && a_stat.stx_size == b_stat.stx_size
        && a_stat.stx_mode == b_stat.stx_mode
        && a_stat.stx_nlink == b_stat.stx_nlink
        && a_stat.stx_uid == b_stat.stx_uid
        && a_stat.stx_gid == b_stat.stx_gid
        && a_stat.stx_mtime.tv_sec == b_stat.stx_mtime.tv_sec
        && a_stat.stx_mtime.tv_nsec == b_stat.stx_mtime.tv_nsec
        && a_stat.stx_ctime.tv_sec == b_stat.stx_ctime.tv_sec
        && a_stat.stx_ctime.tv_nsec == b_stat.stx_ctime.tv_nsec
    {
        Ok(())
    } else {
        Err(Code::SourceChanged)
    }
}

/// Publication itself changes an output directory's timestamps and link count.
/// Keep the retained object/permission identity stable without mistaking our
/// own exclusive staging entry for a source-directory replacement.
pub(super) fn same_output_directory(a: &Snapshot, b: &Snapshot) -> Result<(), Code> {
    if a.id == b.id
        && a.stat.stx_mnt_id == b.stat.stx_mnt_id
        && a.stat.stx_uid == b.stat.stx_uid
        && a.stat.stx_gid == b.stat.stx_gid
        && a.stat.stx_mode == b.stat.stx_mode
    {
        Ok(())
    } else {
        Err(Code::SourceChanged)
    }
}
