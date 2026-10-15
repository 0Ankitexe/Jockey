use super::{ConfigPaths, Configuration, FileIdentity, InputFile};
use jocky_shared::collection::Code;
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Stat},
    io::Errno,
};
use std::{
    io::Read,
    time::{Duration, Instant},
};

mod handles;

pub(super) fn error(error: Errno) -> Code {
    match error {
        Errno::ACCESS | Errno::PERM => Code::PermissionDenied,
        Errno::NOENT => Code::NotFound,
        Errno::LOOP | Errno::XDEV => Code::AliasDenied,
        Errno::NOSYS | Errno::NOTSUP | Errno::INVAL => Code::Unsupported,
        Errno::NOMEM | Errno::MFILE | Errno::NFILE => Code::ResourceLimit,
        _ => Code::FacilityUnavailable,
    }
}
fn identity(stat: &Stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    }
}
fn same(a: &Stat, b: &Stat) -> bool {
    identity(a) == identity(b)
        && a.st_size == b.st_size
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}
fn regular(stat: &Stat, authority: bool, maximum: usize, uid: u32) -> Result<(), Code> {
    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink || stat.st_nlink > 1 {
        return Err(Code::AliasDenied);
    }
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(Code::InvalidInput);
    }
    if authority && (stat.st_uid != uid || stat.st_mode & 0o7777 != 0o600) {
        return Err(Code::PermissionDenied);
    }
    let length = usize::try_from(stat.st_size).map_err(|_| Code::InvalidInput)?;
    if length > maximum {
        return Err(Code::ResourceLimit);
    }
    Ok(())
}
struct Deadline(Instant);
impl Deadline {
    fn check(&self) -> Result<(), Code> {
        if self.0.elapsed() >= Duration::from_secs(60) {
            Err(Code::Timeout)
        } else {
            Ok(())
        }
    }
}

fn read_one(
    path: &str,
    authority: bool,
    maximum: usize,
    deadline: &Deadline,
) -> Result<InputFile, Code> {
    deadline.check()?;
    let uid = rustix::process::geteuid().as_raw();
    let pinned = handles::pin(path, authority, uid)?;
    let before = fs::fstat(&pinned).map_err(error)?;
    regular(&before, authority, maximum, uid)?;
    // Keep O_PATH alive throughout reopen/read; this is not a retry by pathname.
    let fd = handles::readable(&pinned)?;
    read_pinned(pinned, fd, before, authority, maximum, uid, deadline)
}
fn read_pinned(
    _pinned: OwnedFd,
    fd: OwnedFd,
    before: Stat,
    authority: bool,
    maximum: usize,
    uid: u32,
    deadline: &Deadline,
) -> Result<InputFile, Code> {
    let current = fs::fstat(&fd).map_err(error)?;
    regular(&current, authority, maximum, uid)?;
    if !same(&before, &current) {
        return Err(Code::SourceChanged);
    }
    let mut file = std::fs::File::from(fd);
    let expected = usize::try_from(before.st_size).map_err(|_| Code::InvalidInput)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected)
        .map_err(|_| Code::ResourceLimit)?;
    let mut buffer = [0u8; 8192];
    while bytes.len() < expected {
        deadline.check()?;
        let size = buffer.len().min(expected - bytes.len());
        let read = file.read(&mut buffer[..size]).map_err(|e| {
            e.raw_os_error()
                .map(Errno::from_raw_os_error)
                .map(error)
                .unwrap_or(Code::FacilityUnavailable)
        })?;
        if read == 0 {
            return Err(Code::SourceChanged);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    deadline.check()?;
    let after = fs::fstat(&file).map_err(error)?;
    if !same(&before, &after) {
        return Err(Code::SourceChanged);
    }
    Ok(InputFile {
        _file: file,
        bytes,
        identity: identity(&after),
    })
}
pub(super) fn read(paths: &ConfigPaths) -> Result<Configuration, Code> {
    let deadline = Deadline(Instant::now());
    let mut files: Vec<InputFile> = Vec::with_capacity(5);
    let mut total = 0usize;
    for (index, path) in paths
        .required
        .iter()
        .chain(paths.indicators.iter())
        .enumerate()
    {
        let maximum = if index == 4 { 524288 } else { 65536 };
        let input = read_one(path, index < 3, maximum, &deadline)?;
        if files.iter().any(|f| f.identity == input.identity) {
            return Err(Code::AliasDenied);
        }
        total = total
            .checked_add(input.bytes.len())
            .filter(|n| *n <= 786432)
            .ok_or(Code::ResourceLimit)?;
        files.push(input);
    }
    let indicators = if files.len() == 5 { files.pop() } else { None };
    let files = files.try_into().map_err(|_| Code::InvalidInput)?;
    Ok(Configuration { files, indicators })
}

/// Read only a named local report. The same pin/reopen/identity checks used for
/// input documents prevent symlink, special-file and pathname replacement reads.
pub(super) fn read_report(path: &str) -> Result<Vec<u8>, Code> {
    super::paths::validate(path)?;
    let input = read_one(path, false, 10_485_760, &Deadline(Instant::now()))?;
    Ok(input.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_input_is_rejected_even_though_the_open_descriptor_is_owned() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let file = tempfile::NamedTempFile::new_in(root).unwrap();
        std::fs::write(file.path(), b"original").unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let pinned = handles::pin(file.path().to_str().unwrap(), true, uid).unwrap();
        let before = fs::fstat(&pinned).unwrap();
        let fd = handles::readable(&pinned).unwrap();
        std::fs::write(file.path(), b"short").unwrap();
        assert!(matches!(
            read_pinned(
                pinned,
                fd,
                before,
                true,
                65536,
                uid,
                &Deadline(Instant::now())
            ),
            Err(Code::SourceChanged)
        ));
    }
    #[test]
    fn metadata_owner_mode_size_and_deadline_checks_fail_closed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        let file = tempfile::NamedTempFile::new_in(root).unwrap();
        let mut stat = fs::fstat(&file).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        regular(&stat, true, 65536, uid).unwrap();
        stat.st_uid = uid.wrapping_add(1);
        assert_eq!(
            regular(&stat, true, 65536, uid),
            Err(Code::PermissionDenied)
        );
        stat.st_uid = uid;
        stat.st_size = 65537;
        assert_eq!(regular(&stat, true, 65536, uid), Err(Code::ResourceLimit));
        stat.st_size = 65536;
        assert!(regular(&stat, true, 65536, uid).is_ok());
        assert_eq!(
            Deadline(Instant::now() - Duration::from_secs(61)).check(),
            Err(Code::Timeout)
        );
    }
}
