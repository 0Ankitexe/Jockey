use crate::sources::capabilities::OutputDirectory;
use crate::worker::accounting::PublicationQuota;
use jocky_forensic::collection::clock::Clock;
use jocky_shared::collection::worker::CreatedIdentity;
use jocky_shared::collection::{Code, identity::Uuid};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, Mode, OFlags, ResolveFlags},
};
use std::io::Write;

/// One invocation-owned staging directory beside the destination. It is
/// deliberately not removed by Drop: cleanup failures must be reported by the
/// supervisor, and an unexpected crash must leave a discoverable owned name.
pub(crate) struct Stage {
    directory: OwnedFd,
    file: std::fs::File,
    name: String,
    written: u64,
}

impl Stage {
    pub fn create(
        output: &OutputDirectory<'_>,
        collection: &Uuid,
        clock: &mut dyn Clock,
    ) -> Result<Self, Code> {
        output.check_for_publication(clock)?;
        Self::create_in(output.fd(), collection)
    }

    /// Narrow raw-descriptor seam for owned temporary-directory tests only.
    pub(super) fn create_in(parent: BorrowedFd<'_>, collection: &Uuid) -> Result<Self, Code> {
        let name = format!(".jocky-{}.stage", collection.as_str());
        fs::mkdirat(parent, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(map_create)?;
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
            Ok(directory) => directory,
            Err(_) => {
                return Err(
                    if fs::unlinkat(parent, &name, fs::AtFlags::REMOVEDIR).is_ok() {
                        Code::PublicationFailed
                    } else {
                        Code::CleanupIncomplete
                    },
                );
            }
        };
        let file = match fs::openat2(
            &directory,
            "report.json",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(file) => file,
            Err(error) => {
                let code = map_create(error);
                return Err(
                    if fs::unlinkat(parent, &name, fs::AtFlags::REMOVEDIR).is_ok() {
                        code
                    } else {
                        Code::CleanupIncomplete
                    },
                );
            }
        };
        Ok(Self {
            directory,
            file: file.into(),
            name,
            written: 0,
        })
    }

    pub fn write(
        &mut self,
        output: &OutputDirectory<'_>,
        bytes: &[u8],
        quota: &mut PublicationQuota,
        clock: &mut dyn Clock,
    ) -> Result<(), Code> {
        for chunk in bytes.chunks(65_536) {
            output.check_for_publication(clock)?;
            self.write_in(chunk, quota)?;
            output.check_for_publication(clock)?;
        }
        Ok(())
    }

    pub(super) fn write_in(
        &mut self,
        bytes: &[u8],
        quota: &mut PublicationQuota,
    ) -> Result<(), Code> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= 10_485_760)
            .ok_or(Code::ResourceLimit)?;
        quota.charge_staging(bytes.len() as u64)?;
        // A failed or short write may already have reached disk. Consume the
        // full attempted allowance rather than allowing a retry to refund it.
        self.written = next;
        write_chunks(&mut self.file, bytes)
    }

    pub fn sync(&self) -> Result<(), Code> {
        fs::fsync(&self.file).map_err(|_| Code::PublicationFailed)?;
        fs::fsync(&self.directory).map_err(|_| Code::PublicationFailed)
    }

    pub fn sync_directory(&self) -> Result<(), Code> {
        fs::fsync(&self.directory).map_err(|_| Code::PublicationFailed)
    }

    pub fn directory(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    pub fn created_identity(&self) -> Result<CreatedIdentity, Code> {
        let stat = fs::fstat(&self.file).map_err(|_| Code::PublicationFailed)?;
        Ok(CreatedIdentity {
            device_id: stat.st_dev.to_string(),
            inode: stat.st_ino.to_string(),
        })
    }
}

fn map_create(error: rustix::io::Errno) -> Code {
    match error {
        rustix::io::Errno::EXIST => Code::OutputExists,
        rustix::io::Errno::NOSPC | rustix::io::Errno::DQUOT => Code::ResourceLimit,
        rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => Code::PermissionDenied,
        _ => Code::PublicationFailed,
    }
}

fn map_write(error: std::io::Error) -> Code {
    if error.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error()) {
        Code::ResourceLimit
    } else {
        Code::PublicationFailed
    }
}

fn write_chunks(writer: &mut impl Write, bytes: &[u8]) -> Result<(), Code> {
    for chunk in bytes.chunks(65_536) {
        writer.write_all(chunk).map_err(map_write)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};

    struct ShortWriter {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self
                .fail_after
                .is_some_and(|limit| self.bytes.len() >= limit)
            {
                return Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::NOSPC.raw_os_error(),
                ));
            }
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_writes_are_retried_and_enospc_is_not_success() {
        let mut short = ShortWriter {
            bytes: Vec::new(),
            fail_after: None,
        };
        write_chunks(&mut short, b"12345678").unwrap();
        assert_eq!(short.bytes, b"12345678");
        let mut full = ShortWriter {
            bytes: Vec::new(),
            fail_after: Some(3),
        };
        assert_eq!(
            write_chunks(&mut full, b"12345678"),
            Err(Code::ResourceLimit)
        );
        assert_eq!(full.bytes, b"123");
    }
}
