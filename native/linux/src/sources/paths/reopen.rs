//! ADR-0016's narrow owned-FD reopen; never follows an evidence pathname/link.
use super::{CONFINED, PIN};
use crate::sources::{error, operation::Operation};
use jocky_shared::collection::Code;
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, Mode, OFlags},
};

pub(super) fn readable(pinned: &OwnedFd, op: &mut Operation<'_, '_>) -> Result<OwnedFd, Code> {
    let proc =
        op.run(|| fs::open("/proc", PIN | OFlags::DIRECTORY, Mode::empty()).map_err(error))?;
    let kind = op.run(|| fs::fstatfs(&proc).map_err(error))?.f_type;
    if kind != fs::PROC_SUPER_MAGIC {
        return Err(Code::Unsupported);
    }
    let own = format!("{}/fd", rustix::process::getpid().as_raw_nonzero());
    let directory = op.run(|| {
        fs::openat2(
            &proc,
            own.as_str(),
            PIN | OFlags::DIRECTORY,
            Mode::empty(),
            CONFINED,
        )
        .map_err(error)
    })?;
    let number = pinned.as_raw_fd().to_string();
    op.run(|| {
        fs::openat(
            &directory,
            number.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(error)
    })
}
