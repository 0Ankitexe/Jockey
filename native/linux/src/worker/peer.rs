//! Metadata for this invocation's parent/self only, never endpoint inventory.
//! Must be combined with fixed executable/FD/current-authority checks at entry.
use jocky_shared::collection::{Code, launch::ParentIdentity};
use rustix::{
    fd::AsFd,
    fs::{self, Mode, OFlags, ResolveFlags},
    net::{AddressFamily, SocketType, sockopt},
    process,
};
use std::io::Read;

pub(crate) fn own_identity() -> Result<ParentIdentity, Code> {
    let pid = process::getpid().as_raw_nonzero().get() as u32;
    Ok(ParentIdentity {
        pid,
        uid: process::geteuid().as_raw(),
        start_ticks: ticks(pid)?.to_string(),
    })
}

pub(crate) fn require_parent(fd: impl AsFd, claim: &ParentIdentity) -> Result<(), Code> {
    let parent = require_parent_channel(fd)?;
    if parent.as_raw_nonzero().get() as u32 != claim.pid || claim.uid != process::geteuid().as_raw()
    {
        return Err(Code::WorkerProtocol);
    }
    let observed = ticks(claim.pid)?;
    if claim
        .start_ticks
        .parse::<u64>()
        .map_err(|_| Code::WorkerProtocol)?
        != observed
        || process::getppid() != Some(parent)
    {
        return Err(Code::WorkerProtocol);
    }
    Ok(())
}

/// Reject ordinary stdin/stdout and unrelated socket peers before reading a
/// launch packet. The claimed start time is checked separately after decode.
pub(crate) fn require_parent_channel(fd: impl AsFd) -> Result<process::Pid, Code> {
    if sockopt::socket_domain(&fd).map_err(|_| Code::WorkerProtocol)? != AddressFamily::UNIX
        || sockopt::socket_type(&fd).map_err(|_| Code::WorkerProtocol)? != SocketType::STREAM
    {
        return Err(Code::WorkerProtocol);
    }
    let peer = sockopt::socket_peercred(&fd).map_err(|_| Code::WorkerProtocol)?;
    let parent = process::getppid().ok_or(Code::WorkerProtocol)?;
    if peer.pid != parent
        || peer.uid.as_raw() != process::geteuid().as_raw()
        || process::getuid() != process::geteuid()
    {
        return Err(Code::WorkerProtocol);
    }
    Ok(parent)
}

/// The parent checks that this stream is its own privately created socket
/// pair. SO_PEERCRED on socketpair reflects creation credentials, not the
/// subsequently spawned child; child identity is retained by OwnedWorker.
pub(crate) fn require_owned_pair(fd: impl AsFd) -> Result<(), Code> {
    if sockopt::socket_domain(&fd).map_err(|_| Code::WorkerProtocol)? != AddressFamily::UNIX
        || sockopt::socket_type(&fd).map_err(|_| Code::WorkerProtocol)? != SocketType::STREAM
    {
        return Err(Code::WorkerProtocol);
    }
    let peer = sockopt::socket_peercred(&fd).map_err(|_| Code::WorkerProtocol)?;
    if peer.pid != process::getpid()
        || peer.uid.as_raw() != process::geteuid().as_raw()
        || peer.gid.as_raw() != process::getegid().as_raw()
    {
        return Err(Code::WorkerProtocol);
    }
    Ok(())
}
fn ticks(pid: u32) -> Result<u64, Code> {
    // Only the current process or the already kernel-verified actual parent.
    let proc = fs::open(
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Code::Unsupported)?;
    if fs::fstatfs(&proc).map_err(|_| Code::Unsupported)?.f_type != fs::PROC_SUPER_MAGIC {
        return Err(Code::Unsupported);
    }
    let path = format!("{pid}/stat");
    let fd = fs::openat2(
        &proc,
        path.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| Code::WorkerProtocol)?;
    let mut raw = Vec::new();
    std::fs::File::from(fd)
        .take(4097)
        .read_to_end(&mut raw)
        .map_err(|_| Code::WorkerProtocol)?;
    if raw.len() > 4096 {
        return Err(Code::ResourceLimit);
    }
    parse_ticks(&raw, pid)
}
fn parse_ticks(raw: &[u8], pid: u32) -> Result<u64, Code> {
    let text = std::str::from_utf8(raw).map_err(|_| Code::WorkerProtocol)?;
    let (first, rest) = text.split_once(' ').ok_or(Code::WorkerProtocol)?;
    if first.parse::<u32>().ok() != Some(pid) || !rest.starts_with('(') {
        return Err(Code::WorkerProtocol);
    }
    let close = rest.rfind(')').ok_or(Code::WorkerProtocol)?;
    rest[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(Code::WorkerProtocol)?
        .parse()
        .map_err(|_| Code::WorkerProtocol)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bounded_stat_parser_handles_embedded_delimiters_and_rejects_rebinding() {
        use super::*;
        let fields = format!("123 (a ) b\n) S {}42 0", "0 ".repeat(18));
        assert_eq!(parse_ticks(fields.as_bytes(), 123), Ok(42));
        assert_eq!(
            parse_ticks(fields.as_bytes(), 124),
            Err(Code::WorkerProtocol)
        );
        for bad in [
            b"".as_slice(),
            b"123 (missing",
            b"123 unclosed) S 0",
            b"123 (x) S",
            b"bad (x) S",
        ] {
            assert_eq!(parse_ticks(bad, 123), Err(Code::WorkerProtocol));
        }
    }
}
