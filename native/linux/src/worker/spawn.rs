//! Fixed-self worker process creation. This private seam cannot choose an
//! executable from a request, PATH, policy file or environment variable.
use jocky_shared::collection::Code;
use std::{
    io,
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, Stdio},
    time::Duration,
};

pub(crate) struct Spawned {
    pub child: Child,
    pub channel: UnixStream,
}

/// Spawn only the running image via the kernel's own self-executable link.
/// The caller must still authenticate the peer, transfer/validate launch
/// control, apply resource limits and supervise/reap this exact Child before
/// treating it as a collector worker.
pub(crate) fn fixed_self() -> Result<Spawned, Code> {
    let (parent, child) = UnixStream::pair().map_err(map_error)?;
    parent
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(map_error)?;
    parent
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(map_error)?;
    let child_stdout = child.try_clone().map_err(map_error)?;
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("__worker")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::null());
    let child = command.spawn().map_err(map_error)?;
    Ok(Spawned {
        child,
        channel: parent,
    })
}

pub(crate) fn close_write(channel: &UnixStream) -> Result<(), Code> {
    channel.shutdown(Shutdown::Write).map_err(map_error)
}

pub(crate) fn map_error(error: io::Error) -> Code {
    match error.kind() {
        io::ErrorKind::PermissionDenied => Code::PermissionDenied,
        io::ErrorKind::Unsupported | io::ErrorKind::NotFound => Code::Unsupported,
        io::ErrorKind::OutOfMemory => Code::ResourceLimit,
        _ => Code::WorkerFailed,
    }
}
