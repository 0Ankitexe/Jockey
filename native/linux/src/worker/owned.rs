//! Signals use the retained kernel process handle, never a supplied/recycled PID.
//! Capture accepts an owned Child, not a process name or JSON identifier.
use jocky_shared::collection::Code;
use rustix::{
    fd::OwnedFd,
    process::{self, Pid, PidfdFlags, Signal},
};
use std::process::{Child, ExitStatus};

#[derive(Debug)]
pub(crate) struct CaptureFailure {
    pub code: Code,
    pub child: Child,
}
pub(crate) struct OwnedWorker {
    child: Child,
    handle: Option<OwnedFd>,
    status: Option<ExitStatus>,
    signalled: bool,
}
impl OwnedWorker {
    pub fn capture(mut child: Child) -> Result<Self, CaptureFailure> {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => {
                return Err(CaptureFailure {
                    code: Code::WorkerFailed,
                    child,
                });
            }
        };
        if status.is_some() {
            return Ok(Self {
                child,
                handle: None,
                status,
                signalled: false,
            });
        }
        let Some(pid) = Pid::from_raw(child.id() as i32) else {
            return Err(CaptureFailure {
                code: Code::WorkerProtocol,
                child,
            });
        };
        let handle = match process::pidfd_open(pid, PidfdFlags::empty()) {
            Ok(handle) => handle,
            Err(error) => {
                if error == rustix::io::Errno::SRCH
                    && let Ok(Some(status)) = child.try_wait()
                {
                    return Ok(Self {
                        child,
                        handle: None,
                        status: Some(status),
                        signalled: false,
                    });
                }
                return Err(CaptureFailure {
                    code: capture_error(error),
                    child,
                });
            }
        };
        Ok(Self {
            child,
            handle: Some(handle),
            status: None,
            signalled: false,
        })
    }
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn poll(&mut self) -> Result<Option<ExitStatus>, Code> {
        if self.status.is_none() {
            self.status = self.child.try_wait().map_err(|_| Code::WorkerFailed)?;
        }
        if self.status.is_some() {
            self.handle = None;
        }
        Ok(self.status)
    }
    pub fn kill_owned(&mut self) -> Result<(), Code> {
        if self.poll()?.is_some() || self.signalled {
            return Err(Code::WorkerProtocol);
        }
        let handle = self.handle.as_ref().ok_or(Code::WorkerProtocol)?;
        match process::pidfd_send_signal(handle, Signal::KILL) {
            Ok(()) => {
                self.signalled = true;
                Ok(())
            }
            Err(rustix::io::Errno::SRCH) if self.poll()?.is_some() => Ok(()),
            Err(_) => Err(Code::WorkerFailed),
        }
    }
}

fn capture_error(error: rustix::io::Errno) -> Code {
    use rustix::io::Errno;
    match error {
        Errno::NOSYS | Errno::NOTSUP | Errno::INVAL => Code::Unsupported,
        Errno::ACCESS | Errno::PERM => Code::PermissionDenied,
        Errno::NOMEM | Errno::MFILE | Errno::NFILE => Code::ResourceLimit,
        _ => Code::WorkerFailed,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn capture_failures_distinguish_unavailable_resources_and_permission() {
        use super::*;
        for (errno, expected) in [
            (rustix::io::Errno::NOSYS, Code::Unsupported),
            (rustix::io::Errno::PERM, Code::PermissionDenied),
            (rustix::io::Errno::MFILE, Code::ResourceLimit),
            (rustix::io::Errno::SRCH, Code::WorkerFailed),
        ] {
            assert_eq!(capture_error(errno), expected);
        }
    }
}
