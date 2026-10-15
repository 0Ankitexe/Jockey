//! Metadata-only procfs link exceptions. Returned bytes are never opened as
//! paths, namespace handles, sockets or executable instructions.
use super::{FixedMount, MountKind, error, inspect, same};
use crate::sources::operation::Operation;
use jocky_forensic::collection::{
    budget::Counter, cancellation::Cancellation, clock::Clock, context::OperationTarget,
};
use jocky_shared::collection::{Code, inputs::SourceKind};
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode, OFlags, ResolveFlags},
};

const PIN_DIRECTORY: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
const CONFINED: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkQuery {
    Exe(u32),
    Fd(u32, u32),
    NetNamespace(u32),
}
impl LinkQuery {
    pub(super) fn source(self) -> SourceKind {
        match self {
            Self::Exe(_) => SourceKind::ProcProcesses,
            Self::Fd(_, _) | Self::NetNamespace(_) => SourceKind::ProcNet,
        }
    }
    pub(super) fn parts(self) -> Result<(String, Option<&'static str>, String), Code> {
        let pid = match self {
            Self::Exe(pid) | Self::Fd(pid, _) | Self::NetNamespace(pid) => pid,
        };
        if pid == 0 {
            return Err(Code::InvalidInput);
        }
        let (parent, name) = match self {
            Self::Exe(_) => (None, "exe".into()),
            Self::Fd(_, fd) if fd <= 1_048_576 => (Some("fd"), fd.to_string()),
            Self::Fd(_, _) => return Err(Code::InvalidInput),
            Self::NetNamespace(_) => (Some("ns"), "net".into()),
        };
        Ok((pid.to_string(), parent, name))
    }
}

impl FixedMount<'_> {
    pub fn read_link(
        &self,
        query: LinkQuery,
        clock: &mut dyn Clock,
        cancel: &dyn Cancellation,
    ) -> Result<Vec<u8>, Code> {
        if self.mount_kind != MountKind::Proc || self.source_kind != query.source() {
            return Err(Code::ScopeDenied);
        }
        let permit = self.context.permit(
            OperationTarget::Source(self.source_id),
            &clock.read()?,
            cancel.cancelled(),
        )?;
        let mut op = Operation {
            permit,
            clock,
            cancel,
        };
        op.permit.charge(Counter::RetainedBytes, 64)?;
        let (pid, directory, name) = query.parts()?;
        same(self.before, inspect(&self.fd, &mut op)?)?;
        let process = pin_directory(&self.fd, &pid, &mut op)?;
        let before_process = inspect(&process, &mut op)?;
        require_directory(before_process.mode, before_process.mount, self.before.mount)?;
        let parent = if let Some(directory) = directory {
            pin_directory(&process, directory, &mut op)?
        } else {
            op.run(|| rustix::io::dup(&process).map_err(error))?
        };
        let before_parent = inspect(&parent, &mut op)?;
        require_directory(before_parent.mode, before_parent.mount, self.before.mount)?;
        op.entry()?;
        let value = read_metadata_link(&parent, &name, &mut op)?;
        same(before_parent, inspect(&parent, &mut op)?)?;
        same(before_process, inspect(&process, &mut op)?)?;
        same(self.before, inspect(&self.fd, &mut op)?)?;
        Ok(value)
    }
}

fn pin_directory(fd: &OwnedFd, name: &str, op: &mut Operation<'_, '_>) -> Result<OwnedFd, Code> {
    op.entry()?;
    op.run(|| fs::openat2(fd, name, PIN_DIRECTORY, Mode::empty(), CONFINED).map_err(error))
}

fn require_directory(mode: u16, mount: u64, expected_mount: u64) -> Result<(), Code> {
    if mount != expected_mount || FileType::from_raw_mode(u32::from(mode)) != FileType::Directory {
        Err(Code::AliasDenied)
    } else {
        Ok(())
    }
}

fn read_metadata_link(
    parent: &OwnedFd,
    name: &str,
    op: &mut Operation<'_, '_>,
) -> Result<Vec<u8>, Code> {
    let mut buffer = [0u8; 4097];
    op.check()?;
    let result = fs::readlinkat_raw(parent, name, &mut buffer[..]);
    let length = match result {
        Ok(length) => length,
        Err(err) => {
            op.permit.charge(Counter::Errors, 1)?;
            op.check()?;
            return Err(error(err));
        }
    };
    op.permit.charge(Counter::SourceBytes, length as u64)?;
    op.check()?;
    if length == buffer.len() || op.permit.require_item(length as u64).is_err() {
        op.permit.charge(Counter::Errors, 1)?;
        return Err(Code::ResourceLimit);
    }
    op.permit.charge(Counter::RetainedBytes, length as u64)?;
    Ok(buffer[..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jocky_forensic::collection::{ClockReading, InputSet, admit};
    use jocky_shared::collection::identity::{UtcTime, Uuid};
    use std::os::{fd::OwnedFd, unix::fs::symlink};

    struct Frozen(ClockReading);
    impl Clock for Frozen {
        fn read(&mut self) -> Result<ClockReading, Code> {
            Ok(self.0.clone())
        }
    }
    fn context() -> jocky_forensic::collection::ValidatedCollectionContext {
        let now = ClockReading {
            utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
            monotonic_ms: 0,
        };
        admit(
            InputSet {
                designation: include_bytes!(
                    "../../../../../fixtures/valid/collection/endpoint-designation.json"
                ),
                authorisation: Some(include_bytes!(
                    "../../../../../fixtures/valid/collection/authorisation.json"
                )),
                policy: include_bytes!("../../../../../fixtures/valid/collection/policy.json"),
                request: include_bytes!("../../../../../fixtures/valid/collection/request.json"),
                indicators: None,
            },
            now,
        )
        .unwrap()
    }
    fn limited_context(item_bytes: u64) -> jocky_forensic::collection::ValidatedCollectionContext {
        let mut request: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../../fixtures/valid/collection/request.json"
        ))
        .unwrap();
        request["limits"]["max_item_bytes"] = item_bytes.into();
        let request = serde_json::to_vec(&request).unwrap();
        admit(
            InputSet {
                designation: include_bytes!(
                    "../../../../../fixtures/valid/collection/endpoint-designation.json"
                ),
                authorisation: Some(include_bytes!(
                    "../../../../../fixtures/valid/collection/authorisation.json"
                )),
                policy: include_bytes!("../../../../../fixtures/valid/collection/policy.json"),
                request: &request,
                indicators: None,
            },
            ClockReading {
                utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
                monotonic_ms: 0,
            },
        )
        .unwrap()
    }
    fn source() -> Uuid {
        Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap()
    }
    fn owned() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("v5-link-test-")
            .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
            .unwrap()
    }
    #[test]
    fn metadata_link_reads_only_the_link_text_and_charges_observed_bytes() {
        let dir = owned();
        symlink("/not-an-opened-evidence-source", dir.path().join("link")).unwrap();
        let fd = OwnedFd::from(std::fs::File::open(dir.path()).unwrap());
        let ctx = context();
        let id = source();
        let mut clock = Frozen(ctx.invocation_start().clone());
        let permit = ctx
            .permit(OperationTarget::Source(&id), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        let bytes = read_metadata_link(&fd, "link", &mut op).unwrap();
        assert_eq!(bytes, b"/not-an-opened-evidence-source");
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(bytes.len() as u64));
        assert_eq!(ctx.charged(Counter::Errors), Ok(0));
    }
    #[test]
    fn non_link_and_cancellation_fail_without_evidence_bytes() {
        let dir = owned();
        std::fs::write(dir.path().join("ordinary"), b"do not read content").unwrap();
        let fd = OwnedFd::from(std::fs::File::open(dir.path()).unwrap());
        let ctx = context();
        let id = source();
        let mut clock = Frozen(ctx.invocation_start().clone());
        let permit = ctx
            .permit(OperationTarget::Source(&id), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        assert_eq!(
            read_metadata_link(&fd, "ordinary", &mut op),
            Err(Code::Unsupported)
        );
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(0));
        assert_eq!(ctx.charged(Counter::Errors), Ok(1));

        let ctx = context();
        let mut clock = Frozen(ctx.invocation_start().clone());
        let permit = ctx
            .permit(OperationTarget::Source(&id), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &true,
        };
        assert_eq!(
            read_metadata_link(&fd, "ordinary", &mut op),
            Err(Code::Cancelled)
        );
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(0));
    }

    #[test]
    fn item_limit_excess_is_charged_but_never_returned_as_prefix() {
        let dir = owned();
        symlink("abc", dir.path().join("link")).unwrap();
        let fd = OwnedFd::from(std::fs::File::open(dir.path()).unwrap());
        let ctx = limited_context(2);
        let id = source();
        let mut clock = Frozen(ctx.invocation_start().clone());
        let permit = ctx
            .permit(OperationTarget::Source(&id), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        assert_eq!(
            read_metadata_link(&fd, "link", &mut op),
            Err(Code::ResourceLimit)
        );
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(3));
        assert_eq!(ctx.charged(Counter::Errors), Ok(1));
    }
}
