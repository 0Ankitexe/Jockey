//! Bounded copy of an explicitly selected journal file into worker-private staging.
//! The caller must supply an admitted stable source read and an owned staging file.
use jocky_shared::collection::Code;
use std::io::{Read, Write};

pub(crate) const JOURNAL_CAP: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_ns: i128,
}

pub(crate) fn copy_explicit(
    mut source: impl Read,
    mut stage: impl Write,
    before: Identity,
    after: impl FnOnce() -> Result<Identity, Code>,
    mut charge_source: impl FnMut(u64) -> Result<(), Code>,
    mut charge_stage: impl FnMut(u64) -> Result<(), Code>,
) -> Result<u64, Code> {
    if before.size > JOURNAL_CAP {
        return Err(Code::ResourceLimit);
    }
    let mut copied = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let n = source
            .read(&mut buffer)
            .map_err(|_| Code::FacilityUnavailable)?;
        charge_source(n as u64)?;
        if n == 0 {
            break;
        }
        copied = copied.checked_add(n as u64).ok_or(Code::ResourceLimit)?;
        if copied > JOURNAL_CAP || copied > before.size {
            return Err(Code::ResourceLimit);
        }
        stage
            .write_all(&buffer[..n])
            .map_err(|_| Code::FacilityUnavailable)?;
        charge_stage(n as u64)?;
    }
    if copied != before.size || after()? != before {
        return Err(Code::SourceChanged);
    }
    stage.flush().map_err(|_| Code::FacilityUnavailable)?;
    Ok(copied)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    fn id(size: u64) -> Identity {
        Identity {
            device: 1,
            inode: 2,
            size,
            modified_ns: 3,
        }
    }
    #[test]
    fn exact_copy_and_charges() {
        let mut out = Vec::new();
        let mut read = 0;
        let mut staged = 0;
        assert_eq!(
            copy_explicit(
                &b"abc"[..],
                &mut out,
                id(3),
                || Ok(id(3)),
                |n| {
                    read += n;
                    Ok(())
                },
                |n| {
                    staged += n;
                    Ok(())
                }
            ),
            Ok(3)
        );
        assert_eq!(out, b"abc");
        assert_eq!((read, staged), (3, 3));
    }
    #[test]
    fn rotation_short_copy_and_cap_are_errors() {
        assert_eq!(
            copy_explicit(
                &b"abc"[..],
                Vec::new(),
                id(3),
                || Ok(id(4)),
                |_| Ok(()),
                |_| Ok(())
            ),
            Err(Code::SourceChanged)
        );
        assert_eq!(
            copy_explicit(
                &b"ab"[..],
                Vec::new(),
                id(3),
                || Ok(id(3)),
                |_| Ok(()),
                |_| Ok(())
            ),
            Err(Code::SourceChanged)
        );
        assert_eq!(
            copy_explicit(
                &b""[..],
                Vec::new(),
                id(JOURNAL_CAP + 1),
                || Ok(id(0)),
                |_| Ok(()),
                |_| Ok(())
            ),
            Err(Code::ResourceLimit)
        );
    }
}

/// Private worker-owned journal copy. The named file is required by
/// libsystemd; the reader unlinks it immediately after opening, and the
/// temporary-file guard cleans up any earlier failure.
pub(crate) struct StagedJournal {
    file: tempfile::NamedTempFile,
    copied: u64,
}
impl StagedJournal {
    pub(crate) fn copied(&self) -> u64 {
        self.copied
    }
    pub(crate) fn named_path(&self) -> String {
        self.file.path().to_string_lossy().into_owned()
    }
}

/// Read only a pinned file selected through a scoped `JournalFile` source.
/// The per-file cap is additionally bounded by the sealed policy; the global
/// source and staging counters enforce cumulative limits across copies.
pub(crate) fn snapshot_admitted(
    root: &super::paths::ConfinedRoot<'_>,
    path: &jocky_shared::collection::inputs::PathRef,
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
    cancel: &dyn jocky_forensic::collection::cancellation::Cancellation,
) -> Result<StagedJournal, Code> {
    use jocky_forensic::collection::budget::Counter;
    if root.root_id() != &path.root_id {
        return Err(Code::ScopeDenied);
    }
    let pinned = root.pin_file(&path.relative_path, clock, cancel)?;
    let readable = pinned.reopen(clock, cancel)?;
    let expected = readable.facts().size;
    if expected == 0 || expected > JOURNAL_CAP || expected > readable.maximum_file_bytes() {
        return Err(Code::ResourceLimit);
    }
    let mut op = readable.begin(clock, cancel)?;
    readable.verify(&mut op)?;
    let mut stage = op.run(|| {
        tempfile::Builder::new()
            .prefix("jocky-journal-")
            .suffix(".journal")
            .tempfile()
            .map_err(|_| Code::FacilityUnavailable)
    })?;
    let mut copied = 0u64;
    let mut buf = [0u8; 65_536];
    while copied < expected {
        op.check()?;
        readable.verify(&mut op)?;
        let allowance = op.permit.remaining(Counter::SourceBytes)?;
        let wanted = buf
            .len()
            .min(allowance as usize)
            .min((expected - copied) as usize);
        if wanted == 0 {
            return Err(Code::ResourceLimit);
        }
        let got =
            op.run(|| rustix::io::read(readable.fd(), &mut buf[..wanted]).map_err(super::error))?;
        op.permit.charge(Counter::SourceBytes, got as u64)?;
        if got == 0 {
            return Err(Code::SourceChanged);
        }
        copied = copied.checked_add(got as u64).ok_or(Code::ResourceLimit)?;
        if copied > expected || copied > JOURNAL_CAP {
            return Err(Code::SourceChanged);
        }
        let mut written = 0;
        while written < got {
            op.check()?;
            let n = op.run(|| {
                rustix::io::write(stage.as_file_mut(), &buf[written..got]).map_err(super::error)
            })?;
            if n == 0 {
                return Err(Code::FacilityUnavailable);
            }
            op.permit.charge(Counter::StagingBytes, n as u64)?;
            written += n;
        }
    }
    readable.verify(&mut op)?;
    if copied != expected {
        return Err(Code::SourceChanged);
    }
    stage
        .as_file_mut()
        .sync_all()
        .map_err(|_| Code::FacilityUnavailable)?;
    Ok(StagedJournal {
        file: stage,
        copied,
    })
}
