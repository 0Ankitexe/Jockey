//! Charged read of one already transferred fixed OS-release descriptor.
//! The caller must bind the descriptor to the selected kernel-profile source.
use super::{error, operation::Operation};
use jocky_forensic::collection::{
    ValidatedCollectionContext, budget::Counter, cancellation::Cancellation, clock::Clock,
    context::OperationTarget,
};
use jocky_shared::collection::{Code, identity::Uuid, inputs::SourceKind};
use rustix::{
    fd::{BorrowedFd, OwnedFd},
    fs::{self, AtFlags, FileType, StatxFlags},
};

/// Pin the code-owned release file after a current source permit. Missing is
/// an attributable optional facility; other failures remain typed denials.
pub(crate) fn pin_release_fallback(
    context: &ValidatedCollectionContext,
    source_id: &Uuid,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<Option<OwnedFd>, Code> {
    if !context.sources().iter().any(|source| {
        source.definition().id() == source_id
            && source.definition().kind() == SourceKind::KernelProfile
    }) {
        return Err(Code::ScopeDenied);
    }
    context.permit(
        OperationTarget::Source(source_id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    let fd = match fs::open(
        "/usr/lib/os-release",
        fs::OFlags::RDONLY | fs::OFlags::CLOEXEC | fs::OFlags::NOFOLLOW,
        fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(super::error(error)),
    };
    context.permit(
        OperationTarget::Source(source_id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    let stat = fs::statx(
        &fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID,
    )
    .map_err(super::error)?;
    if stat.stx_mask
        & (StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID).bits()
        != (StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID).bits()
        || FileType::from_raw_mode(u32::from(stat.stx_mode)) != FileType::RegularFile
    {
        return Err(Code::Unsupported);
    }
    Ok(Some(fd))
}

/// Bound the local uname observation to the admitted kernel-profile source.
pub(crate) fn machine_architecture(
    context: &ValidatedCollectionContext,
    source_id: &Uuid,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<String, Code> {
    if !context.sources().iter().any(|source| {
        source.definition().id() == source_id
            && source.definition().kind() == SourceKind::KernelProfile
    }) {
        return Err(Code::ScopeDenied);
    }
    let permit = context.permit(
        OperationTarget::Source(source_id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    let mut op = Operation {
        permit,
        clock,
        cancel,
    };
    op.entry()?;
    let value = op.run(|| {
        rustix::system::uname()
            .machine()
            .to_str()
            .map(str::to_owned)
            .map_err(|_| Code::UnsupportedEncoding)
    })?;
    op.permit.charge(Counter::SourceBytes, value.len() as u64)?;
    Ok(value)
}

pub(crate) fn read_release(
    context: &ValidatedCollectionContext,
    source_id: &Uuid,
    fd: BorrowedFd<'_>,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<Vec<u8>, Code> {
    if !context.sources().iter().any(|source| {
        source.definition().id() == source_id
            && source.definition().kind() == SourceKind::KernelProfile
    }) {
        return Err(Code::ScopeDenied);
    }
    let permit = context.permit(
        OperationTarget::Source(source_id),
        &clock.read()?,
        cancel.cancelled(),
    )?;
    let mut op = Operation {
        permit,
        clock,
        cancel,
    };
    const FLAGS: StatxFlags = StatxFlags::TYPE
        .union(StatxFlags::MODE)
        .union(StatxFlags::INO)
        .union(StatxFlags::SIZE)
        .union(StatxFlags::MTIME)
        .union(StatxFlags::CTIME)
        .union(StatxFlags::MNT_ID);
    let inspect = |op: &mut Operation<'_, '_>| {
        op.run(|| {
            fs::statx(fd, "", AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT, FLAGS).map_err(error)
        })
    };
    let before = inspect(&mut op)?;
    if before.stx_mask & FLAGS.bits() != FLAGS.bits()
        || FileType::from_raw_mode(u32::from(before.stx_mode)) != FileType::RegularFile
    {
        return Err(Code::Unsupported);
    }
    let maximum = context.limits().max_item_bytes.min(65_536);
    if before.stx_size > maximum {
        return Err(Code::ResourceLimit);
    }
    op.permit.charge(Counter::RetainedBytes, maximum)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(before.stx_size as usize)
        .map_err(|_| Code::ResourceLimit)?;
    let mut block = [0u8; 4096];
    loop {
        op.check()?;
        let remaining = maximum.saturating_sub(result.len() as u64);
        // A one-byte probe at the ceiling detects growth without publishing a
        // successful prefix. Its attempted read is included in source work.
        let request = block.len().min(remaining.saturating_add(1) as usize);
        let size = op.run(|| {
            rustix::io::pread(fd, &mut block[..request], result.len() as u64).map_err(error)
        })?;
        op.permit.charge(Counter::SourceBytes, size as u64)?;
        op.check()?;
        if size == 0 {
            break;
        }
        if size as u64 > remaining {
            return Err(Code::ResourceLimit);
        }
        result.extend_from_slice(&block[..size]);
    }
    let after = inspect(&mut op)?;
    if before.stx_ino != after.stx_ino
        || before.stx_mnt_id != after.stx_mnt_id
        || before.stx_size != after.stx_size
        || (before.stx_mtime.tv_sec, before.stx_mtime.tv_nsec)
            != (after.stx_mtime.tv_sec, after.stx_mtime.tv_nsec)
        || (before.stx_ctime.tv_sec, before.stx_ctime.tv_nsec)
            != (after.stx_ctime.tv_sec, after.stx_ctime.tv_nsec)
        || result.len() as u64 != before.stx_size
    {
        return Err(Code::SourceChanged);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support;
    use jocky_forensic::collection::{ClockReading, InputSet, admit};
    use jocky_shared::collection::identity::UtcTime;
    use std::os::fd::AsFd;

    #[test]
    fn admitted_release_read_uses_owned_regular_descriptor_and_denial_reads_nothing() {
        let context = admit(
            InputSet {
                designation: include_bytes!(
                    "../../../../fixtures/valid/collection/endpoint-designation.json"
                ),
                authorisation: Some(include_bytes!(
                    "../../../../fixtures/valid/collection/authorisation.json"
                )),
                policy: include_bytes!("../../../../fixtures/valid/collection/policy.json"),
                request: include_bytes!("../../../../fixtures/valid/collection/request.json"),
                indicators: None,
            },
            ClockReading {
                utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
                monotonic_ms: 0,
            },
        )
        .unwrap();
        let owned = support::scratch();
        let path = owned.path().join("release");
        std::fs::write(&path, b"ID=debian\nVERSION_ID=13\n").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let source = Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap();
        let mut clock = support::Frozen::default();
        assert_eq!(
            read_release(&context, &source, file.as_fd(), &mut clock, &false).unwrap(),
            b"ID=debian\nVERSION_ID=13\n"
        );
        let wrong = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
        assert_eq!(
            read_release(&context, &wrong, file.as_fd(), &mut clock, &false),
            Err(Code::ScopeDenied)
        );
        let mut first = [0; 1];
        assert_eq!(rustix::io::read(file.as_fd(), &mut first).unwrap(), 1);
        assert_eq!(first[0], b'I'); // pread did not consume the shared cursor
    }
}
