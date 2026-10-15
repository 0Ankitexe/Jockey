//! Owned-worker-only address-space ceiling. Call inside the child after the
//! private peer handshake and before evidence I/O; never in a test parent or
//! a caller's shell. This is not the complete supervisor memory accounting.
use jocky_shared::collection::Code;
use rustix::process::{self, Resource, Rlimit};
use std::sync::atomic::{AtomicBool, Ordering};

const WORKER_MAX: u64 = 192 * 1024 * 1024;
const PARENT_MAX: u64 = 64 * 1024 * 1024;
static OWNED_PARENT_LIMIT_APPLIED: AtomicBool = AtomicBool::new(false);

fn parent_soft_limit_permits(
    previous: Option<u64>,
    requested: u64,
    child: u64,
    owned: bool,
) -> bool {
    previous.is_none_or(|limit| limit >= child || limit == requested && owned)
}

/// Split the requested aggregate address-space budget without widening the
/// fixed 64/192 MiB process ceilings. Actual limits are applied separately in
/// the respective owned processes before evidence I/O.
pub(crate) fn split_address_space(aggregate: u64) -> Result<(u64, u64), Code> {
    if aggregate == 0 || aggregate > PARENT_MAX + WORKER_MAX {
        return Err(Code::InvalidInput);
    }
    let parent = aggregate / 4;
    let worker = aggregate - parent;
    if parent == 0 || worker == 0 || parent > PARENT_MAX || worker > WORKER_MAX {
        return Err(Code::ResourceLimit);
    }
    Ok((parent, worker))
}

pub(crate) fn limit_worker_address_space(requested: u64) -> Result<(), Code> {
    if requested == 0 || requested > WORKER_MAX {
        return Err(Code::InvalidInput);
    }
    let previous = process::getrlimit(Resource::As);
    // The only lower soft cap accepted is the parent's deliberate 1:3 split
    // inherited through fixed-self spawn. Any other external soft cap remains
    // authoritative and cannot be raised by this worker.
    if previous.maximum.is_some_and(|limit| limit < requested)
        || previous
            .current
            .is_some_and(|limit| limit < requested && limit != requested / 3)
    {
        return Err(Code::ResourceLimit);
    }
    process::setrlimit(
        Resource::As,
        Rlimit {
            current: Some(requested),
            maximum: Some(requested),
        },
    )
    .map_err(|error| match error {
        rustix::io::Errno::PERM | rustix::io::Errno::ACCESS => Code::PermissionDenied,
        _ => Code::ResourceLimit,
    })?;
    let observed = process::getrlimit(Resource::As);
    if observed.current == Some(requested) && observed.maximum == Some(requested) {
        Ok(())
    } else {
        Err(Code::ResourceLimit)
    }
}

/// Apply the parent's part of the fixed 64/192 MiB split in the dedicated
/// collector process before spawning a worker or accepting source traffic.
/// Never call this on a caller's shell or an in-process test harness.
pub(crate) fn limit_parent_address_space(requested: u64, child: u64) -> Result<(), Code> {
    if requested == 0 || requested > PARENT_MAX || child == 0 || child > WORKER_MAX {
        return Err(Code::InvalidInput);
    }
    let previous = process::getrlimit(Resource::As);
    // Preserve the original hard limit so the owned child may take its
    // separately checked worker ceiling. A pre-existing lower soft cap must
    // not be widened by the worker after fork/exec.
    if !parent_soft_limit_permits(
        previous.current,
        requested,
        child,
        OWNED_PARENT_LIMIT_APPLIED.load(Ordering::SeqCst),
    ) || previous.maximum.is_some_and(|limit| limit < child)
    {
        return Err(Code::ResourceLimit);
    }
    process::setrlimit(
        Resource::As,
        Rlimit {
            current: Some(requested),
            maximum: previous.maximum,
        },
    )
    .map_err(|error| match error {
        rustix::io::Errno::PERM | rustix::io::Errno::ACCESS => Code::PermissionDenied,
        _ => Code::ResourceLimit,
    })?;
    let observed = process::getrlimit(Resource::As);
    if observed.current == Some(requested) && observed.maximum == previous.maximum {
        OWNED_PARENT_LIMIT_APPLIED.store(true, Ordering::SeqCst);
        Ok(())
    } else {
        Err(Code::ResourceLimit)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sequential_owned_parent_limit_does_not_accept_an_external_lower_cap() {
        let parent = 64 * 1024 * 1024;
        let worker = 192 * 1024 * 1024;
        assert!(super::parent_soft_limit_permits(
            None, parent, worker, false
        ));
        assert!(!super::parent_soft_limit_permits(
            Some(parent),
            parent,
            worker,
            false
        ));
        assert!(super::parent_soft_limit_permits(
            Some(parent),
            parent,
            worker,
            true
        ));
        assert!(!super::parent_soft_limit_permits(
            Some(parent / 2),
            parent,
            worker,
            true
        ));
    }
}
