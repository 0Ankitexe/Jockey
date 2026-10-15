//! Start/input commitment for an already authenticated owned worker. This
//! transition grants no implicit source descriptor or ambient path fallback.
use super::{
    handles,
    order::Direction,
    protocol::{self, FrameDecoder},
    session::{Receipt, Session},
};
use jocky_forensic::collection::{
    ClockReading, ValidatedCollectionContext, admit_for_invocation, clock::Clock,
};
use jocky_shared::collection::{Code, launch::WorkerLaunch, outcomes::Collector, worker::Job};
use std::io::Read;

pub(crate) struct AdmittedCollect {
    pub context: ValidatedCollectionContext,
    pub collector: Collector,
    pub session: Session,
    pub decoder: FrameDecoder,
}

/// Read only the declared Start and ordered input chunks. Full logical
/// admission, original invocation clocks, narrowed work and selected descriptor
/// purposes must all pass before the caller may emit Ready or read evidence.
/// The channel reader must remain unbuffered so later frame/FD boundaries stay
/// exact. A parent supervisor owns the external bound on a blocked read.
pub(crate) fn receive_committed(
    reader: &mut impl Read,
    launch: &WorkerLaunch,
    clock: &mut dyn Clock,
) -> Result<AdmittedCollect, Code> {
    if launch.job != Job::Collect {
        return Err(Code::WorkerProtocol);
    }
    let mut session = Session::for_launch(launch)?;
    let mut decoder = FrameDecoder::new(launch.collection_id.clone());
    let deadline = launch
        .invocation_origin
        .monotonic_ms
        .checked_add(launch.global_limits.timeout_ms)
        .ok_or(Code::ResourceLimit)?;
    let mut last = launch.launch_observed.clone();
    // InputTransfer enforces the 786,432-byte aggregate. The original
    // invocation deadline bounds a sender using many legal short chunks.
    loop {
        let now = clock.read()?;
        if now.monotonic_ms < last.monotonic_ms || now.utc.unix_nanos() < last.utc.unix_nanos() {
            return Err(Code::ClockUncertain);
        }
        if now.monotonic_ms >= deadline {
            return Err(Code::Timeout);
        }
        last.utc = now.utc.clone();
        last.monotonic_ms = now.monotonic_ms;
        let frame = protocol::read_frame(reader, &mut decoder)?;
        let receipt = session.accept(Direction::Parent, &frame)?;
        if let Receipt::Inputs(input) = receipt {
            let now = clock.read()?;
            let origin = ClockReading {
                utc: launch.invocation_origin.utc.clone(),
                monotonic_ms: launch.invocation_origin.monotonic_ms,
            };
            let context = admit_for_invocation(input.inputs(), origin, now.clone())?;
            context.restrict_work(&launch.allowance)?;
            handles::verify_scope(&context, launch.job, &launch.descriptors)?;
            session.confirm_admission(&context, &now, false)?;
            return Ok(AdmittedCollect {
                context,
                collector: input.collector(),
                session,
                decoder,
            });
        }
    }
}
