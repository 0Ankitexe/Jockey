//! Owned-worker supervision. The caller supplies already selected input and
//! capability descriptors; no path is discovered or read by this module.
use super::{
    accounting::{Acknowledged, ReservationLedger},
    handles,
    order::Direction,
    owned::OwnedWorker,
    peer, protocol,
    session::{Receipt, Session},
    spawn::{self, Spawned},
    stop::{Action, StopSchedule},
};
use jocky_forensic::collection::{ClockReading, admit_for_invocation, clock::Clock};
use jocky_shared::collection::{
    Code,
    inputs::CollectionVersion,
    launch::WorkerLaunch,
    worker::{Body, Cancel, Done, Job, WorkerFrame},
};

/// Publish through a distinct, output-only fixed-self child. The caller has
/// already opened the admitted output directory; the child receives exactly
/// that descriptor and the prevalidated report frames, never source handles.
pub(crate) fn publish_owned(
    launch: &WorkerLaunch,
    frames: &[WorkerFrame],
    output: BorrowedFd<'_>,
    ledger: &mut ReservationLedger,
    clock: &mut dyn Clock,
    cancelled: impl FnMut() -> bool,
) -> Result<Done, Code> {
    let (parent_limit, worker_limit) =
        super::resource::split_address_space(launch.global_limits.max_memory_bytes)?;
    super::resource::limit_parent_address_space(parent_limit, worker_limit)?;
    let signals = super::signals::SignalWatch::start()?;
    let mut cancelled = cancelled;
    publish_with(
        launch,
        frames,
        output,
        ledger,
        clock,
        || signals.cancelled() || cancelled(),
        spawn::fixed_self,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_with(
    launch: &WorkerLaunch,
    frames: &[WorkerFrame],
    output: BorrowedFd<'_>,
    ledger: &mut ReservationLedger,
    clock: &mut dyn Clock,
    mut cancelled: impl FnMut() -> bool,
    spawn: impl FnOnce() -> Result<Spawned, Code>,
) -> Result<Done, Code> {
    use jocky_shared::collection::{
        report::StatusCode,
        worker::{Ready, Start},
    };
    if launch.job != Job::Publish
        || launch.parent != peer::own_identity()?
        || launch.descriptors.len() != 1
        || launch.allowance.records != 0
        || launch.allowance.source_bytes != 0
        || launch.allowance.errors != 0
        || launch.allowance.entries != 0
        || launch.allowance.indicator_comparisons != 0
        || frames.len() < 3
        || cancelled()
    {
        return Err(Code::WorkerProtocol);
    }
    let Body::Start(Start::Publish {
        report_byte_length, ..
    }) = &frames[0].body
    else {
        return Err(Code::WorkerProtocol);
    };
    let report_bytes = *report_byte_length;
    let checked = output
        .try_clone_to_owned()
        .map_err(|_| Code::WorkerProtocol)?;
    handles::verify_objects(&launch.descriptors, &[checked], &launch.config_exclusions)?;
    if report_bytes > launch.allowance.report_bytes || report_bytes > launch.allowance.staging_bytes
    {
        return Err(Code::ResourceLimit);
    }
    let ready = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Ready(Ready { job: Job::Publish }),
    };
    // Verify the entire report and frame sequence before creating the child.
    let mut preflight = Session::for_launch(launch)?;
    preflight.accept(Direction::Parent, &frames[0])?;
    preflight.accept(Direction::Worker, &ready)?;
    let mut committed = false;
    for frame in &frames[1..] {
        if matches!(
            preflight.accept(Direction::Parent, frame)?,
            Receipt::Report(_)
        ) {
            committed = true;
        }
    }
    if !committed {
        return Err(Code::WorkerProtocol);
    }
    let stage_absent =
        super::publisher_cleanup::abandoned_stage_absent(output, &launch.collection_id)?;
    let mut session = Session::for_launch(launch)?;
    session.accept(Direction::Parent, &frames[0])?;
    ledger.reserve(&launch.allowance)?;
    let mut last = ClockReading {
        utc: launch.launch_observed.utc.clone(),
        monotonic_ms: launch.launch_observed.monotonic_ms,
    };
    let run = (|| {
        check_publish_clock(launch, clock, &mut cancelled, &mut last)?;
        let spawned = spawn()?;
        let mut worker = match OwnedWorker::capture(spawned.child) {
            Ok(worker) => worker,
            Err(mut failure) => {
                let _ = spawned.channel.shutdown(Shutdown::Both);
                let began = Instant::now();
                loop {
                    if failure
                        .child
                        .try_wait()
                        .map_err(|_| Code::CleanupIncomplete)?
                        .is_some()
                    {
                        return Err(failure.code);
                    }
                    if began.elapsed() >= Duration::from_secs(3) {
                        return Err(Code::CleanupIncomplete);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        let result = exchange_publish(
            launch,
            frames,
            output,
            &mut worker,
            &spawned.channel,
            clock,
            &mut cancelled,
            &mut last,
            &mut session,
        );
        match result {
            Ok(done) => Ok(done),
            Err(code) => {
                let remaining = remaining_ms(launch, clock).unwrap_or(3000).clamp(1, 6000);
                let stopped =
                    stop_owned(&mut worker, &spawned.channel, remaining, stop_cause(code));
                if stopped.is_err() && worker.poll()?.is_none() {
                    Err(Code::CleanupIncomplete)
                } else {
                    Err(code)
                }
            }
        }
    })();
    let run = if stage_absent && !matches!(run, Err(Code::CleanupIncomplete)) {
        match super::publisher_cleanup::cleanup_abandoned_stage(output, &launch.collection_id) {
            Ok(()) => run,
            Err(_) => Err(Code::CleanupIncomplete),
        }
    } else {
        run
    };
    match &run {
        Ok(Done::Publish {
            code: StatusCode::Success(_),
            ..
        }) => {
            ledger.acknowledge(Acknowledged {
                records: 0,
                report_bytes,
                work: jocky_shared::collection::outcomes::WorkUsed {
                    entries: 0,
                    indicator_comparisons: 0,
                    errors: 0,
                    source_bytes: 0,
                    staging_bytes: report_bytes,
                    retained_bytes: launch.allowance.retained_bytes,
                },
            })?;
        }
        _ => ledger.lost()?,
    }
    run
}

#[allow(clippy::too_many_arguments)]
fn exchange_publish(
    launch: &WorkerLaunch,
    frames: &[WorkerFrame],
    output: BorrowedFd<'_>,
    worker: &mut OwnedWorker,
    channel: &UnixStream,
    clock: &mut dyn Clock,
    cancelled: &mut impl FnMut() -> bool,
    last: &mut ClockReading,
    session: &mut Session,
) -> Result<Done, Code> {
    if worker.poll()?.is_some() {
        return Err(Code::WorkerFailed);
    }
    peer::require_owned_pair(channel)?;
    let mut writer = channel;
    writer
        .write_all(&super::control::encode_launch(launch)?)
        .map_err(spawn::map_error)?;
    handles::send(channel, &[output])?;
    check_publish_clock(launch, clock, cancelled, last)?;
    protocol::write_frame(&mut writer, &frames[0])?;
    let mut decoder = protocol::FrameDecoder::new(launch.collection_id.clone());
    check_publish_clock(launch, clock, cancelled, last)?;
    let ready = protocol::read_frame(&mut &*channel, &mut decoder)?;
    if !matches!(ready.body, Body::Ready(_)) {
        return Err(Code::WorkerProtocol);
    }
    session.accept(Direction::Worker, &ready)?;
    for frame in &frames[1..] {
        check_publish_clock(launch, clock, cancelled, last)?;
        session.accept(Direction::Parent, frame)?;
        protocol::write_frame(&mut writer, frame)?;
    }
    check_publish_clock(launch, clock, cancelled, last)?;
    let done_frame = protocol::read_frame(&mut &*channel, &mut decoder)?;
    if !matches!(
        session.accept(Direction::Worker, &done_frame)?,
        Receipt::Done(None)
    ) {
        return Err(Code::WorkerProtocol);
    }
    let Body::Done(done) = done_frame.body else {
        return Err(Code::WorkerProtocol);
    };
    session.finish()?;
    decoder.finish()?;
    channel
        .shutdown(Shutdown::Write)
        .map_err(spawn::map_error)?;
    let mut trailing = [0u8; 1];
    if (&*channel).read(&mut trailing).map_err(spawn::map_error)? != 0 {
        return Err(Code::WorkerProtocol);
    }
    let began = Instant::now();
    loop {
        if let Some(status) = worker.poll()? {
            return if status.success() {
                Ok(done)
            } else {
                Err(Code::WorkerFailed)
            };
        }
        if began.elapsed() >= Duration::from_secs(2) {
            return Err(Code::WorkerFailed);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn check_publish_clock(
    launch: &WorkerLaunch,
    clock: &mut dyn Clock,
    cancelled: &mut impl FnMut() -> bool,
    last: &mut ClockReading,
) -> Result<(), Code> {
    if cancelled() {
        return Err(Code::Cancelled);
    }
    let now = clock.read()?;
    if now.monotonic_ms < last.monotonic_ms || now.utc.unix_nanos() < last.utc.unix_nanos() {
        return Err(Code::ClockUncertain);
    }
    if remaining_ms(launch, &mut OnceClock(now.clone()))? == 0 {
        return Err(Code::Timeout);
    }
    *last = now;
    Ok(())
}

struct OnceClock(ClockReading);
impl Clock for OnceClock {
    fn read(&mut self) -> Result<ClockReading, Code> {
        Ok(self.0.clone())
    }
}
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::{fd::BorrowedFd, unix::net::UnixStream},
    process::ExitStatus,
    time::{Duration, Instant},
};

/// Run one sequential collect job using only a fixed self image. This accepts
/// pre-resolved descriptors, never executable names or source paths. The
/// observation callback is invoked only after the session validates a frame.
pub(crate) fn collect_owned(
    launch: &WorkerLaunch,
    input_frames: &[WorkerFrame],
    descriptors: &[BorrowedFd<'_>],
    ledger: &mut ReservationLedger,
    clock: &mut dyn Clock,
    observation: impl FnMut(&WorkerFrame) -> Result<(), Code>,
    cancelled: impl FnMut() -> bool,
) -> Result<Done, Code> {
    let (parent_limit, worker_limit) =
        super::resource::split_address_space(launch.global_limits.max_memory_bytes)?;
    super::resource::limit_parent_address_space(parent_limit, worker_limit)?;
    let signals = super::signals::SignalWatch::start()?;
    let mut cancelled = cancelled;
    collect_with(
        launch,
        input_frames,
        descriptors,
        ledger,
        clock,
        observation,
        || signals.cancelled() || cancelled(),
        spawn::fixed_self,
    )
}

/// An injectable spawn seam permits actual-product-binary and fault tests;
/// the production entry above always uses the fixed running image.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_with(
    launch: &WorkerLaunch,
    input_frames: &[WorkerFrame],
    descriptors: &[BorrowedFd<'_>],
    ledger: &mut ReservationLedger,
    clock: &mut dyn Clock,
    mut observation: impl FnMut(&WorkerFrame) -> Result<(), Code>,
    mut cancelled: impl FnMut() -> bool,
    spawn: impl FnOnce() -> Result<Spawned, Code>,
) -> Result<Done, Code> {
    if launch.job != Job::Collect
        || launch.parent != peer::own_identity()?
        || launch.descriptors.len() != descriptors.len()
        || input_frames.is_empty()
        || cancelled()
    {
        return Err(Code::WorkerProtocol);
    }
    let checked = descriptors
        .iter()
        .map(|fd| fd.try_clone_to_owned().map_err(|_| Code::WorkerProtocol))
        .collect::<Result<Vec<_>, _>>()?;
    handles::verify_objects(&launch.descriptors, &checked, &launch.config_exclusions)?;
    let mut session = Session::for_launch(launch)?;
    let origin = ClockReading {
        utc: launch.invocation_origin.utc.clone(),
        monotonic_ms: launch.invocation_origin.monotonic_ms,
    };
    let mut admitted = None;
    for frame in input_frames {
        match session.accept(Direction::Parent, frame)? {
            Receipt::Inputs(input) => {
                if admitted.is_some() {
                    return Err(Code::WorkerProtocol);
                }
                let now = clock.read()?;
                let context = admit_for_invocation(input.inputs(), origin.clone(), now.clone())?;
                context.restrict_work(&launch.allowance)?;
                handles::verify_scope(&context, launch.job, &launch.descriptors)?;
                session.confirm_admission(&context, &now, false)?;
                admitted = Some(context);
            }
            Receipt::None => (),
            _ => return Err(Code::WorkerProtocol),
        }
    }
    let mut context = admitted.ok_or(Code::WorkerProtocol)?;
    ledger.reserve(&launch.allowance)?;
    let run = (|| {
        let spawned = spawn()?;
        let mut worker = match OwnedWorker::capture(spawned.child) {
            Ok(worker) => worker,
            Err(mut failure) => {
                let _ = spawned.channel.shutdown(Shutdown::Both);
                let began = Instant::now();
                loop {
                    if failure
                        .child
                        .try_wait()
                        .map_err(|_| Code::CleanupIncomplete)?
                        .is_some()
                    {
                        return Err(failure.code);
                    }
                    if began.elapsed() >= Duration::from_secs(3) {
                        return Err(Code::CleanupIncomplete);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        let result = exchange_collect(
            launch,
            input_frames,
            descriptors,
            &mut worker,
            &spawned.channel,
            &mut context,
            clock,
            &mut observation,
            &mut cancelled,
            &mut session,
        );
        match result {
            Ok(done) => Ok(done),
            Err(code) => {
                let remaining = remaining_ms(launch, clock).unwrap_or(3000).clamp(1, 6000);
                let cause = stop_cause(code);
                let cancel = WorkerFrame {
                    schema_version: CollectionVersion::V1,
                    frame_seq: input_frames.last().ok_or(Code::WorkerProtocol)?.frame_seq + 1,
                    collection_id: launch.collection_id.clone(),
                    body: Body::Cancel(Cancel { code: cause }),
                };
                let stopped = if session.accept(Direction::Parent, &cancel).is_ok() {
                    cancel_owned(&mut worker, &spawned.channel, &cancel, remaining, cause)
                } else {
                    stop_owned(&mut worker, &spawned.channel, remaining, cause)
                };
                match stopped {
                    Ok(_) => Err(code),
                    Err(Code::CleanupIncomplete) => Err(Code::CleanupIncomplete),
                    Err(_) => match worker.poll() {
                        Ok(Some(_)) => Err(code),
                        _ => Err(Code::CleanupIncomplete),
                    },
                }
            }
        }
    })();
    match &run {
        Ok(Done::Collect { outcome, usage }) => {
            ledger.acknowledge(Acknowledged {
                records: outcome.accepted_records,
                report_bytes: 0,
                work: usage.clone(),
            })?;
        }
        Ok(_) => {
            ledger.lost()?;
            return Err(Code::WorkerProtocol);
        }
        Err(_) => ledger.lost()?,
    }
    run
}

#[allow(clippy::too_many_arguments)]
fn exchange_collect(
    launch: &WorkerLaunch,
    input_frames: &[WorkerFrame],
    descriptors: &[BorrowedFd<'_>],
    worker: &mut OwnedWorker,
    channel: &UnixStream,
    context: &mut jocky_forensic::collection::ValidatedCollectionContext,
    clock: &mut dyn Clock,
    observation: &mut impl FnMut(&WorkerFrame) -> Result<(), Code>,
    cancelled: &mut impl FnMut() -> bool,
    session: &mut Session,
) -> Result<Done, Code> {
    if worker.poll()?.is_some() {
        return Err(Code::WorkerFailed);
    }
    peer::require_owned_pair(channel)?;
    let mut writer = channel;
    writer
        .write_all(&super::control::encode_launch(launch)?)
        .map_err(spawn::map_error)?;
    if !descriptors.is_empty() {
        handles::send(channel, descriptors)?;
    }
    for frame in input_frames {
        context.check_active(&clock.read()?, cancelled())?;
        protocol::write_frame(&mut writer, frame)?;
    }
    let mut decoder = protocol::FrameDecoder::new(launch.collection_id.clone());
    let done = loop {
        context.check_active(&clock.read()?, cancelled())?;
        let frame = match protocol::read_frame(&mut &*channel, &mut decoder) {
            Ok(frame) => frame,
            Err(code) => {
                // A signal or original cutoff can arrive during a bounded
                // socket read. Preserve that cause instead of turning it into
                // an unrelated peer failure.
                context.check_active(&clock.read()?, cancelled())?;
                return Err(code);
            }
        };
        let receipt = session.accept(Direction::Worker, &frame)?;
        if matches!(frame.body, Body::Record(_) | Body::ItemError(_)) {
            observation(&frame)?;
        }
        if let Receipt::Done(Some(_)) = receipt {
            let Body::Done(done) = frame.body else {
                return Err(Code::WorkerProtocol);
            };
            break done;
        }
    };
    session.finish()?;
    decoder.finish()?;
    channel
        .shutdown(Shutdown::Write)
        .map_err(spawn::map_error)?;
    let mut trailing = [0u8; 1];
    if (&*channel).read(&mut trailing).map_err(spawn::map_error)? != 0 {
        return Err(Code::WorkerProtocol);
    }
    let began = Instant::now();
    loop {
        if let Some(status) = worker.poll()? {
            return if status.success() {
                Ok(done)
            } else {
                Err(Code::WorkerFailed)
            };
        }
        if began.elapsed() >= Duration::from_secs(2) {
            return Err(Code::WorkerFailed);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn remaining_ms(launch: &WorkerLaunch, clock: &mut dyn Clock) -> Result<u64, Code> {
    let now = clock.read()?;
    let deadline = launch
        .invocation_origin
        .monotonic_ms
        .checked_add(launch.global_limits.timeout_ms)
        .ok_or(Code::ResourceLimit)?;
    Ok(deadline.saturating_sub(now.monotonic_ms))
}

fn stop_cause(code: Code) -> Code {
    match code {
        Code::Cancelled
        | Code::AuthorisationExpired
        | Code::Timeout
        | Code::ResourceLimit
        | Code::ClockUncertain => code,
        _ => Code::Cancelled,
    }
}

pub(crate) fn stop_owned(
    worker: &mut OwnedWorker,
    channel: &UnixStream,
    deadline_ms: u64,
    cause: Code,
) -> Result<ExitStatus, Code> {
    stop_owned_with(worker, deadline_ms, cause, || {
        channel
            .shutdown(Shutdown::Write)
            .map_err(|_| Code::WorkerFailed)
    })
}

/// Send the already session-validated cooperative Cancel on the private
/// channel, then close the write half and retain the same bounded pidfd-based
/// kill/reap schedule. A malformed frame cannot be used as a signal shortcut.
pub(crate) fn cancel_owned(
    worker: &mut OwnedWorker,
    channel: &UnixStream,
    frame: &WorkerFrame,
    deadline_ms: u64,
    cause: Code,
) -> Result<ExitStatus, Code> {
    if !matches!(&frame.body, Body::Cancel(cancel) if cancel.code == cause) {
        return Err(Code::WorkerProtocol);
    }
    stop_owned_with(worker, deadline_ms, cause, || {
        let mut writer = channel;
        protocol::write_frame(&mut writer, frame)?;
        channel
            .shutdown(Shutdown::Write)
            .map_err(|_| Code::WorkerFailed)
    })
}

/// The injected close is only an offline fault seam. A failed close never
/// skips pidfd termination and reaping of the already owned child.
pub(crate) fn stop_owned_with(
    worker: &mut OwnedWorker,
    deadline_ms: u64,
    cause: Code,
    mut close: impl FnMut() -> Result<(), Code>,
) -> Result<ExitStatus, Code> {
    if deadline_ms == 0 || deadline_ms > 6000 {
        return Err(Code::InvalidInput);
    }
    let began = Instant::now();
    let mut schedule = StopSchedule::new(0, deadline_ms, cause)?;
    let mut channel_failed = false;
    loop {
        let elapsed = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        let reaped = worker.poll()?.is_some();
        match schedule.poll(elapsed, reaped)? {
            Action::Cancel(_) => {
                if close().is_err() {
                    channel_failed = true;
                }
            }
            Action::Wait => std::thread::sleep(Duration::from_millis(
                schedule
                    .finalization_deadline()
                    .saturating_sub(elapsed)
                    .min(5),
            )),
            Action::KillOwned => {
                if let Err(code) = worker.kill_owned()
                    && worker.poll()?.is_none()
                {
                    return Err(code);
                }
            }
            Action::Reaped => {
                let status = worker.poll()?.ok_or(Code::WorkerProtocol)?;
                return if channel_failed {
                    Err(Code::WorkerFailed)
                } else {
                    Ok(status)
                };
            }
            Action::Incomplete => return Err(Code::CleanupIncomplete),
        }
    }
}
