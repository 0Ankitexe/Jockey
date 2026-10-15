//! Pure conversation validation. Receipts are checked data, never live permits.
//! Trusted process ownership, current authority, original deadlines, native
//! accounting and final evidence semantics remain the supervisor's obligations.
use super::{
    chunks::ChunkTransfer,
    inputs::{InputTransfer, VerifiedInputs},
    order::{Direction, JobOrder},
    progress::ProgressTracker,
    protocol::encode_frame,
};
use jocky_forensic::collection::{
    ClockReading, ValidatedCollectionContext, outcome::summarize, verify::verify_report,
};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    inputs::Limits,
    outcomes::{Collector, CollectorStatus, WorkUsed},
    records::LocalContext,
    report::{StatusCode, WorkerCleanup},
    worker::{Body, Commit, Done, Start, WorkerFrame},
};

mod admission;
mod observations;

pub(crate) enum Receipt {
    None,
    Inputs(Box<VerifiedInputs>),
    Report(Vec<u8>),
    Usage(WorkUsed),
    Done(Option<WorkUsed>),
}
enum Transfer {
    Inputs(InputTransfer),
    Report {
        bytes: ChunkTransfer,
        expected: Commit,
        context: LocalContext,
    },
}
pub(crate) struct Session {
    collection: Uuid,
    next: [u64; 2],
    order: JobOrder,
    limits: Limits,
    transfer: Option<Transfer>,
    collector: Option<Collector>,
    context: Option<LocalContext>,
    fingerprint: Option<jocky_shared::collection::report::Inputs>,
    admitted: bool,
    progress: Option<ProgressTracker>,
    records: u64,
    errors: u64,
    record_base: u64,
    error_base: u64,
    unavailable: bool,
    cancelled: Option<Code>,
    closed: bool,
    launch: Option<jocky_shared::collection::launch::WorkerLaunch>,
}
impl Session {
    /// Checked launch metadata, not native peer/descriptor authentication. The
    /// future owned entry must verify those objects and apply the worker budget.
    pub fn for_launch(
        launch: &jocky_shared::collection::launch::WorkerLaunch,
    ) -> Result<Self, Code> {
        let value = jocky_shared::collection::bounded_value(launch, 65536).map_err(|e| e.code)?;
        let raw = jocky_forensic::collection::canonical::encode(&value, 65536)?;
        let launch = jocky_shared::collection::launch::decode_launch(&raw).map_err(|e| e.code)?;
        let mut session = Self::new_at(
            launch.collection_id.clone(),
            launch.global_limits.clone(),
            launch.record_base,
            launch.error_base,
        );
        session.launch = Some(launch);
        Ok(session)
    }
    pub fn new(collection: Uuid, limits: Limits) -> Self {
        Self::new_at(collection, limits, 0, 0)
    }
    /// Bases are report-wide ordinals retained by the supervisor across workers.
    pub fn new_at(collection: Uuid, limits: Limits, record_base: u64, error_base: u64) -> Self {
        Self {
            collection,
            next: [0, 0],
            order: JobOrder::new(),
            limits,
            transfer: None,
            collector: None,
            context: None,
            fingerprint: None,
            admitted: false,
            progress: None,
            records: 0,
            errors: 0,
            record_base,
            error_base,
            unavailable: false,
            cancelled: None,
            closed: false,
            launch: None,
        }
    }
    pub fn accept(&mut self, side: Direction, frame: &WorkerFrame) -> Result<Receipt, Code> {
        if self.closed {
            return Err(Code::WorkerProtocol);
        }
        let result = self.accept_inner(side, frame);
        if result.is_err() {
            self.closed = true;
            self.transfer = None;
        }
        result
    }
    /// Bind full current admission to exactly the committed input bundle. This
    /// remains a protocol guard; native ownership/deadline/resource checks apply.
    pub fn confirm_admission(
        &mut self,
        context: &ValidatedCollectionContext,
        now: &ClockReading,
        cancelled: bool,
    ) -> Result<(), Code> {
        let result = self.confirm_inner(context, now, cancelled);
        if result.is_err() {
            self.closed = true;
            self.transfer = None;
        }
        result
    }
    fn accept_inner(&mut self, side: Direction, frame: &WorkerFrame) -> Result<Receipt, Code> {
        let stream = if side == Direction::Parent { 0 } else { 1 };
        if frame.collection_id != self.collection || frame.frame_seq != self.next[stream] {
            return Err(Code::WorkerProtocol);
        }
        // Also protects callers using deserialized DTOs rather than FrameDecoder.
        let packet = encode_frame(frame).map_err(|_| Code::WorkerProtocol)?;
        if let (Some(launch), Body::Start(start)) = (&self.launch, &frame.body) {
            let job = match start {
                Start::Collect { .. } => jocky_shared::collection::worker::Job::Collect,
                Start::Publish { .. } => jocky_shared::collection::worker::Job::Publish,
            };
            if launch.job != job
                || jocky_forensic::collection::identity::digest(&packet[4..])?
                    != launch.start_sha256
            {
                return Err(Code::WorkerProtocol);
            }
            match start {
                Start::Collect { inputs, .. } if inputs.len() != launch.config_exclusions.len() => {
                    return Err(Code::WorkerProtocol);
                }
                Start::Publish {
                    output_descriptor, ..
                } if launch.descriptors.first().is_none_or(|binding| {
                    binding.kind != jocky_shared::collection::launch::HandleKind::OutputDirectory
                        || binding.fd != *output_descriptor
                }) =>
                {
                    return Err(Code::WorkerProtocol);
                }
                _ => {}
            }
        }
        self.order.accept(side, &frame.body)?;
        self.next[stream] += 1; // Schema bounds frame_seq to the JSON safe integer range.
        let receipt = match &frame.body {
            Body::Start(start) => {
                self.progress = Some(if let Some(launch) = &self.launch {
                    ProgressTracker::for_allowance(&self.limits, &launch.allowance)?
                } else {
                    ProgressTracker::new(&self.limits)?
                });
                self.transfer = Some(match start {
                    Start::Collect { collector, .. } => {
                        self.collector = Some(*collector);
                        Transfer::Inputs(InputTransfer::new(self.collection.clone(), start)?)
                    }
                    Start::Publish {
                        context,
                        report_byte_length,
                        report_sha256,
                        ..
                    } => {
                        if context.collection_id != self.collection {
                            return Err(Code::WorkerProtocol);
                        }
                        self.context = Some(context.clone());
                        let expected = Commit {
                            byte_length: *report_byte_length,
                            sha256: report_sha256.clone(),
                        };
                        Transfer::Report {
                            bytes: ChunkTransfer::new(&expected, self.limits.max_report_bytes)?,
                            expected,
                            context: context.clone(),
                        }
                    }
                });
                Receipt::None
            }
            Body::StartChunk(chunk) => {
                let Some(Transfer::Inputs(input)) = &mut self.transfer else {
                    return Err(Code::WorkerProtocol);
                };
                input.push(chunk)?;
                Receipt::None
            }
            Body::StartCommit(commit) => {
                let Some(Transfer::Inputs(input)) = &mut self.transfer else {
                    return Err(Code::WorkerProtocol);
                };
                let input = input.commit(commit)?;
                self.context = Some(input.context().clone());
                self.fingerprint = Some(input.fingerprint().clone());
                self.transfer = None;
                Receipt::Inputs(Box::new(input))
            }
            Body::PublishChunk(chunk) => {
                let Some(Transfer::Report { bytes, .. }) = &mut self.transfer else {
                    return Err(Code::WorkerProtocol);
                };
                bytes.push(chunk)?;
                Receipt::None
            }
            Body::PublishCommit(commit) => {
                let Some(Transfer::Report { bytes, context, .. }) = &mut self.transfer else {
                    return Err(Code::WorkerProtocol);
                };
                let raw = bytes.commit(commit)?;
                let report = verify_report(&raw).map_err(|_| Code::WorkerProtocol)?;
                if report.context != *context
                    || report.records.len() as u64 > self.limits.max_records
                    || report.errors.len() as u64 > self.limits.max_errors
                {
                    return Err(Code::WorkerProtocol);
                }
                Receipt::Report(raw)
            }
            Body::Record(record) => {
                self.record(record)?;
                Receipt::None
            }
            Body::ItemError(error) => {
                self.item_error(error)?;
                Receipt::None
            }
            Body::Progress(usage) => Receipt::Usage(
                self.progress
                    .as_mut()
                    .ok_or(Code::WorkerProtocol)?
                    .observe(usage)?,
            ),
            Body::Done(Done::Collect { outcome, usage }) => {
                if Some(outcome.collector) != self.collector
                    || outcome.accepted_records != self.records
                    || outcome.errors != self.errors
                    || outcome.status == CollectorStatus::Complete
                        && (self.unavailable || self.cancelled.is_some())
                {
                    return Err(Code::WorkerProtocol);
                }
                summarize(
                    std::slice::from_ref(outcome),
                    self.cancelled,
                    WorkerCleanup::Complete,
                )
                .map_err(|_| Code::WorkerProtocol)?;
                let delta = self
                    .progress
                    .as_mut()
                    .ok_or(Code::WorkerProtocol)?
                    .finish(usage, self.errors)?;
                Receipt::Done(Some(delta))
            }
            Body::Done(Done::Publish {
                code,
                sha256,
                byte_length,
                created_identity,
            }) => {
                let Some(Transfer::Report { expected, .. }) = &self.transfer else {
                    return Err(Code::WorkerProtocol);
                };
                if sha256.is_some() != byte_length.is_some()
                    || sha256.as_ref().is_some_and(|v| v != &expected.sha256)
                    || byte_length.is_some_and(|v| v != expected.byte_length)
                {
                    return Err(Code::WorkerProtocol);
                }
                if matches!(code, StatusCode::Success(_))
                    && (self.cancelled.is_some() || sha256.is_none() || created_identity.is_none())
                {
                    return Err(Code::WorkerProtocol);
                }
                Receipt::Done(None)
            }
            Body::Cancel(cancel) => {
                self.cancelled = Some(cancel.code);
                Receipt::None
            }
            Body::Ready(ready) => {
                if ready.job == jocky_shared::collection::worker::Job::Collect && !self.admitted {
                    return Err(Code::WorkerProtocol);
                }
                Receipt::None
            }
        };
        Ok(receipt)
    }
    pub fn finish(&mut self) -> Result<(), Code> {
        if self.closed {
            return Err(Code::WorkerProtocol);
        }
        self.closed = true;
        self.transfer = None;
        self.order.finish()
    }
}
