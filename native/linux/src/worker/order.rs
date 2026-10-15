//! Direction/order validation only, never authority, transfer integrity or job success.
//! Apply strict framing and transfer verification BEFORE accepting their events.
//! A clean terminal exchange still needs outcome, usage and evidence verification.
use jocky_shared::collection::{
    Code,
    outcomes::CollectorStatus,
    report::StatusCode,
    worker::{Body, Done, Job, Start},
};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Direction {
    Parent,
    Worker,
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Initial,
    Inputs,
    AwaitReady,
    Collecting,
    PublishReady,
    Report,
    Publishing,
    Terminal,
    Closed,
}

pub(crate) struct JobOrder {
    phase: Phase,
    job: Option<Job>,
    cancelled: bool,
    chunks_seen: bool,
}
impl JobOrder {
    pub fn awaiting_admission(&self) -> bool {
        self.phase == Phase::AwaitReady && !self.cancelled
    }
    pub fn new() -> Self {
        Self {
            phase: Phase::Initial,
            job: None,
            cancelled: false,
            chunks_seen: false,
        }
    }
    /// In-flight worker observations remain legal after cancel. The supervisor
    /// must distinguish already admitted observations from new forbidden I/O.
    pub fn accept(&mut self, direction: Direction, body: &Body) -> Result<(), Code> {
        let result = self.advance(direction, body);
        if result.is_err() {
            self.phase = Phase::Closed;
        }
        result
    }
    fn advance(&mut self, direction: Direction, body: &Body) -> Result<(), Code> {
        use Direction::{Parent, Worker};
        use Phase::*;
        if matches!(self.phase, Terminal | Closed) {
            return Err(Code::WorkerProtocol);
        }
        if matches!(body, Body::Cancel(_)) {
            if direction != Parent || self.phase == Initial || self.cancelled {
                return Err(Code::WorkerProtocol);
            }
            self.cancelled = true;
            return Ok(());
        }
        if self.cancelled && direction == Parent {
            return Err(Code::WorkerProtocol);
        }
        self.phase = match (self.phase, direction, body) {
            (Initial, Parent, Body::Start(Start::Collect { .. })) => {
                self.job = Some(Job::Collect);
                Inputs
            }
            (Initial, Parent, Body::Start(Start::Publish { .. })) => {
                self.job = Some(Job::Publish);
                PublishReady
            }
            (Inputs, Parent, Body::StartChunk(_)) => {
                self.chunks_seen = true;
                Inputs
            }
            (Inputs, Parent, Body::StartCommit(_)) if self.chunks_seen => AwaitReady,
            (AwaitReady, Worker, Body::Ready(r)) if r.job == Job::Collect => Collecting,
            (PublishReady, Worker, Body::Ready(r)) if r.job == Job::Publish => Report,
            (Report, Parent, Body::PublishChunk(_)) => {
                self.chunks_seen = true;
                Report
            }
            (Report, Parent, Body::PublishCommit(_)) if self.chunks_seen => Publishing,
            (Collecting, Worker, Body::Record(_) | Body::ItemError(_) | Body::Progress(_)) => {
                Collecting
            }
            (Collecting, Worker, Body::Done(Done::Collect { .. })) => Terminal,
            (Publishing, Worker, Body::Progress(_)) => Publishing,
            (Publishing, Worker, Body::Done(Done::Publish { .. })) => Terminal,
            (AwaitReady, Worker, Body::Done(Done::Collect { outcome, .. }))
                if outcome.status != CollectorStatus::Complete
                    && outcome.accepted_records == 0
                    && outcome.errors == 0
                    && outcome.stop_reason.is_some_and(|c| c != Code::NotRequested) =>
            {
                Terminal
            }
            (
                PublishReady | Report,
                Worker,
                Body::Done(Done::Publish {
                    code: StatusCode::Error(code),
                    sha256: None,
                    byte_length: None,
                    created_identity: None,
                }),
            ) if *code != Code::NotRequested => Terminal,
            // A cancelled transfer can terminate without receiving its remaining
            // bytes, but only a failure outcome (checked separately) is valid.
            (_, Worker, Body::Done(done)) if self.cancelled && self.matches(done) => Terminal,
            _ => return Err(Code::WorkerProtocol),
        };
        Ok(())
    }
    fn matches(&self, done: &Done) -> bool {
        matches!(
            (self.job, done),
            (Some(Job::Collect), Done::Collect { .. }) | (Some(Job::Publish), Done::Publish { .. })
        )
    }
    /// Completion of protocol ordering, not successful collection/publication.
    /// EOF before Done is a worker failure, even if framing ended cleanly.
    pub fn finish(&mut self) -> Result<(), Code> {
        let result = match self.phase {
            Phase::Terminal => Ok(()),
            Phase::Closed => Err(Code::WorkerProtocol),
            _ => Err(Code::WorkerFailed),
        };
        self.phase = Phase::Closed;
        result
    }
}
