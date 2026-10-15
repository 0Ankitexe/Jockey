//! Bounded scheduling only. Actions must be applied to an owned process handle;
//! this never proves an actual stop/reap or extends collection authority.
use jocky_shared::collection::Code;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Cancel(Code),
    Wait,
    KillOwned,
    Reaped,
    Incomplete,
}
enum Phase {
    Initial,
    Cooperative,
    Killing,
    Reaped,
    Failed,
}
pub(crate) struct StopSchedule {
    last: u64,
    deadline: u64,
    cooperative_until: u64,
    reap_until: u64,
    cause: Code,
    phase: Phase,
}
impl StopSchedule {
    pub fn new(now: u64, deadline: u64, cause: Code) -> Result<Self, Code> {
        if !matches!(
            cause,
            Code::Cancelled
                | Code::AuthorisationExpired
                | Code::Timeout
                | Code::ResourceLimit
                | Code::ClockUncertain
        ) {
            return Err(Code::InvalidInput);
        }
        if now >= deadline {
            return Err(Code::Timeout);
        }
        let cooperative_until = now.saturating_add(2000).min(deadline.saturating_sub(4000));
        let reap_until = cooperative_until
            .saturating_add(1000)
            .min(deadline.saturating_sub(3000));
        Ok(Self {
            last: now,
            deadline,
            cooperative_until,
            reap_until,
            cause,
            phase: Phase::Initial,
        })
    }
    pub fn finalization_deadline(&self) -> u64 {
        self.deadline
    }
    pub fn poll(&mut self, now: u64, reaped: bool) -> Result<Action, Code> {
        if matches!(self.phase, Phase::Failed) {
            return Err(Code::CleanupIncomplete);
        }
        if matches!(self.phase, Phase::Reaped) {
            return Err(Code::WorkerProtocol);
        }
        if now < self.last {
            self.phase = Phase::Failed;
            return Err(Code::ClockUncertain);
        }
        self.last = now;
        if reaped {
            self.phase = Phase::Reaped;
            return Ok(Action::Reaped);
        }
        if now >= self.deadline {
            self.phase = Phase::Failed;
            return Ok(Action::Incomplete);
        }
        match self.phase {
            Phase::Initial => {
                self.phase = Phase::Cooperative;
                Ok(Action::Cancel(self.cause))
            }
            Phase::Cooperative if now >= self.cooperative_until => {
                self.phase = Phase::Killing;
                Ok(Action::KillOwned)
            }
            Phase::Killing if now >= self.reap_until => {
                self.phase = Phase::Failed;
                Ok(Action::Incomplete)
            }
            _ => Ok(Action::Wait),
        }
    }
}
