use jocky_shared::collection::{Code, identity::UtcTime, inputs::Limits};

#[derive(Clone, Debug)]
pub struct ClockReading {
    pub utc: UtcTime,
    pub monotonic_ms: u64,
}
pub trait Clock {
    fn read(&mut self) -> Result<ClockReading, Code>;
}

#[derive(Debug)]
pub struct Lifetime {
    last: ClockReading,
    expiry: UtcTime,
    expiry_ms: u64,
    deadline_ms: u64,
    cutoff_ms: u64,
    stopped: Option<Code>,
}
impl Lifetime {
    pub fn new(limits: &Limits, start: ClockReading, expiry: UtcTime) -> Result<Self, Code> {
        super::budget::validate_limits(limits)?;
        let left = expiry.unix_nanos() - start.utc.unix_nanos();
        if left < 6_000_000_000 {
            return Err(Code::AuthorisationExpired);
        }
        let remaining = u64::try_from(left / 1_000_000).map_err(|_| Code::ResourceLimit)?;
        let expiry_ms = start
            .monotonic_ms
            .checked_add(remaining)
            .ok_or(Code::ResourceLimit)?;
        let deadline_ms = start
            .monotonic_ms
            .checked_add(limits.timeout_ms)
            .ok_or(Code::ResourceLimit)?;
        let cutoff_ms = (deadline_ms - 6000).min(expiry_ms);
        Ok(Self {
            last: start,
            expiry,
            expiry_ms,
            deadline_ms,
            cutoff_ms,
            stopped: None,
        })
    }
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    pub const fn evidence_cutoff_ms(&self) -> u64 {
        self.cutoff_ms
    }
    pub const fn stop_reason(&self) -> Option<Code> {
        self.stopped
    }
    pub fn check(&mut self, now: &ClockReading, cancelled: bool) -> Result<(), Code> {
        if let Some(code) = self.stopped {
            return Err(code);
        }
        let reason = if now.monotonic_ms < self.last.monotonic_ms
            || now.utc.unix_nanos() < self.last.utc.unix_nanos()
        {
            Some(Code::ClockUncertain)
        } else if cancelled {
            Some(Code::Cancelled)
        } else if now.utc.unix_nanos() >= self.expiry.unix_nanos() {
            Some(Code::AuthorisationExpired)
        } else {
            let projected =
                u64::try_from((self.expiry.unix_nanos() - now.utc.unix_nanos()) / 1_000_000)
                    .ok()
                    .and_then(|remaining| now.monotonic_ms.checked_add(remaining));
            match projected {
                None => Some(Code::ResourceLimit),
                Some(projected) => {
                    self.expiry_ms = self.expiry_ms.min(projected);
                    self.cutoff_ms = self.cutoff_ms.min(self.expiry_ms);
                    if now.monotonic_ms >= self.expiry_ms {
                        Some(Code::AuthorisationExpired)
                    } else if now.monotonic_ms >= self.cutoff_ms {
                        Some(Code::Timeout)
                    } else {
                        None
                    }
                }
            }
        };
        self.last = now.clone();
        self.stopped = reason;
        reason.map_or(Ok(()), Err)
    }

    /// Local report finalization may continue after evidence stops, including
    /// authority expiry, but can never renew the original whole-run deadline.
    /// This grants no source permit and does not clear a stopped collection.
    pub fn check_finalization(&mut self, now: &ClockReading) -> Result<(), Code> {
        if now.monotonic_ms < self.last.monotonic_ms {
            self.stopped = Some(Code::ClockUncertain);
            return Err(Code::ClockUncertain);
        }
        if now.monotonic_ms >= self.deadline_ms {
            return Err(Code::Timeout);
        }
        if now.utc.unix_nanos() < self.last.utc.unix_nanos() {
            self.stopped = Some(Code::ClockUncertain);
        }
        self.last = now.clone();
        Ok(())
    }
}
