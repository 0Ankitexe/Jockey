//! Parent-side worker reservation ledger. It neither authenticates a worker nor
//! grants a collection permit. The supervisor owns this ledger across jobs.
use jocky_forensic::collection::budget::Budget;
use jocky_shared::collection::{Code, inputs::Limits, launch::WorkAllowance, outcomes::WorkUsed};

#[derive(Clone)]
pub(crate) struct Acknowledged {
    pub records: u64,
    pub report_bytes: u64,
    pub work: WorkUsed,
}

pub(crate) struct ReservationLedger {
    maxima: [u64; 8],
    committed: [u64; 8],
    active: Option<[u64; 8]>,
}

impl ReservationLedger {
    pub fn new(limits: Limits) -> Result<Self, Code> {
        Budget::new(limits.clone())?;
        Ok(Self {
            maxima: [
                limits.max_records,
                limits.max_report_bytes,
                limits.max_source_bytes,
                limits.max_errors,
                limits.max_entries,
                limits.max_indicator_comparisons,
                limits.max_staging_bytes,
                limits.max_memory_bytes,
            ],
            committed: [0; 8],
            active: None,
        })
    }

    /// Hold the publisher's allowance before any collector starts. A lost
    /// collector can burn its entire partition without consuming the terminal
    /// report and output-worker reserve.
    pub fn with_publisher_reserve(limits: Limits, publisher: &WorkAllowance) -> Result<Self, Code> {
        let mut ledger = Self::new(limits)?;
        for (maximum, reserved) in ledger.maxima.iter_mut().zip(costs(publisher)) {
            *maximum = maximum.checked_sub(reserved).ok_or(Code::ResourceLimit)?;
        }
        Ok(ledger)
    }

    pub fn reserve(&mut self, allowance: &WorkAllowance) -> Result<(), Code> {
        if self.active.is_some() {
            return Err(Code::WorkerProtocol);
        }
        let requested = costs(allowance);
        if (0..8).any(|i| {
            self.committed[i]
                .checked_add(requested[i])
                .is_none_or(|sum| sum > self.maxima[i])
        }) {
            return Err(Code::ResourceLimit);
        }
        self.active = Some(requested);
        Ok(())
    }

    /// A completed, validated Done acknowledgement releases only its observed
    /// unused allowance. The caller must have validated identity and final
    /// cumulative counters before invoking this method.
    pub fn acknowledge(&mut self, actual: Acknowledged) -> Result<(), Code> {
        let reserved = self.active.take().ok_or(Code::WorkerProtocol)?;
        let observed = [
            actual.records,
            actual.report_bytes,
            actual.work.source_bytes,
            actual.work.errors,
            actual.work.entries,
            actual.work.indicator_comparisons,
            actual.work.staging_bytes,
            actual.work.retained_bytes,
        ];
        // A malformed acknowledgement burns the entire allowance just like a
        // lost worker; it cannot create a later retry budget.
        let trustworthy = (0..8).all(|i| observed[i] <= reserved[i]);
        self.commit(if trustworthy { observed } else { reserved });
        if trustworthy {
            Ok(())
        } else {
            Err(Code::WorkerProtocol)
        }
    }

    /// Crash, timeout, protocol fault or uncertain exit consumes all unobserved
    /// allowance. An owned child being reaped is a separate supervisor duty.
    pub fn lost(&mut self) -> Result<(), Code> {
        let reserved = self.active.take().ok_or(Code::WorkerProtocol)?;
        self.commit(reserved);
        Ok(())
    }

    fn commit(&mut self, amounts: [u64; 8]) {
        for (used, amount) in self.committed.iter_mut().zip(amounts) {
            *used += amount;
        }
    }

    pub fn remaining_records(&self) -> u64 {
        self.remaining(0)
    }
    pub fn remaining_report_bytes(&self) -> u64 {
        self.remaining(1)
    }
    pub fn remaining_source_bytes(&self) -> u64 {
        self.remaining(2)
    }
    fn remaining(&self, index: usize) -> u64 {
        self.maxima[index] - self.committed[index] - self.active.map_or(0, |held| held[index])
    }
}

fn costs(allowance: &WorkAllowance) -> [u64; 8] {
    [
        allowance.records,
        allowance.report_bytes,
        allowance.source_bytes,
        allowance.errors,
        allowance.entries,
        allowance.indicator_comparisons,
        allowance.staging_bytes,
        allowance.retained_bytes,
    ]
}

/// Publisher-local conservative charge ledger. It is deliberately separate
/// from the worker's source allowance: evidence reads cannot borrow the 64-KiB
/// terminal failure envelope or the disk staging ceiling.
pub(crate) struct PublicationQuota {
    report_limit: u64,
    staging_limit: u64,
    report_charged: u64,
    failure_charged: u64,
    staging_charged: u64,
    errors: u64,
    error_limit: u64,
    summary_emitted: bool,
}

impl PublicationQuota {
    pub fn new(limits: &Limits) -> Result<Self, Code> {
        Budget::new(limits.clone())?;
        if limits.max_report_bytes < 65_536 {
            return Err(Code::ResourceLimit);
        }
        Ok(Self {
            report_limit: limits.max_report_bytes,
            staging_limit: limits.max_staging_bytes.min(83_886_080),
            report_charged: 0,
            failure_charged: 0,
            staging_charged: 0,
            errors: 0,
            error_limit: limits.max_errors.min(1000),
            summary_emitted: false,
        })
    }

    /// Charge serialization attempts before allocating the output buffer. The
    /// failure reserve remains unavailable to normal reports until completion.
    pub fn charge_report(&mut self, bytes: u64) -> Result<(), Code> {
        Self::advance(&mut self.report_charged, bytes, self.report_limit - 65_536)
    }

    /// The reserved envelope is for a verified failed report only. Attempts
    /// are charged separately and cannot be borrowed by a normal result.
    pub fn charge_failure_report(&mut self, bytes: u64) -> Result<(), Code> {
        Self::advance(&mut self.failure_charged, bytes, 65_536)
    }

    /// Staging attempts, including short or failed writes, are never refunded.
    pub fn charge_staging(&mut self, bytes: u64) -> Result<(), Code> {
        Self::advance(&mut self.staging_charged, bytes, self.staging_limit)
    }

    pub fn charge_error(&mut self) -> Result<(), Code> {
        Self::advance(&mut self.errors, 1, self.error_limit)
    }

    /// Exactly one bounded omission summary is permitted after the error cap.
    pub fn omission_summary(&mut self) -> Result<(), Code> {
        if self.errors != self.error_limit || self.summary_emitted {
            return Err(Code::WorkerProtocol);
        }
        self.summary_emitted = true;
        Ok(())
    }

    pub fn charged(&self) -> (u64, u64, u64) {
        (self.report_charged, self.staging_charged, self.errors)
    }
    pub fn failure_charged(&self) -> u64 {
        self.failure_charged
    }

    fn advance(used: &mut u64, amount: u64, maximum: u64) -> Result<(), Code> {
        *used = used
            .checked_add(amount)
            .filter(|next| *next <= maximum)
            .ok_or(Code::ResourceLimit)?;
        Ok(())
    }
}
