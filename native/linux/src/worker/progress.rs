//! Validate cumulative worker acknowledgements. This does not reserve quota or
//! justify refunding an unobserved allowance after worker loss.
use jocky_forensic::collection::budget::Budget;
use jocky_shared::collection::{Code, inputs::Limits, outcomes::WorkUsed};

pub(crate) struct ProgressTracker {
    maximum: WorkUsed,
    last: WorkUsed,
    closed: bool,
}
impl ProgressTracker {
    pub fn for_allowance(
        limits: &Limits,
        allowance: &jocky_shared::collection::launch::WorkAllowance,
    ) -> Result<Self, Code> {
        let mut budget = Budget::new(limits.clone())?;
        budget.narrow_work(allowance)?;
        Ok(Self {
            maximum: WorkUsed {
                entries: allowance.entries,
                indicator_comparisons: allowance.indicator_comparisons,
                errors: allowance.errors,
                source_bytes: allowance.source_bytes,
                staging_bytes: allowance.staging_bytes,
                retained_bytes: allowance.retained_bytes,
            },
            last: WorkUsed {
                entries: 0,
                indicator_comparisons: 0,
                errors: 0,
                source_bytes: 0,
                staging_bytes: 0,
                retained_bytes: 0,
            },
            closed: false,
        })
    }
    /// Limits must be the supervisor's already reserved allowance for this job.
    pub fn new(reserved: &Limits) -> Result<Self, Code> {
        Budget::new(reserved.clone())?;
        Ok(Self {
            maximum: WorkUsed {
                entries: reserved.max_entries,
                indicator_comparisons: reserved.max_indicator_comparisons,
                errors: reserved.max_errors,
                source_bytes: reserved.max_source_bytes,
                staging_bytes: reserved.max_staging_bytes,
                retained_bytes: reserved.max_memory_bytes,
            },
            last: WorkUsed {
                entries: 0,
                indicator_comparisons: 0,
                errors: 0,
                source_bytes: 0,
                staging_bytes: 0,
                retained_bytes: 0,
            },
            closed: false,
        })
    }
    pub fn last(&self) -> &WorkUsed {
        &self.last
    }
    pub fn observe(&mut self, usage: &WorkUsed) -> Result<WorkUsed, Code> {
        if self.closed {
            return Err(Code::WorkerProtocol);
        }
        let current = values(usage);
        let previous = values(&self.last);
        let maximum = values(&self.maximum);
        if (0..6).any(|i| current[i] < previous[i] || current[i] > maximum[i]) {
            self.closed = true;
            return Err(Code::WorkerProtocol);
        }
        let delta = WorkUsed {
            entries: usage.entries - self.last.entries,
            indicator_comparisons: usage.indicator_comparisons - self.last.indicator_comparisons,
            errors: usage.errors - self.last.errors,
            source_bytes: usage.source_bytes - self.last.source_bytes,
            staging_bytes: usage.staging_bytes - self.last.staging_bytes,
            retained_bytes: usage.retained_bytes - self.last.retained_bytes,
        };
        self.last = usage.clone();
        Ok(delta)
    }
    /// Check final accounting after separately validating Done's outcome/counts.
    /// The caller must charge the returned delta before retaining the reply.
    pub fn finish(&mut self, usage: &WorkUsed, delivered_errors: u64) -> Result<WorkUsed, Code> {
        if self.closed || usage.errors < delivered_errors {
            self.closed = true;
            return Err(Code::WorkerProtocol);
        }
        let result = self.observe(usage);
        self.closed = true;
        result
    }
}
fn values(v: &WorkUsed) -> [u64; 6] {
    [
        v.entries,
        v.indicator_comparisons,
        v.errors,
        v.source_bytes,
        v.staging_bytes,
        v.retained_bytes,
    ]
}
