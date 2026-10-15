use jocky_shared::collection::{Code, inputs::Limits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Counter {
    Records,
    ReportBytes,
    SourceBytes,
    Errors,
    Entries,
    IndicatorComparisons,
    StagingBytes,
    RetainedBytes,
}
impl Counter {
    pub const ALL: [Self; 8] = [
        Self::Records,
        Self::ReportBytes,
        Self::SourceBytes,
        Self::Errors,
        Self::Entries,
        Self::IndicatorComparisons,
        Self::StagingBytes,
        Self::RetainedBytes,
    ];
}

#[derive(Debug)]
pub struct Budget {
    limits: Limits,
    used: [u64; 8],
    narrowed: Option<[u64; 8]>,
}
impl Budget {
    pub fn new(limits: Limits) -> Result<Self, Code> {
        validate_limits(&limits)?;
        Ok(Self {
            limits,
            used: [0; 8],
            narrowed: None,
        })
    }
    pub fn maximum(&self, counter: Counter) -> u64 {
        if let Some(ceilings) = self.narrowed {
            return ceilings[counter as usize];
        }
        match counter {
            Counter::Records => self.limits.max_records,
            Counter::ReportBytes => self.limits.max_report_bytes,
            Counter::SourceBytes => self.limits.max_source_bytes,
            Counter::Errors => self.limits.max_errors,
            Counter::Entries => self.limits.max_entries,
            Counter::IndicatorComparisons => self.limits.max_indicator_comparisons,
            Counter::StagingBytes => self.limits.max_staging_bytes,
            Counter::RetainedBytes => self.limits.max_memory_bytes,
        }
    }
    /// Narrow worker-local ceilings atomically; never refund charges or reset
    /// scope/time. This is not the parent's pre-launch reservation ledger.
    pub fn narrow_work(
        &mut self,
        allowance: &jocky_shared::collection::launch::WorkAllowance,
    ) -> Result<(), Code> {
        let ceilings = [
            allowance.records,
            allowance.report_bytes,
            allowance.source_bytes,
            allowance.errors,
            allowance.entries,
            allowance.indicator_comparisons,
            allowance.staging_bytes,
            allowance.retained_bytes,
        ];
        for (counter, ceiling) in Counter::ALL.into_iter().zip(ceilings) {
            if ceiling > self.maximum(counter) {
                return Err(Code::ScopeDenied);
            }
            if ceiling < self.used(counter) {
                return Err(Code::ResourceLimit);
            }
        }
        self.narrowed = Some(ceilings);
        Ok(())
    }
    pub fn used(&self, counter: Counter) -> u64 {
        self.used[counter as usize]
    }
    pub fn charge(&mut self, counter: Counter, amount: u64) -> Result<(), Code> {
        self.charge_many(&[(counter, amount)])
    }
    /// Reserve a bounded operation's costs before doing work. Either every
    /// charge fits or none is admitted; earlier work is never refunded. Duplicate
    /// counters accumulate, and at most eight entries can be submitted per call.
    pub fn charge_many(&mut self, charges: &[(Counter, u64)]) -> Result<(), Code> {
        if charges.len() > Counter::ALL.len() {
            return Err(Code::ResourceLimit);
        }
        let mut next = self.used;
        for &(counter, amount) in charges {
            let value = &mut next[counter as usize];
            *value = value
                .checked_add(amount)
                .filter(|value| *value <= self.maximum(counter))
                .ok_or(Code::ResourceLimit)?;
        }
        self.used = next;
        Ok(())
    }
    pub fn require_item(&self, bytes: u64) -> Result<(), Code> {
        if bytes > self.limits.max_item_bytes {
            Err(Code::ResourceLimit)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn values(l: &Limits) -> [u64; 13] {
    [
        l.max_records,
        l.max_report_bytes,
        l.max_source_bytes,
        l.max_file_bytes,
        l.max_item_bytes,
        l.max_errors,
        l.max_entries,
        l.max_depth,
        l.max_indicator_comparisons,
        l.timeout_ms,
        l.operation_timeout_ms,
        l.max_staging_bytes,
        l.max_memory_bytes,
    ]
}
pub(crate) fn validate_limits(l: &Limits) -> Result<(), Code> {
    let maxima = [
        10000, 10485760, 67108864, 16777216, 65536, 1000, 20000, 16, 10000000, 60000, 2000,
        83886080, 268435456,
    ];
    if values(l)
        .iter()
        .zip(maxima)
        .any(|(n, max)| *n == 0 || *n > max)
        || l.timeout_ms < 10000
    {
        Err(Code::InvalidInput)
    } else {
        Ok(())
    }
}
