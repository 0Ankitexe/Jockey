use super::{
    ClockReading,
    budget::{Budget, Counter},
    clock::Lifetime,
    inputs::{ApprovedPath, ApprovedSource, DecodedInputs},
    policy::EffectiveScope,
};
use jocky_shared::collection::{
    Code,
    identity::{ClockBasis, TimeObservation, Uuid},
    inputs::{Limits, PathRef},
    records::LocalContext,
    report::{CollectionReport, SummaryStatus},
};
use std::{
    cell::{RefCell, RefMut},
    fmt,
};

/// Sealed admission result. Raw deserialized DTOs cannot construct this context.
///
/// ```compile_fail
/// use jocky_forensic::collection::ValidatedCollectionContext;
/// let context = ValidatedCollectionContext {};
/// ```
pub struct ValidatedCollectionContext {
    pub(crate) input: DecodedInputs,
    scope: EffectiveScope,
    identity: LocalContext,
    provenance: jocky_shared::collection::report::Inputs,
    start: TimeObservation,
    origin: ClockReading,
    failure_reserve: usize,
    runtime: RefCell<Runtime>,
}
struct Runtime {
    budget: Budget,
    lifetime: Lifetime,
    stopped: Option<Code>,
    normal_report_attempted: bool,
    failure_report_attempted: bool,
}
impl fmt::Debug for ValidatedCollectionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedCollectionContext")
            .field("collection_id", &self.identity.collection_id)
            .field("endpoint_id", &self.identity.endpoint_id)
            .finish_non_exhaustive()
    }
}
impl ValidatedCollectionContext {
    pub(crate) fn new(
        input: DecodedInputs,
        scope: EffectiveScope,
        identity: LocalContext,
        budget: Budget,
        lifetime: Lifetime,
        start: ClockReading,
    ) -> Result<Self, Code> {
        let provenance = super::inputs::provenance(&input)?;
        let mut context = Self {
            input,
            scope,
            identity,
            provenance,
            start: TimeObservation {
                value: start.utc.clone(),
                basis: ClockBasis::LocalClock,
                uncertainty_ms: None,
                clock_uncertain: false,
            },
            origin: start,
            failure_reserve: 0,
            runtime: RefCell::new(Runtime {
                budget,
                lifetime,
                stopped: None,
                normal_report_attempted: false,
                failure_report_attempted: false,
            }),
        };
        use jocky_shared::collection::report::{ReportKind, WorkerCleanup};
        let longest = Code::ALL
            .iter()
            .copied()
            .filter(|c| *c != Code::NotRequested)
            .max_by_key(|c| c.as_str().len())
            .ok_or(Code::InvalidInput)?;
        let failure = super::report::failure(
            &context,
            ReportKind::SyntheticTest,
            context.start.clone(),
            longest,
            WorkerCleanup::NotStarted,
        )?;
        // Bounded early-failure envelope plus room for timestamp precision changes.
        context.failure_reserve = super::report::finalize(failure, 65536)?
            .len()
            .checked_add(128)
            .filter(|v| *v <= 65536)
            .ok_or(Code::ResourceLimit)?;
        if context.failure_reserve as u64 > context.limits().max_report_bytes {
            return Err(Code::ResourceLimit);
        }
        Ok(context)
    }
    pub fn identity(&self) -> &LocalContext {
        &self.identity
    }
    pub fn limits(&self) -> &Limits {
        &self.input.request.limits
    }
    /// Apply a worker-local allowance without changing input provenance or
    /// deadline. Zero means no permitted work, never unlimited. The supervisor
    /// must separately reserve this allowance before spawning its owned child.
    pub fn restrict_work(
        &self,
        allowance: &jocky_shared::collection::launch::WorkAllowance,
    ) -> Result<(), Code> {
        let mut state = self
            .runtime
            .try_borrow_mut()
            .map_err(|_| Code::ResourceLimit)?;
        if let Some(code) = state.stopped.or(state.lifetime.stop_reason()) {
            return Err(code);
        }
        let result = state.budget.narrow_work(allowance);
        if let Err(code) = result {
            state.stopped = Some(code);
        }
        result
    }
    /// Recheck the original invocation before a supervisor sends or accepts
    /// more evidence traffic. This is a stop check, not a source permit.
    pub fn check_active(&self, now: &ClockReading, cancelled: bool) -> Result<(), Code> {
        let mut state = self
            .runtime
            .try_borrow_mut()
            .map_err(|_| Code::ResourceLimit)?;
        if let Some(code) = state.stopped {
            return Err(code);
        }
        let result = state.lifetime.check(now, cancelled);
        if let Err(code) = result {
            state.stopped = Some(code);
        }
        result
    }
    /// Immutable accounting for finalization, including after a stop. Reading
    /// it neither clears the stop nor renews evidence authority.
    pub fn charged(&self, counter: Counter) -> Result<u64, Code> {
        let runtime = self.runtime.try_borrow().map_err(|_| Code::ResourceLimit)?;
        Ok(runtime.budget.used(counter))
    }
    pub fn sources(&self) -> &[ApprovedSource] {
        &self.scope.sources
    }
    pub fn paths(&self) -> &[ApprovedPath] {
        &self.scope.paths
    }
    /// Inert admitted path metadata, never a native handle or a fresh permit.
    /// Fixed proc/kernel/bus facilities and unselected paths have no ordinary root.
    pub fn path_scope(&self, target: OperationTarget<'_>) -> Result<ApprovedPath, Code> {
        use jocky_shared::collection::inputs::SourceRef;
        match target {
            OperationTarget::File(path) => self
                .scope
                .paths
                .iter()
                .find(|p| p.path() == path)
                .cloned()
                .ok_or(Code::ScopeDenied),
            OperationTarget::Source(id) => {
                let source = self
                    .scope
                    .sources
                    .iter()
                    .find(|s| s.definition().id() == id)
                    .ok_or(Code::ScopeDenied)?;
                let path = match source.definition() {
                    SourceRef::JournalFile { path, .. }
                    | SourceRef::TextLog { path, .. }
                    | SourceRef::StartupDirectory { path, .. } => path,
                    _ => return Err(Code::ScopeDenied),
                };
                let root = self
                    .input
                    .policy
                    .scope
                    .roots
                    .iter()
                    .find(|r| r.root_id == path.root_id)
                    .ok_or(Code::ScopeDenied)?;
                Ok(ApprovedPath {
                    root: root.clone(),
                    path: path.clone(),
                })
            }
            OperationTarget::Indicators => Err(Code::ScopeDenied),
        }
    }
    pub fn input_provenance(&self) -> &jocky_shared::collection::report::Inputs {
        &self.provenance
    }
    pub fn started_at(&self) -> &TimeObservation {
        &self.start
    }
    /// Original invocation clock pair, preserved across admission. Copying this
    /// metadata does not transfer native permissions or authenticate a worker.
    pub fn invocation_start(&self) -> &ClockReading {
        &self.origin
    }
    pub fn failure_report_reserve(&self) -> usize {
        self.failure_reserve
    }
    /// Serialize a report against this invocation's one-way byte ledger.
    /// The entire allowed attempt is reserved before serialization so failed
    /// encoding and later clock faults cannot silently refund work. A bounded
    /// failure envelope remains available after a normal report attempt.
    pub fn finalize_report(
        &self,
        report: CollectionReport,
        clock: &mut dyn super::clock::Clock,
    ) -> Result<Vec<u8>, Code> {
        if report.context != self.identity || report.inputs != self.provenance {
            return Err(Code::ScopeDenied);
        }
        self.check_finalization(&clock.read()?)?;
        // A failed collection can still contain admitted observations. Only
        // the no-observation terminal envelope may consume the small reserve.
        let failed = report.summary.status == SummaryStatus::Failed
            && report.records.is_empty()
            && report.errors.is_empty();
        let maximum = if failed {
            self.failure_reserve as u64
        } else {
            self.limits()
                .max_report_bytes
                .checked_sub(self.failure_reserve as u64)
                .ok_or(Code::ResourceLimit)?
        };
        let mut runtime = self
            .runtime
            .try_borrow_mut()
            .map_err(|_| Code::ResourceLimit)?;
        if if failed {
            runtime.failure_report_attempted
        } else {
            runtime.normal_report_attempted
        } {
            return Err(Code::ResourceLimit);
        }
        runtime.budget.charge(Counter::ReportBytes, maximum)?;
        if failed {
            runtime.failure_report_attempted = true;
        } else {
            runtime.normal_report_attempted = true;
        }
        drop(runtime);
        let encoded = super::report::finalize(
            report,
            usize::try_from(maximum).map_err(|_| Code::ResourceLimit)?,
        );
        self.check_finalization(&clock.read()?)?;
        encoded
    }
    /// Output-only finalization clock check. It can be used after evidence
    /// cutoff or cancellation, but never grants a new source operation permit.
    pub fn check_finalization(&self, now: &ClockReading) -> Result<(), Code> {
        self.runtime
            .try_borrow_mut()
            .map_err(|_| Code::ResourceLimit)?
            .lifetime
            .check_finalization(now)
    }
    pub(crate) fn empty_report_usage(
        &self,
    ) -> Result<jocky_shared::collection::outcomes::WorkUsed, Code> {
        let runtime = self.runtime.try_borrow().map_err(|_| Code::ResourceLimit)?;
        let used = |counter| runtime.budget.used(counter);
        if used(Counter::Records) != 0 {
            return Err(Code::InvalidInput);
        }
        Ok(jocky_shared::collection::outcomes::WorkUsed {
            entries: used(Counter::Entries),
            indicator_comparisons: used(Counter::IndicatorComparisons),
            errors: used(Counter::Errors),
            source_bytes: used(Counter::SourceBytes),
            staging_bytes: used(Counter::StagingBytes),
            retained_bytes: used(Counter::RetainedBytes),
        })
    }
    pub fn event_window(&self) -> &jocky_shared::collection::inputs::UtcWindow {
        &self.input.request.event_window
    }
    pub fn indicators(&self) -> Option<super::indicators::ValidatedIndicatorSet<'_>> {
        self.input
            .indicators
            .as_ref()
            .map(|set| super::indicators::ValidatedIndicatorSet {
                collection_id: &self.identity.collection_id,
                set,
            })
    }
    /// A permit borrows the unique accounting state for one bounded operation.
    /// Renew at each chunk; renewal never restarts the operation's deadline.
    pub fn permit<'a>(
        &'a self,
        target: OperationTarget<'a>,
        now: &ClockReading,
        cancelled: bool,
    ) -> Result<OperationPermit<'a>, Code> {
        let admitted = match target {
            OperationTarget::Source(id) => self.scope.sources.iter().any(|s| s.0.id() == id),
            OperationTarget::File(path) => self.scope.paths.iter().any(|p| &p.path == path),
            OperationTarget::Indicators => self.input.indicators.is_some(),
        };
        if !admitted {
            return Err(Code::ScopeDenied);
        }
        let mut state = self
            .runtime
            .try_borrow_mut()
            .map_err(|_| Code::ResourceLimit)?;
        if let Some(code) = state.stopped {
            return Err(code);
        }
        state.lifetime.check(now, cancelled)?;
        let remaining = state.lifetime.evidence_cutoff_ms() - now.monotonic_ms;
        // The duration is <= remaining, so this sum cannot exceed the already
        // checked global cutoff or overflow, even near u64::MAX.
        let deadline_ms = now.monotonic_ms + remaining.min(self.limits().operation_timeout_ms);
        Ok(OperationPermit {
            state,
            target,
            deadline_ms,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OperationTarget<'a> {
    Source(&'a Uuid),
    File(&'a PathRef),
    Indicators,
}
pub struct OperationPermit<'a> {
    state: RefMut<'a, Runtime>,
    target: OperationTarget<'a>,
    deadline_ms: u64,
}
impl OperationPermit<'_> {
    /// Validate a bounded item's declared size against the admitted policy.
    /// Unlike global budget exhaustion, an oversized individual item need not
    /// prohibit other admitted items; the caller must record its omission.
    pub fn require_item(&self, bytes: u64) -> Result<(), Code> {
        if let Some(code) = self.state.stopped.or(self.state.lifetime.stop_reason()) {
            return Err(code);
        }
        self.state.budget.require_item(bytes)
    }
    /// Available pre-admission quota. This is not a reservation: charge actual
    /// completed work before the next operation and check time/cancellation too.
    pub fn remaining(&self, counter: Counter) -> Result<u64, Code> {
        if let Some(code) = self.state.stopped.or(self.state.lifetime.stop_reason()) {
            return Err(code);
        }
        Ok(self.state.budget.maximum(counter) - self.state.budget.used(counter))
    }
    pub fn target(&self) -> OperationTarget<'_> {
        self.target
    }
    /// Monotonic cutoff to pass to a native timed operation. The adapter must
    /// still renew before/after I/O; this value itself is not OS cancellation.
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
            .min(self.state.lifetime.evidence_cutoff_ms())
    }
    pub fn renew(&mut self, now: &ClockReading, cancelled: bool) -> Result<(), Code> {
        if let Some(code) = self.state.stopped {
            return Err(code);
        }
        self.state.lifetime.check(now, cancelled)?;
        if now.monotonic_ms >= self.deadline_ms() {
            self.state.stopped = Some(Code::Timeout);
            return Err(Code::Timeout);
        }
        Ok(())
    }
    pub fn charge(&mut self, counter: Counter, amount: u64) -> Result<(), Code> {
        self.charge_many(&[(counter, amount)])
    }
    /// All-or-nothing pre-admission; failure permanently stops this context.
    /// Charge work already done separately before attempting another operation.
    pub fn charge_many(&mut self, charges: &[(Counter, u64)]) -> Result<(), Code> {
        if let Some(code) = self.state.stopped.or(self.state.lifetime.stop_reason()) {
            return Err(code);
        }
        let result = self.state.budget.charge_many(charges);
        if let Err(code) = result {
            self.state.stopped = Some(code);
        }
        result
    }
}
