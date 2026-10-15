use jocky_shared::collection::{
    Code,
    outcomes::{Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState},
    report::{SummaryStatus, WorkerCleanup},
};

pub fn unsupported(collector: Collector) -> CollectorOutcome {
    CollectorOutcome {
        collector,
        status: CollectorStatus::Unsupported,
        coverage: Vec::new(),
        accepted_records: 0,
        omitted_records: None,
        omitted_reason: Some(Code::Unsupported),
        errors: 0,
        stop_reason: Some(Code::Unsupported),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutcomeSummary {
    pub status: SummaryStatus,
    pub stop_reason: Option<Code>,
    pub accepted_records: u64,
    pub errors: u64,
    pub omitted_known: u64,
    pub omitted_unknown: bool,
}

/// Deterministic precedence within the documented classes; enum order breaks ties.
/// NotRequested describes optional absence, never an execution failure.
pub fn priority(code: Code) -> (u8, Code) {
    let rank = match code {
        Code::CleanupIncomplete => 5,
        Code::PublicationFailed | Code::OutputExists => 4,
        Code::AuthorisationExpired
        | Code::AuthorisationDenied
        | Code::MissingAuthorisation
        | Code::ScopeDenied
        | Code::Cancelled
        | Code::Timeout
        | Code::ResourceLimit
        | Code::ClockUncertain => 3,
        Code::NotRequested => 0,
        _ => 1,
    };
    (rank, code)
}

pub(crate) fn coverage(value: &Coverage) -> Result<(), Code> {
    let valid = match value.state {
        FacilityState::Supported => value.reason.is_none(),
        FacilityState::PermissionDenied => value.reason == Some(Code::PermissionDenied),
        FacilityState::Unsupported => {
            matches!(value.reason, Some(Code::Unsupported | Code::NotImplemented))
        }
        FacilityState::Unavailable | FacilityState::Partial => {
            value.reason.is_some_and(|c| c != Code::NotRequested)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(Code::InvalidInput)
    }
}

/// Reconcile bounded outcomes, not evidence truth. The report verifier separately
/// checks records, unavailable fields, source coverage and error identities.
pub fn summarize(
    outcomes: &[CollectorOutcome],
    stop: Option<Code>,
    cleanup: WorkerCleanup,
) -> Result<OutcomeSummary, Code> {
    if stop == Some(Code::NotRequested)
        || outcomes.is_empty()
        || outcomes.len() > 9
        || outcomes
            .windows(2)
            .any(|p| p[0].collector >= p[1].collector)
    {
        return Err(Code::InvalidInput);
    }
    let mut result = OutcomeSummary {
        status: SummaryStatus::Complete,
        stop_reason: stop,
        accepted_records: 0,
        errors: 0,
        omitted_known: 0,
        omitted_unknown: false,
    };
    let mut reasons = Vec::with_capacity(29);
    reasons.extend(stop);
    if cleanup == WorkerCleanup::Incomplete {
        reasons.push(Code::CleanupIncomplete);
    }
    let mut complete = true;
    for value in outcomes {
        if value.stop_reason == Some(Code::NotRequested)
            || value.omitted_reason == Some(Code::NotRequested)
            || value.coverage.len() > 256
            || value.accepted_records > 10000
            || value.errors > 1000
            || value.omitted_records.is_some_and(|n| n > 9007199254740991)
        {
            return Err(Code::InvalidInput);
        }
        let mut ids = std::collections::BTreeSet::new();
        for item in &value.coverage {
            coverage(item)?;
            if !ids.insert(&item.source_id) {
                return Err(Code::InvalidInput);
            }
            reasons.extend(item.reason);
        }
        if value.omitted_records != Some(0) && value.omitted_reason.is_none() {
            return Err(Code::InvalidInput);
        }
        let failure = value.errors > 0
            || value.omitted_records != Some(0)
            || value.omitted_reason.is_some()
            || value.stop_reason.is_some()
            || value
                .coverage
                .iter()
                .any(|c| c.state != FacilityState::Supported);
        let valid = match value.status {
            CollectorStatus::Complete => !failure && !value.coverage.is_empty(),
            CollectorStatus::Partial => value.accepted_records > 0 && failure,
            CollectorStatus::Unsupported => {
                value.accepted_records == 0
                    && matches!(
                        value.stop_reason,
                        Some(Code::Unsupported | Code::NotImplemented)
                    )
            }
            CollectorStatus::PermissionDenied => {
                value.accepted_records == 0 && value.stop_reason == Some(Code::PermissionDenied)
            }
            CollectorStatus::Unavailable | CollectorStatus::Failed => {
                value.accepted_records == 0
                    && value.stop_reason.is_some_and(|c| c != Code::NotRequested)
            }
        };
        if !valid {
            return Err(Code::InvalidInput);
        }
        complete &= value.status == CollectorStatus::Complete;
        result.accepted_records += value.accepted_records;
        result.errors += value.errors;
        result.omitted_known = result
            .omitted_known
            .checked_add(value.omitted_records.unwrap_or(0))
            .filter(|v| *v <= 9007199254740991)
            .ok_or(Code::InvalidInput)?;
        result.omitted_unknown |= value.omitted_records.is_none();
        reasons.extend(value.stop_reason);
        reasons.extend(value.omitted_reason);
    }
    if result.accepted_records > 10000 || result.errors > 1000 {
        return Err(Code::InvalidInput);
    }
    result.stop_reason = reasons.into_iter().max_by_key(|c| priority(*c));
    complete &= result.stop_reason.is_none_or(|c| c == Code::NotRequested);
    result.status = if complete {
        SummaryStatus::Complete
    } else if result.accepted_records == 0 {
        SummaryStatus::Failed
    } else {
        SummaryStatus::Partial
    };
    Ok(result)
}
