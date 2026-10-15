//! Adapt pure matches over admitted records into supplied-set evidence.
use jocky_forensic::collection::{
    ValidatedCollectionContext,
    budget::Counter,
    clock::Clock,
    context::OperationTarget,
    indicator_match::{Completeness, evaluate},
};
use jocky_shared::collection::{
    Code,
    identity::{ClockBasis, TimeObservation},
    outcomes::{Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState},
    records::{Adapter, Category, ForensicRecord, Payload, ProvenanceKind, SourceScope},
};

pub(crate) fn adapt(
    context: &ValidatedCollectionContext,
    prior: &[ForensicRecord],
    completeness: Completeness,
    clock: &mut dyn Clock,
) -> Result<(Vec<ForensicRecord>, CollectorOutcome, u64), Code> {
    let set = context.indicators().ok_or(Code::ScopeDenied)?;
    let input = context
        .input_provenance()
        .indicators
        .as_ref()
        .ok_or(Code::InvalidInput)?;
    let evaluation = evaluate(
        set,
        prior,
        completeness,
        context.limits().max_indicator_comparisons,
        context
            .limits()
            .max_records
            .saturating_sub(prior.len() as u64) as usize,
    )?;
    {
        let mut permit = context.permit(OperationTarget::Indicators, &clock.read()?, false)?;
        permit.charge(Counter::IndicatorComparisons, evaluation.comparisons)?;
        permit.charge(Counter::Records, evaluation.matches.len() as u64)?;
    }
    let mut records = Vec::with_capacity(evaluation.matches.len());
    for matched in evaluation.matches {
        let now = clock.read()?;
        context.check_active(&now, false)?;
        let observed = TimeObservation {
            value: now.utc,
            basis: ClockBasis::LocalClock,
            uncertainty_ms: None,
            clock_uncertain: false,
        };
        let mut record = super::record::make(
            context,
            Collector::Indicators,
            Adapter::Indicators,
            Category::Indicator,
            ProvenanceKind::SuppliedIndicatorSet,
            input.id.clone(),
            SourceScope::Indicators {
                indicator_set_id: input.id.clone(),
            },
            Payload::Indicator(matched.clone()),
            prior.len() as u64 + records.len() as u64,
            observed,
        )?;
        record.provenance.indicator_set_sha256 = Some(input.sha256.clone());
        record.provenance.rules_version = Some(matched.rules_version);
        records.push(record);
    }
    let complete = evaluation.unevaluated.is_empty();
    let count = records.len() as u64;
    Ok((
        records,
        CollectorOutcome {
            collector: Collector::Indicators,
            status: if complete {
                CollectorStatus::Complete
            } else if count > 0 {
                CollectorStatus::Partial
            } else {
                CollectorStatus::Unavailable
            },
            coverage: vec![Coverage {
                source_id: input.id.clone(),
                state: if complete {
                    FacilityState::Supported
                } else if count > 0 {
                    FacilityState::Partial
                } else {
                    FacilityState::Unavailable
                },
                reason: (!complete).then_some(Code::FacilityUnavailable),
            }],
            accepted_records: count,
            omitted_records: Some(evaluation.unevaluated.len() as u64),
            omitted_reason: (!complete).then_some(Code::FacilityUnavailable),
            errors: 0,
            stop_reason: (!complete).then_some(Code::FacilityUnavailable),
        },
        evaluation.comparisons,
    ))
}
