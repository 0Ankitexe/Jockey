//! Worker allowance narrowing is pure accounting, never process admission.
use jocky_forensic::collection::{
    ClockReading, InputSet, admit, budget::Counter, context::OperationTarget,
};
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    launch::WorkAllowance,
};

fn now() -> ClockReading {
    ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        monotonic_ms: 0,
    }
}
fn context() -> jocky_forensic::collection::ValidatedCollectionContext {
    admit(
        InputSet {
            designation: include_bytes!(
                "../../fixtures/valid/collection/endpoint-designation.json"
            ),
            authorisation: Some(include_bytes!(
                "../../fixtures/valid/collection/authorisation.json"
            )),
            policy: include_bytes!("../../fixtures/valid/collection/policy.json"),
            request: include_bytes!("../../fixtures/valid/collection/request.json"),
            indicators: None,
        },
        now(),
    )
    .unwrap()
}
fn allowance() -> WorkAllowance {
    WorkAllowance {
        records: 2,
        report_bytes: 3,
        source_bytes: 4,
        errors: 5,
        entries: 6,
        indicator_comparisons: 7,
        staging_bytes: 8,
        retained_bytes: 9,
    }
}
fn source() -> Uuid {
    Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap()
}

#[test]
fn every_reserved_counter_replaces_only_its_ceiling_not_wire_limits_or_provenance() {
    let ctx = context();
    let fingerprint = ctx.input_provenance().clone();
    let original = ctx.limits().clone();
    ctx.restrict_work(&allowance()).unwrap();
    let id = source();
    let permit = ctx
        .permit(OperationTarget::Source(&id), &now(), false)
        .unwrap();
    for (counter, expected) in Counter::ALL.into_iter().zip(2..=9) {
        assert_eq!(permit.remaining(counter), Ok(expected));
    }
    drop(permit);
    assert_eq!(ctx.limits(), &original);
    assert_eq!(ctx.input_provenance(), &fingerprint);
    assert_eq!(ctx.invocation_start().monotonic_ms, 0);
}

#[test]
fn narrowing_keeps_charged_work_and_cannot_reopen_or_refund_exhausted_quota() {
    let ctx = context();
    let id = source();
    let mut permit = ctx
        .permit(OperationTarget::Source(&id), &now(), false)
        .unwrap();
    permit.charge(Counter::SourceBytes, 2).unwrap();
    drop(permit);
    ctx.restrict_work(&allowance()).unwrap();
    let mut permit = ctx
        .permit(OperationTarget::Source(&id), &now(), false)
        .unwrap();
    assert_eq!(permit.remaining(Counter::SourceBytes), Ok(2));
    permit.charge(Counter::SourceBytes, 2).unwrap();
    assert_eq!(
        permit.charge(Counter::SourceBytes, 1),
        Err(Code::ResourceLimit)
    );
    drop(permit);
    assert_eq!(ctx.charged(Counter::SourceBytes), Ok(4));
    assert_eq!(ctx.restrict_work(&allowance()), Err(Code::ResourceLimit));
}

#[test]
fn zero_allowance_is_not_an_implicit_unlimited_budget() {
    for counter in Counter::ALL {
        let ctx = context();
        let id = source();
        let mut a = allowance();
        a.records = 0;
        a.report_bytes = 0;
        a.source_bytes = 0;
        a.errors = 0;
        a.entries = 0;
        a.indicator_comparisons = 0;
        a.staging_bytes = 0;
        a.retained_bytes = 0;
        ctx.restrict_work(&a).unwrap();
        let mut permit = ctx
            .permit(OperationTarget::Source(&id), &now(), false)
            .unwrap();
        assert_eq!(permit.remaining(counter), Ok(0));
        assert_eq!(permit.charge(counter, 1), Err(Code::ResourceLimit));
    }
}

#[test]
fn widening_or_narrowing_below_completed_work_fails_closed_without_erasing_usage() {
    for widen in [true, false] {
        let ctx = context();
        let id = source();
        let mut permit = ctx
            .permit(OperationTarget::Source(&id), &now(), false)
            .unwrap();
        permit.charge(Counter::SourceBytes, 3).unwrap();
        drop(permit);
        ctx.restrict_work(&allowance()).unwrap();
        let mut a = allowance();
        a.source_bytes = if widen { 5 } else { 2 };
        let expected = if widen {
            Code::ScopeDenied
        } else {
            Code::ResourceLimit
        };
        assert_eq!(ctx.restrict_work(&a), Err(expected));
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(3));
        assert!(
            matches!(ctx.permit(OperationTarget::Source(&id), &now(), false), Err(code) if code == expected)
        );
    }
}

#[test]
fn active_permit_conflict_and_cancelled_context_cannot_be_reconfigured() {
    let ctx = context();
    let id = source();
    let mut permit = ctx
        .permit(OperationTarget::Source(&id), &now(), false)
        .unwrap();
    assert_eq!(ctx.restrict_work(&allowance()), Err(Code::ResourceLimit));
    permit.renew(&now(), true).unwrap_err();
    drop(permit);
    assert_eq!(ctx.restrict_work(&allowance()), Err(Code::Cancelled));
}
