use jocky_forensic::collection::{
    ClockReading, InputSet, ValidatedCollectionContext, admit, budget::Counter, clock::Clock,
    context::OperationTarget, report,
};
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    report::{ReportKind, WorkerCleanup},
};
struct Frozen(ClockReading);
impl Clock for Frozen {
    fn read(&mut self) -> Result<ClockReading, Code> {
        Ok(self.0.clone())
    }
}
fn now() -> ClockReading {
    ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        monotonic_ms: 0,
    }
}
fn source() -> Uuid {
    Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap()
}
fn context() -> ValidatedCollectionContext {
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

#[test]
fn every_counter_snapshot_and_available_quota_reconcile_without_reserving() {
    let ctx = context();
    let source = source();
    for counter in Counter::ALL {
        assert_eq!(ctx.charged(counter), Ok(0));
        let mut permit = ctx
            .permit(OperationTarget::Source(&source), &now(), false)
            .unwrap();
        let maximum = permit.remaining(counter).unwrap();
        assert_eq!(permit.remaining(counter).unwrap(), maximum);
        permit.charge(counter, 1).unwrap();
        assert_eq!(permit.remaining(counter), Ok(maximum - 1));
        drop(permit);
        assert_eq!(ctx.charged(counter), Ok(1));
    }
}

#[test]
fn snapshot_during_an_active_operation_returns_typed_borrow_conflict() {
    let ctx = context();
    let source = source();
    let permit = ctx
        .permit(OperationTarget::Source(&source), &now(), false)
        .unwrap();
    assert_eq!(ctx.charged(Counter::SourceBytes), Err(Code::ResourceLimit));
    drop(permit);
    assert_eq!(ctx.charged(Counter::SourceBytes), Ok(0));
}

#[test]
fn stopped_quota_is_unavailable_but_charged_work_remains_observable() {
    let ctx = context();
    let source = source();
    let mut permit = ctx
        .permit(OperationTarget::Source(&source), &now(), false)
        .unwrap();
    let maximum = permit.remaining(Counter::SourceBytes).unwrap();
    permit.charge(Counter::SourceBytes, maximum).unwrap();
    assert_eq!(permit.remaining(Counter::SourceBytes), Ok(0));
    assert_eq!(
        permit.charge(Counter::SourceBytes, 1),
        Err(Code::ResourceLimit)
    );
    assert_eq!(permit.remaining(Counter::Records), Err(Code::ResourceLimit));
    drop(permit);
    assert_eq!(ctx.charged(Counter::SourceBytes), Ok(maximum));
    assert!(matches!(
        ctx.permit(OperationTarget::Source(&source), &now(), false),
        Err(Code::ResourceLimit)
    ));
}

#[test]
fn cancellation_does_not_erase_charges_or_let_snapshots_renew_authority() {
    let ctx = context();
    let source = source();
    let mut permit = ctx
        .permit(OperationTarget::Source(&source), &now(), false)
        .unwrap();
    permit.charge(Counter::Entries, 2).unwrap();
    assert_eq!(permit.renew(&now(), true), Err(Code::Cancelled));
    assert_eq!(permit.remaining(Counter::SourceBytes), Err(Code::Cancelled));
    assert_eq!(permit.require_item(1), Err(Code::Cancelled));
    drop(permit);
    assert_eq!(ctx.charged(Counter::Entries), Ok(2));
    assert!(matches!(
        ctx.permit(OperationTarget::Source(&source), &now(), false),
        Err(Code::Cancelled)
    ));
}

#[test]
fn item_size_checks_obey_policy_without_refunding_or_stopping_other_items() {
    let ctx = context();
    let source = source();
    let mut permit = ctx
        .permit(OperationTarget::Source(&source), &now(), false)
        .unwrap();
    assert_eq!(permit.require_item(ctx.limits().max_item_bytes), Ok(()));
    assert_eq!(
        permit.require_item(ctx.limits().max_item_bytes + 1),
        Err(Code::ResourceLimit)
    );
    assert_eq!(permit.require_item(1), Ok(()));
    permit.charge(Counter::SourceBytes, 1).unwrap();
    drop(permit);
    assert_eq!(ctx.charged(Counter::SourceBytes), Ok(1));
}

#[test]
fn failed_report_serialization_is_charged_once_and_bound_to_its_context() {
    let ctx = context();
    let report = report::failure(
        &ctx,
        ReportKind::SyntheticTest,
        ctx.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let mut wrong = report.clone();
    wrong.context.case_id = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    assert_eq!(
        ctx.finalize_report(wrong, &mut Frozen(now())),
        Err(Code::ScopeDenied)
    );
    assert_eq!(ctx.charged(Counter::ReportBytes), Ok(0));
    let bytes = ctx
        .finalize_report(report.clone(), &mut Frozen(now()))
        .unwrap();
    assert!(jocky_forensic::collection::verify::verify_report(&bytes).is_ok());
    assert_eq!(
        ctx.charged(Counter::ReportBytes),
        Ok(ctx.failure_report_reserve() as u64)
    );
    assert_eq!(
        ctx.finalize_report(report, &mut Frozen(now())),
        Err(Code::ResourceLimit)
    );
}

#[test]
fn report_finalization_after_evidence_cutoff_uses_remaining_whole_run_deadline() {
    let ctx = context();
    let report = report::failure(
        &ctx,
        ReportKind::SyntheticTest,
        ctx.started_at().clone(),
        Code::Timeout,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let mut finalization = Frozen(ClockReading {
        utc: UtcTime::parse("2020-01-01T00:01:05Z").unwrap(),
        monotonic_ms: 55_000,
    });
    assert!(
        ctx.finalize_report(report.clone(), &mut finalization)
            .is_ok()
    );
    let other = context();
    finalization.0.monotonic_ms = 60_000;
    finalization.0.utc = UtcTime::parse("2020-01-01T00:01:10Z").unwrap();
    assert_eq!(
        other.finalize_report(report, &mut finalization),
        Err(Code::Timeout)
    );
    assert_eq!(other.charged(Counter::ReportBytes), Ok(0));
}

#[test]
fn failed_normal_serialization_keeps_its_charge_and_preserves_terminal_reserve() {
    use jocky_shared::collection::report::SummaryStatus;
    let ctx = context();
    let terminal = report::failure(
        &ctx,
        ReportKind::SyntheticTest,
        ctx.started_at().clone(),
        Code::ResourceLimit,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let mut inconsistent = terminal.clone();
    inconsistent.summary.status = SummaryStatus::Partial;
    assert!(
        ctx.finalize_report(inconsistent, &mut Frozen(now()))
            .is_err()
    );
    assert_eq!(
        ctx.charged(Counter::ReportBytes),
        Ok(ctx.limits().max_report_bytes - ctx.failure_report_reserve() as u64)
    );
    assert!(ctx.finalize_report(terminal, &mut Frozen(now())).is_ok());
    assert_eq!(
        ctx.charged(Counter::ReportBytes),
        Ok(ctx.limits().max_report_bytes)
    );
}
