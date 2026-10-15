use jocky_forensic::collection::{
    ClockReading, InputSet, admit_for_invocation, context::OperationTarget,
};
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
};
fn reading(ms: u64, utc: &str) -> ClockReading {
    ClockReading {
        utc: UtcTime::parse(utc).unwrap(),
        monotonic_ms: ms,
    }
}
fn inputs() -> InputSet<'static> {
    InputSet {
        designation: include_bytes!("../../fixtures/valid/collection/endpoint-designation.json"),
        authorisation: Some(include_bytes!(
            "../../fixtures/valid/collection/authorisation.json"
        )),
        policy: include_bytes!("../../fixtures/valid/collection/policy.json"),
        request: include_bytes!("../../fixtures/valid/collection/request.json"),
        indicators: None,
    }
}
fn source() -> Uuid {
    Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap()
}

#[test]
fn admission_keeps_original_start_and_charges_configuration_elapsed_time() {
    let start = reading(1000, "2020-01-01T00:00:00Z");
    let now = reading(51000, "2020-01-01T00:00:50Z");
    let ctx = admit_for_invocation(inputs(), start.clone(), now.clone()).unwrap();
    assert_eq!(ctx.started_at().value, start.utc);
    assert_eq!(ctx.invocation_start().monotonic_ms, 1000);
    assert_eq!(ctx.invocation_start().utc, start.utc);
    let source = source();
    let permit = ctx
        .permit(OperationTarget::Source(&source), &now, false)
        .unwrap();
    assert_eq!(permit.deadline_ms(), 53000);
    drop(permit);
    let at_cutoff = reading(55000, "2020-01-01T00:00:54Z");
    assert!(matches!(
        ctx.permit(OperationTarget::Source(&source), &at_cutoff, false),
        Err(Code::Timeout)
    ));
}

#[test]
fn supervisor_active_check_is_one_way_and_never_grants_a_source() {
    let fresh = || {
        admit_for_invocation(
            inputs(),
            reading(1000, "2020-01-01T00:00:00Z"),
            reading(2000, "2020-01-01T00:00:01Z"),
        )
        .unwrap()
    };
    let context = fresh();
    assert_eq!(
        context.check_active(&reading(3000, "2020-01-01T00:00:02Z"), false),
        Ok(())
    );
    assert_eq!(
        context.check_active(&reading(4000, "2020-01-01T00:00:03Z"), true),
        Err(Code::Cancelled)
    );
    assert_eq!(
        context.check_active(&reading(5000, "2020-01-01T00:00:04Z"), false),
        Err(Code::Cancelled)
    );
    let context = fresh();
    assert_eq!(
        context.check_active(&reading(55000, "2020-01-01T00:00:54Z"), false),
        Err(Code::Timeout)
    );
    let context = fresh();
    assert_eq!(
        context.check_active(&reading(3000, "2019-12-31T23:59:59Z"), false),
        Err(Code::ClockUncertain)
    );
}

#[test]
fn full_timeout_is_not_restarted_after_slow_configuration() {
    for elapsed in [54000, 60000, 60001] {
        assert!(matches!(
            admit_for_invocation(
                inputs(),
                reading(0, "2020-01-01T00:00:00Z"),
                reading(elapsed, "2020-01-01T00:01:00Z")
            ),
            Err(Code::Timeout)
        ));
    }
}

#[test]
fn future_origin_and_clock_rollback_cannot_extend_authority() {
    for start in [
        reading(2, "2020-01-01T00:00:00Z"),
        reading(0, "2020-01-01T00:00:20Z"),
    ] {
        assert!(matches!(
            admit_for_invocation(inputs(), start, reading(1, "2020-01-01T00:00:10Z")),
            Err(Code::ClockUncertain)
        ));
    }
}

#[test]
fn current_expiry_and_current_valid_from_checks_still_precede_collection() {
    assert!(matches!(
        admit_for_invocation(
            inputs(),
            reading(0, "2020-01-01T00:00:00Z"),
            reading(1, "2020-01-01T01:00:00Z")
        ),
        Err(Code::AuthorisationExpired)
    ));
    assert!(matches!(
        admit_for_invocation(
            inputs(),
            reading(0, "2019-12-31T23:59:59Z"),
            reading(1, "2019-12-31T23:59:59Z")
        ),
        Err(Code::AuthorisationDenied)
    ));
}

#[test]
fn earlier_origin_is_not_a_grant_to_collect_before_valid_from() {
    let start = reading(0, "2019-12-31T23:59:59Z");
    let now = reading(2000, "2020-01-01T00:00:01Z");
    assert!(admit_for_invocation(inputs(), start, now).is_ok());
    // The context can be admitted now while retaining the earlier invocation
    // timestamp. Its sources still need current operation permits.
}

#[test]
fn finalization_uses_original_deadline_without_restoring_evidence_permits() {
    let source = source();
    let ctx = admit_for_invocation(
        inputs(),
        reading(1000, "2020-01-01T00:00:00Z"),
        reading(51000, "2020-01-01T00:00:50Z"),
    )
    .unwrap();
    let cutoff = reading(55000, "2020-01-01T00:00:54Z");
    assert_eq!(
        ctx.permit(OperationTarget::Source(&source), &cutoff, false)
            .err(),
        Some(Code::Timeout)
    );
    assert_eq!(
        ctx.check_finalization(&reading(59000, "2020-01-01T00:00:58Z")),
        Ok(())
    );
    assert_eq!(
        ctx.permit(
            OperationTarget::Source(&source),
            &reading(59000, "2020-01-01T00:00:58Z"),
            false
        )
        .err(),
        Some(Code::Timeout)
    );
    assert_eq!(
        ctx.check_finalization(&reading(61000, "2020-01-01T00:01:00Z")),
        Err(Code::Timeout)
    );
}

#[test]
fn finalization_rejects_monotonic_rollback() {
    let ctx = admit_for_invocation(
        inputs(),
        reading(1000, "2020-01-01T00:00:00Z"),
        reading(5000, "2020-01-01T00:00:04Z"),
    )
    .unwrap();
    assert_eq!(
        ctx.check_finalization(&reading(4999, "2020-01-01T00:00:05Z")),
        Err(Code::ClockUncertain)
    );
}

#[test]
fn wall_clock_rollback_can_finalize_but_stops_all_new_evidence() {
    let ctx = admit_for_invocation(
        inputs(),
        reading(1000, "2020-01-01T00:00:00Z"),
        reading(5000, "2020-01-01T00:00:04Z"),
    )
    .unwrap();
    let rolled_back = reading(6000, "2020-01-01T00:00:03Z");
    assert_eq!(ctx.check_finalization(&rolled_back), Ok(()));
    let selected = source();
    assert_eq!(
        ctx.permit(OperationTarget::Source(&selected), &rolled_back, false)
            .err(),
        Some(Code::ClockUncertain)
    );
}
