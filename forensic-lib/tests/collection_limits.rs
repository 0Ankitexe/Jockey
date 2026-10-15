use jocky_forensic::collection::{
    ClockReading,
    budget::{Budget, Counter},
    clock::Lifetime,
};
use jocky_shared::collection::{Code, identity::UtcTime, inputs::Limits};

fn limits() -> Limits {
    let request: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/valid/collection/request.json")).unwrap();
    serde_json::from_value(request["limits"].clone()).unwrap()
}
fn reading(ms: u64, utc: &str) -> ClockReading {
    ClockReading {
        monotonic_ms: ms,
        utc: UtcTime::parse(utc).unwrap(),
    }
}

#[test]
fn every_cumulative_counter_accepts_boundary_and_rejects_plus_one_without_refund() {
    for counter in Counter::ALL {
        let mut budget = Budget::new(limits()).unwrap();
        let maximum = budget.maximum(counter);
        budget.charge(counter, maximum).unwrap();
        assert_eq!(budget.used(counter), maximum);
        assert_eq!(budget.charge(counter, 1), Err(Code::ResourceLimit));
        assert_eq!(budget.used(counter), maximum);
        assert_eq!(budget.charge(counter, u64::MAX), Err(Code::ResourceLimit));
    }
}

#[test]
fn hard_limits_and_per_item_limits_cannot_be_widened() {
    let mut value = limits();
    value.max_records = 10001;
    assert!(matches!(Budget::new(value), Err(Code::InvalidInput)));
    let mut value = limits();
    value.timeout_ms = 9999;
    assert!(matches!(Budget::new(value), Err(Code::InvalidInput)));
    let mut value = limits();
    value.max_item_bytes = 0;
    assert!(matches!(Budget::new(value), Err(Code::InvalidInput)));
    let budget = Budget::new(limits()).unwrap();
    assert_eq!(budget.require_item(65536), Ok(()));
    assert_eq!(budget.require_item(65537), Err(Code::ResourceLimit));
}

#[test]
fn whole_deadline_has_a_single_six_second_reserve() {
    let start = reading(1000, "2020-01-01T00:00:00Z");
    let mut clock = Lifetime::new(
        &limits(),
        start,
        UtcTime::parse("2020-01-01T01:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(clock.deadline_ms(), 61000);
    assert_eq!(clock.evidence_cutoff_ms(), 55000);
    assert_eq!(
        clock.check(&reading(54999, "2020-01-01T00:00:53.999Z"), false),
        Ok(())
    );
    assert_eq!(
        clock.check(&reading(55000, "2020-01-01T00:00:54Z"), false),
        Err(Code::Timeout)
    );
    assert_eq!(
        clock.check(&reading(55001, "2020-01-01T00:00:54.001Z"), false),
        Err(Code::Timeout)
    );
    assert_eq!(clock.deadline_ms(), 61000);
}

#[test]
fn expiry_forward_jump_rollback_and_cancellation_are_sticky() {
    for (next, cancel, expected) in [
        (
            reading(1, "2020-01-01T01:00:00Z"),
            false,
            Code::AuthorisationExpired,
        ),
        (
            reading(1, "2019-12-31T23:59:59Z"),
            false,
            Code::ClockUncertain,
        ),
        (
            reading(1, "2020-01-01T00:00:00.001Z"),
            true,
            Code::Cancelled,
        ),
    ] {
        let mut clock = Lifetime::new(
            &limits(),
            reading(0, "2020-01-01T00:00:00Z"),
            UtcTime::parse("2020-01-01T01:00:00Z").unwrap(),
        )
        .unwrap();
        assert_eq!(clock.check(&next, cancel), Err(expected));
        assert_eq!(
            clock.check(&reading(2, "2020-01-01T00:00:00.002Z"), false),
            Err(expected)
        );
    }
    let mut clock = Lifetime::new(
        &limits(),
        reading(1000, "2020-01-01T00:00:00Z"),
        UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
    )
    .unwrap();
    assert_eq!(clock.evidence_cutoff_ms(), 11000);
    clock
        .check(&reading(1001, "2020-01-01T00:00:05Z"), false)
        .unwrap();
    assert_eq!(clock.evidence_cutoff_ms(), 6001);
    assert_eq!(
        clock.check(&reading(1000, "2020-01-01T00:00:05Z"), false),
        Err(Code::ClockUncertain)
    );
}

#[test]
fn insufficient_validity_and_monotonic_overflow_fail_closed() {
    assert!(matches!(
        Lifetime::new(
            &limits(),
            reading(0, "2020-01-01T00:00:00Z"),
            UtcTime::parse("2020-01-01T00:00:05Z").unwrap()
        ),
        Err(Code::AuthorisationExpired)
    ));
    assert!(matches!(
        Lifetime::new(
            &limits(),
            reading(u64::MAX, "2020-01-01T00:00:00Z"),
            UtcTime::parse("2020-01-01T01:00:00Z").unwrap()
        ),
        Err(Code::ResourceLimit)
    ));
}

#[test]
fn projection_overflow_is_a_permanent_stop_not_a_retryable_clock_error() {
    let start = reading(0, "2020-01-01T00:00:00Z");
    let mut clock = Lifetime::new(
        &limits(),
        start.clone(),
        UtcTime::parse("2020-01-01T01:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(
        clock.check(&reading(u64::MAX, "2020-01-01T00:00:01Z"), false),
        Err(Code::ResourceLimit)
    );
    assert_eq!(clock.stop_reason(), Some(Code::ResourceLimit));
    assert_eq!(clock.check(&start, false), Err(Code::ResourceLimit));
}

#[test]
fn outcome_precedence_is_deterministic_and_never_hides_failed_cleanup() {
    use jocky_forensic::collection::outcome::{summarize, unsupported};
    use jocky_shared::collection::{
        outcomes::{Collector, CollectorStatus},
        report::{SummaryStatus, WorkerCleanup},
    };
    let one = unsupported(Collector::System);
    assert_eq!(
        summarize(std::slice::from_ref(&one), None, WorkerCleanup::NotStarted)
            .unwrap()
            .status,
        SummaryStatus::Failed
    );
    let mut two = unsupported(Collector::Processes);
    two.status = CollectorStatus::Failed;
    two.stop_reason = Some(Code::Cancelled);
    assert_eq!(
        summarize(&[one.clone(), two.clone()], None, WorkerCleanup::Complete)
            .unwrap()
            .stop_reason,
        Some(Code::Cancelled)
    );
    assert_eq!(
        summarize(
            &[one.clone(), two.clone()],
            Some(Code::Timeout),
            WorkerCleanup::Incomplete
        )
        .unwrap()
        .stop_reason,
        Some(Code::CleanupIncomplete)
    );
    assert_eq!(
        summarize(
            &[one.clone(), two],
            Some(Code::PublicationFailed),
            WorkerCleanup::Complete
        )
        .unwrap()
        .stop_reason,
        Some(Code::PublicationFailed)
    );
    assert_eq!(
        summarize(&[], None, WorkerCleanup::Complete).unwrap_err(),
        Code::InvalidInput
    );
    assert_eq!(
        summarize(&[one.clone(), one], None, WorkerCleanup::Complete).unwrap_err(),
        Code::InvalidInput
    );
}

#[test]
fn all_thirteen_limit_fields_reject_zero_and_hard_cap_plus_one() {
    let value = serde_json::to_value(limits()).unwrap();
    for (key, maximum) in value.as_object().unwrap() {
        for bad in [0, maximum.as_u64().unwrap() + 1] {
            let mut changed = value.clone();
            changed[key] = serde_json::json!(bad);
            assert!(
                matches!(
                    Budget::new(serde_json::from_value(changed).unwrap()),
                    Err(Code::InvalidInput)
                ),
                "{key}={bad}"
            );
        }
    }
}

#[test]
fn multi_counter_admission_is_atomic_bounded_and_has_no_refunds() {
    let mut budget = Budget::new(limits()).unwrap();
    let charges = Counter::ALL.map(|counter| (counter, budget.maximum(counter)));
    budget.charge_many(&charges).unwrap();
    for counter in Counter::ALL {
        assert_eq!(budget.used(counter), budget.maximum(counter));
    }
    assert_eq!(
        budget.charge_many(&[(Counter::Records, 1)]),
        Err(Code::ResourceLimit)
    );
    assert!(budget.charge_many(&[]).is_ok());

    let mut budget = Budget::new(limits()).unwrap();
    budget.charge(Counter::SourceBytes, 10).unwrap();
    for failing in [
        vec![(Counter::Entries, 1), (Counter::SourceBytes, u64::MAX)],
        vec![
            (Counter::Entries, 1),
            (Counter::Entries, budget.maximum(Counter::Entries)),
        ],
        vec![(Counter::Entries, 0); 9],
    ] {
        assert_eq!(budget.charge_many(&failing), Err(Code::ResourceLimit));
        assert_eq!(budget.used(Counter::Entries), 0);
        assert_eq!(budget.used(Counter::SourceBytes), 10);
    }
    budget
        .charge_many(&[(Counter::Entries, 2), (Counter::Entries, 3)])
        .unwrap();
    assert_eq!(budget.used(Counter::Entries), 5);
}

#[path = "support/limit_cases.rs"]
mod limit_cases;

#[test]
fn contract_limit_matrix_covers_every_configurable_and_static_boundary() {
    let cases = limit_cases::hard_limits();
    assert_eq!(cases.len(), 13);
    for case in &cases {
        let mut value = serde_json::to_value(limits()).unwrap();
        value[case.field] = serde_json::json!(case.exact);
        assert!(
            Budget::new(serde_json::from_value(value.clone()).unwrap()).is_ok(),
            "{}",
            case.field
        );
        value[case.field] = serde_json::json!(case.plus_one);
        assert!(
            matches!(
                Budget::new(serde_json::from_value(value).unwrap()),
                Err(Code::InvalidInput)
            ),
            "{}",
            case.field
        );
    }
    let static_cases = limit_cases::static_bounds();
    assert_eq!(static_cases.len(), 16);
    assert!(
        static_cases
            .iter()
            .all(|case| case.plus_one == case.exact + 1)
    );
}

#[test]
fn document_byte_depth_and_indicator_caps_have_real_decoder_boundaries() {
    use jocky_shared::collection::{DecodeReason, DocumentKind, decode};
    let static_cases = limit_cases::static_bounds();
    let role = static_cases
        .iter()
        .find(|case| case.field == "configuration_bytes_per_role")
        .unwrap();
    let indicator = static_cases
        .iter()
        .find(|case| case.field == "indicator_bytes")
        .unwrap();
    for (kind, boundary) in [
        (DocumentKind::Request, role),
        (DocumentKind::Indicators, indicator),
    ] {
        let exact = vec![b' '; boundary.exact as usize];
        assert_ne!(decode(kind, &exact).unwrap_err().reason, DecodeReason::Size);
        let over = vec![b' '; boundary.plus_one as usize];
        assert_eq!(decode(kind, &over).unwrap_err().reason, DecodeReason::Size);
    }
    let depth = static_cases
        .iter()
        .find(|case| case.field == "depth")
        .unwrap();
    for (count, expected) in [
        (depth.exact, DecodeReason::Schema),
        (depth.plus_one, DecodeReason::Depth),
    ] {
        let raw = format!(
            "{}0{}",
            "[".repeat(count as usize),
            "]".repeat(count as usize)
        );
        assert_eq!(
            decode(DocumentKind::Request, raw.as_bytes())
                .unwrap_err()
                .reason,
            expected
        );
    }
}

#[test]
fn source_path_and_indicator_arrays_accept_exact_maximum_and_reject_one_more() {
    use jocky_shared::collection::{DocumentKind, decode};
    let uuid = |n: usize| format!("10000000-0000-4000-8000-{n:012x}");
    let cases = [
        (DocumentKind::Request, "source_ids", 64usize),
        (DocumentKind::Request, "paths", 256),
        (DocumentKind::Policy, "sources", 64),
        (DocumentKind::Indicators, "indicators", 1000),
    ];
    for (kind, field, maximum) in cases {
        let fixture = match kind {
            DocumentKind::Request => include_str!("../../fixtures/valid/collection/request.json"),
            DocumentKind::Policy => include_str!("../../fixtures/valid/collection/policy.json"),
            DocumentKind::Indicators => {
                include_str!("../../fixtures/valid/collection/indicator-set.json")
            }
            _ => unreachable!(),
        };
        let mut value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let entries: Vec<serde_json::Value> = (1..=maximum + 1)
            .map(|i| match field {
                "source_ids" => serde_json::json!(uuid(i)),
                "paths" => serde_json::json!({"root_id":uuid(90),"relative_path":format!("file-{i}")}),
                "sources" => serde_json::json!({"source_id":uuid(i),"kind":"kernel_profile"}),
                _ => serde_json::json!({"indicator_id":uuid(i),"kind":"sha256","value":"0".repeat(64)}),
            })
            .collect();
        value[field] = serde_json::json!(&entries[..maximum]);
        let exact = serde_json::to_vec(&value).unwrap();
        assert!(decode(kind, &exact).is_ok(), "{field} exact");
        value[field] = serde_json::json!(entries);
        let over = serde_json::to_vec(&value).unwrap();
        assert!(decode(kind, &over).is_err(), "{field} +1");
    }
}

#[test]
fn root_grant_array_accepts_sixteen_disjoint_roots_and_denies_seventeen() {
    use jocky_shared::collection::{DocumentKind, decode};
    let mut authority: serde_json::Value = serde_json::from_str(include_str!(
        "../../fixtures/valid/collection/authorisation.json"
    ))
    .unwrap();
    let roots: Vec<_> = (0..17)
        .map(|index| {
            serde_json::json!({
                "root_id": format!("10000000-0000-4000-8000-{index:012x}"),
                "absolute_path": format!("/synthetic/owned-{index}"),
                "purposes": ["files"]
            })
        })
        .collect();
    authority["scope"]["roots"] = serde_json::json!(&roots[..16]);
    assert!(
        decode(
            DocumentKind::Authorisation,
            &serde_json::to_vec(&authority).unwrap()
        )
        .is_ok()
    );
    authority["scope"]["roots"] = serde_json::json!(roots);
    assert!(
        decode(
            DocumentKind::Authorisation,
            &serde_json::to_vec(&authority).unwrap()
        )
        .is_err()
    );
}
