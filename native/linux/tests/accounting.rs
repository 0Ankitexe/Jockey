//! Parent-side reservations are pure bookkeeping; these tests launch no worker.
#[allow(dead_code)]
#[path = "../src/worker/accounting.rs"]
mod accounting;
#[path = "../../../forensic-lib/tests/support/limit_cases.rs"]
mod limit_cases;

use accounting::{Acknowledged, PublicationQuota, ReservationLedger};
use jocky_shared::collection::{Code, launch::decode_launch, outcomes::WorkUsed};

fn example() -> (
    jocky_shared::collection::inputs::Limits,
    jocky_shared::collection::launch::WorkAllowance,
) {
    let launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    (launch.global_limits, launch.allowance)
}

fn zero_usage() -> WorkUsed {
    WorkUsed {
        entries: 0,
        indicator_comparisons: 0,
        errors: 0,
        source_bytes: 0,
        staging_bytes: 0,
        retained_bytes: 0,
    }
}

#[test]
fn parent_ledger_uses_every_contract_limit_exactly_and_rejects_plus_one() {
    let (limits, _) = example();
    let original = serde_json::to_value(limits).unwrap();
    let cases = limit_cases::hard_limits();
    assert_eq!(cases.len(), 13);
    for case in cases {
        let mut at_limit = original.clone();
        at_limit[case.field] = serde_json::json!(case.exact);
        assert!(
            ReservationLedger::new(serde_json::from_value(at_limit.clone()).unwrap()).is_ok(),
            "{} exact",
            case.field
        );
        at_limit[case.field] = serde_json::json!(case.plus_one);
        assert!(
            matches!(
                ReservationLedger::new(serde_json::from_value(at_limit).unwrap()),
                Err(Code::InvalidInput)
            ),
            "{} +1",
            case.field
        );
    }
}

#[test]
fn only_one_outstanding_reservation_and_overlimit_is_rejected() {
    let (limits, mut allowance) = example();
    let mut ledger = ReservationLedger::new(limits).unwrap();
    allowance.records += 1;
    assert_eq!(ledger.reserve(&allowance), Err(Code::ResourceLimit));
    allowance.records -= 1;
    ledger.reserve(&allowance).unwrap();
    assert_eq!(ledger.reserve(&allowance), Err(Code::WorkerProtocol));
}

#[test]
fn crash_burns_full_unobserved_allowance_without_refund() {
    let (limits, allowance) = example();
    let mut ledger = ReservationLedger::new(limits).unwrap();
    ledger.reserve(&allowance).unwrap();
    ledger.lost().unwrap();
    assert_eq!(ledger.remaining_records(), 0);
    assert_eq!(ledger.reserve(&allowance), Err(Code::ResourceLimit));
    assert_eq!(ledger.lost(), Err(Code::WorkerProtocol));
}

#[test]
fn acknowledged_final_usage_releases_only_proven_unused_allowance() {
    let (limits, allowance) = example();
    let mut ledger = ReservationLedger::new(limits).unwrap();
    ledger.reserve(&allowance).unwrap();
    ledger
        .acknowledge(Acknowledged {
            records: 2,
            report_bytes: 100,
            work: WorkUsed {
                source_bytes: 9,
                ..zero_usage()
            },
        })
        .unwrap();
    assert_eq!(ledger.remaining_records(), allowance.records - 2);
    assert_eq!(ledger.remaining_source_bytes(), allowance.source_bytes - 9);
    assert_eq!(
        ledger.remaining_report_bytes(),
        allowance.report_bytes - 100
    );
    assert_eq!(ledger.lost(), Err(Code::WorkerProtocol));
}

#[test]
fn forged_acknowledgement_consumes_reservation_and_cannot_reopen_quota() {
    let (limits, allowance) = example();
    let mut ledger = ReservationLedger::new(limits).unwrap();
    ledger.reserve(&allowance).unwrap();
    assert_eq!(
        ledger.acknowledge(Acknowledged {
            records: allowance.records + 1,
            report_bytes: 0,
            work: zero_usage(),
        }),
        Err(Code::WorkerProtocol)
    );
    assert_eq!(ledger.remaining_records(), 0);
    assert_eq!(ledger.reserve(&allowance), Err(Code::ResourceLimit));
}

#[test]
fn zero_allowance_does_not_mean_unlimited() {
    let (limits, mut allowance) = example();
    allowance.records = 0;
    allowance.report_bytes = 0;
    allowance.source_bytes = 0;
    allowance.errors = 0;
    allowance.entries = 0;
    allowance.indicator_comparisons = 0;
    allowance.staging_bytes = 0;
    allowance.retained_bytes = 0;
    let mut ledger = ReservationLedger::new(limits).unwrap();
    ledger.reserve(&allowance).unwrap();
    assert_eq!(
        ledger.acknowledge(Acknowledged {
            records: 0,
            report_bytes: 0,
            work: WorkUsed {
                entries: 1,
                ..zero_usage()
            },
        }),
        Err(Code::WorkerProtocol)
    );
}

#[test]
fn publication_reserves_failure_envelope_and_charges_staging_without_refund() {
    let (mut limits, _) = example();
    limits.max_report_bytes = 65_537;
    limits.max_staging_bytes = 5;
    let mut quota = PublicationQuota::new(&limits).unwrap();
    quota.charge_report(1).unwrap();
    assert_eq!(quota.charge_report(1), Err(Code::ResourceLimit));
    quota.charge_staging(5).unwrap();
    assert_eq!(quota.charge_staging(1), Err(Code::ResourceLimit));
    assert_eq!(quota.charged(), (1, 5, 0));
    limits.max_report_bytes = 65_535;
    assert!(matches!(
        PublicationQuota::new(&limits),
        Err(Code::ResourceLimit)
    ));
}

#[test]
fn failure_envelope_has_its_own_nonrefundable_boundary() {
    let (mut limits, _) = example();
    limits.max_report_bytes = 65_536;
    let mut quota = PublicationQuota::new(&limits).unwrap();
    assert_eq!(quota.charge_report(1), Err(Code::ResourceLimit));
    quota.charge_failure_report(65_536).unwrap();
    assert_eq!(quota.failure_charged(), 65_536);
    assert_eq!(quota.charge_failure_report(1), Err(Code::ResourceLimit));
    assert_eq!(quota.failure_charged(), 65_536);
    assert_eq!(quota.charged().0, 0);
}

#[test]
fn error_cap_allows_only_one_summary_and_never_refunds() {
    let (mut limits, _) = example();
    limits.max_errors = 2;
    let mut quota = PublicationQuota::new(&limits).unwrap();
    assert_eq!(quota.omission_summary(), Err(Code::WorkerProtocol));
    quota.charge_error().unwrap();
    quota.charge_error().unwrap();
    assert_eq!(quota.charge_error(), Err(Code::ResourceLimit));
    quota.omission_summary().unwrap();
    assert_eq!(quota.omission_summary(), Err(Code::WorkerProtocol));
    assert_eq!(quota.charged().2, 2);
}

#[test]
fn all_eight_parent_allowances_reject_exact_boundary_plus_one() {
    let (limits, allowance) = example();
    let fields = [
        allowance.records,
        allowance.report_bytes,
        allowance.source_bytes,
        allowance.errors,
        allowance.entries,
        allowance.indicator_comparisons,
        allowance.staging_bytes,
        allowance.retained_bytes,
    ];
    for index in 0..fields.len() {
        let mut ledger = ReservationLedger::new(limits.clone()).unwrap();
        let mut over = allowance.clone();
        match index {
            0 => over.records += 1,
            1 => over.report_bytes += 1,
            2 => over.source_bytes += 1,
            3 => over.errors += 1,
            4 => over.entries += 1,
            5 => over.indicator_comparisons += 1,
            6 => over.staging_bytes += 1,
            _ => over.retained_bytes = limits.max_memory_bytes + 1,
        }
        assert_eq!(
            ledger.reserve(&over),
            Err(Code::ResourceLimit),
            "dimension {index}"
        );
        ledger.reserve(&allowance).unwrap();
    }
}

#[test]
fn publication_staging_and_error_caps_accept_boundary_then_reject_one_more() {
    let (limits, _) = example();
    let mut quota = PublicationQuota::new(&limits).unwrap();
    quota.charge_staging(83_886_080).unwrap();
    assert_eq!(quota.charge_staging(1), Err(Code::ResourceLimit));
    for _ in 0..1000 {
        quota.charge_error().unwrap();
    }
    assert_eq!(quota.charge_error(), Err(Code::ResourceLimit));
    quota.omission_summary().unwrap();
    assert_eq!(quota.omission_summary(), Err(Code::WorkerProtocol));
    assert_eq!(quota.charged(), (0, 83_886_080, 1000));
}

#[test]
fn lost_collector_cannot_consume_preheld_publisher_failure_capacity() {
    let (limits, mut collector) = example();
    let mut publisher = collector.clone();
    collector.report_bytes = 0;
    collector.staging_bytes = 64 * 1024 * 1024;
    publisher.records = 0;
    publisher.source_bytes = 0;
    publisher.errors = 0;
    publisher.entries = 0;
    publisher.indicator_comparisons = 0;
    publisher.staging_bytes = 16 * 1024 * 1024;
    publisher.retained_bytes = 64 * 1024 * 1024;
    let mut ledger = ReservationLedger::with_publisher_reserve(limits.clone(), &publisher).unwrap();
    ledger.reserve(&collector).unwrap();
    ledger.lost().unwrap();
    assert_eq!(ledger.remaining_report_bytes(), 0);
    assert_eq!(ledger.remaining_source_bytes(), 0);
    let mut global = ReservationLedger::new(limits).unwrap();
    global.reserve(&publisher).unwrap();
    assert_eq!(global.remaining_report_bytes(), 0);
    let mut too_large = publisher;
    too_large.staging_bytes += 1;
    assert!(ReservationLedger::with_publisher_reserve(example().0, &too_large).is_ok());
    let mut combined = collector;
    combined.staging_bytes += 1;
    let mut partitioned =
        ReservationLedger::with_publisher_reserve(example().0, &too_large).unwrap();
    assert_eq!(partitioned.reserve(&combined), Err(Code::ResourceLimit));
}
