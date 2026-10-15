#[path = "../src/worker/progress.rs"]
mod progress;
use jocky_shared::collection::{Code, inputs::Limits, outcomes::WorkUsed};
use progress::ProgressTracker;

fn limits() -> Limits {
    serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../fixtures/valid/collection/request.json"
    ))
    .and_then(|v| serde_json::from_value(v["limits"].clone()))
    .unwrap()
}
fn zero() -> WorkUsed {
    WorkUsed {
        entries: 0,
        indicator_comparisons: 0,
        errors: 0,
        source_bytes: 0,
        staging_bytes: 0,
        retained_bytes: 0,
    }
}
fn maximum(l: &Limits) -> WorkUsed {
    WorkUsed {
        entries: l.max_entries,
        indicator_comparisons: l.max_indicator_comparisons,
        errors: l.max_errors,
        source_bytes: l.max_source_bytes,
        staging_bytes: l.max_staging_bytes,
        retained_bytes: l.max_memory_bytes,
    }
}
fn fields(v: &mut WorkUsed) -> [&mut u64; 6] {
    [
        &mut v.entries,
        &mut v.indicator_comparisons,
        &mut v.errors,
        &mut v.source_bytes,
        &mut v.staging_bytes,
        &mut v.retained_bytes,
    ]
}

#[test]
fn cumulative_progress_returns_only_new_cost_without_refunds() {
    let mut tracker = ProgressTracker::new(&limits()).unwrap();
    let mut one = zero();
    for f in fields(&mut one) {
        *f = 1;
    }
    assert_eq!(tracker.observe(&one).unwrap(), one);
    assert_eq!(tracker.observe(&one).unwrap(), zero());
    let mut two = one.clone();
    two.source_bytes += 3;
    let delta = tracker.observe(&two).unwrap();
    assert_eq!(delta.source_bytes, 3);
    assert_eq!(delta.errors, 0);
    assert_eq!(tracker.last(), &two);
}

#[test]
fn every_counter_accepts_exact_limit_and_rejects_limit_plus_one() {
    let l = limits();
    for index in 0..6 {
        let max = maximum(&l);
        let mut tracker = ProgressTracker::new(&l).unwrap();
        assert_eq!(tracker.observe(&max).unwrap(), max);
        let mut excess = max.clone();
        *fields(&mut excess)[index] += 1;
        assert_eq!(tracker.observe(&excess), Err(Code::WorkerProtocol));
        assert_eq!(tracker.last(), &max);
        assert_eq!(tracker.observe(&max), Err(Code::WorkerProtocol));
    }
}

#[test]
fn every_counter_rollback_fails_closed_without_mutating_charged_usage() {
    let l = limits();
    for index in 0..6 {
        let mut tracker = ProgressTracker::new(&l).unwrap();
        let max = maximum(&l);
        tracker.observe(&max).unwrap();
        let mut less = max.clone();
        *fields(&mut less)[index] -= 1;
        assert_eq!(tracker.observe(&less), Err(Code::WorkerProtocol));
        assert_eq!(tracker.last(), &max);
        assert_eq!(tracker.finish(&max, 0), Err(Code::WorkerProtocol));
    }
}

#[test]
fn final_usage_cannot_hide_delivered_errors_or_reset_progress() {
    let l = limits();
    let mut tracker = ProgressTracker::new(&l).unwrap();
    assert_eq!(tracker.finish(&zero(), 1), Err(Code::WorkerProtocol));
    assert_eq!(tracker.finish(&maximum(&l), 1), Err(Code::WorkerProtocol));
    let mut tracker = ProgressTracker::new(&l).unwrap();
    tracker.observe(&maximum(&l)).unwrap();
    assert_eq!(tracker.finish(&zero(), 0), Err(Code::WorkerProtocol));
}

#[test]
fn terminal_acknowledgement_is_one_shot_and_accounts_final_delta() {
    let l = limits();
    let mut tracker = ProgressTracker::new(&l).unwrap();
    let max = maximum(&l);
    assert_eq!(tracker.finish(&max, l.max_errors).unwrap(), max);
    assert_eq!(tracker.observe(&max), Err(Code::WorkerProtocol));
    assert_eq!(tracker.finish(&max, 0), Err(Code::WorkerProtocol));
}

#[test]
fn narrowing_and_invalid_reservations_are_enforced() {
    let mut l = limits();
    l.max_source_bytes = 2;
    let mut tracker = ProgressTracker::new(&l).unwrap();
    let mut used = zero();
    used.source_bytes = 3;
    assert_eq!(tracker.observe(&used), Err(Code::WorkerProtocol));
    for bad in [0, 67108865, u64::MAX] {
        l.max_source_bytes = bad;
        assert!(matches!(ProgressTracker::new(&l), Err(Code::InvalidInput)));
    }
}

#[test]
fn explicit_allowance_including_zero_is_checked_against_global_limits() {
    let launch = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    let mut allowance = launch.allowance;
    allowance.source_bytes = 0;
    let mut tracker = ProgressTracker::for_allowance(&limits(), &allowance).unwrap();
    tracker.observe(&zero()).unwrap();
    let mut used = zero();
    used.source_bytes = 1;
    assert_eq!(tracker.observe(&used), Err(Code::WorkerProtocol));
    allowance.source_bytes = limits().max_source_bytes + 1;
    assert!(matches!(
        ProgressTracker::for_allowance(&limits(), &allowance),
        Err(Code::ScopeDenied)
    ));
}
