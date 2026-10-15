//! Pure stop scheduling and uninterruptible fault doubles, never host signals.
#[path = "../src/worker/stop.rs"]
mod stop;
use jocky_shared::collection::Code;
use stop::{Action, StopSchedule};

#[test]
fn cooperative_kill_reap_and_finalization_share_one_original_deadline() {
    let mut stop = StopSchedule::new(54000, 60000, Code::Cancelled).unwrap();
    assert_eq!(stop.poll(54000, false), Ok(Action::Cancel(Code::Cancelled)));
    assert_eq!(stop.poll(55999, false), Ok(Action::Wait));
    assert_eq!(stop.poll(56000, false), Ok(Action::KillOwned));
    assert_eq!(stop.poll(56999, false), Ok(Action::Wait));
    assert_eq!(stop.poll(57000, false), Ok(Action::Incomplete));
    assert_eq!(stop.poll(57001, true), Err(Code::CleanupIncomplete));
}

#[test]
fn early_reap_does_not_signal_or_restart_a_publication_timeout() {
    let mut stop = StopSchedule::new(54000, 60000, Code::Timeout).unwrap();
    assert_eq!(stop.poll(54000, true), Ok(Action::Reaped));
    assert_eq!(stop.finalization_deadline(), 60000);
    assert_eq!(stop.poll(54001, false), Err(Code::WorkerProtocol));
    let mut stop = StopSchedule::new(54000, 60000, Code::Timeout).unwrap();
    stop.poll(54000, false).unwrap();
    assert_eq!(stop.poll(54001, true), Ok(Action::Reaped));
}

#[test]
fn rollback_short_remaining_time_and_unsupported_causes_fail_closed() {
    let mut stop = StopSchedule::new(54000, 60000, Code::AuthorisationExpired).unwrap();
    stop.poll(54001, false).unwrap();
    assert_eq!(stop.poll(54000, false), Err(Code::ClockUncertain));
    assert_eq!(stop.poll(54002, true), Err(Code::CleanupIncomplete));
    assert!(matches!(
        StopSchedule::new(60000, 60000, Code::Timeout),
        Err(Code::Timeout)
    ));
    assert!(matches!(
        StopSchedule::new(54000, 60000, Code::NotRequested),
        Err(Code::InvalidInput)
    ));
}

#[test]
fn late_stop_never_consumes_a_fresh_two_plus_one_second_window() {
    let mut stop = StopSchedule::new(59500, 60000, Code::Cancelled).unwrap();
    assert_eq!(stop.poll(59500, false), Ok(Action::Cancel(Code::Cancelled)));
    assert_eq!(stop.poll(59501, false), Ok(Action::KillOwned));
    assert_eq!(stop.poll(59502, false), Ok(Action::Incomplete));
    assert_eq!(stop.finalization_deadline(), 60000);
}
