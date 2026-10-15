use super::*;
use crate::support;
use jocky_forensic::collection::{ClockReading, context::OperationTarget};
use std::cell::Cell;

struct StepClock {
    now: ClockReading,
    step: u64,
}
impl Clock for StepClock {
    fn read(&mut self) -> Result<ClockReading, Code> {
        let reading = self.now.clone();
        self.now.monotonic_ms += self.step;
        Ok(reading)
    }
}

#[test]
fn post_call_deadline_failure_discards_result_and_prevents_further_attempts() {
    let ctx = support::context(&support::values("/synthetic/case", "file"));
    let reference = support::path("file");
    let now = support::Frozen::default().0;
    let permit = ctx
        .permit(OperationTarget::File(&reference), &now, false)
        .unwrap();
    let mut clock = StepClock {
        now,
        step: ctx.limits().operation_timeout_ms,
    };
    let mut op = Operation {
        permit,
        clock: &mut clock,
        cancel: &false,
    };
    let attempts = Cell::new(0);
    let call = || {
        attempts.set(attempts.get() + 1);
        Ok(42)
    };
    assert_eq!(op.run(call), Err(Code::Timeout));
    assert_eq!(attempts.get(), 1);
    assert_eq!(op.run(call), Err(Code::Timeout));
    assert_eq!(op.entry(), Err(Code::Timeout));
    assert_eq!(attempts.get(), 1);
}

#[test]
fn cancellation_and_read_failures_cannot_yield_an_io_result() {
    struct Cancel(Cell<bool>);
    impl Cancellation for Cancel {
        fn cancelled(&self) -> bool {
            self.0.get()
        }
    }
    let ctx = support::context(&support::values("/synthetic/case", "file"));
    let reference = support::path("file");
    let mut clock = support::Frozen::default();
    let permit = ctx
        .permit(OperationTarget::File(&reference), &clock.0, false)
        .unwrap();
    let cancel = Cancel(Cell::new(false));
    let mut op = Operation {
        permit,
        clock: &mut clock,
        cancel: &cancel,
    };
    assert_eq!(
        op.run::<()>(|| Err(Code::PermissionDenied)),
        Err(Code::PermissionDenied)
    );
    assert_eq!(
        op.run(|| {
            cancel.0.set(true);
            Ok(42)
        }),
        Err(Code::Cancelled)
    );
    let attempts = Cell::new(0);
    assert_eq!(
        op.run(|| {
            attempts.set(1);
            Ok(42)
        }),
        Err(Code::Cancelled)
    );
    assert_eq!(attempts.get(), 0);
}

#[test]
fn failed_native_calls_charge_errors_without_refunding_retries() {
    let ctx = support::context(&support::values("/synthetic/case", "file"));
    let reference = support::path("file");
    let mut clock = support::Frozen::default();
    let permit = ctx
        .permit(OperationTarget::File(&reference), &clock.0, false)
        .unwrap();
    let mut op = Operation {
        permit,
        clock: &mut clock,
        cancel: &false,
    };
    assert_eq!(
        op.run::<()>(|| Err(Code::PermissionDenied)),
        Err(Code::PermissionDenied)
    );
    assert_eq!(
        op.run::<()>(|| Err(Code::SourceChanged)),
        Err(Code::SourceChanged)
    );
    drop(op);
    assert_eq!(ctx.charged(Counter::Errors).unwrap(), 2);
}

#[test]
fn failed_native_call_is_charged_even_when_post_call_deadline_wins() {
    let ctx = support::context(&support::values("/synthetic/case", "file"));
    let reference = support::path("file");
    let now = support::Frozen::default().0;
    let permit = ctx
        .permit(OperationTarget::File(&reference), &now, false)
        .unwrap();
    let mut clock = StepClock {
        now,
        step: ctx.limits().operation_timeout_ms,
    };
    let mut op = Operation {
        permit,
        clock: &mut clock,
        cancel: &false,
    };
    assert_eq!(
        op.run::<()>(|| Err(Code::PermissionDenied)),
        Err(Code::Timeout)
    );
    drop(op);
    assert_eq!(ctx.charged(Counter::Errors).unwrap(), 1);
}
