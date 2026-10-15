use super::*;
use crate::support::{Frozen, context, path, values};
use jocky_forensic::collection::{ClockReading, context::OperationTarget};
use std::{cell::Cell, rc::Rc};

struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn read(&mut self) -> Result<ClockReading, Code> {
        let mut now = Frozen::default().0;
        now.monotonic_ms = self.0.get();
        Ok(now)
    }
}
struct Fake {
    calls: usize,
    returned: usize,
    fail: Option<Code>,
    changed: bool,
    short: bool,
    clock: Rc<Cell<u64>>,
    expire: bool,
}
impl Reader for Fake {
    fn verify(&mut self, _: &mut Operation<'_, '_>) -> Result<(), Code> {
        if self.changed && self.calls > 0 {
            Err(Code::SourceChanged)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Code> {
        self.calls += 1;
        if self.expire {
            self.clock.set(3000);
        }
        if let Some(code) = self.fail {
            return Err(code);
        }
        if self.short && self.calls > 1 {
            return Ok(0);
        }
        let n = buffer.len().min(12345);
        buffer[..n].fill(42);
        self.returned += n;
        Ok(n)
    }
}
fn fake() -> Fake {
    Fake {
        calls: 0,
        returned: 0,
        fail: None,
        changed: false,
        short: false,
        clock: Rc::new(Cell::new(0)),
        expire: false,
    }
}

struct Finite(usize);
impl Reader for Finite {
    fn verify(&mut self, _: &mut Operation<'_, '_>) -> Result<(), Code> {
        Ok(())
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Code> {
        let n = buffer.len().min(self.0);
        buffer[..n].fill(42);
        self.0 -= n;
        Ok(n)
    }
}

struct InvalidCount;
impl Reader for InvalidCount {
    fn verify(&mut self, _: &mut Operation<'_, '_>) -> Result<(), Code> {
        Ok(())
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Code> {
        Ok(buffer.len() + 1)
    }
}

#[test]
fn impossible_read_counts_charge_a_protocol_error_in_both_read_modes() {
    for pseudo in [false, true] {
        let ctx = context(&values("/synthetic/owned", "selected"));
        let reference = path("selected");
        let mut clock = Frozen::default();
        let permit = ctx
            .permit(OperationTarget::File(&reference), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        let result = if pseudo {
            bounded(&mut InvalidCount, 16, &mut op)
        } else {
            exact(&mut InvalidCount, 16, 16, &mut op)
        };
        assert_eq!(result, Err(Code::WorkerProtocol));
        drop(op);
        assert_eq!(ctx.charged(Counter::Errors), Ok(1));
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(0));
    }
}

#[test]
fn stream_requires_eof_and_rejects_item_boundary_plus_one_without_prefix_success() {
    for amount in [0, 1, 65535, 65536, 65537] {
        let ctx = context(&values("/synthetic/owned", "selected"));
        let reference = path("selected");
        let mut clock = Frozen::default();
        let permit = ctx
            .permit(OperationTarget::File(&reference), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        let result = bounded(&mut Finite(amount), 65536, &mut op);
        if amount <= 65536 {
            assert_eq!(result.unwrap().len(), amount);
        } else {
            assert_eq!(result, Err(Code::ResourceLimit));
        }
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes), Ok(amount as u64));
    }
}

#[test]
fn stream_policy_and_memory_denials_precede_read_calls() {
    for mode in 0..3 {
        let mut input = values("/synthetic/owned", "selected");
        if mode == 0 {
            input[3]["limits"]["max_item_bytes"] = serde_json::json!(2);
        }
        if mode == 1 {
            input[3]["limits"]["max_memory_bytes"] = serde_json::json!(1);
        }
        let ctx = context(&input);
        let reference = path("selected");
        let mut reader = fake();
        let mut clock = Frozen::default();
        let permit = ctx
            .permit(OperationTarget::File(&reference), &clock.0, false)
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        assert_eq!(
            bounded(&mut reader, if mode == 2 { 0 } else { 3 }, &mut op),
            Err(Code::ResourceLimit)
        );
        assert_eq!(reader.calls, 0);
    }
}

#[test]
fn stream_timeout_and_source_failure_preserve_cost_without_retry() {
    for timed in [false, true] {
        let ctx = context(&values("/synthetic/owned", "selected"));
        let reference = path("selected");
        let mut reader = fake();
        reader.expire = timed;
        if !timed {
            reader.fail = Some(Code::PermissionDenied);
        }
        let mut clock = TestClock(reader.clock.clone());
        let permit = ctx
            .permit(
                OperationTarget::File(&reference),
                &Frozen::default().0,
                false,
            )
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        assert_eq!(
            bounded(&mut reader, 65536, &mut op),
            Err(if timed {
                Code::Timeout
            } else {
                Code::PermissionDenied
            })
        );
        assert_eq!(reader.calls, 1);
        drop(op);
        assert_eq!(
            ctx.charged(Counter::SourceBytes),
            Ok(if timed { 12345 } else { 0 })
        );
    }
}

#[test]
fn stream_rechecks_identity_after_each_chunk_and_charges_discarded_bytes() {
    let ctx = context(&values("/synthetic/owned", "selected"));
    let reference = path("selected");
    let mut reader = fake();
    reader.changed = true;
    let mut clock = TestClock(reader.clock.clone());
    let permit = ctx
        .permit(
            OperationTarget::File(&reference),
            &Frozen::default().0,
            false,
        )
        .unwrap();
    let mut op = Operation {
        permit,
        clock: &mut clock,
        cancel: &false,
    };
    assert_eq!(
        bounded(&mut reader, 65536, &mut op),
        Err(Code::SourceChanged)
    );
    drop(op);
    assert_eq!(reader.calls, 1);
    assert_eq!(ctx.charged(Counter::SourceBytes).unwrap(), 12345);
    assert_eq!(ctx.charged(Counter::Errors).unwrap(), 1);
}

#[test]
fn actual_short_reads_are_charged_once_and_eof_needs_no_extra_byte() {
    for expected in [0, 65536, 65537, 16777216] {
        let ctx = context(&values("/synthetic/owned", "selected"));
        let reference = path("selected");
        let mut source = fake();
        let mut clock = TestClock(source.clock.clone());
        let permit = ctx
            .permit(
                OperationTarget::File(&reference),
                &Frozen::default().0,
                false,
            )
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        let bytes = exact(&mut source, expected, 16777216, &mut op).unwrap();
        assert_eq!(bytes.len(), expected as usize);
        assert!(bytes.iter().all(|n| *n == 42));
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes).unwrap(), expected);
        assert_eq!(source.returned as u64, expected);
        assert_eq!(
            ctx.charged(Counter::RetainedBytes).unwrap(),
            expected + 65536
        );
    }
}

#[test]
fn denial_size_limit_and_retention_exhaustion_precede_source_reads() {
    for mode in 0..3 {
        let mut input = values("/synthetic/owned", "selected");
        if mode == 2 {
            input[3]["limits"]["max_memory_bytes"] = serde_json::json!(65535);
        }
        let ctx = context(&input);
        let reference = path("selected");
        let mut source = fake();
        let mut clock = TestClock(source.clock.clone());
        let permit = ctx
            .permit(
                OperationTarget::File(&reference),
                &Frozen::default().0,
                false,
            )
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        let (size, cap) = if mode == 0 {
            (10, 9)
        } else if mode == 1 {
            (0, 0)
        } else {
            (1, 10)
        };
        assert_eq!(
            exact(&mut source, size, cap, &mut op),
            Err(Code::ResourceLimit)
        );
        assert_eq!(source.calls, 0);
    }
}

#[test]
fn source_errors_are_charged_and_never_automatically_retried() {
    for code in [
        Code::PermissionDenied,
        Code::FacilityUnavailable,
        Code::SourceDisappeared,
    ] {
        let ctx = context(&values("/synthetic/owned", "selected"));
        let reference = path("selected");
        let mut source = fake();
        source.fail = Some(code);
        let mut clock = TestClock(source.clock.clone());
        let permit = ctx
            .permit(
                OperationTarget::File(&reference),
                &Frozen::default().0,
                false,
            )
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        assert_eq!(exact(&mut source, 1, 10, &mut op), Err(code));
        drop(op);
        assert_eq!(source.calls, 1);
        assert_eq!(ctx.charged(Counter::Errors).unwrap(), 1);
        assert_eq!(ctx.charged(Counter::SourceBytes).unwrap(), 0);
    }
}

#[test]
fn expired_and_changed_reads_preserve_the_cost_of_bytes_obtained() {
    for mode in 0..3 {
        let ctx = context(&values("/synthetic/owned", "selected"));
        let reference = path("selected");
        let mut source = fake();
        source.expire = mode == 0;
        source.changed = mode == 1;
        source.short = mode == 2;
        let mut clock = TestClock(source.clock.clone());
        let permit = ctx
            .permit(
                OperationTarget::File(&reference),
                &Frozen::default().0,
                false,
            )
            .unwrap();
        let mut op = Operation {
            permit,
            clock: &mut clock,
            cancel: &false,
        };
        assert_eq!(
            exact(&mut source, 65536, 65536, &mut op),
            Err(if mode == 0 {
                Code::Timeout
            } else {
                Code::SourceChanged
            })
        );
        drop(op);
        assert_eq!(ctx.charged(Counter::SourceBytes).unwrap(), 12345);
        assert_eq!(source.calls, if mode == 2 { 2 } else { 1 });
        if mode == 0 {
            assert!(matches!(
                ctx.permit(
                    OperationTarget::File(&reference),
                    &Frozen::default().0,
                    false
                ),
                Err(Code::Timeout)
            ));
        }
    }
}

#[test]
fn global_source_exhaustion_forbids_another_read_and_never_refunds_prefix() {
    let mut input = values("/synthetic/owned", "selected");
    input[3]["limits"]["max_source_bytes"] = serde_json::json!(2);
    let ctx = context(&input);
    let reference = path("selected");
    let mut source = fake();
    let mut clock = TestClock(source.clock.clone());
    let permit = ctx
        .permit(
            OperationTarget::File(&reference),
            &Frozen::default().0,
            false,
        )
        .unwrap();
    let mut op = Operation {
        permit,
        clock: &mut clock,
        cancel: &false,
    };
    assert_eq!(exact(&mut source, 3, 10, &mut op), Err(Code::ResourceLimit));
    drop(op);
    assert_eq!(source.calls, 1);
    assert_eq!(ctx.charged(Counter::SourceBytes).unwrap(), 2);
    assert!(matches!(
        ctx.permit(
            OperationTarget::File(&reference),
            &Frozen::default().0,
            false
        ),
        Err(Code::ResourceLimit)
    ));
}
