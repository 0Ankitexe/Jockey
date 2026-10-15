use jocky_forensic::collection::{
    budget::Counter, cancellation::Cancellation, clock::Clock, context::OperationPermit,
};
use jocky_shared::collection::Code;

#[cfg(test)]
mod tests;

/// Every native operation is bracketed by a fresh clock/cancellation check.
/// The future owned worker provides the bound on a kernel-blocked call.
pub(super) struct Operation<'a, 'ctx> {
    pub permit: OperationPermit<'ctx>,
    pub clock: &'a mut dyn Clock,
    pub cancel: &'a dyn Cancellation,
}
impl Operation<'_, '_> {
    pub fn check(&mut self) -> Result<(), Code> {
        self.permit
            .renew(&self.clock.read()?, self.cancel.cancelled())
    }
    pub fn entry(&mut self) -> Result<(), Code> {
        self.check()?;
        self.permit.charge(Counter::Entries, 1)
    }
    pub fn run<T>(&mut self, call: impl FnOnce() -> Result<T, Code>) -> Result<T, Code> {
        self.check()?;
        let result = call();
        // Charge a failed native attempt before the post-call clock check so
        // expiry cannot erase work already performed by the kernel.
        if result.is_err() {
            self.permit.charge(Counter::Errors, 1)?;
        }
        self.check()?;
        result
    }
}
