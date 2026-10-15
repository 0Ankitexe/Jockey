use super::Session;
use jocky_forensic::collection::{
    ClockReading, ValidatedCollectionContext, context::OperationTarget,
};
use jocky_shared::collection::{Code, inputs::SourceKind, outcomes::Collector};

impl Session {
    pub(super) fn confirm_inner(
        &mut self,
        context: &ValidatedCollectionContext,
        now: &ClockReading,
        cancelled: bool,
    ) -> Result<(), Code> {
        if let Some(launch) = &self.launch {
            let origin = context.invocation_start();
            if origin.monotonic_ms != launch.invocation_origin.monotonic_ms
                || origin.utc != launch.invocation_origin.utc
            {
                return Err(Code::WorkerProtocol);
            }
            if now.monotonic_ms < launch.launch_observed.monotonic_ms
                || now.utc.unix_nanos() < launch.launch_observed.utc.unix_nanos()
            {
                return Err(Code::ClockUncertain);
            }
        }
        if self.closed
            || !self.order.awaiting_admission()
            || self.admitted
            || self.fingerprint.as_ref() != Some(context.input_provenance())
            || self.context.as_ref() != Some(context.identity())
            || self.limits != *context.limits()
        {
            return Err(Code::WorkerProtocol);
        }
        let collector = self.collector.ok_or(Code::WorkerProtocol)?;
        let target = match collector {
            Collector::Files => {
                OperationTarget::File(context.paths().first().ok_or(Code::ScopeDenied)?.path())
            }
            Collector::Indicators => OperationTarget::Indicators,
            _ => {
                let kinds: &[SourceKind] = match collector {
                    Collector::System => &[SourceKind::KernelProfile],
                    Collector::Processes => &[SourceKind::ProcProcesses],
                    Collector::Services => &[SourceKind::SystemdBus],
                    Collector::Connections => &[SourceKind::ProcNet],
                    Collector::Persistence => &[SourceKind::StartupDirectory],
                    Collector::Events => &[SourceKind::JournalFile, SourceKind::TextLog],
                    Collector::Drivers => &[SourceKind::SysModules],
                    _ => return Err(Code::WorkerProtocol),
                };
                let source = context
                    .sources()
                    .iter()
                    .find(|s| kinds.contains(&s.definition().kind()))
                    .ok_or(Code::ScopeDenied)?;
                OperationTarget::Source(source.definition().id())
            }
        };
        context.permit(target, now, cancelled)?;
        self.admitted = true;
        Ok(())
    }
}
