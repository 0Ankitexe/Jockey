use super::{
    ValidatedCollectionContext,
    inputs::{ApprovedPath, ApprovedSource},
};
use jocky_shared::collection::{
    Code,
    inputs::{SourceKind, UtcWindow},
    outcomes::{Collector, CollectorOutcome},
    records::ForensicRecord,
};

pub enum CollectorRequest<'a> {
    System(&'a ApprovedSource),
    Processes(&'a ApprovedSource),
    Services(&'a ApprovedSource),
    Connections(&'a ApprovedSource),
    Persistence(&'a [ApprovedSource]),
    Files(&'a [ApprovedPath]),
    Events {
        sources: &'a [ApprovedSource],
        window: &'a UtcWindow,
    },
    Drivers(&'a ApprovedSource),
    Indicators(super::indicators::ValidatedIndicatorSet<'a>),
}
impl CollectorRequest<'_> {
    pub const fn collector(&self) -> Collector {
        match self {
            Self::System(_) => Collector::System,
            Self::Processes(_) => Collector::Processes,
            Self::Services(_) => Collector::Services,
            Self::Connections(_) => Collector::Connections,
            Self::Persistence(_) => Collector::Persistence,
            Self::Files(_) => Collector::Files,
            Self::Events { .. } => Collector::Events,
            Self::Drivers(_) => Collector::Drivers,
            Self::Indicators(_) => Collector::Indicators,
        }
    }

    /// Every adapter must validate the request against the supplied context before I/O.
    pub fn validate(&self, context: &ValidatedCollectionContext) -> Result<(), Code> {
        if !context.input.request.collectors.contains(&self.collector()) {
            return Err(Code::ScopeDenied);
        }
        let source = |value: &ApprovedSource, kinds: &[SourceKind]| {
            kinds.contains(&value.definition().kind())
                && context
                    .sources()
                    .iter()
                    .any(|s| s.definition() == value.definition())
        };
        let multiple = |values: &[ApprovedSource], kinds: &[SourceKind]| {
            !values.is_empty()
                && values.len() <= context.sources().len()
                && values.iter().enumerate().all(|(i, s)| {
                    source(s, kinds)
                        && !values[..i]
                            .iter()
                            .any(|p| p.definition().id() == s.definition().id())
                })
        };
        let valid = match self {
            Self::System(s) => source(s, &[SourceKind::KernelProfile]),
            Self::Processes(s) => source(s, &[SourceKind::ProcProcesses]),
            Self::Services(s) => source(s, &[SourceKind::SystemdBus]),
            Self::Connections(s) => source(s, &[SourceKind::ProcNet]),
            Self::Drivers(s) => source(s, &[SourceKind::SysModules]),
            Self::Persistence(s) => multiple(s, &[SourceKind::StartupDirectory]),
            Self::Events { sources, window } => {
                let approved = &context.input.request.event_window;
                window.start.unix_nanos() >= approved.start.unix_nanos()
                    && window.end.unix_nanos() <= approved.end.unix_nanos()
                    && window.start.unix_nanos() < window.end.unix_nanos()
                    && multiple(sources, &[SourceKind::JournalFile, SourceKind::TextLog])
            }
            Self::Files(paths) => {
                !paths.is_empty()
                    && paths.len() <= context.paths().len()
                    && paths.iter().enumerate().all(|(i, p)| {
                        context
                            .paths()
                            .iter()
                            .any(|a| a.path() == p.path() && a.root() == p.root())
                            && !paths[..i].iter().any(|a| a.path() == p.path())
                    })
            }
            Self::Indicators(set) => {
                set.collection_id == &context.identity().collection_id
                    && context.indicators().is_some_and(|a| a.set == set.set)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Code::ScopeDenied)
        }
    }
}
pub trait RecordSink {
    fn accept(&mut self, record: ForensicRecord) -> Result<(), Code>;
}
pub trait PlatformCollector {
    fn collect(
        &mut self,
        context: &ValidatedCollectionContext,
        request: &CollectorRequest<'_>,
        sink: &mut dyn RecordSink,
    ) -> CollectorOutcome;
}
