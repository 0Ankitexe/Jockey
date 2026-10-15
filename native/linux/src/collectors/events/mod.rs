pub(crate) mod journal;
pub(crate) mod text;

pub(crate) fn collect_owned(
    context: &jocky_forensic::collection::ValidatedCollectionContext,
    launch: &jocky_shared::collection::launch::WorkerLaunch,
    handles: &[rustix::fd::OwnedFd],
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
) -> Result<crate::collection::Collected, jocky_shared::collection::Code> {
    use crate::{
        collectors::facility::{self, Fact, SourceFacts},
        sources::{
            journal as journal_source, journal_snapshot,
            paths::ConfinedRoot,
            text_log::{self, LogSource},
        },
    };
    use jocky_forensic::collection::{budget::Counter, context::OperationTarget};
    use jocky_shared::collection::{
        Code,
        inputs::SourceRef,
        launch::HandleKind,
        outcomes::Collector,
        records::{Adapter, Category, Payload, ProvenanceKind, SourceScope},
    };
    use rustix::fd::AsFd;
    let excluded = facility::exclusions(launch)?;
    let mut sources = Vec::new();
    for selected in context.sources() {
        let (source_id, path, kind, adapter) = match selected.definition() {
            SourceRef::JournalFile { source_id, path } => (
                source_id,
                path,
                ProvenanceKind::JournalFile,
                Adapter::Journal,
            ),
            SourceRef::TextLog {
                source_id, path, ..
            } => (source_id, path, ProvenanceKind::TextLog, Adapter::TextLog),
            _ => continue,
        };
        let handle = launch
            .descriptors
            .iter()
            .zip(handles)
            .find_map(|(binding, handle)| {
                (binding.kind == HandleKind::OrdinaryRoot
                    && binding.subject_id.as_ref() == Some(&path.root_id))
                .then_some(handle)
            })
            .ok_or(Code::WorkerProtocol)?;
        let root = ConfinedRoot::inherited(
            context,
            OperationTarget::Source(source_id),
            handle
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| Code::WorkerProtocol)?,
            excluded.clone(),
            clock,
            &false,
        )?;
        let result = match selected.definition() {
            SourceRef::JournalFile { .. } => {
                if !cfg!(feature = "journal") {
                    Err(Code::Unsupported)
                } else {
                    let stage = journal_snapshot::snapshot_admitted(&root, path, clock, &false);
                    stage
                        .and_then(|stage| {
                            journal_source::read_staged(&stage, |n| {
                                let mut permit = context.permit(
                                    OperationTarget::Source(source_id),
                                    &clock.read()?,
                                    false,
                                )?;
                                permit.charge(Counter::SourceBytes, n)
                            })
                        })
                        .and_then(|facts| {
                            journal::parse_facts(&facts, source_id.clone(), context.event_window())
                        })
                }
            }
            SourceRef::TextLog { .. } => {
                text_log::read_admitted(LogSource::Approved, &root, path, clock, &false)
                    .and_then(|raw| text::parse(&raw, source_id.clone(), context.event_window()))
            }
            _ => unreachable!(),
        };
        sources.push(match result {
            Ok(rows) => SourceFacts::complete(
                source_id.clone(),
                rows.into_iter()
                    .map(|row| Fact {
                        payload: Payload::Event(row),
                        adapter,
                        category: Category::Event,
                        kind,
                        scope: SourceScope::Path { path: path.clone() },
                    })
                    .collect(),
            ),
            Err(code) => SourceFacts::unavailable(source_id.clone(), code),
        });
    }
    facility::assemble(context, launch, clock, Collector::Events, sources)
}
