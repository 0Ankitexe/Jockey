//! Read-only parsers for already scoped, stable startup-source snapshots.
pub(crate) mod autostart;
pub(crate) mod cron;
pub(crate) mod systemd;

use jocky_forensic::collection::identity::digest;
use jocky_shared::collection::{
    Code,
    inputs::{PathRef, StartupFormat},
    outcomes::Field,
    records::PersistenceRecord,
};

pub(crate) fn stable_bytes(raw: Result<&[u8], Code>, same_identity: bool) -> Result<&[u8], Code> {
    let raw = raw?;
    if !same_identity {
        return Err(Code::SourceChanged);
    }
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    Ok(raw)
}

fn lines(raw: &[u8]) -> Result<Vec<&str>, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let source = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    if source.contains('\0') {
        return Err(Code::MalformedSource);
    }
    let mut lines = Vec::new();
    for line in source.lines() {
        if line.len() > 4096 || lines.len() == 1024 {
            return Err(Code::ResourceLimit);
        }
        lines.push(line.trim());
    }
    Ok(lines)
}

fn record(
    kind: StartupFormat,
    location: PathRef,
    raw: &[u8],
    targets: Vec<String>,
    enabled: Field<String>,
) -> Result<PersistenceRecord, Code> {
    if targets.len() > 32
        || targets.iter().any(|value| {
            value.is_empty() || value.len() > 1024 || value.contains(['\0', '\n', '\r'])
        })
    {
        return Err(Code::ResourceLimit);
    }
    Ok(PersistenceRecord {
        kind,
        location,
        enabled_state: enabled,
        referenced_targets: Field::Available { value: targets },
        content_sha256: Field::Available {
            value: digest(raw)?,
        },
    })
}

fn not_requested() -> Field<String> {
    Field::Unavailable {
        reason: Code::NotRequested,
    }
}

fn validated_location(location: &PathRef, suffix: &str) -> Result<(), Code> {
    if location.relative_path.len() > 4096
        || !location.relative_path.ends_with(suffix)
        || location
            .relative_path
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(Code::ScopeDenied);
    }
    Ok(())
}

/// Enumerate only selected direct children under inherited approved root pins.
pub(crate) fn collect_owned(
    context: &jocky_forensic::collection::ValidatedCollectionContext,
    launch: &jocky_shared::collection::launch::WorkerLaunch,
    handles: &[rustix::fd::OwnedFd],
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
) -> Result<crate::collection::Collected, Code> {
    use crate::{
        collectors::facility::{self, Fact, SourceFacts},
        sources::{paths::ConfinedRoot, reads::read_all},
    };
    use jocky_forensic::collection::context::OperationTarget;
    use jocky_shared::collection::{
        inputs::SourceRef,
        launch::HandleKind,
        outcomes::Collector,
        records::{Adapter, Category, Payload, ProvenanceKind, SourceScope},
    };
    use rustix::fd::AsFd;
    let excluded = facility::exclusions(launch)?;
    let mut sources = Vec::new();
    for selected in context.sources() {
        let SourceRef::StartupDirectory {
            source_id,
            path,
            format,
        } = selected.definition()
        else {
            continue;
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
        let names = match root.list_children(&path.relative_path, clock, &false) {
            Ok(names) => names,
            Err(code) => {
                sources.push(SourceFacts::unavailable(source_id.clone(), code));
                continue;
            }
        };
        let mut facts = Vec::new();
        let mut issues = Vec::new();
        for name in names {
            let selected = match format {
                StartupFormat::SystemdUnits => name.ends_with(".service"),
                StartupFormat::SystemdTimers => name.ends_with(".timer"),
                StartupFormat::Cron => !name.starts_with('.'),
                StartupFormat::Autostart => name.ends_with(".desktop"),
            };
            if !selected {
                continue;
            }
            let relative = format!("{}/{}", path.relative_path, name);
            let location =
                PathRef::new(path.root_id.clone(), &relative).map_err(|_| Code::MalformedSource)?;
            let result = (|| {
                let pin = root.pin_file(&relative, clock, &false)?;
                let readable = pin.reopen(clock, &false)?;
                let raw = read_all(&readable, 65_536, clock, &false)?;
                readable.check_unchanged(clock, &false)?;
                match format {
                    StartupFormat::SystemdUnits => systemd::parse_unit(&raw, location.clone()),
                    StartupFormat::SystemdTimers => systemd::parse_timer(&raw, location.clone()),
                    StartupFormat::Cron => cron::parse(&raw, location.clone()),
                    StartupFormat::Autostart => autostart::parse(&raw, location.clone()),
                }
            })();
            match result {
                Ok(row) => facts.push(Fact {
                    payload: Payload::Persistence(row),
                    adapter: Adapter::Startup,
                    category: Category::Persistence,
                    kind: ProvenanceKind::StartupDirectory,
                    scope: SourceScope::Path { path: path.clone() },
                }),
                Err(code) => issues.push(code),
            }
        }
        sources.push(SourceFacts {
            id: source_id.clone(),
            facts,
            issues,
            unavailable: None,
        });
    }
    facility::assemble(context, launch, clock, Collector::Persistence, sources)
}
