use super::{
    budget,
    inputs::{ApprovedPath, ApprovedSource, DecodedInputs},
};
use jocky_shared::collection::{Code, inputs::*, outcomes::Collector};

pub(crate) struct EffectiveScope {
    pub sources: Vec<ApprovedSource>,
    pub paths: Vec<ApprovedPath>,
}
fn contains_window(outer: &UtcWindow, inner: &UtcWindow) -> bool {
    outer.start.unix_nanos() <= inner.start.unix_nanos()
        && inner.end.unix_nanos() <= outer.end.unix_nanos()
}
fn root<'a>(
    input: &'a DecodedInputs,
    path: &PathRef,
    purpose: RootPurpose,
) -> Result<&'a RootGrant, Code> {
    if path.relative_path.split('/').count() as u64 > input.request.limits.max_depth {
        return Err(Code::ScopeDenied);
    }
    let grant = input
        .authorisation
        .scope
        .roots
        .iter()
        .find(|r| r.root_id == path.root_id)
        .ok_or(Code::ScopeDenied)?;
    let policy = input
        .policy
        .scope
        .roots
        .iter()
        .find(|r| r.root_id == path.root_id)
        .ok_or(Code::ScopeDenied)?;
    if grant.absolute_path != policy.absolute_path
        || !grant.purposes.contains(&purpose)
        || !policy.purposes.contains(&purpose)
    {
        return Err(Code::ScopeDenied);
    }
    Ok(policy)
}
pub(crate) fn intersect(input: &DecodedInputs) -> Result<EffectiveScope, Code> {
    let request = &input.request;
    for (scope, limits) in [
        (&input.authorisation.scope, &input.authorisation.limits),
        (&input.policy.scope, &input.policy.limits),
    ] {
        if request
            .capabilities
            .iter()
            .any(|c| !scope.capabilities.contains(c))
            || !contains_window(&scope.event_window, &request.event_window)
            || budget::values(&request.limits)
                .iter()
                .zip(budget::values(limits))
                .any(|(n, max)| *n > max)
        {
            return Err(Code::ScopeDenied);
        }
    }
    let mut sources = Vec::new();
    for id in &request.source_ids {
        let source = input
            .policy
            .sources
            .iter()
            .find(|s| s.id() == id)
            .ok_or(Code::ScopeDenied)?;
        let owner = match source.kind() {
            SourceKind::KernelProfile => Collector::System,
            SourceKind::ProcProcesses => Collector::Processes,
            SourceKind::ProcNet => Collector::Connections,
            SourceKind::SysModules => Collector::Drivers,
            SourceKind::SystemdBus => Collector::Services,
            SourceKind::JournalFile | SourceKind::TextLog => Collector::Events,
            SourceKind::StartupDirectory => Collector::Persistence,
        };
        if !request.collectors.contains(&owner) {
            return Err(Code::ScopeDenied);
        }
        if !input
            .authorisation
            .scope
            .source_groups
            .contains(&source.kind())
            || !input.policy.scope.source_groups.contains(&source.kind())
        {
            return Err(Code::ScopeDenied);
        }
        match source {
            SourceRef::JournalFile { path, .. } => {
                root(input, path, RootPurpose::Journal)?;
            }
            SourceRef::TextLog { path, .. } => {
                root(input, path, RootPurpose::Logs)?;
            }
            SourceRef::StartupDirectory { path, .. } => {
                root(input, path, RootPurpose::Persistence)?;
            }
            _ => {}
        }
        sources.push(ApprovedSource(source.clone()));
    }
    for collector in &request.collectors {
        let allowed: &[SourceKind] = match collector {
            Collector::System => &[SourceKind::KernelProfile],
            Collector::Processes => &[SourceKind::ProcProcesses],
            Collector::Services => &[SourceKind::SystemdBus],
            Collector::Connections => &[SourceKind::ProcNet],
            Collector::Persistence => &[SourceKind::StartupDirectory],
            Collector::Events => &[SourceKind::JournalFile, SourceKind::TextLog],
            Collector::Drivers => &[SourceKind::SysModules],
            Collector::Files | Collector::Indicators => &[],
        };
        if !allowed.is_empty() && !sources.iter().any(|s| allowed.contains(&s.0.kind())) {
            return Err(Code::ScopeDenied);
        }
    }
    let mut paths = Vec::new();
    if !request.paths.is_empty() && !request.collectors.contains(&Collector::Files) {
        return Err(Code::ScopeDenied);
    }
    for path in &request.paths {
        paths.push(ApprovedPath {
            root: root(input, path, RootPurpose::Files)?.clone(),
            path: path.clone(),
        });
    }
    if let Some(set) = &input.indicators {
        for criterion in &set.indicators {
            if let Indicator::Path { value, .. } = criterion {
                root(input, value, RootPurpose::Files)?;
            }
        }
    }
    Ok(EffectiveScope { sources, paths })
}
