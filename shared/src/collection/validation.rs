//! Pure wire invariants. Cross-document authority and evidence integrity are separate gates.
use super::{
    DecodeReason, Document, InputError,
    identity::UtcTime,
    inputs::*,
    outcomes::{Capability, Collector},
};
use serde_json::Value;
use std::collections::BTreeSet;

fn invalid(reason: DecodeReason) -> InputError {
    InputError::new(reason)
}

pub(crate) fn wire_values(value: &Value) -> Result<(), InputError> {
    let mut pending = vec![("", value)];
    while let Some((key, value)) = pending.pop() {
        if key == "details"
            && serde_json::to_vec(value)
                .map_err(|_| invalid(DecodeReason::Schema))?
                .len()
                > 4096
        {
            return Err(invalid(DecodeReason::Size));
        }
        match value {
            Value::String(s) => {
                let cap = match key {
                    "relative_path" | "absolute_path" | "owned_scratch_root" | "output_root" => {
                        4096
                    }
                    "data" => 87384,
                    _ => 65536,
                };
                if s.len() > cap || s.contains('\0') {
                    return Err(invalid(DecodeReason::Size));
                }
                match key {
                    "relative_path" => validate_relative(s)?,
                    "absolute_path" | "owned_scratch_root" | "output_root" => absolute(s)?,
                    _ => {}
                }
            }
            Value::Array(values) => pending.extend(values.iter().map(|v| (key, v))),
            Value::Object(values) => pending.extend(values.iter().map(|(k, v)| (k.as_str(), v))),
            _ => {}
        }
    }
    Ok(())
}

fn absolute(path: &str) -> Result<(), InputError> {
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| invalid(DecodeReason::Path))?;
    if relative.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || relative.split('/').any(|p| matches!(p, "" | "." | ".."))
        || ["/proc", "/sys", "/dev"].iter().any(|p| under(path, p))
    {
        return Err(invalid(DecodeReason::Path));
    }
    Ok(())
}
fn under(child: &str, parent: &str) -> bool {
    child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|tail| tail.starts_with('/'))
}
fn interval(start: &UtcTime, end: &UtcTime, bounded: bool) -> Result<(), InputError> {
    let duration = end.unix_nanos() - start.unix_nanos();
    if duration <= 0 || (bounded && duration > 86_400_000_000_000) {
        return Err(invalid(DecodeReason::Timestamp));
    }
    Ok(())
}
fn scope(value: &Scope) -> Result<(), InputError> {
    interval(&value.event_window.start, &value.event_window.end, true)?;
    let mut ids = BTreeSet::new();
    for (i, root) in value.roots.iter().enumerate() {
        absolute(&root.absolute_path)?;
        if !ids.insert(&root.root_id)
            || value.roots[..i].iter().any(|p| {
                under(&root.absolute_path, &p.absolute_path)
                    || under(&p.absolute_path, &root.absolute_path)
            })
        {
            return Err(invalid(DecodeReason::Path));
        }
    }
    Ok(())
}
fn required(collector: Collector) -> Capability {
    match collector {
        Collector::System | Collector::Services => Capability::System,
        Collector::Processes => Capability::Processes,
        Collector::Connections => Capability::Network,
        Collector::Files => Capability::Files,
        Collector::Events => Capability::Events,
        Collector::Persistence => Capability::Persistence,
        Collector::Drivers => Capability::Drivers,
        Collector::Indicators => Capability::Indicators,
    }
}

pub(crate) fn document(doc: &Document) -> Result<(), InputError> {
    match doc {
        Document::Designation(v) => interval(&v.valid_from, &v.valid_until, false)?,
        Document::Authorisation(v) => {
            interval(&v.valid_from, &v.valid_until, true)?;
            scope(&v.scope)?;
        }
        Document::Policy(v) => {
            interval(&v.valid_from, &v.valid_until, false)?;
            scope(&v.scope)?;
            let mut ids = BTreeSet::new();
            for source in &v.sources {
                if !ids.insert(source.id()) || !v.scope.source_groups.contains(&source.kind()) {
                    return Err(invalid(DecodeReason::Context));
                }
                let path = match source {
                    SourceRef::JournalFile { path, .. } => Some((path, RootPurpose::Journal)),
                    SourceRef::TextLog { path, .. } => Some((path, RootPurpose::Logs)),
                    SourceRef::StartupDirectory { path, .. } => {
                        Some((path, RootPurpose::Persistence))
                    }
                    _ => None,
                };
                if let Some((path, purpose)) = path
                    && !v
                        .scope
                        .roots
                        .iter()
                        .any(|r| r.root_id == path.root_id && r.purposes.contains(&purpose))
                {
                    return Err(invalid(DecodeReason::Context));
                }
            }
        }
        Document::Request(v) => {
            interval(&v.event_window.start, &v.event_window.end, true)?;
            if v.collectors.windows(2).any(|p| p[0] >= p[1])
                || v.collectors
                    .iter()
                    .any(|c| !v.capabilities.contains(&required(*c)))
                || (v.collectors.contains(&Collector::Events) && v.source_ids.is_empty())
            {
                return Err(invalid(DecodeReason::Context));
            }
        }
        Document::Indicators(v) => {
            let mut ids = BTreeSet::new();
            for indicator in &v.indicators {
                if !ids.insert(indicator.id()) {
                    return Err(invalid(DecodeReason::Identifier));
                }
            }
        }
        Document::LabScenario(v) => {
            interval(&v.valid_from, &v.valid_until, true)?;
            if under(&v.owned_scratch_root, &v.output_root)
                || under(&v.output_root, &v.owned_scratch_root)
            {
                return Err(invalid(DecodeReason::Path));
            }
        }
        Document::Report(v) => {
            if v.manifest.context != v.context
                || v.records.iter().any(|r| r.context != v.context)
                || v.endpoint
                    .as_ref()
                    .is_some_and(|e| e.endpoint_id != v.context.endpoint_id)
                || v.inputs.designation.id != v.context.designation_id
                || v.inputs.authorisation.id != v.context.authorisation_id
                || v.inputs.policy.id != v.context.policy_id
                || v.inputs.request.id != v.context.collection_id
            {
                return Err(invalid(DecodeReason::Context));
            }
        }
        // These shapes have no standalone cross-document admission semantics.
        // Framing/ordering and report digests require their independent verifiers.
        Document::Types(_)
        | Document::Endpoint(_)
        | Document::Record(_)
        | Document::Manifest(_)
        | Document::Status(_)
        | Document::Worker(_) => {}
    }
    Ok(())
}
