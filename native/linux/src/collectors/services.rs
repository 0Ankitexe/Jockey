//! Pure service inventory normalization from admitted systemd bus facts.
use crate::sources::systemd::{Property, Snapshot, UnitFact};
use jocky_shared::collection::{Code, outcomes::Field, records::ServiceRecord};
use std::collections::BTreeMap;

fn field(value: Option<Result<String, Code>>, fallback: Option<&str>) -> Field<String> {
    match value {
        Some(Ok(value)) => Field::Available { value },
        Some(Err(reason)) => Field::Unavailable { reason },
        None => match fallback {
            Some(value) => Field::Available {
                value: value.into(),
            },
            None => Field::Unavailable {
                reason: Code::NotFound,
            },
        },
    }
}

fn loaded_field(
    snapshot: &Snapshot,
    unit: Option<&UnitFact>,
    name: &str,
    property: Property,
    fallback: impl FnOnce(&UnitFact) -> &str,
) -> Field<String> {
    field(
        snapshot
            .properties
            .get(&(name.to_owned(), property))
            .cloned(),
        unit.map(fallback),
    )
}

pub(crate) fn normalize(snapshot: Snapshot) -> Result<Vec<ServiceRecord>, Code> {
    let mut units = BTreeMap::new();
    for unit in &snapshot.units {
        if units.insert(unit.name.clone(), unit).is_some() {
            return Err(Code::MalformedSource);
        }
    }
    let mut files = BTreeMap::new();
    for file in &snapshot.files {
        if files
            .insert(file.name.clone(), file.state.as_str())
            .is_some()
        {
            return Err(Code::MalformedSource);
        }
    }
    let mut names: Vec<_> = units.keys().chain(files.keys()).cloned().collect();
    names.sort();
    names.dedup();
    if names.len() > 512 {
        return Err(Code::ResourceLimit);
    }
    Ok(names
        .into_iter()
        .map(|name| {
            let unit = units.get(&name).copied();
            ServiceRecord {
                description: loaded_field(&snapshot, unit, &name, Property::Description, |u| {
                    &u.description
                }),
                load_state: loaded_field(&snapshot, unit, &name, Property::LoadState, |u| {
                    &u.load_state
                }),
                active_state: loaded_field(&snapshot, unit, &name, Property::ActiveState, |u| {
                    &u.active_state
                }),
                sub_state: loaded_field(&snapshot, unit, &name, Property::SubState, |u| {
                    &u.sub_state
                }),
                unit_file_state: field(files.get(&name).map(|s| Ok((*s).into())), None),
                unit_name: name,
            }
        })
        .collect())
}

pub(crate) fn non_systemd() -> Result<Vec<ServiceRecord>, Code> {
    Err(Code::Unsupported)
}

/// Real standalone service collector. The bus path is the fixed, admitted
/// system socket; no `systemctl`, activation or unit mutation is used.
pub(crate) fn collect_owned(
    context: &jocky_forensic::collection::ValidatedCollectionContext,
    launch: &jocky_shared::collection::launch::WorkerLaunch,
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
) -> Result<crate::collection::Collected, Code> {
    use jocky_shared::collection::{
        inputs::SourceRef,
        outcomes::Collector,
        records::{Adapter, Category, Payload, ProvenanceKind},
    };
    let mut sources = Vec::new();
    for selected in context.sources() {
        let SourceRef::SystemdBus { source_id, .. } = selected.definition() else {
            continue;
        };
        let result = crate::sources::systemd::connect_admitted(context, source_id, clock, &false)
            .and_then(|mut bus| crate::sources::systemd::query_listed(&mut bus))
            .and_then(|(snapshot, malformed)| normalize(snapshot).map(|rows| (rows, malformed)));
        sources.push(match result {
            Ok((rows, malformed)) => {
                let missing = rows.iter().find_map(|row| {
                    [
                        &row.description,
                        &row.load_state,
                        &row.active_state,
                        &row.sub_state,
                        &row.unit_file_state,
                    ]
                    .into_iter()
                    .find_map(|field| match field {
                        Field::Unavailable { reason } if *reason != Code::NotRequested => {
                            Some(*reason)
                        }
                        _ => None,
                    })
                });
                crate::collectors::facility::SourceFacts {
                    id: source_id.clone(),
                    issues: missing
                        .into_iter()
                        .chain(malformed.then_some(Code::MalformedSource))
                        .collect(),
                    unavailable: None,
                    facts: rows
                        .into_iter()
                        .map(|row| crate::collectors::facility::Fact {
                            payload: Payload::Service(row),
                            adapter: Adapter::Systemd,
                            category: Category::System,
                            kind: ProvenanceKind::SystemdBus,
                            scope: crate::collectors::record::facility_scope(source_id.clone()),
                        })
                        .collect(),
                }
            }
            Err(code) => {
                crate::collectors::facility::SourceFacts::unavailable(source_id.clone(), code)
            }
        });
    }
    crate::collectors::facility::assemble(context, launch, clock, Collector::Services, sources)
}
