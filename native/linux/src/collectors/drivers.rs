//! Detection-only decoding of an admitted `/proc/modules` snapshot.
use jocky_shared::collection::{Code, outcomes::Field, records::DriverRecord};

const MAX_BYTES: usize = 65_536;

fn version(value: Result<Vec<u8>, Code>) -> Result<Field<String>, Code> {
    match value {
        Err(reason)
            if matches!(
                reason,
                Code::NotFound
                    | Code::PermissionDenied
                    | Code::FacilityUnavailable
                    | Code::Unsupported
            ) =>
        {
            Ok(Field::Unavailable { reason })
        }
        Err(reason) => Err(reason),
        Ok(raw) => {
            if raw.len() > 256 {
                return Err(Code::ResourceLimit);
            }
            let text = std::str::from_utf8(&raw)
                .map_err(|_| Code::UnsupportedEncoding)?
                .trim();
            if text.is_empty() || text.contains(['\0', '\n', '\r']) {
                return Err(Code::MalformedSource);
            }
            Ok(Field::Available {
                value: text.to_owned(),
            })
        }
    }
}

/// `metadata` is supplied by a scoped sysfs reader; this parser never opens paths.
pub(crate) fn parse_loaded(
    proc: &[u8],
    mut metadata: impl FnMut(&str, &str) -> Result<Vec<u8>, Code>,
) -> Result<Vec<DriverRecord>, Code> {
    if proc.len() > MAX_BYTES {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(proc).map_err(|_| Code::UnsupportedEncoding)?;
    let mut records = Vec::new();
    for line in text.lines() {
        if records.len() >= 512 || line.len() > 4096 {
            return Err(Code::ResourceLimit);
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 {
            return Err(Code::MalformedSource);
        }
        let name = fields[0];
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Code::MalformedSource);
        }
        let size = fields[1]
            .parse::<u64>()
            .map_err(|_| Code::MalformedSource)?;
        let refs = fields[2]
            .parse::<u64>()
            .map_err(|_| Code::MalformedSource)?;
        if !matches!(fields[4], "Live" | "Loading" | "Unloading") {
            return Err(Code::MalformedSource);
        }
        // The sixth kernel field is an address. Never retain it.
        if !fields[5].starts_with("0x") || !fields[5][2..].bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Code::MalformedSource);
        }
        records.push(DriverRecord {
            name: name.to_owned(),
            size_bytes: Field::Available { value: size },
            reference_count: Field::Available { value: refs },
            state: fields[4].to_owned(),
            version: version(metadata(name, "version"))?,
            source_version: version(metadata(name, "srcversion"))?,
        });
    }
    Ok(records)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    #[test]
    fn loaded_metadata_and_missing_are_distinct() {
        let rows = parse_loaded(b"labmod 4096 1 - Live 0xffff000000000000\n", |_, field| {
            if field == "version" {
                Ok(b"1.2\n".to_vec())
            } else {
                Err(Code::NotFound)
            }
        })
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].version,
            Field::Available {
                value: "1.2".into()
            }
        );
        assert_eq!(
            rows[0].source_version,
            Field::Unavailable {
                reason: Code::NotFound
            }
        );
        assert!(!serde_json::to_string(&rows).unwrap().contains("ffff"));
        let denied = parse_loaded(b"labmod 4096 1 - Live 0xffff000000000000\n", |_, _| {
            Err(Code::PermissionDenied)
        })
        .unwrap();
        assert_eq!(
            denied[0].version,
            Field::Unavailable {
                reason: Code::PermissionDenied
            }
        );
    }
    #[test]
    fn malformed_and_oversize_fail_closed() {
        assert_eq!(
            parse_loaded(b"../escape 4096 1 - Live 0x0\n", |_, _| Ok(vec![])),
            Err(Code::MalformedSource)
        );
        assert_eq!(
            parse_loaded(&vec![b'x'; 65_537], |_, _| Ok(vec![])),
            Err(Code::ResourceLimit)
        );
        assert_eq!(
            parse_loaded(b"labmod 4096 1 - Live 0x0\n", |_, _| Err(
                Code::ResourceLimit
            )),
            Err(Code::ResourceLimit)
        );
    }
}

/// Query only the fixed proc/sys module facts for an already admitted source.
/// Missing sysfs version facts remain fields on a loaded module record.
pub(crate) fn collect_admitted(
    proc_mount: &crate::sources::procfs::FixedMount<'_>,
    sys_mount: Option<&crate::sources::procfs::FixedMount<'_>>,
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
    cancel: &dyn jocky_forensic::collection::cancellation::Cancellation,
) -> Result<Vec<DriverRecord>, Code> {
    collect_admitted_with_sys(proc_mount, sys_mount.ok_or(Code::NotFound), clock, cancel)
}

fn collect_admitted_with_sys(
    proc_mount: &crate::sources::procfs::FixedMount<'_>,
    sys_mount: Result<&crate::sources::procfs::FixedMount<'_>, Code>,
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
    cancel: &dyn jocky_forensic::collection::cancellation::Cancellation,
) -> Result<Vec<DriverRecord>, Code> {
    use crate::sources::procfs::Query;
    let proc = proc_mount.read(Query::Modules, clock, cancel)?;
    parse_loaded(&proc, |module, key| {
        let sys = sys_mount?;
        let query = match key {
            "version" => Query::ModuleVersion(module.to_owned()),
            "srcversion" => Query::ModuleSourceVersion(module.to_owned()),
            _ => return Err(Code::InvalidInput),
        };
        sys.read(query, clock, cancel)
    })
}

pub(crate) fn collect_owned(
    context: &jocky_forensic::collection::ValidatedCollectionContext,
    launch: &jocky_shared::collection::launch::WorkerLaunch,
    handles: &[rustix::fd::OwnedFd],
    clock: &mut dyn jocky_forensic::collection::clock::Clock,
) -> Result<crate::collection::Collected, Code> {
    use crate::{
        collectors::{
            facility::{self, Fact, SourceFacts},
            record,
        },
        sources::procfs::{FixedMount, MountKind},
    };
    use jocky_shared::collection::{
        inputs::SourceRef,
        launch::HandleKind,
        outcomes::Collector,
        records::{Adapter, Category, Payload, ProvenanceKind},
    };
    use rustix::fd::AsFd;
    let mut sources = Vec::new();
    for selected in context.sources() {
        let SourceRef::SysModules { source_id } = selected.definition() else {
            continue;
        };
        let proc_handle = launch
            .descriptors
            .iter()
            .zip(handles)
            .find_map(|(binding, handle)| {
                (binding.kind == HandleKind::ProcMount
                    && binding.subject_id.as_ref() == Some(source_id))
                .then_some(handle)
            })
            .ok_or(Code::WorkerProtocol)?;
        let sys_handle = launch
            .descriptors
            .iter()
            .zip(handles)
            .find_map(|(binding, handle)| {
                (binding.kind == HandleKind::SysMount
                    && binding.subject_id.as_ref() == Some(source_id))
                .then_some(handle)
            });
        let result = (|| {
            let proc = FixedMount::inherited(
                context,
                source_id,
                MountKind::Proc,
                proc_handle
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(|_| Code::WorkerProtocol)?,
                clock,
                &false,
            )?;
            let sys = match sys_handle {
                Some(handle) => FixedMount::inherited(
                    context,
                    source_id,
                    MountKind::Sys,
                    handle
                        .as_fd()
                        .try_clone_to_owned()
                        .map_err(|_| Code::WorkerProtocol)?,
                    clock,
                    &false,
                ),
                None => FixedMount::open(context, source_id, MountKind::Sys, clock, &false),
            };
            collect_admitted_with_sys(&proc, sys.as_ref().map_err(|code| *code), clock, &false)
        })();
        sources.push(match result {
            Ok(rows) => {
                let missing = rows.iter().find_map(|row| {
                    [&row.version, &row.source_version]
                        .into_iter()
                        .find_map(|field| match field {
                            Field::Unavailable { reason } if *reason != Code::NotRequested => {
                                Some(*reason)
                            }
                            _ => None,
                        })
                });
                SourceFacts {
                    id: source_id.clone(),
                    issues: missing.into_iter().collect(),
                    unavailable: None,
                    facts: rows
                        .into_iter()
                        .map(|row| Fact {
                            payload: Payload::Driver(row),
                            adapter: Adapter::Modules,
                            category: Category::Driver,
                            kind: ProvenanceKind::SysModules,
                            scope: record::facility_scope(source_id.clone()),
                        })
                        .collect(),
                }
            }
            Err(code) => SourceFacts::unavailable(source_id.clone(), code),
        });
    }
    facility::assemble(context, launch, clock, Collector::Drivers, sources)
}
