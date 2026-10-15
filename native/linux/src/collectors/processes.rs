//! Pure procfs stat/status decoders. No environment or memory interface.
use crate::{
    collection::Collected,
    sources::procfs::{FixedMount, MountKind, Query},
};
use jocky_forensic::collection::{
    ValidatedCollectionContext,
    budget::Counter,
    cancellation::Cancellation,
    clock::Clock,
    context::OperationTarget,
    identity::{IdentityKind, derive_id},
};
use jocky_shared::collection::{
    Code,
    identity::{ClockBasis, TimeObservation, Uuid},
    inputs::SourceKind,
    launch::{HandleKind, WorkerLaunch},
    outcomes::{
        Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState, Field, ItemError,
    },
    records::{Adapter, Category, Payload, ProcessIdentity, ProcessRecord, ProvenanceKind},
};
use rustix::fd::{AsFd, OwnedFd};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcStat {
    pub pid: u32,
    pub parent_pid: u32,
    pub command: String,
    pub start_ticks: String,
}

pub(crate) fn parse_stat(raw: &[u8], expected_pid: u32) -> Result<ProcStat, Code> {
    if raw.len() > 65_536 || expected_pid == 0 {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    let (pid, rest) = text
        .trim_end()
        .split_once(" (")
        .ok_or(Code::MalformedSource)?;
    let pid = pid.parse::<u32>().map_err(|_| Code::MalformedSource)?;
    if pid != expected_pid {
        return Err(Code::SourceChanged);
    }
    // The comm field may contain spaces and parentheses; its final ") "
    // precedes the fixed stat fields. The kernel limits comm to 15 bytes.
    let (command, tail) = rest.rsplit_once(") ").ok_or(Code::MalformedSource)?;
    if command.is_empty() || command.len() > 256 {
        return Err(Code::MalformedSource);
    }
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    if fields.len() < 20 {
        return Err(Code::MalformedSource);
    }
    let parent_pid = fields[1].parse().map_err(|_| Code::MalformedSource)?;
    let start = fields[19]; // field 22 after state (field 3)
    start.parse::<u64>().map_err(|_| Code::MalformedSource)?;
    Ok(ProcStat {
        pid,
        parent_pid,
        command: command.to_owned(),
        start_ticks: start.to_owned(),
    })
}

pub(crate) fn parse_uid(raw: &[u8]) -> Result<u32, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    let mut found = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            let real = value
                .split_ascii_whitespace()
                .next()
                .ok_or(Code::MalformedSource)?;
            let uid = real.parse::<u32>().map_err(|_| Code::MalformedSource)?;
            if found.replace(uid).is_some() {
                return Err(Code::MalformedSource);
            }
        }
    }
    found.ok_or(Code::NotFound)
}

pub(crate) fn same_start(before: &ProcStat, after: &ProcStat) -> Result<(), Code> {
    if before.pid == after.pid && before.start_ticks == after.start_ticks {
        Ok(())
    } else {
        Err(Code::SourceChanged)
    }
}

fn decode_boot(raw: &[u8]) -> Result<Uuid, Code> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| Code::UnsupportedEncoding)?
        .trim_end();
    Uuid::parse(text).map_err(|_| Code::MalformedSource)
}

fn decode_exe(raw: &[u8]) -> Result<String, Code> {
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    if text.is_empty() || text.len() > 4096 || text.contains('\0') {
        return Err(Code::MalformedSource);
    }
    Ok(text.to_owned())
}

fn field<T>(result: Result<T, Code>) -> Field<T> {
    match result {
        Ok(value) => Field::Available { value },
        Err(reason) => Field::Unavailable { reason },
    }
}

fn field_failures(process: &ProcessRecord) -> Vec<(&'static str, Code)> {
    let mut failures = Vec::new();
    if let Field::Unavailable { reason } = &process.uid {
        failures.push(("/payload/uid", *reason));
    }
    if let Field::Unavailable { reason } = &process.executable {
        failures.push(("/payload/executable", *reason));
    }
    if let Field::Unavailable { reason } = &process.start_identity {
        failures.push(("/payload/start_identity", *reason));
    }
    failures
}

/// Decode only caller-supplied bytes. This seam keeps offline identity and
/// field-failure assertions independent from the host proc mount.
pub(crate) fn join_process(
    pid: u32,
    before_raw: &[u8],
    after_raw: &[u8],
    boot_raw: Result<&[u8], Code>,
    status_raw: Result<&[u8], Code>,
    exe_raw: Result<&[u8], Code>,
) -> Result<ProcessRecord, Code> {
    let before = parse_stat(before_raw, pid)?;
    let after = parse_stat(after_raw, pid)?;
    same_start(&before, &after)?;
    let boot = boot_raw.and_then(decode_boot);
    let status = status_raw.and_then(parse_uid);
    let exe = exe_raw.and_then(decode_exe);
    Ok(ProcessRecord {
        pid: u64::from(pid),
        parent_pid: Field::Available {
            value: u64::from(before.parent_pid),
        },
        uid: field(status.map(u64::from)),
        command: Field::Available {
            value: before.command,
        },
        executable: field(exe),
        start_identity: field(boot.map(|boot_id| ProcessIdentity {
            boot_id,
            pid: u64::from(pid),
            start_ticks: before.start_ticks,
        })),
    })
}

/// One PID's documented fields, always bracketed by the same start identity.
/// The only link read is the exe metadata target; no target is opened.
pub(crate) fn collect_process(
    source: &FixedMount<'_>,
    pid: u32,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<ProcessRecord, Code> {
    let before = source.read(Query::ProcessStat(pid), clock, cancel)?;
    parse_stat(&before, pid)?;
    let boot = source.read(Query::ProcessBootId, clock, cancel);
    let status = source.read(Query::ProcessStatus(pid), clock, cancel);
    let exe = source.read_link(
        crate::sources::procfs::links::LinkQuery::Exe(pid),
        clock,
        cancel,
    );
    let after = source.read(Query::ProcessStat(pid), clock, cancel)?;
    join_process(
        pid,
        &before,
        &after,
        boot.as_deref().map_err(|code| *code),
        status.as_deref().map_err(|code| *code),
        exe.as_deref().map_err(|code| *code),
    )
}

/// Inventory from the selected, inherited proc mount. A vanished or reused
/// PID is an omission with a typed error, never a fabricated stable record.
pub(crate) fn collect_owned(
    context: &ValidatedCollectionContext,
    launch: &WorkerLaunch,
    handles: &[OwnedFd],
    clock: &mut dyn Clock,
) -> Result<Collected, Code> {
    let source_id = context
        .sources()
        .iter()
        .find(|source| source.definition().kind() == SourceKind::ProcProcesses)
        .ok_or(Code::ScopeDenied)?
        .definition()
        .id()
        .clone();
    let proc = launch
        .descriptors
        .iter()
        .zip(handles)
        .find_map(|(binding, handle)| {
            (binding.kind == HandleKind::ProcMount
                && binding.subject_id.as_ref() == Some(&source_id))
            .then_some(handle)
        })
        .ok_or(Code::WorkerProtocol)?;
    let mount = FixedMount::inherited(
        context,
        &source_id,
        MountKind::Proc,
        proc.as_fd()
            .try_clone_to_owned()
            .map_err(|_| Code::WorkerProtocol)?,
        clock,
        &false,
    )?;
    let pids = mount.list_pids(clock, &false)?;
    let truncated = pids.len() as u64 > launch.allowance.records;
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut omissions = 0u64;
    let mut error_limit_hit = false;
    for (index, pid) in pids.iter().copied().enumerate() {
        if index as u64 >= launch.allowance.records {
            omissions += 1;
            continue;
        }
        match collect_process(&mount, pid, clock, &false) {
            Ok(process) => {
                let failures = field_failures(&process);
                let ordinal = launch.record_base + records.len() as u64;
                let now = clock.read()?;
                let observed = TimeObservation {
                    value: now.utc,
                    basis: ClockBasis::LocalClock,
                    uncertainty_ms: None,
                    clock_uncertain: false,
                };
                let record = super::record::make(
                    context,
                    Collector::Processes,
                    Adapter::Processes,
                    Category::Process,
                    ProvenanceKind::ProcProcesses,
                    source_id.clone(),
                    super::record::facility_scope(source_id.clone()),
                    Payload::Process(process),
                    ordinal,
                    observed,
                )?;
                let mut permit =
                    context.permit(OperationTarget::Source(&source_id), &clock.read()?, false)?;
                permit.charge(Counter::Records, 1)?;
                records.push(record);
                for (field_path, code) in failures {
                    if errors.len() as u64 >= launch.allowance.errors {
                        error_limit_hit = true;
                        break;
                    }
                    let error_ordinal = launch.error_base + errors.len() as u64;
                    permit.charge(Counter::Errors, 1)?;
                    errors.push(ItemError {
                        error_id: derive_id(
                            IdentityKind::Error,
                            &context.identity().collection_id,
                            error_ordinal,
                        )?,
                        collector: Collector::Processes,
                        source_id: Some(source_id.clone()),
                        item_ref: u64::from(pid),
                        field_path: Some(field_path.into()),
                        code,
                        retryable: false,
                        counted_omission: false,
                    });
                }
            }
            Err(code) => {
                omissions += 1;
                if errors.len() as u64 >= launch.allowance.errors {
                    error_limit_hit = true;
                    continue;
                }
                let ordinal = launch.error_base + errors.len() as u64;
                let mut permit =
                    context.permit(OperationTarget::Source(&source_id), &clock.read()?, false)?;
                permit.charge(Counter::Errors, 1)?;
                errors.push(ItemError {
                    error_id: derive_id(
                        IdentityKind::Error,
                        &context.identity().collection_id,
                        ordinal,
                    )?,
                    collector: Collector::Processes,
                    source_id: Some(source_id.clone()),
                    item_ref: u64::from(pid),
                    field_path: None,
                    code,
                    retryable: false,
                    counted_omission: true,
                });
            }
        }
    }
    let partial = !errors.is_empty() || truncated || error_limit_hit;
    let reason = if truncated || error_limit_hit {
        Some(Code::ResourceLimit)
    } else {
        errors.first().map(|error| error.code)
    };
    let usage = super::usage(context)?;
    Ok(Collected {
        outcome: CollectorOutcome {
            collector: Collector::Processes,
            status: if partial {
                if records.is_empty() {
                    CollectorStatus::Failed
                } else {
                    CollectorStatus::Partial
                }
            } else {
                CollectorStatus::Complete
            },
            coverage: vec![Coverage {
                source_id,
                state: if partial {
                    FacilityState::Partial
                } else {
                    FacilityState::Supported
                },
                reason,
            }],
            accepted_records: records.len() as u64,
            omitted_records: Some(omissions),
            omitted_reason: reason,
            errors: errors.len() as u64,
            stop_reason: reason,
        },
        usage,
        records,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inaccessible_fields_remain_attributable() {
        let record = ProcessRecord {
            pid: 42,
            parent_pid: Field::Available { value: 1 },
            uid: Field::Unavailable {
                reason: Code::PermissionDenied,
            },
            command: Field::Available {
                value: "benign".into(),
            },
            executable: Field::Unavailable {
                reason: Code::SourceDisappeared,
            },
            start_identity: Field::Unavailable {
                reason: Code::MalformedSource,
            },
        };
        assert_eq!(
            field_failures(&record),
            vec![
                ("/payload/uid", Code::PermissionDenied),
                ("/payload/executable", Code::SourceDisappeared),
                ("/payload/start_identity", Code::MalformedSource),
            ]
        );
    }
}
