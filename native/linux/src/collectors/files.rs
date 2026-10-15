//! A full-file hash requires the charged confined reader's success and stability.
use crate::{
    collection::Collected,
    sources::{
        metadata::{Exclusions, ObjectId},
        paths::ConfinedRoot,
        reads::read_all,
    },
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
    identity::{ClockBasis, TimeObservation},
    inputs::PathRef,
    launch::{HandleKind, WorkerLaunch},
    outcomes::{
        Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState, Field, ItemError,
    },
    records::{Adapter, Category, FileRecord, Payload, ProvenanceKind, ReadStability, SourceScope},
};
use rustix::fd::{AsFd, OwnedFd};
use std::collections::BTreeMap;

pub(crate) fn digest_complete(
    raw: &[u8],
    expected_size: u64,
    stable: bool,
) -> Result<String, Code> {
    if expected_size > 16_777_216 {
        return Err(Code::ResourceLimit);
    }
    if !stable || raw.len() as u64 != expected_size {
        return Err(Code::SourceChanged);
    }
    jocky_forensic::collection::identity::digest(raw)
}

pub(crate) fn collect_file(
    root: &ConfinedRoot<'_>,
    path: &PathRef,
    clock: &mut dyn Clock,
    cancel: &dyn Cancellation,
) -> Result<FileRecord, Code> {
    if root.root_id() != &path.root_id {
        return Err(Code::ScopeDenied);
    }
    let pin = root.pin_file(&path.relative_path, clock, cancel)?;
    let readable = pin.reopen(clock, cancel)?;
    let facts = readable.facts();
    let bytes = read_all(&readable, 16_777_216, clock, cancel)?;
    readable.check_unchanged(clock, cancel)?;
    let digest = digest_complete(&bytes, facts.size, true)?;
    let mtime = crate::cli::clock::unix_utc(facts.mtime_seconds)?;
    let ctime = crate::cli::clock::unix_utc(facts.ctime_seconds)?;
    Ok(FileRecord {
        location: path.clone(),
        size_bytes: Field::Available { value: facts.size },
        mode: Field::Available { value: facts.mode },
        uid: Field::Available { value: facts.uid },
        gid: Field::Available { value: facts.gid },
        mtime: Field::Available { value: mtime },
        ctime: Field::Available { value: ctime },
        sha256: Field::Available { value: digest },
        read_stability: ReadStability::StableObserved,
    })
}

/// Collect exactly the approved paths using authenticated inherited root pins.
/// A failed hash or changed file never yields a complete digest record.
pub(crate) fn collect_owned(
    context: &ValidatedCollectionContext,
    launch: &WorkerLaunch,
    handles: &[OwnedFd],
    clock: &mut dyn Clock,
) -> Result<Collected, Code> {
    let excluded = Exclusions::new(
        &launch
            .config_exclusions
            .iter()
            .map(|id| {
                Ok(ObjectId {
                    device: id.device_id.parse().map_err(|_| Code::WorkerProtocol)?,
                    inode: id.inode.parse().map_err(|_| Code::WorkerProtocol)?,
                })
            })
            .collect::<Result<Vec<_>, Code>>()?,
    )?;
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut coverage = BTreeMap::new();
    let mut omissions = 0u64;
    let mut error_limit_hit = false;
    for approved in context.paths() {
        let path = approved.path();
        if records.len() as u64 >= launch.allowance.records {
            omissions += 1;
            coverage.insert(path.root_id.clone(), Some(Code::ResourceLimit));
            continue;
        }
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
        let file = ConfinedRoot::inherited(
            context,
            OperationTarget::File(path),
            handle
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| Code::WorkerProtocol)?,
            excluded.clone(),
            clock,
            &false,
        )
        .and_then(|root| collect_file(&root, path, clock, &false));
        match file {
            Ok(file) => {
                let ordinal = launch.record_base + records.len() as u64;
                let now = clock.read()?;
                let observed = TimeObservation {
                    value: now.utc,
                    basis: ClockBasis::LocalClock,
                    uncertainty_ms: None,
                    clock_uncertain: false,
                };
                records.push(super::record::make(
                    context,
                    Collector::Files,
                    Adapter::Files,
                    Category::File,
                    ProvenanceKind::ScopedFile,
                    path.root_id.clone(),
                    SourceScope::Path { path: path.clone() },
                    Payload::File(file),
                    ordinal,
                    observed,
                )?);
                let mut permit =
                    context.permit(OperationTarget::File(path), &clock.read()?, false)?;
                permit.charge(Counter::Records, 1)?;
                coverage.entry(path.root_id.clone()).or_insert(None);
            }
            Err(code) => {
                omissions += 1;
                coverage.insert(path.root_id.clone(), Some(code));
                if errors.len() as u64 >= launch.allowance.errors {
                    error_limit_hit = true;
                    continue;
                }
                let ordinal = launch.error_base + errors.len() as u64;
                let mut permit =
                    context.permit(OperationTarget::File(path), &clock.read()?, false)?;
                permit.charge(Counter::Errors, 1)?;
                errors.push(ItemError {
                    error_id: derive_id(
                        IdentityKind::Error,
                        &context.identity().collection_id,
                        ordinal,
                    )?,
                    collector: Collector::Files,
                    source_id: Some(path.root_id.clone()),
                    item_ref: ordinal,
                    field_path: Some("/payload/sha256".into()),
                    code,
                    retryable: false,
                    counted_omission: true,
                });
            }
        }
    }
    let partial = !errors.is_empty() || omissions != 0 || error_limit_hit;
    let reason = if error_limit_hit {
        Some(Code::ResourceLimit)
    } else {
        errors
            .first()
            .map(|error| error.code)
            .or((omissions != 0).then_some(Code::ResourceLimit))
    };
    let usage = super::usage(context)?;
    Ok(Collected {
        outcome: CollectorOutcome {
            collector: Collector::Files,
            status: if partial {
                if records.is_empty() {
                    CollectorStatus::Failed
                } else {
                    CollectorStatus::Partial
                }
            } else {
                CollectorStatus::Complete
            },
            coverage: coverage
                .into_iter()
                .map(|(source_id, reason)| Coverage {
                    source_id,
                    state: if reason.is_some() {
                        FacilityState::Partial
                    } else {
                        FacilityState::Supported
                    },
                    reason,
                })
                .collect(),
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
