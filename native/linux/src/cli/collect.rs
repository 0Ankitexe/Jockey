//! One admitted native invocation. Only code-owned sources and pinned input
//! descriptors enter the fixed-self worker channel.
use super::{clock, commands::Reply, config};
use crate::{
    collection::{self, CollectJob},
    sources::{
        self,
        inventory::ResolvedCapabilities,
        procfs::{FixedMount, MountKind},
    },
    worker::{peer, protocol},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::{
    ClockReading, ValidatedCollectionContext, clock::Clock, identity::digest, report,
};
use jocky_shared::collection::{
    Code,
    inputs::{CollectionVersion, SourceRef},
    launch::{
        ClockBasis, ClockPair, DescriptorBinding, HandleKind, LaunchVersion, ObjectIdentity,
        WorkAllowance, WorkerLaunch,
    },
    outcomes::Collector,
    report::{ReportKind, Stage, StatusCode, WorkerCleanup},
    worker::{Body, Chunk, Commit, Done, InputDescriptor, Job, Start, WorkerFrame},
};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{self, AtFlags, StatxFlags},
};

struct NativeClock;
impl Clock for NativeClock {
    fn read(&mut self) -> Result<ClockReading, Code> {
        clock::read()
    }
}

pub(crate) fn object_identity(fd: BorrowedFd<'_>) -> Result<ObjectIdentity, Code> {
    let stat = fs::statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID,
    )
    .map_err(|_| Code::FacilityUnavailable)?;
    if stat.stx_mask
        & (StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID).bits()
        != (StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID).bits()
    {
        return Err(Code::Unsupported);
    }
    Ok(ObjectIdentity {
        device_id: fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
        inode: stat.stx_ino.to_string(),
        mount_id: Some(stat.stx_mnt_id.to_string()),
    })
}

struct Prepared {
    launch: WorkerLaunch,
    frames: Vec<WorkerFrame>,
    handles: Vec<OwnedFd>,
}

fn frames(
    config: &config::Configuration,
    collector: Collector,
    id: &jocky_shared::collection::identity::Uuid,
) -> Result<Vec<WorkerFrame>, Code> {
    let docs = config.documents();
    let mut joined = Vec::new();
    let mut inputs = Vec::new();
    for (role, bytes) in docs {
        inputs.push(InputDescriptor {
            role,
            byte_length: bytes.len() as u64,
            sha256: digest(bytes)?,
        });
        joined.extend_from_slice(bytes);
    }
    let joined_hash = digest(&joined)?;
    let mut result = vec![WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: id.clone(),
        body: Body::Start(Start::Collect {
            collector,
            inputs,
            input_byte_length: joined.len() as u64,
            input_sha256: joined_hash.clone(),
        }),
    }];
    for (index, block) in joined.chunks(24 * 1024).enumerate() {
        result.push(WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: (index + 1) as u64,
            collection_id: id.clone(),
            body: Body::StartChunk(Chunk {
                offset: (index * 24 * 1024) as u64,
                data: STANDARD.encode(block),
            }),
        });
    }
    result.push(WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: result.len() as u64,
        collection_id: id.clone(),
        body: Body::StartCommit(Commit {
            byte_length: joined.len() as u64,
            sha256: joined_hash,
        }),
    });
    Ok(result)
}

fn bind(
    handles: &mut Vec<OwnedFd>,
    bindings: &mut Vec<DescriptorBinding>,
    kind: HandleKind,
    subject: jocky_shared::collection::identity::Uuid,
    fd: BorrowedFd<'_>,
) -> Result<(), Code> {
    let owned = fd.try_clone_to_owned().map_err(|_| Code::ResourceLimit)?;
    let object = object_identity(owned.as_fd())?;
    bindings.push(DescriptorBinding {
        kind,
        subject_id: Some(subject),
        fd: 3 + handles.len() as u32,
        object,
    });
    handles.push(owned);
    Ok(())
}

fn selected_handles(
    context: &ValidatedCollectionContext,
    inventory: &ResolvedCapabilities<'_>,
    collector: Collector,
    clock: &mut dyn Clock,
) -> Result<(Vec<DescriptorBinding>, Vec<OwnedFd>), Code> {
    let mut bindings = Vec::new();
    let mut handles = Vec::new();
    if matches!(
        collector,
        Collector::Files | Collector::Persistence | Collector::Events
    ) {
        for (path, root) in inventory.ordinary_roots() {
            let selected = match collector {
                Collector::Files => context.paths().iter().any(|item| item.path().root_id == path.root_id),
                Collector::Persistence => context.sources().iter().any(|item| matches!(item.definition(), SourceRef::StartupDirectory { path: source_path, .. } if source_path.root_id == path.root_id)),
                Collector::Events => context.sources().iter().any(|item| matches!(item.definition(), SourceRef::JournalFile { path: source_path, .. } | SourceRef::TextLog { path: source_path, .. } if source_path.root_id == path.root_id)),
                _ => false,
            };
            if !selected {
                continue;
            }
            let id = path.root_id.clone();
            if bindings.iter().any(|binding: &DescriptorBinding| {
                binding.kind == HandleKind::OrdinaryRoot && binding.subject_id.as_ref() == Some(&id)
            }) {
                continue;
            }
            bind(
                &mut handles,
                &mut bindings,
                HandleKind::OrdinaryRoot,
                id,
                root.fd(),
            )?;
        }
    }
    if matches!(
        collector,
        Collector::System | Collector::Processes | Collector::Connections | Collector::Drivers
    ) {
        for source in context.sources().iter().filter(|source| match collector {
            Collector::System => matches!(source.definition(), SourceRef::KernelProfile { .. }),
            Collector::Processes => matches!(source.definition(), SourceRef::ProcProcesses { .. }),
            Collector::Connections => matches!(source.definition(), SourceRef::ProcNet { .. }),
            Collector::Drivers => matches!(source.definition(), SourceRef::SysModules { .. }),
            _ => false,
        }) {
            let id = source.definition().id().clone();
            let mount = FixedMount::open(
                context,
                source.definition().id(),
                MountKind::Proc,
                clock,
                &false,
            )?;
            bind(
                &mut handles,
                &mut bindings,
                HandleKind::ProcMount,
                id.clone(),
                mount.fd(),
            )?;
            if collector == Collector::Drivers {
                // sysfs is optional metadata. If this parent probe fails, the
                // worker repeats the selected fixed-facility probe and retains
                // its actual missing/denied/unsupported reason per field.
                if let Ok(sys) = FixedMount::open(
                    context,
                    source.definition().id(),
                    MountKind::Sys,
                    clock,
                    &false,
                ) {
                    bind(
                        &mut handles,
                        &mut bindings,
                        HandleKind::SysMount,
                        id.clone(),
                        sys.fd(),
                    )?;
                }
            }
            if collector == Collector::System {
                // The primary path is commonly a symlink. The code-owned
                // fallback is a regular file; the worker reports a typed
                // omission if it is unavailable.
                if let Some(file) =
                    sources::system::pin_release_fallback(context, &id, clock, &false)?
                {
                    bind(
                        &mut handles,
                        &mut bindings,
                        HandleKind::OsReleaseFallback,
                        id,
                        file.as_fd(),
                    )?;
                }
            }
        }
    }
    Ok((bindings, handles))
}

fn retained_shares(
    memory_bytes: u64,
    count: u64,
    has_processes: bool,
    has_connections: bool,
) -> Result<(u64, u64, u64), Code> {
    if count == 0 {
        return Err(Code::InvalidInput);
    }
    let denominator = count
        .checked_add(if has_processes { 2 } else { 0 })
        .and_then(|value| value.checked_add(if has_connections { 2 } else { 0 }))
        .ok_or(Code::ResourceLimit)?;
    let ordinary = (memory_bytes / 2) / denominator;
    let processes = if has_processes {
        ordinary.checked_mul(3).ok_or(Code::ResourceLimit)?
    } else {
        ordinary
    };
    let connections = if has_connections {
        ordinary.checked_mul(3).ok_or(Code::ResourceLimit)?
    } else {
        ordinary
    };
    if ordinary == 0 {
        return Err(Code::ResourceLimit);
    }
    Ok((ordinary, processes, connections))
}

fn error_shares(
    max_errors: u64,
    count: u64,
    has_processes: bool,
    has_connections: bool,
) -> Result<(u64, u64, u64), Code> {
    if count == 0 {
        return Err(Code::InvalidInput);
    }
    let denominator = count
        .checked_add(if has_processes { 7 } else { 0 })
        .and_then(|value| value.checked_add(if has_connections { 14 } else { 0 }))
        .ok_or(Code::ResourceLimit)?;
    let ordinary = max_errors / denominator;
    let processes = if has_processes {
        ordinary.checked_mul(8).ok_or(Code::ResourceLimit)?
    } else {
        ordinary
    };
    let connections = if has_connections {
        ordinary.checked_mul(15).ok_or(Code::ResourceLimit)?
    } else {
        ordinary
    };
    if ordinary == 0 {
        return Err(Code::ResourceLimit);
    }
    Ok((ordinary, processes, connections))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod retained_share_tests {
    use super::*;

    #[test]
    fn process_reservation_fits_the_unchanged_aggregate_limit() {
        const LIMIT: u64 = 268_435_456;
        for count in 2..=9 {
            let (ordinary, processes, connections) =
                retained_shares(LIMIT, count, true, true).unwrap();
            assert!(processes > ordinary);
            assert!(connections > ordinary);
            assert!(processes + connections + (count - 2) * ordinary <= LIMIT / 2);
            let (equal, unused, another) = retained_shares(LIMIT, count, false, false).unwrap();
            assert_eq!(equal, unused);
            assert_eq!(equal, another);
            assert!(count * equal <= LIMIT / 2);
        }
    }

    #[test]
    fn empty_or_insufficient_retention_is_rejected() {
        assert!(matches!(
            retained_shares(268_435_456, 0, true, true),
            Err(Code::InvalidInput)
        ));
        assert!(matches!(
            retained_shares(1, 6, true, true),
            Err(Code::ResourceLimit)
        ));
    }

    #[test]
    fn process_error_reservation_fits_aggregate_and_has_disjoint_bases() {
        for count in 2..=9 {
            let (ordinary, processes, connections) = error_shares(1000, count, true, true).unwrap();
            assert!(processes >= 260);
            assert!(connections >= 490);
            assert!(processes + connections + (count - 2) * ordinary <= 1000);
        }
        assert!(matches!(
            error_shares(1, 9, true, true),
            Err(Code::ResourceLimit)
        ));
    }
}

fn allowances(
    context: &ValidatedCollectionContext,
    count: u64,
    has_processes: bool,
    has_connections: bool,
) -> Result<(WorkAllowance, WorkAllowance, u64, u64, u64, u64), Code> {
    if count == 0 {
        return Err(Code::InvalidInput);
    }
    let l = context.limits();
    let (ordinary_retained, process_retained, connection_retained) =
        retained_shares(l.max_memory_bytes, count, has_processes, has_connections)?;
    let (ordinary_errors, process_errors, connection_errors) =
        error_shares(l.max_errors, count, has_processes, has_connections)?;
    let collect = WorkAllowance {
        records: l.max_records / count,
        report_bytes: 0,
        source_bytes: l.max_source_bytes / count,
        errors: ordinary_errors,
        entries: l.max_entries / count,
        indicator_comparisons: l.max_indicator_comparisons / count,
        staging_bytes: (l.max_staging_bytes.saturating_sub(l.max_report_bytes)) / count,
        retained_bytes: ordinary_retained,
    };
    let publish = WorkAllowance {
        records: 0,
        report_bytes: l.max_report_bytes,
        source_bytes: 0,
        errors: 0,
        entries: 0,
        indicator_comparisons: 0,
        staging_bytes: l.max_report_bytes,
        retained_bytes: l.max_memory_bytes / 4,
    };
    if ordinary_retained == 0
        || collect.records == 0
        || collect.errors == 0
        || collect.source_bytes == 0
        || publish.report_bytes < 65_536
    {
        return Err(Code::ResourceLimit);
    }
    Ok((
        collect,
        publish,
        process_retained,
        connection_retained,
        process_errors,
        connection_errors,
    ))
}

pub(crate) fn execute(
    config: &config::Configuration,
    output_path: &str,
    start: ClockReading,
) -> Result<Reply, (Code, Stage, bool)> {
    let mut clock = NativeClock;
    let current = clock
        .read()
        .map_err(|code| (code, Stage::Admission, false))?;
    let context = config
        .admit_for_invocation(start, current)
        .map_err(|code| (code, Stage::Admission, false))?;
    let ids = (
        context.identity().collection_id.clone(),
        context.identity().endpoint_id.clone(),
        context.identity().case_id.clone(),
    );
    let exclusions = config
        .exclusions()
        .map_err(|code| (code, Stage::Admission, false))?;
    let inventory = ResolvedCapabilities::admit(
        &context,
        &config.object_ids(),
        output_path,
        &mut clock,
        &false,
    )
    .map_err(|code| (code, Stage::Admission, false))?;
    let expected = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .map_err(|code| (code, Stage::Admission, false))?;
    let (
        collect_allowance,
        publish_allowance,
        process_retained,
        connection_retained,
        process_errors,
        connection_errors,
    ) = allowances(
        &context,
        expected.collectors.len() as u64,
        expected
            .collectors
            .iter()
            .any(|outcome| outcome.collector == Collector::Processes),
        expected
            .collectors
            .iter()
            .any(|outcome| outcome.collector == Collector::Connections),
    )
    .map_err(|code| (code, Stage::Admission, false))?;
    let parent = peer::own_identity().map_err(|code| (code, Stage::Admission, false))?;
    let origin = ClockPair {
        utc: context.invocation_start().utc.clone(),
        monotonic_ms: context.invocation_start().monotonic_ms,
    };
    let mut prepared = Vec::new();
    let mut error_base = 0u64;
    for (index, outcome) in expected.collectors.iter().enumerate() {
        let collector = outcome.collector;
        let (bindings, handles) = selected_handles(&context, &inventory, collector, &mut clock)
            .map_err(|code| (code, Stage::Admission, false))?;
        let frames =
            frames(config, collector, &ids.0).map_err(|code| (code, Stage::Admission, false))?;
        let observed = clock
            .read()
            .map_err(|code| (code, Stage::Admission, false))?;
        let mut allowance = collect_allowance.clone();
        if collector == Collector::Processes {
            allowance.retained_bytes = process_retained;
            allowance.errors = process_errors;
        } else if collector == Collector::Connections {
            allowance.retained_bytes = connection_retained;
            allowance.errors = connection_errors;
        }
        let next_error_base = error_base.checked_add(allowance.errors).ok_or((
            Code::ResourceLimit,
            Stage::Admission,
            false,
        ))?;
        let launch = WorkerLaunch {
            schema_version: LaunchVersion::V1_1,
            worker_schema_version: CollectionVersion::V1,
            collection_id: ids.0.clone(),
            job: Job::Collect,
            clock_basis: ClockBasis::LinuxMonotonic,
            invocation_origin: origin.clone(),
            launch_observed: ClockPair {
                utc: observed.utc,
                monotonic_ms: observed.monotonic_ms,
            },
            parent: parent.clone(),
            start_sha256: digest(
                &protocol::encode_frame(&frames[0])
                    .map_err(|code| (code, Stage::Admission, false))?[4..],
            )
            .map_err(|code| (code, Stage::Admission, false))?,
            record_base: (index as u64).saturating_mul(collect_allowance.records),
            error_base,
            global_limits: context.limits().clone(),
            allowance,
            descriptors: bindings,
            config_exclusions: exclusions.clone(),
        };
        prepared.push(Prepared {
            launch,
            frames,
            handles,
        });
        error_base = next_error_base;
    }
    let observed = clock
        .read()
        .map_err(|code| (code, Stage::Admission, false))?;
    let publish_launch = WorkerLaunch {
        schema_version: LaunchVersion::V1_1,
        worker_schema_version: CollectionVersion::V1,
        collection_id: ids.0.clone(),
        job: Job::Publish,
        clock_basis: ClockBasis::LinuxMonotonic,
        invocation_origin: origin,
        launch_observed: ClockPair {
            utc: observed.utc,
            monotonic_ms: observed.monotonic_ms,
        },
        parent,
        start_sha256: "0".repeat(64),
        record_base: 0,
        error_base: 0,
        global_limits: context.limits().clone(),
        allowance: publish_allowance,
        descriptors: vec![DescriptorBinding {
            kind: HandleKind::OutputDirectory,
            subject_id: None,
            fd: 3,
            object: object_identity(inventory.output().sync_fd())
                .map_err(|code| (code, Stage::Admission, false))?,
        }],
        config_exclusions: exclusions,
    };
    let borrowed: Vec<Vec<_>> = prepared
        .iter()
        .map(|job| job.handles.iter().map(AsFd::as_fd).collect())
        .collect();
    let jobs: Vec<_> = prepared
        .iter()
        .zip(&borrowed)
        .map(|(job, descriptors)| CollectJob {
            launch: &job.launch,
            frames: &job.frames,
            descriptors,
        })
        .collect();
    let done = collection::run_owned(
        &context,
        &jobs,
        inventory.output(),
        publish_launch,
        &mut clock,
        || false,
    )
    .map_err(|code| {
        (
            code,
            Stage::Finalization,
            crate::worker::signals::was_interrupted() && code == Code::Cancelled,
        )
    })?;
    match done {
        Done::Publish {
            code,
            sha256,
            byte_length,
            ..
        } => Ok(Reply {
            code: if crate::worker::signals::was_interrupted() {
                StatusCode::Error(Code::Cancelled)
            } else {
                code
            },
            stage: Stage::Finalization,
            identifiers: Some(ids),
            report: sha256.zip(byte_length),
            interrupted: crate::worker::signals::was_interrupted(),
        }),
        _ => Err((Code::WorkerProtocol, Stage::Finalization, false)),
    }
}
