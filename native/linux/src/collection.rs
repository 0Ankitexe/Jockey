//! Private sequential collection-to-publication assembly. All source access
//! remains in admitted workers; this module only handles validated frames.
use crate::{
    sources::capabilities::OutputDirectory,
    worker::{accounting::ReservationLedger, supervisor},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::{ValidatedCollectionContext, clock::Clock, outcome, report};
use jocky_shared::collection::{
    Code,
    identity::{ClockBasis, TimeObservation, Uuid},
    inputs::CollectionVersion,
    launch::WorkerLaunch,
    outcomes::{CollectorOutcome, CollectorStatus, Coverage, FacilityState, ItemError, WorkUsed},
    records::{EndpointObservation, ForensicRecord},
    report::{ReportKind, WorkerCleanup},
    worker::{Body, Chunk, Commit, Done, Job, Start, WorkerFrame},
};
use rustix::fd::BorrowedFd;
use std::collections::BTreeSet;

pub(crate) struct Collected {
    pub outcome: CollectorOutcome,
    pub usage: WorkUsed,
    pub records: Vec<ForensicRecord>,
    pub errors: Vec<ItemError>,
}

pub(crate) struct CollectJob<'a> {
    pub launch: &'a WorkerLaunch,
    pub frames: &'a [WorkerFrame],
    pub descriptors: &'a [BorrowedFd<'a>],
}

fn interrupted(
    collector: jocky_shared::collection::outcomes::Collector,
    code: Code,
    records: Vec<ForensicRecord>,
    errors: Vec<ItemError>,
    usage: WorkUsed,
) -> Collected {
    let sources: BTreeSet<_> = records
        .iter()
        .map(|record| record.provenance.source_id.clone())
        .chain(errors.iter().filter_map(|error| error.source_id.clone()))
        .collect();
    let accepted_records = records.len() as u64;
    let error_count = errors.len() as u64;
    Collected {
        outcome: CollectorOutcome {
            collector,
            status: if accepted_records == 0 {
                CollectorStatus::Failed
            } else {
                CollectorStatus::Partial
            },
            coverage: sources
                .into_iter()
                .map(|source_id| Coverage {
                    source_id,
                    state: FacilityState::Partial,
                    reason: Some(code),
                })
                .collect(),
            accepted_records,
            omitted_records: None,
            omitted_reason: Some(code),
            errors: error_count,
            stop_reason: Some(code),
        },
        usage,
        records,
        errors,
    }
}

fn charged_allowance(
    value: &jocky_shared::collection::launch::WorkAllowance,
    baseline: &WorkUsed,
    parts: &[Collected],
) -> WorkUsed {
    // A lost child retains its full ledger reservation. The public report has
    // fixed schema ceilings, so charge only the remaining representable room
    // after parent admission and earlier workers.
    let mut used = baseline.clone();
    for part in parts {
        used.entries = used.entries.saturating_add(part.usage.entries);
        used.indicator_comparisons = used
            .indicator_comparisons
            .saturating_add(part.usage.indicator_comparisons);
        used.errors = used.errors.saturating_add(part.usage.errors);
        used.source_bytes = used.source_bytes.saturating_add(part.usage.source_bytes);
        used.staging_bytes = used.staging_bytes.saturating_add(part.usage.staging_bytes);
        used.retained_bytes = used
            .retained_bytes
            .saturating_add(part.usage.retained_bytes);
    }
    WorkUsed {
        entries: value.entries.min(20_000u64.saturating_sub(used.entries)),
        indicator_comparisons: value
            .indicator_comparisons
            .min(10_000_000u64.saturating_sub(used.indicator_comparisons)),
        errors: value.errors.min(1_001u64.saturating_sub(used.errors)),
        source_bytes: value
            .source_bytes
            .min(67_108_864u64.saturating_sub(used.source_bytes)),
        staging_bytes: value
            .staging_bytes
            .min(83_886_080u64.saturating_sub(used.staging_bytes)),
        retained_bytes: value
            .retained_bytes
            .min(268_435_456u64.saturating_sub(used.retained_bytes)),
    }
}

fn no_work() -> WorkUsed {
    WorkUsed {
        entries: 0,
        indicator_comparisons: 0,
        errors: 0,
        source_bytes: 0,
        staging_bytes: 0,
        retained_bytes: 0,
    }
}

pub(crate) fn canonicalize_records(records: &mut [ForensicRecord], id: &Uuid) -> Result<(), Code> {
    jocky_forensic::collection::normalize::records(records)?;
    for (index, record) in records.iter_mut().enumerate() {
        record.sequence = index as u64;
        record.record_id = jocky_forensic::collection::identity::derive_id(
            jocky_forensic::collection::identity::IdentityKind::Record,
            id,
            index as u64,
        )?;
    }
    Ok(())
}

/// Join already validated, sequential worker outcomes into one canonical
/// report. A failed or partial collector never becomes a successful empty
/// result. The report verifier remains an independent final check.
pub(crate) fn assemble(
    context: &ValidatedCollectionContext,
    parts: Vec<Collected>,
    endpoint: Option<EndpointObservation>,
    finished_at: TimeObservation,
    clock: &mut dyn Clock,
) -> Result<Vec<u8>, Code> {
    let mut report = report::failure(
        context,
        ReportKind::LiveLab,
        finished_at.clone(),
        Code::Unsupported,
        WorkerCleanup::Complete,
    )?;
    if parts.len() != report.collectors.len() {
        return Err(Code::WorkerProtocol);
    }
    report.collectors.clear();
    report.endpoint = endpoint;
    report.finished_at = finished_at.clone();
    report.manifest.created_at = finished_at;
    let mut work = report.summary.work_used.clone();
    for part in parts {
        if part.outcome.accepted_records != part.records.len() as u64
            || part.outcome.errors != part.errors.len() as u64
        {
            return Err(Code::WorkerProtocol);
        }
        report.collectors.push(part.outcome);
        report.records.extend(part.records);
        report.errors.extend(part.errors);
        work.entries = work
            .entries
            .checked_add(part.usage.entries)
            .ok_or(Code::ResourceLimit)?;
        work.indicator_comparisons = work
            .indicator_comparisons
            .checked_add(part.usage.indicator_comparisons)
            .ok_or(Code::ResourceLimit)?;
        work.errors = work
            .errors
            .checked_add(part.usage.errors)
            .ok_or(Code::ResourceLimit)?;
        work.source_bytes = work
            .source_bytes
            .checked_add(part.usage.source_bytes)
            .ok_or(Code::ResourceLimit)?;
        work.staging_bytes = work
            .staging_bytes
            .checked_add(part.usage.staging_bytes)
            .ok_or(Code::ResourceLimit)?;
        work.retained_bytes = work
            .retained_bytes
            .checked_add(part.usage.retained_bytes)
            .ok_or(Code::ResourceLimit)?;
    }
    // Facility workers enumerate native sources in source order. Canonical
    // reports require payload-key order, which can differ (notably module
    // names and startup paths). Renumber only after validating worker IDs.
    canonicalize_records(&mut report.records, &context.identity().collection_id)?;
    if context.indicators().is_some()
        && report.collectors.iter().any(|outcome| {
            outcome.collector == jocky_shared::collection::outcomes::Collector::Indicators
        })
    {
        let status = |collector| {
            report
                .collectors
                .iter()
                .find(|outcome| outcome.collector == collector)
                .is_some_and(|outcome| outcome.status == CollectorStatus::Complete)
        };
        let completeness = jocky_forensic::collection::indicator_match::Completeness {
            hashes: status(jocky_shared::collection::outcomes::Collector::Files),
            paths: status(jocky_shared::collection::outcomes::Collector::Files)
                && status(jocky_shared::collection::outcomes::Collector::Persistence),
            addresses: status(jocky_shared::collection::outcomes::Collector::Connections),
            domains: status(jocky_shared::collection::outcomes::Collector::System)
                && status(jocky_shared::collection::outcomes::Collector::Events),
        };
        let (matched, indicator_outcome, comparisons) =
            crate::collectors::indicators::adapt(context, &report.records, completeness, clock)?;
        let indicator = report
            .collectors
            .iter_mut()
            .find(|outcome| {
                outcome.collector == jocky_shared::collection::outcomes::Collector::Indicators
            })
            .ok_or(Code::WorkerProtocol)?;
        if indicator.accepted_records != 0 || indicator.errors != 0 {
            return Err(Code::WorkerProtocol);
        }
        *indicator = indicator_outcome;
        report.records.extend(matched);
        work.indicator_comparisons = work
            .indicator_comparisons
            .checked_add(comparisons)
            .ok_or(Code::ResourceLimit)?;
    }
    let stop = report
        .errors
        .iter()
        .map(|error| error.code)
        .max_by_key(|code| outcome::priority(*code));
    let summary = outcome::summarize(&report.collectors, stop, WorkerCleanup::Complete)?;
    report.summary.status = summary.status;
    report.summary.stop_reason = summary.stop_reason;
    report.summary.accepted_records = summary.accepted_records;
    report.summary.errors = summary.errors;
    report.summary.omitted_known = summary.omitted_known;
    report.summary.omitted_unknown = summary.omitted_unknown;
    report.summary.source_bytes = work.source_bytes;
    report.summary.work_used = work;
    context.finalize_report(report, clock)
}

/// Product path: sequential owned collection workers followed by the separate
/// output-only publisher. The caller must have admitted the context and output
/// capability before invoking this private boundary.
pub(crate) fn run_owned(
    context: &ValidatedCollectionContext,
    jobs: &[CollectJob<'_>],
    output: &OutputDirectory<'_>,
    publish_launch: WorkerLaunch,
    clock: &mut dyn Clock,
    cancelled: impl FnMut() -> bool,
) -> Result<Done, Code> {
    run_with(
        context,
        jobs,
        output,
        publish_launch,
        clock,
        cancelled,
        |job, ledger, clock, observation, cancelled| {
            supervisor::collect_owned(
                job.launch,
                job.frames,
                job.descriptors,
                ledger,
                clock,
                observation,
                cancelled,
            )
        },
        |launch, frames, output, ledger, clock, cancelled| {
            supervisor::publish_owned(launch, frames, output, ledger, clock, cancelled)
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with(
    context: &ValidatedCollectionContext,
    jobs: &[CollectJob<'_>],
    output: &OutputDirectory<'_>,
    publish_launch: WorkerLaunch,
    clock: &mut dyn Clock,
    mut cancelled: impl FnMut() -> bool,
    mut collect: impl FnMut(
        &CollectJob<'_>,
        &mut ReservationLedger,
        &mut dyn Clock,
        &mut dyn FnMut(&WorkerFrame) -> Result<(), Code>,
        &mut dyn FnMut() -> bool,
    ) -> Result<Done, Code>,
    mut publish: impl FnMut(
        &WorkerLaunch,
        &[WorkerFrame],
        BorrowedFd<'_>,
        &mut ReservationLedger,
        &mut dyn Clock,
        &mut dyn FnMut() -> bool,
    ) -> Result<Done, Code>,
) -> Result<Done, Code> {
    let expected = report::failure(
        context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        Code::Unsupported,
        WorkerCleanup::NotStarted,
    )?;
    if jobs.len() != expected.collectors.len()
        || publish_launch.job != Job::Publish
        || publish_launch.collection_id != context.identity().collection_id
        || publish_launch.global_limits != *context.limits()
        || publish_launch.allowance.report_bytes < 65_536
        || publish_launch.allowance.staging_bytes < 65_536
        || jobs.iter().zip(&expected.collectors).any(|(job, outcome)| {
            job.launch.job != Job::Collect
                || job.launch.collection_id != context.identity().collection_id
                || job.launch.global_limits != *context.limits()
                || job.launch.allowance.report_bytes != 0
                || !matches!(job.frames.first().map(|f| &f.body), Some(Body::Start(Start::Collect { collector, .. })) if *collector == outcome.collector)
        })
    {
        return Err(Code::WorkerProtocol);
    }
    for job in jobs {
        let mut probe = ReservationLedger::with_publisher_reserve(
            context.limits().clone(),
            &publish_launch.allowance,
        )?;
        probe.reserve(&job.launch.allowance)?;
    }
    // This preflight rejects an impossible individual launch before evidence
    // I/O. Runtime reservations still account earlier workers cumulatively.
    let mut ledger = ReservationLedger::with_publisher_reserve(
        context.limits().clone(),
        &publish_launch.allowance,
    )?;
    output.check_for_publication(clock)?;
    let mut parts = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        let mut records = Vec::new();
        let mut errors = Vec::new();
        let started = !cancelled();
        let done = if !started {
            Err(Code::Cancelled)
        } else {
            collect(
                job,
                &mut ledger,
                clock,
                &mut |frame| match &frame.body {
                    Body::Record(record) => {
                        records.push(record.as_ref().clone());
                        Ok(())
                    }
                    Body::ItemError(error) => {
                        errors.push(error.clone());
                        Ok(())
                    }
                    _ => Err(Code::WorkerProtocol),
                },
                &mut cancelled,
            )
        };
        let done = match done {
            Ok(done) => done,
            Err(Code::CleanupIncomplete) => return Err(Code::CleanupIncomplete),
            Err(code) => {
                parts.push(interrupted(
                    expected.collectors[index].collector,
                    code,
                    records,
                    errors,
                    if started {
                        charged_allowance(
                            &job.launch.allowance,
                            &expected.summary.work_used,
                            &parts,
                        )
                    } else {
                        no_work()
                    },
                ));
                for remaining in &expected.collectors[index + 1..] {
                    parts.push(interrupted(
                        remaining.collector,
                        code,
                        Vec::new(),
                        Vec::new(),
                        no_work(),
                    ));
                }
                break;
            }
        };
        let Done::Collect { outcome, usage } = done else {
            return Err(Code::WorkerProtocol);
        };
        parts.push(Collected {
            outcome,
            usage,
            records,
            errors,
        });
    }
    // Worker IDs occupy disjoint reserved ranges. Validate those ranges before
    // folding the accepted observations into the report's contiguous wire
    // ordinals; this cannot turn a forged worker ID into valid evidence.
    let mut next_record = 0u64;
    let mut next_error = 0u64;
    for (part, job) in parts.iter_mut().zip(jobs) {
        for (offset, record) in part.records.iter_mut().enumerate() {
            let original = job
                .launch
                .record_base
                .checked_add(offset as u64)
                .ok_or(Code::WorkerProtocol)?;
            if record.sequence != original
                || record.record_id
                    != jocky_forensic::collection::identity::derive_id(
                        jocky_forensic::collection::identity::IdentityKind::Record,
                        &context.identity().collection_id,
                        original,
                    )?
            {
                return Err(Code::WorkerProtocol);
            }
            record.sequence = next_record;
            record.record_id = jocky_forensic::collection::identity::derive_id(
                jocky_forensic::collection::identity::IdentityKind::Record,
                &context.identity().collection_id,
                next_record,
            )?;
            next_record = next_record.checked_add(1).ok_or(Code::ResourceLimit)?;
        }
        for (offset, error) in part.errors.iter_mut().enumerate() {
            let original = job
                .launch
                .error_base
                .checked_add(offset as u64)
                .ok_or(Code::WorkerProtocol)?;
            if error.error_id
                != jocky_forensic::collection::identity::derive_id(
                    jocky_forensic::collection::identity::IdentityKind::Error,
                    &context.identity().collection_id,
                    original,
                )?
            {
                return Err(Code::WorkerProtocol);
            }
            error.error_id = jocky_forensic::collection::identity::derive_id(
                jocky_forensic::collection::identity::IdentityKind::Error,
                &context.identity().collection_id,
                next_error,
            )?;
            next_error = next_error.checked_add(1).ok_or(Code::ResourceLimit)?;
        }
    }
    let now = clock.read()?;
    let finished_at = TimeObservation {
        value: now.utc,
        basis: ClockBasis::LocalClock,
        uncertainty_ms: None,
        clock_uncertain: false,
    };
    let endpoint = endpoint_from_parts(context, &parts)?;
    let raw = assemble(context, parts, endpoint, finished_at, clock)?;
    let verified = jocky_forensic::collection::verify::verify_report(&raw)?;
    output.check_report(&verified)?;
    output.check_for_publication(clock)?;
    let (publish_launch, frames) =
        publication_frames(publish_launch, context, output.name(), &raw)?;
    let mut publisher_ledger = ReservationLedger::new(context.limits().clone())?;
    let delivered = publish(
        &publish_launch,
        &frames,
        output.sync_fd(),
        &mut publisher_ledger,
        clock,
        &mut || false,
    )?;
    match delivered {
        Done::Publish {
            code:
                jocky_shared::collection::report::StatusCode::Success(
                    jocky_shared::collection::report::SuccessCode::PublishedComplete,
                ),
            sha256,
            byte_length,
            created_identity,
        } => {
            let code = match verified.summary.status {
                jocky_shared::collection::report::SummaryStatus::Complete => {
                    jocky_shared::collection::report::SuccessCode::PublishedComplete
                }
                jocky_shared::collection::report::SummaryStatus::Partial => {
                    jocky_shared::collection::report::SuccessCode::PublishedPartial
                }
                jocky_shared::collection::report::SummaryStatus::Failed => {
                    if verified.records.is_empty()
                        && verified.errors.is_empty()
                        && verified
                            .collectors
                            .iter()
                            .all(|outcome| outcome.status == CollectorStatus::Unsupported)
                    {
                        return Ok(Done::Publish {
                            code: jocky_shared::collection::report::StatusCode::Error(
                                Code::Unsupported,
                            ),
                            sha256,
                            byte_length,
                            created_identity,
                        });
                    }
                    jocky_shared::collection::report::SuccessCode::PublishedFailed
                }
            };
            Ok(Done::Publish {
                code: jocky_shared::collection::report::StatusCode::Success(code),
                sha256,
                byte_length,
                created_identity,
            })
        }
        other => Ok(other),
    }
}

pub(crate) fn endpoint_from_parts(
    context: &ValidatedCollectionContext,
    parts: &[Collected],
) -> Result<Option<EndpointObservation>, Code> {
    use jocky_shared::collection::{
        inputs::CollectionVersion,
        records::{Distribution, NamespaceScope, OsFamily, Payload},
    };
    let profile = parts
        .iter()
        .flat_map(|part| &part.records)
        .find_map(|record| {
            if let Payload::System(profile) = &record.payload {
                Some((record, profile))
            } else {
                None
            }
        });
    let Some((record, profile)) = profile else {
        return Ok(None);
    };
    if record.context.endpoint_id != context.identity().endpoint_id
        || profile.os_family != OsFamily::Linux
    {
        return Err(Code::WorkerProtocol);
    }
    let facilities = parts
        .iter()
        .flat_map(|part| part.outcome.coverage.iter().cloned())
        .collect();
    Ok(Some(EndpointObservation {
        schema_version: CollectionVersion::V1,
        endpoint_id: context.identity().endpoint_id.clone(),
        os_family: OsFamily::Linux,
        architecture: profile.architecture.clone(),
        distribution: Distribution {
            id: profile.distribution_id.clone(),
            version: profile.distribution_version.clone(),
        },
        kernel_release: profile.kernel_release.clone(),
        // This describes the collector binary's own target ABI, not a libc
        // version inferred from the distribution label.
        abi: if cfg!(target_env = "gnu") {
            jocky_shared::collection::outcomes::Field::Available {
                value: "gnu".to_owned(),
            }
        } else {
            jocky_shared::collection::outcomes::Field::Unavailable {
                reason: Code::Unsupported,
            }
        },
        namespace_scope: NamespaceScope::Current,
        observed_at: record.collected_at.clone(),
        facilities,
    }))
}

fn publication_frames(
    mut launch: WorkerLaunch,
    context: &ValidatedCollectionContext,
    name: &str,
    raw: &[u8],
) -> Result<(WorkerLaunch, Vec<WorkerFrame>), Code> {
    if launch.job != Job::Publish || launch.collection_id != context.identity().collection_id {
        return Err(Code::WorkerProtocol);
    }
    let sha256 = jocky_forensic::collection::identity::digest(raw)?;
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Publish {
            context: context.identity().clone(),
            output_descriptor: launch.descriptors.first().ok_or(Code::WorkerProtocol)?.fd,
            output_name: name.to_owned(),
            report_byte_length: raw.len() as u64,
            report_sha256: sha256.clone(),
        }),
    };
    let packet = crate::worker::protocol::encode_frame(&start)?;
    launch.start_sha256 = jocky_forensic::collection::identity::digest(&packet[4..])?;
    let mut frames = Vec::with_capacity(raw.len() / 65_536 + 3);
    frames.push(start);
    for (offset, chunk) in raw.chunks(65_536).enumerate() {
        frames.push(WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: frames.len() as u64,
            collection_id: launch.collection_id.clone(),
            body: Body::PublishChunk(Chunk {
                offset: (offset * 65_536) as u64,
                data: STANDARD.encode(chunk),
            }),
        });
    }
    frames.push(WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: frames.len() as u64,
        collection_id: launch.collection_id.clone(),
        body: Body::PublishCommit(Commit {
            byte_length: raw.len() as u64,
            sha256,
        }),
    });
    Ok((launch, frames))
}
