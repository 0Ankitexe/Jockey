use super::{links, require, temporal};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    outcomes::{Collector, FacilityState, Field},
    records::*,
    report::CollectionReport,
};
use std::collections::BTreeMap;

pub(super) fn check(
    record: &ForensicRecord,
    report: &CollectionReport,
    prior_records: &BTreeMap<&Uuid, &ForensicRecord>,
) -> Result<(), Code> {
    let p = &record.provenance;
    require(
        p.policy_sha256 == report.inputs.policy.sha256
            && p.authorisation_sha256 == report.inputs.authorisation.sha256
            && p.request_sha256 == report.inputs.request.sha256,
    )?;
    temporal::within(&p.observed_start, report)?;
    temporal::within(&p.observed_end, report)?;
    temporal::ordered(&p.observed_start, &p.observed_end)?;
    temporal::ordered(&p.observed_end, &record.collected_at)?;
    let (collector, category, kind) = match &record.payload {
        Payload::System(system) => {
            require(system.os_family == OsFamily::Linux)?;
            (
                Collector::System,
                Category::System,
                ProvenanceKind::KernelProfile,
            )
        }
        Payload::Process(r) => {
            if let Field::Available { value } = &r.start_identity {
                require(value.pid == r.pid)?;
            }
            (
                Collector::Processes,
                Category::Process,
                ProvenanceKind::ProcProcesses,
            )
        }
        Payload::Service(_) => (
            Collector::Services,
            Category::System,
            ProvenanceKind::SystemdBus,
        ),
        Payload::Connection(_) => (
            Collector::Connections,
            Category::Network,
            ProvenanceKind::ProcNet,
        ),
        Payload::Persistence(entry) => {
            let SourceScope::Path { path } = &p.source_scope else {
                return Err(Code::InvalidInput);
            };
            require(
                entry.location.root_id == path.root_id
                    && (entry.location.relative_path == path.relative_path
                        || entry
                            .location
                            .relative_path
                            .strip_prefix(&path.relative_path)
                            .is_some_and(|tail| tail.starts_with('/'))),
            )?;
            (
                Collector::Persistence,
                Category::Persistence,
                ProvenanceKind::StartupDirectory,
            )
        }
        Payload::File(file) => {
            require(matches!(&p.source_scope,SourceScope::Path {path} if *path==file.location))?;
            require(p.source_id == file.location.root_id)?;
            if matches!(file.sha256, Field::Available { .. }) {
                require(file.read_stability == ReadStability::StableObserved)?;
            }
            (Collector::Files, Category::File, ProvenanceKind::ScopedFile)
        }
        Payload::Event(event) => {
            require(event.source_id == p.source_id)?;
            require(matches!(
                p.source_kind,
                ProvenanceKind::JournalFile | ProvenanceKind::TextLog
            ))?;
            (Collector::Events, Category::Event, p.source_kind)
        }
        Payload::Driver(_) => (
            Collector::Drivers,
            Category::Driver,
            ProvenanceKind::SysModules,
        ),
        Payload::Indicator(indicator) => {
            let input = report
                .inputs
                .indicators
                .as_ref()
                .ok_or(Code::InvalidInput)?;
            require(
                indicator.indicator_set_id == input.id
                    && p.source_id == input.id
                    && p.indicator_set_sha256.as_ref() == Some(&input.sha256)
                    && p.rules_version == Some(indicator.rules_version),
            )?;
            let observed = prior_records
                .get(&indicator.matched_record_id)
                .ok_or(Code::InvalidInput)?;
            require(
                observed.sequence < record.sequence && observed.category != Category::Indicator,
            )?;
            links::candidate(indicator, observed)?;
            (
                Collector::Indicators,
                Category::Indicator,
                ProvenanceKind::SuppliedIndicatorSet,
            )
        }
    };
    require(
        record.collector.name == collector && record.category == category && p.source_kind == kind,
    )?;
    let adapter = match collector {
        Collector::System => Adapter::KernelProfile,
        Collector::Processes => Adapter::Processes,
        Collector::Services => Adapter::Systemd,
        Collector::Connections => Adapter::Network,
        Collector::Persistence => Adapter::Startup,
        Collector::Files => Adapter::Files,
        Collector::Events => {
            if kind == ProvenanceKind::JournalFile {
                Adapter::Journal
            } else {
                Adapter::TextLog
            }
        }
        Collector::Drivers => Adapter::Modules,
        Collector::Indicators => Adapter::Indicators,
    };
    require(record.collector.adapter == adapter)?;
    require(report.collectors.iter().any(|c| {
        c.collector == collector
            && c.coverage.iter().any(|s| {
                s.source_id == p.source_id
                    && matches!(s.state, FacilityState::Supported | FacilityState::Partial)
            })
    }))?;
    if !record.collected_at.clock_uncertain
        && !report.started_at.clock_uncertain
        && !report.finished_at.clock_uncertain
    {
        require(
            record.collected_at.value.unix_nanos() >= report.started_at.value.unix_nanos()
                && record.collected_at.value.unix_nanos() <= report.finished_at.value.unix_nanos(),
        )?;
    }
    if category != Category::Indicator {
        require(p.indicator_set_sha256.is_none() && p.rules_version.is_none())?;
    }
    require(match p.source_kind {
        ProvenanceKind::ScopedFile
        | ProvenanceKind::StartupDirectory
        | ProvenanceKind::JournalFile
        | ProvenanceKind::TextLog => matches!(p.source_scope, SourceScope::Path { .. }),
        ProvenanceKind::SuppliedIndicatorSet => {
            matches!(p.source_scope, SourceScope::Indicators { .. })
        }
        _ => matches!(p.source_scope, SourceScope::Facility { .. }),
    })?;
    match &p.source_scope {
        SourceScope::Facility { source_id, .. } => require(*source_id == p.source_id)?,
        SourceScope::Path { path } => require(
            path.root_id == p.source_id
                || matches!(
                    p.source_kind,
                    ProvenanceKind::TextLog
                        | ProvenanceKind::JournalFile
                        | ProvenanceKind::StartupDirectory
                ),
        )?,
        SourceScope::Indicators { indicator_set_id } => {
            require(*indicator_set_id == p.source_id && category == Category::Indicator)?
        }
    }
    Ok(())
}
