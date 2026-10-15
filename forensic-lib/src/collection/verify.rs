//! Independent integrity verification reads supplied report bytes only, never source paths.
use super::{
    canonical,
    identity::{IdentityKind, derive_id, digest},
};
use jocky_shared::collection::{
    Code, Document, DocumentKind, bounded_value, decode,
    outcomes::{Collector, CollectorStatus, FacilityState},
    records::*,
    report::*,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

mod links;
mod record;
mod temporal;

fn require(ok: bool) -> Result<(), Code> {
    if ok { Ok(()) } else { Err(Code::InvalidInput) }
}
fn check_digest(value: &Value) -> Result<(), Code> {
    let expected = value.get("content_sha256").ok_or(Code::InvalidInput)?;
    require(expected.as_str() == Some(digest(&canonical::body(value, 10485760)?)?.as_str()))
}
fn unavailable(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(v) = stack.pop() {
        match v {
            Value::Object(o) => {
                if o.get("state").and_then(Value::as_str) == Some("unavailable")
                    && o.get("reason").and_then(Value::as_str) != Some("NotRequested")
                {
                    return true;
                }
                stack.extend(o.values());
            }
            Value::Array(a) => stack.extend(a),
            _ => {}
        }
    }
    false
}
pub fn verify_report(bytes: &[u8]) -> Result<CollectionReport, Code> {
    let Document::Report(report) = decode(DocumentKind::Report, bytes).map_err(|e| e.code)? else {
        return Err(Code::InvalidInput);
    };
    let value = bounded_value(&report, 10485760).map_err(|e| e.code)?;
    let canonical = canonical::encode(&value, 10485759)?;
    require(
        bytes.len() == canonical.len() + 1
            && bytes.last() == Some(&b'\n')
            && bytes[..bytes.len() - 1] == canonical,
    )?;
    require(report.summary.report_bytes == bytes.len() as u64)?;
    check_digest(&value)?;
    check_digest(&value["manifest"])?;
    require(
        report.manifest.manifest_id
            == derive_id(IdentityKind::Manifest, &report.context.collection_id, 0)?,
    )?;
    require(
        report.manifest.entries.len() == report.records.len()
            && report.summary.accepted_records == report.records.len() as u64
            && report.summary.errors == report.errors.len() as u64,
    )?;
    require(super::normalize::is_ordered(&report.records)?)?;
    if !report.started_at.clock_uncertain && !report.finished_at.clock_uncertain {
        require(report.started_at.value.unix_nanos() <= report.finished_at.value.unix_nanos())?;
    }
    let mut counts: BTreeMap<Collector, u64> = BTreeMap::new();
    let mut prior_records = BTreeMap::new();
    let mut missing = BTreeSet::new();
    for (index, record) in report.records.iter().enumerate() {
        require(
            record.sequence == index as u64
                && record.record_id
                    == derive_id(
                        IdentityKind::Record,
                        &report.context.collection_id,
                        index as u64,
                    )?,
        )?;
        record::check(record, &report, &prior_records)?;
        check_digest(&value["records"][index])?;
        let encoded = canonical::encode(&value["records"][index], 98304)?;
        let entry = &report.manifest.entries[index];
        require(
            entry.record_id == record.record_id
                && entry.sequence == record.sequence
                && entry.byte_length == encoded.len() as u64
                && entry.sha256 == digest(&encoded)?,
        )?;
        *counts.entry(record.collector.name).or_default() += 1;
        if unavailable(&value["records"][index]["payload"]) {
            missing.insert(record.collector.name);
        }
        prior_records.insert(&record.record_id, record);
    }
    let mut errors: BTreeMap<Collector, u64> = BTreeMap::new();
    require(*counts.get(&Collector::System).unwrap_or(&0) <= 1)?;
    for (index, error) in report.errors.iter().enumerate() {
        links::error(error, &report)?;
        require(
            error.error_id
                == derive_id(
                    IdentityKind::Error,
                    &report.context.collection_id,
                    index as u64,
                )?,
        )?;
        *errors.entry(error.collector).or_default() += 1;
    }
    require(
        report
            .collectors
            .windows(2)
            .all(|p| p[0].collector < p[1].collector),
    )?;
    let requested: BTreeSet<_> = report.collectors.iter().map(|c| c.collector).collect();
    require(
        counts
            .keys()
            .chain(errors.keys())
            .all(|c| requested.contains(c)),
    )?;
    for c in &report.collectors {
        let ids: BTreeSet<_> = c.coverage.iter().map(|s| &s.source_id).collect();
        require(ids.len() == c.coverage.len())?;
        require(
            c.accepted_records == *counts.get(&c.collector).unwrap_or(&0)
                && c.errors == *errors.get(&c.collector).unwrap_or(&0),
        )?;
        if c.status == CollectorStatus::Complete {
            require(
                c.errors == 0
                    && c.omitted_records == Some(0)
                    && c.stop_reason.is_none()
                    && !missing.contains(&c.collector),
            )?;
        }
    }
    // A rehashed report cannot hide a higher-priority per-item failure behind a
    // lower-priority outcome. All individual reasons remain in the error list.
    let stop = report
        .errors
        .iter()
        .map(|e| e.code)
        .chain(report.summary.stop_reason)
        .max_by_key(|c| super::outcome::priority(*c));
    let expected =
        super::outcome::summarize(&report.collectors, stop, report.summary.worker_cleanup)?;
    require(
        report.summary.status == expected.status
            && report.summary.stop_reason == expected.stop_reason
            && report.summary.omitted_known == expected.omitted_known
            && report.summary.omitted_unknown == expected.omitted_unknown,
    )?;
    require(report.summary.source_bytes == report.summary.work_used.source_bytes)?;
    require(report.summary.work_used.errors >= report.summary.errors)?;
    require(report.endpoint.is_some() || report.summary.stop_reason.is_some())?;
    temporal::within(&report.manifest.created_at, &report)?;
    if let Some(endpoint) = &report.endpoint {
        require(endpoint.os_family == OsFamily::Linux)?;
        temporal::within(&endpoint.observed_at, &report)?;
        if report.summary.status == SummaryStatus::Complete {
            require(!unavailable(&value["endpoint"]))?;
            require(
                endpoint
                    .facilities
                    .iter()
                    .all(|f| f.state == FacilityState::Supported),
            )?;
        }
        let mut ids = BTreeSet::new();
        for facility in &endpoint.facilities {
            super::outcome::coverage(facility)?;
            require(ids.insert(&facility.source_id))?;
            require(
                report
                    .collectors
                    .iter()
                    .any(|c| c.coverage.iter().any(|f| f.source_id == facility.source_id)),
            )?;
        }
    }
    if report.summary.worker_cleanup == WorkerCleanup::Incomplete {
        require(report.summary.stop_reason == Some(Code::CleanupIncomplete))?;
    }
    Ok(*report)
}
