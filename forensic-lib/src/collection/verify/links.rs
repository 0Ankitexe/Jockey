//! Cross-record attribution only. Digests cannot prove authority or indicator truth.
use super::require;
use jocky_shared::collection::{
    Code,
    outcomes::{Collector, Field, ItemError},
    records::{ForensicRecord, IndicatorKind, IndicatorMatch, Payload, ReadStability},
    report::CollectionReport,
};
use std::net::IpAddr;

pub(super) fn error(error: &ItemError, report: &CollectionReport) -> Result<(), Code> {
    require(error.code != Code::NotRequested)?;
    let outcome = report
        .collectors
        .iter()
        .find(|c| c.collector == error.collector)
        .ok_or(Code::InvalidInput)?;
    if let Some(source) = &error.source_id {
        require(outcome.coverage.iter().any(|c| &c.source_id == source))?;
    }
    if let Some(path) = &error.field_path {
        require(field_belongs_to(error.collector, path))?;
    }
    // item_ref identifies an attempted source item, not necessarily a retained
    // record. Field omissions need not increase the omitted *record* count.
    Ok(())
}

fn field_belongs_to(collector: Collector, path: &str) -> bool {
    let Some(field) = path.strip_prefix("/payload/") else {
        return false;
    };
    match collector {
        Collector::System => matches!(
            field,
            "kernel_release"
                | "kernel_version"
                | "architecture"
                | "hostname"
                | "distribution_id"
                | "distribution_version"
                | "boot_id"
        ),
        Collector::Processes => matches!(
            field,
            "parent_pid" | "uid" | "command" | "executable" | "start_identity"
        ),
        Collector::Services => matches!(
            field,
            "description" | "load_state" | "active_state" | "sub_state" | "unit_file_state"
        ),
        Collector::Connections => matches!(
            field,
            "uid" | "owners" | "namespace" | "local_address" | "remote_address"
        ),
        Collector::Persistence => matches!(
            field,
            "location" | "enabled_state" | "referenced_targets" | "content_sha256"
        ),
        Collector::Files => matches!(
            field,
            "location" | "size_bytes" | "mode" | "uid" | "gid" | "mtime" | "ctime" | "sha256"
        ),
        Collector::Events => matches!(field, "event_time" | "domain"),
        Collector::Drivers => matches!(field, "size_bytes" | "version" | "source_version"),
        // Indicator failures can describe an unavailable candidate on a source
        // record. Only eligible candidate paths are meaningful here.
        Collector::Indicators => matches!(
            field,
            "sha256" | "location" | "local_address" | "remote_address" | "hostname" | "domain"
        ),
    }
}

/// Validate the *eligible observed candidate*, not equality to a supplied
/// criterion: a standalone report contains the input digest, not the input set.
pub(super) fn candidate(indicator: &IndicatorMatch, record: &ForensicRecord) -> Result<(), Code> {
    let eligible = match (
        indicator.kind,
        indicator.field_path.as_str(),
        &record.payload,
    ) {
        (IndicatorKind::Sha256, "/payload/sha256", Payload::File(file)) => {
            matches!(file.sha256, Field::Available { .. })
                && file.read_stability == ReadStability::StableObserved
        }
        (IndicatorKind::Path, "/payload/location", Payload::File(_) | Payload::Persistence(_)) => {
            true
        }
        (
            IndicatorKind::IpAddress,
            "/payload/local_address" | "/payload/remote_address",
            Payload::Connection(_),
        ) => true,
        (IndicatorKind::Domain, "/payload/hostname", Payload::System(system)) => {
            domain(&system.hostname)
        }
        (IndicatorKind::Domain, "/payload/domain", Payload::Event(event)) => domain(&event.domain),
        _ => false,
    };
    require(eligible)
}

fn domain(field: &Field<String>) -> bool {
    let Field::Available { value } = field else {
        return false;
    };
    let name = value.strip_suffix('.').unwrap_or(value);
    name.len() <= 253
        && name.contains('.')
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_collector_error_field_is_closed_and_attributed() {
        for (collector, fields) in [
            (
                Collector::System,
                "kernel_release kernel_version architecture hostname distribution_id distribution_version boot_id",
            ),
            (
                Collector::Processes,
                "parent_pid uid command executable start_identity",
            ),
            (
                Collector::Services,
                "description load_state active_state sub_state unit_file_state",
            ),
            (
                Collector::Connections,
                "uid owners namespace local_address remote_address",
            ),
            (
                Collector::Persistence,
                "location enabled_state referenced_targets content_sha256",
            ),
            (
                Collector::Files,
                "location size_bytes mode uid gid mtime ctime sha256",
            ),
            (Collector::Events, "event_time domain"),
            (Collector::Drivers, "size_bytes version source_version"),
            (
                Collector::Indicators,
                "sha256 location local_address remote_address hostname domain",
            ),
        ] {
            for field in fields.split_whitespace() {
                assert!(field_belongs_to(collector, &format!("/payload/{field}")));
                assert!(!field_belongs_to(collector, field));
            }
            assert!(!field_belongs_to(collector, "/payload/arbitrary"));
            assert!(!field_belongs_to(collector, "/payload/message"));
        }
    }

    #[test]
    fn domain_candidates_enforce_label_and_whole_name_bounds() {
        for (text, expected) in [
            (format!("{}.example", "a".repeat(63)), true),
            (format!("{}.example", "a".repeat(64)), false),
            (
                format!(
                    "{}.{}.{}.{}",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(61)
                ),
                true,
            ),
            (
                format!(
                    "{}.{}.{}.{}",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62)
                ),
                false,
            ),
        ] {
            assert_eq!(domain(&Field::Available { value: text }), expected);
        }
    }
}
