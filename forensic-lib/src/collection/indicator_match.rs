//! Bounded exact correlation over admitted typed evidence only.
use super::indicators::ValidatedIndicatorSet;
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    inputs::{Indicator, PathRef},
    outcomes::Field,
    records::{ForensicRecord, IndicatorKind, IndicatorMatch, Payload, ReadStability},
};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Completeness {
    pub hashes: bool,
    pub paths: bool,
    pub addresses: bool,
    pub domains: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Comparison {
    Match,
    NoMatch,
    Unevaluated,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Evaluation {
    pub matches: Vec<IndicatorMatch>,
    pub no_match: Vec<Uuid>,
    pub unevaluated: Vec<Uuid>,
    pub comparisons: u64,
}

enum Candidate<'a> {
    Hash(&'a str),
    Path(&'a PathRef),
    Address(&'a str),
    Domain(&'a str),
}
fn valid_domain(value: &str) -> Option<String> {
    let name = value.strip_suffix('.').unwrap_or(value);
    if name.len() > 253 || !name.contains('.') || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}
fn exact(indicator: &Indicator, candidate: Candidate<'_>) -> bool {
    match (indicator, candidate) {
        (Indicator::Sha256 { value, .. }, Candidate::Hash(observed)) => value == observed,
        (Indicator::Path { value, .. }, Candidate::Path(observed)) => value == observed,
        (Indicator::IpAddress { value, .. }, Candidate::Address(observed)) => value
            .parse::<IpAddr>()
            .ok()
            .zip(observed.parse::<IpAddr>().ok())
            .is_some_and(|(a, b)| a == b),
        (Indicator::Domain { value, .. }, Candidate::Domain(observed)) => {
            valid_domain(observed).is_some_and(|name| name == *value)
        }
        _ => false,
    }
}
fn candidates(record: &ForensicRecord, mut visit: impl FnMut(&'static str, Candidate<'_>)) {
    match &record.payload {
        Payload::File(file) => {
            if file.read_stability == ReadStability::StableObserved
                && let Field::Available { value } = &file.sha256
            {
                visit("/payload/sha256", Candidate::Hash(value));
            }
            visit("/payload/location", Candidate::Path(&file.location));
        }
        Payload::Persistence(entry) => visit("/payload/location", Candidate::Path(&entry.location)),
        Payload::Connection(connection) => {
            visit(
                "/payload/local_address",
                Candidate::Address(&connection.local_address),
            );
            visit(
                "/payload/remote_address",
                Candidate::Address(&connection.remote_address),
            );
        }
        Payload::System(system) => {
            if let Field::Available { value } = &system.hostname
                && valid_domain(value).is_some()
            {
                visit("/payload/hostname", Candidate::Domain(value));
            }
        }
        Payload::Event(event) => {
            if let Field::Available { value } = &event.domain
                && valid_domain(value).is_some()
            {
                visit("/payload/domain", Candidate::Domain(value));
            }
        }
        _ => {}
    }
}
fn kind(indicator: &Indicator) -> IndicatorKind {
    match indicator {
        Indicator::Sha256 { .. } => IndicatorKind::Sha256,
        Indicator::Path { .. } => IndicatorKind::Path,
        Indicator::IpAddress { .. } => IndicatorKind::IpAddress,
        Indicator::Domain { .. } => IndicatorKind::Domain,
    }
}
fn applicable(criterion: IndicatorKind, candidate: &Candidate<'_>) -> bool {
    matches!(
        (criterion, candidate),
        (IndicatorKind::Sha256, Candidate::Hash(_))
            | (IndicatorKind::Path, Candidate::Path(_))
            | (IndicatorKind::IpAddress, Candidate::Address(_))
            | (IndicatorKind::Domain, Candidate::Domain(_))
    )
}
fn complete(kind: IndicatorKind, state: Completeness) -> bool {
    match kind {
        IndicatorKind::Sha256 => state.hashes,
        IndicatorKind::Path => state.paths,
        IndicatorKind::IpAddress => state.addresses,
        IndicatorKind::Domain => state.domains,
    }
}

/// Every observed candidate comparison is counted. Missing or incomplete
/// evidence remains unevaluated; supplied criteria never manufacture facts.
pub fn evaluate(
    set: ValidatedIndicatorSet<'_>,
    records: &[ForensicRecord],
    completeness: Completeness,
    max_comparisons: u64,
    max_matches: usize,
) -> Result<Evaluation, Code> {
    let mut result = Evaluation {
        matches: Vec::new(),
        no_match: Vec::new(),
        unevaluated: Vec::new(),
        comparisons: 0,
    };
    for indicator in &set.definition().indicators {
        let criterion_kind = kind(indicator);
        let mut observed = false;
        let mut matched = false;
        for record in records {
            candidates(record, |field_path, candidate| {
                if !applicable(criterion_kind, &candidate) {
                    return;
                }
                observed = true;
                result.comparisons = result.comparisons.saturating_add(1);
                if exact(indicator, candidate) {
                    matched = true;
                    result.matches.push(IndicatorMatch {
                        indicator_id: indicator.id().clone(),
                        indicator_set_id: set.definition().indicator_set_id.clone(),
                        rules_version: set.definition().rules_version,
                        matched_record_id: record.record_id.clone(),
                        field_path: field_path.into(),
                        kind: criterion_kind,
                    });
                }
            });
            if result.comparisons > max_comparisons || result.matches.len() > max_matches {
                return Err(Code::ResourceLimit);
            }
        }
        if !matched {
            if observed && complete(criterion_kind, completeness) {
                result.no_match.push(indicator.id().clone());
            } else {
                result.unevaluated.push(indicator.id().clone());
            }
        }
    }
    Ok(result)
}

/// Standalone single-candidate exact behavior for contract tests.
pub fn compare(indicator: &Indicator, candidate: Option<&str>) -> Comparison {
    let Some(candidate) = candidate else {
        return Comparison::Unevaluated;
    };
    let observed = match indicator {
        Indicator::Sha256 { .. } => Candidate::Hash(candidate),
        Indicator::IpAddress { .. } => Candidate::Address(candidate),
        Indicator::Domain { .. } => Candidate::Domain(candidate),
        Indicator::Path { .. } => return Comparison::Unevaluated,
    };
    if exact(indicator, observed) {
        Comparison::Match
    } else {
        Comparison::NoMatch
    }
}
