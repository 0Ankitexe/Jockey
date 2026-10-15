use super::require;
use jocky_shared::collection::{Code, identity::TimeObservation, report::CollectionReport};

pub(super) fn ordered(a: &TimeObservation, b: &TimeObservation) -> Result<(), Code> {
    require(a.clock_uncertain || b.clock_uncertain || a.value.unix_nanos() <= b.value.unix_nanos())
}
pub(super) fn within(value: &TimeObservation, report: &CollectionReport) -> Result<(), Code> {
    ordered(&report.started_at, value)?;
    ordered(value, &report.finished_at)
}
