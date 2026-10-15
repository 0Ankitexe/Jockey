//! Bounded, source-specific decoders for the core Linux checkpoint.
pub(crate) mod connections;
pub(crate) mod drivers;
pub(crate) mod events;
pub(crate) mod facility;
pub(crate) mod files;
pub(crate) mod indicators;
pub(crate) mod persistence;
pub(crate) mod processes;
pub(crate) mod record;
pub(crate) mod services;
pub(crate) mod system;

use jocky_forensic::collection::{ValidatedCollectionContext, budget::Counter};
use jocky_shared::collection::{Code, outcomes::WorkUsed};

pub(crate) fn usage(context: &ValidatedCollectionContext) -> Result<WorkUsed, Code> {
    Ok(WorkUsed {
        entries: context.charged(Counter::Entries)?,
        indicator_comparisons: context.charged(Counter::IndicatorComparisons)?,
        errors: context.charged(Counter::Errors)?,
        source_bytes: context.charged(Counter::SourceBytes)?,
        staging_bytes: context.charged(Counter::StagingBytes)?,
        retained_bytes: context.charged(Counter::RetainedBytes)?,
    })
}
