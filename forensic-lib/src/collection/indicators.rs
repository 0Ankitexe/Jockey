//! Admission/normalization only. Matching collectors remain a later V5 story.
use jocky_shared::collection::{
    Code,
    inputs::{Indicator, IndicatorSet},
};
use std::net::IpAddr;

/// An immutable, case-bound admitted set. It cannot be constructed from a raw DTO.
#[derive(Clone, Copy)]
pub struct ValidatedIndicatorSet<'a> {
    pub(crate) collection_id: &'a jocky_shared::collection::identity::Uuid,
    pub(crate) set: &'a IndicatorSet,
}
impl ValidatedIndicatorSet<'_> {
    pub fn definition(&self) -> &IndicatorSet {
        self.set
    }
}

pub(crate) fn normalize(set: &mut IndicatorSet) -> Result<(), Code> {
    for criterion in &mut set.indicators {
        match criterion {
            Indicator::IpAddress { value, .. } => {
                let address = value.parse::<IpAddr>().map_err(|_| Code::InvalidInput)?;
                *value = address.to_string();
            }
            Indicator::Domain { value, .. } => {
                // Strict wire validation already rejected Unicode, wildcard and invalid labels.
                *value = value
                    .strip_suffix('.')
                    .unwrap_or(value)
                    .to_ascii_lowercase();
            }
            Indicator::Path { .. } | Indicator::Sha256 { .. } => {}
        }
    }
    set.indicators.sort_by(|a, b| a.id().cmp(b.id()));
    Ok(())
}
