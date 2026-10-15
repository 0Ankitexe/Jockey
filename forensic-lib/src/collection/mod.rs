//! Pure collection admission, accounting and evidence integrity.
//! Native effects must remain behind the separately gated native adapter.
pub mod authorisation;
pub mod budget;
pub mod cancellation;
pub mod canonical;
pub mod clock;
pub mod collector;
pub mod context;
pub mod identity;
pub mod indicator_match;
pub mod indicators;
pub mod inputs;
pub mod normalize;
pub mod outcome;
pub mod policy;
pub mod report;
pub mod sources;
pub mod verify;

pub use authorisation::{admit, admit_for_invocation};
pub use clock::ClockReading;
pub use collector::{CollectorRequest, PlatformCollector, RecordSink};
pub use context::ValidatedCollectionContext;
pub use indicators::ValidatedIndicatorSet;
pub use inputs::InputSet;
pub use jocky_shared::collection::{Code, records};
pub use jocky_shared::collection::{outcomes::CollectorOutcome, records::ForensicRecord};
