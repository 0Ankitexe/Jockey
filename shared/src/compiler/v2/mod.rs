//! Additive portable compiler vocabulary; legacy enums remain strict.
mod metadata;
mod types;
pub use metadata::{OsFamily, Platform, Selector};
pub use types::{NamedType, Type};
