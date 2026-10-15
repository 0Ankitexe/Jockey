//! Untrusted, versioned local collection wire data. Decoding never grants authority.
//! No module here opens files, probes a host, reads a clock or contacts a service.

macro_rules! wire {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}

macro_rules! vocabulary {
    ($name:ident { $($variant:ident => $value:literal),* $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
        pub enum $name { $(#[serde(rename = $value)] $variant),* }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),* } }
        }
    };
}

mod decode;
mod document;
pub mod identity;
pub mod inputs;
pub mod launch;
pub mod outcomes;
pub mod records;
pub mod report;
mod schema;
mod serialization;
mod validation;
pub mod worker;

pub use decode::{DecodeReason, InputError, decode};
pub use document::{Document, DocumentKind};
pub use outcomes::Code;
pub use serialization::bounded_value;
