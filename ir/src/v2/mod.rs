//! Version 2 IR is pure, bounded and independently verified.
pub mod identity;
mod json;
pub mod model;
mod verify;
pub use json::decode_ir;
pub use model::IrDocument;
pub use verify::{VerifiedProgram, verify};
