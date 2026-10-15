//! Read-only forensic-library boundary.
//!
//! Inert module contracts and pure local collection admission/integrity checks.
//! Native collectors and host access belong exclusively to the native adapter.

#![forbid(unsafe_code)]

/// Pure, opt-in collection contracts and admission; native effects are separate.
pub mod collection;
pub mod contracts;
