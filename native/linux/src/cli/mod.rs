//! Explicit standalone CLI admission and owned native collection dispatch.
#[cfg(target_os = "linux")]
pub(crate) mod args;
#[cfg(target_os = "linux")]
pub(crate) mod clock;
#[cfg(target_os = "linux")]
pub(crate) mod collect;
#[cfg(target_os = "linux")]
pub(crate) mod commands;
pub mod config;
#[cfg(target_os = "linux")]
pub mod status;
