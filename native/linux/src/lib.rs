//! Native Linux adapter with explicit standalone collection admission.
#![forbid(unsafe_code)]

pub mod cli;

// Native source capabilities remain private to admitted owned workers.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod sources;

// Output-only, private publication primitives.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod publication;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod collection;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod collectors;

#[allow(dead_code)]
mod worker;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/confinement.rs"]
#[allow(dead_code)]
mod support;

/// Library startup remains unavailable; use the explicit standalone CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    NotImplemented,
    Unsupported,
}

/// Fail closed without reading configuration, probing facilities or spawning workers.
pub fn bootstrap() -> Result<(), BootstrapError> {
    if cfg!(target_os = "linux") {
        Err(BootstrapError::NotImplemented)
    } else {
        Err(BootstrapError::Unsupported)
    }
}

/// Reserved binary entry for a child spawned over an authenticated private
/// Unix channel. `None` keeps an ordinary direct invocation on the existing
/// typed CLI rejection path. No evidence source is read by this entry yet.
#[cfg(all(target_os = "linux", not(test)))]
#[doc(hidden)]
pub fn private_worker_entry() -> Option<u8> {
    worker::run::run_if_owned_channel()
}

#[cfg(test)]
mod tests {
    #[test]
    fn bootstrap_never_admits_collection() {
        assert!(super::bootstrap().is_err());
    }
}
