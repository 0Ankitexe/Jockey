//! Private owned-worker protocol, supervision and product-child entry.
//! The standalone collect CLI uses this fixed-self owned-worker path.
pub(crate) mod accounting;
pub(crate) mod chunks;
pub(crate) mod control;
pub(crate) mod entry;
#[cfg(target_os = "linux")]
pub(crate) mod handles;
pub(crate) mod inputs;
pub(crate) mod order;
#[cfg(target_os = "linux")]
pub(crate) mod owned;
#[cfg(target_os = "linux")]
pub(crate) mod peer;
pub(crate) mod progress;
pub(crate) mod protocol;
#[cfg(target_os = "linux")]
pub(crate) mod publisher_cleanup;
#[cfg(target_os = "linux")]
pub(crate) mod resource;
#[cfg(all(target_os = "linux", not(test)))]
pub(crate) mod run;
pub(crate) mod session;
#[cfg(target_os = "linux")]
pub(crate) mod signals;
#[cfg(target_os = "linux")]
pub(crate) mod spawn;
#[cfg(target_os = "linux")]
pub(crate) mod start;
pub(crate) mod stop;
#[cfg(target_os = "linux")]
pub(crate) mod supervisor;
