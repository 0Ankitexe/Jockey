//! Harness-free actual product-child adoption under the original 64/192 MiB
//! address-space split. Uses only synthetic documents and an owned output.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![allow(dead_code, unused_imports)]

#[path = "../src/cli/mod.rs"]
mod cli;
use cli::clock;
#[path = "../src/collection.rs"]
mod collection;
#[path = "../src/collectors/mod.rs"]
mod collectors;
#[path = "support/joined_pipeline.rs"]
mod joined_pipeline;
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;
#[path = "../src/worker/mod.rs"]
mod worker;

fn main() {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).unwrap();
    worker::resource::limit_parent_address_space(64 * 1024 * 1024, 192 * 1024 * 1024).unwrap();
    joined_pipeline::exercise_joined_pipeline();
    println!("ResourcePipelinePassed: 64 MiB parent, 192 MiB owned workers");
}
