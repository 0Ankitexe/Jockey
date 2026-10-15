//! Private owned-file seam; no endpoint or host inventory is inspected.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[allow(dead_code)]
#[path = "support/confinement.rs"]
mod support;
use jocky_forensic::collection::{budget::Counter, context::OperationTarget};
use jocky_shared::collection::Code;
use sources::{metadata::Exclusions, paths::ConfinedRoot, reads::read_all};
use support::{Frozen, context, path, scratch, values};

#[test]
fn complete_owned_file_and_empty_file_use_exact_observed_size() {
    for bytes in [
        vec![],
        vec![b'a'; 65536],
        vec![b'b'; 65537],
        vec![b'c'; 131072],
    ] {
        let dir = scratch();
        std::fs::write(dir.path().join("selected"), &bytes).unwrap();
        let reference = path("selected");
        let ctx = context(&values(dir.path().to_str().unwrap(), "selected"));
        let mut clock = Frozen::default();
        let root = ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut clock,
            &false,
        )
        .unwrap();
        let pin = root.pin_file("selected", &mut clock, &false).unwrap();
        let file = pin.reopen(&mut clock, &false).unwrap();
        assert_eq!(
            read_all(&file, 16777216, &mut clock, &false).unwrap(),
            bytes
        );
        let permit = ctx
            .permit(OperationTarget::File(&reference), &clock.0, false)
            .unwrap();
        assert_eq!(
            ctx.limits().max_source_bytes - permit.remaining(Counter::SourceBytes).unwrap(),
            bytes.len() as u64
        );
        assert_eq!(
            ctx.limits().max_memory_bytes - permit.remaining(Counter::RetainedBytes).unwrap(),
            bytes.len() as u64
                + 65536
                + ((dir.path().to_str().unwrap()[1..].split('/').count() + 1)
                    * std::mem::size_of::<sources::metadata::ObjectId>()) as u64
        );
    }
}

#[test]
fn over_size_and_changed_file_do_not_return_a_successful_prefix() {
    for mutation in [false, true] {
        let dir = scratch();
        let selected = dir.path().join("selected");
        std::fs::write(&selected, b"original").unwrap();
        let reference = path("selected");
        let ctx = context(&values(dir.path().to_str().unwrap(), "selected"));
        let mut clock = Frozen::default();
        let root = ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut clock,
            &false,
        )
        .unwrap();
        let pin = root.pin_file("selected", &mut clock, &false).unwrap();
        let file = pin.reopen(&mut clock, &false).unwrap();
        if mutation {
            std::fs::write(&selected, b"changed").unwrap();
        }
        assert_eq!(
            read_all(&file, if mutation { 100 } else { 7 }, &mut clock, &false),
            Err(if mutation {
                Code::SourceChanged
            } else {
                Code::ResourceLimit
            })
        );
    }
}

#[test]
fn cancellation_prevents_content_io_on_an_existing_descriptor() {
    let dir = scratch();
    std::fs::write(dir.path().join("selected"), b"owned").unwrap();
    let reference = path("selected");
    let ctx = context(&values(dir.path().to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::File(&reference),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let pin = root.pin_file("selected", &mut clock, &false).unwrap();
    let file = pin.reopen(&mut clock, &false).unwrap();
    assert_eq!(
        read_all(&file, 100, &mut clock, &true),
        Err(Code::Cancelled)
    );
    // Read position still zero; the check is confined to this test-owned object.
    let mut bytes = [0u8; 5];
    assert_eq!(rustix::io::read(file.fd(), &mut bytes).unwrap(), 5);
    assert_eq!(&bytes, b"owned");
}
