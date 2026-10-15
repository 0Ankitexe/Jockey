//! File digest is emitted only for a complete, stable, admitted read.
#![cfg(target_os = "linux")]
#[path = "../src/cli/mod.rs"]
#[allow(dead_code)]
mod cli;
#[path = "../src/collection.rs"]
#[allow(dead_code)]
mod collection;
#[path = "../src/collectors/mod.rs"]
#[allow(dead_code)]
mod collectors;
#[path = "../src/sources/mod.rs"]
#[allow(dead_code)]
mod sources;
#[path = "support/confinement.rs"]
#[allow(dead_code)]
mod support;
#[path = "../src/worker/mod.rs"]
#[allow(dead_code)]
mod worker;
use collectors::files;
use jocky_shared::collection::Code;

#[test]
fn empty_and_nonempty_full_file_hashes_match_known_sha256() {
    assert_eq!(
        files::digest_complete(b"", 0, true).unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        files::digest_complete(b"abc", 3, true).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn prefix_mutation_and_cancellation_cannot_claim_a_full_digest() {
    assert_eq!(
        files::digest_complete(b"ab", 3, true),
        Err(Code::SourceChanged)
    );
    assert_eq!(
        files::digest_complete(b"abc", 3, false),
        Err(Code::SourceChanged)
    );
    assert_eq!(
        files::digest_complete(b"abc", 2, true),
        Err(Code::SourceChanged)
    );
    assert_eq!(
        files::digest_complete(b"abc", 16_777_217, true),
        Err(Code::ResourceLimit)
    );
}

#[test]
fn admitted_confined_file_read_produces_real_metadata_and_full_digest() {
    use jocky_forensic::collection::context::OperationTarget;
    use sources::{metadata::Exclusions, paths::ConfinedRoot};
    let owned = support::scratch();
    let root = owned.path().join("source");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("selected"), b"abc").unwrap();
    let context = support::context(&support::values(root.to_str().unwrap(), "selected"));
    let selected = support::path("selected");
    let mut clock = support::Frozen::default();
    let admitted = ConfinedRoot::open(
        &context,
        OperationTarget::File(&selected),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let observed = files::collect_file(&admitted, &selected, &mut clock, &false).unwrap();
    assert!(matches!(
        observed.size_bytes,
        jocky_shared::collection::outcomes::Field::Available { value: 3 }
    ));
    assert!(
        matches!(observed.sha256, jocky_shared::collection::outcomes::Field::Available { ref value } if value == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn inherited_root_uses_the_pin_and_rejects_a_config_file_alias() {
    use jocky_forensic::collection::context::OperationTarget;
    use rustix::fs::{Mode, OFlags};
    use sources::{
        metadata::{Exclusions, ObjectId},
        paths::ConfinedRoot,
    };
    use std::os::unix::fs::MetadataExt;
    let owned = support::scratch();
    let root = owned.path().join("source");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("selected"), b"abc").unwrap();
    let context = support::context(&support::values(root.to_str().unwrap(), "selected"));
    let selected = support::path("selected");
    let mut clock = support::Frozen::default();
    let pin = rustix::fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
    let admitted = ConfinedRoot::inherited(
        &context,
        OperationTarget::File(&selected),
        pin,
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let result = files::collect_file(&admitted, &selected, &mut clock, &false).unwrap();
    assert!(matches!(
        result.size_bytes,
        jocky_shared::collection::outcomes::Field::Available { value: 3 }
    ));
    let metadata = std::fs::metadata(root.join("selected")).unwrap();
    let excluded = Exclusions::new(&[ObjectId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }])
    .unwrap();
    let pin = rustix::fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
    let admitted = ConfinedRoot::inherited(
        &context,
        OperationTarget::File(&selected),
        pin,
        excluded,
        &mut clock,
        &false,
    )
    .unwrap();
    assert_eq!(
        files::collect_file(&admitted, &selected, &mut clock, &false),
        Err(Code::AliasDenied)
    );
}

#[test]
fn cancelled_read_and_mutated_pin_never_yield_a_digest() {
    use jocky_forensic::collection::context::OperationTarget;
    use rustix::fs::{Mode, OFlags};
    use sources::{metadata::Exclusions, paths::ConfinedRoot};
    let owned = support::scratch();
    let root = owned.path().join("source");
    std::fs::create_dir(&root).unwrap();
    let selected = root.join("selected");
    std::fs::write(&selected, b"original").unwrap();
    let context = support::context(&support::values(root.to_str().unwrap(), "selected"));
    let path = support::path("selected");
    let mut clock = support::Frozen::default();
    let pin = rustix::fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
    let admitted = ConfinedRoot::inherited(
        &context,
        OperationTarget::File(&path),
        pin,
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let pinned = admitted
        .pin_file(&path.relative_path, &mut clock, &false)
        .unwrap();
    let readable = pinned.reopen(&mut clock, &false).unwrap();
    std::fs::write(&selected, b"changed length").unwrap();
    assert_eq!(
        readable.check_unchanged(&mut clock, &false),
        Err(Code::SourceChanged)
    );
    assert!(files::collect_file(&admitted, &path, &mut clock, &true).is_err());
}

#[test]
fn inode_replacement_between_pin_and_reopen_cannot_hash_new_path() {
    use jocky_forensic::collection::context::OperationTarget;
    use rustix::fs::{Mode, OFlags};
    use sources::{metadata::Exclusions, paths::ConfinedRoot};
    let owned = support::scratch();
    let root = owned.path().join("source");
    std::fs::create_dir(&root).unwrap();
    let selected = root.join("selected");
    std::fs::write(&selected, b"old inode").unwrap();
    let context = support::context(&support::values(root.to_str().unwrap(), "selected"));
    let path = support::path("selected");
    let mut clock = support::Frozen::default();
    let root_fd = rustix::fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
    let admitted = ConfinedRoot::inherited(
        &context,
        OperationTarget::File(&path),
        root_fd,
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let pinned = admitted
        .pin_file(&path.relative_path, &mut clock, &false)
        .unwrap();
    std::fs::rename(&selected, root.join("old")).unwrap();
    std::fs::write(&selected, b"new inode").unwrap();
    assert_eq!(
        pinned.reopen(&mut clock, &false).err(),
        Some(Code::SourceChanged)
    );
}
