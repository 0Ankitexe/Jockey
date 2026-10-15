//! Owned-object path replacement and alias adversarial tests.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;

use jocky_forensic::collection::context::OperationTarget;
use jocky_shared::collection::Code;
use sources::{metadata::Exclusions, paths::ConfinedRoot};
use std::{fs, os::unix::fs::symlink};
use support::{Frozen, context, path, scratch, values};

#[test]
fn pinned_file_name_replacement_never_yields_replacement_bytes() {
    for iteration in 0..32 {
        for replacement in ["symlink", "regular", "hardlink", "disappear"] {
            let owned = scratch();
            let selected = owned.path().join("selected");
            fs::write(&selected, b"original").unwrap();
            let reference = path("selected");
            let admitted = context(&values(owned.path().to_str().unwrap(), "selected"));
            let mut clock = Frozen::default();
            let root = ConfinedRoot::open(
                &admitted,
                OperationTarget::File(&reference),
                Exclusions::default(),
                &mut clock,
                &false,
            )
            .unwrap();
            let pinned = root.pin_file("selected", &mut clock, &false).unwrap();
            match replacement {
                "hardlink" => fs::hard_link(&selected, owned.path().join("alias")).unwrap(),
                "disappear" => fs::remove_file(&selected).unwrap(),
                "symlink" => {
                    fs::rename(&selected, owned.path().join("old")).unwrap();
                    symlink("old", &selected).unwrap();
                }
                _ => {
                    fs::rename(&selected, owned.path().join("old")).unwrap();
                    fs::write(&selected, b"replacement").unwrap();
                }
            }
            match pinned.reopen(&mut clock, &false) {
                Err(Code::SourceChanged | Code::SourceDisappeared | Code::AliasDenied) => (),
                Ok(opened) if replacement == "regular" || replacement == "symlink" => {
                    let mut bytes = [0u8; 32];
                    let n = rustix::io::read(opened.fd(), &mut bytes).unwrap();
                    assert_eq!(&bytes[..n], b"original");
                }
                _ => panic!("unexpected path race result for {replacement} at {iteration}"),
            }
        }
    }
}
