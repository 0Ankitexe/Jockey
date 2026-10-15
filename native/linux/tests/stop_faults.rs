//! Test-owned stop checks: no source byte after cancellation or expiry.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;

use jocky_forensic::collection::{budget::Counter, context::OperationTarget};
use jocky_shared::collection::{Code, identity::UtcTime};
use sources::{metadata::Exclusions, paths::ConfinedRoot, reads::read_all};
use std::fs;
use support::{Frozen, context, path, scratch, values};

#[test]
fn cancel_or_expire_after_pin_rejects_reopen_and_keeps_source_budget() {
    for reason in [Code::Cancelled, Code::AuthorisationExpired] {
        let owned = scratch();
        fs::write(owned.path().join("selected"), b"owned evidence").unwrap();
        let reference = path("selected");
        let admitted = context(&values(owned.path().to_str().unwrap(), "selected"));
        let target = OperationTarget::File(&reference);
        let mut clock = Frozen::default();
        let root = ConfinedRoot::open(&admitted, target, Exclusions::default(), &mut clock, &false)
            .unwrap();
        let pinned = root.pin_file("selected", &mut clock, &false).unwrap();
        let before = admitted
            .permit(target, &clock.0, false)
            .unwrap()
            .remaining(Counter::SourceBytes)
            .unwrap();
        if reason == Code::AuthorisationExpired {
            clock.0.utc = UtcTime::parse("2020-01-01T01:00:00Z").unwrap();
        }
        assert!(
            matches!(pinned.reopen(&mut clock, &(reason == Code::Cancelled)), Err(code) if code == reason)
        );
        assert_eq!(admitted.limits().max_source_bytes, before);
    }
}

#[test]
fn cancellation_during_owned_read_returns_no_prefix_and_keeps_offset() {
    let owned = scratch();
    fs::write(owned.path().join("selected"), b"owned evidence").unwrap();
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
    let opened = root
        .pin_file("selected", &mut clock, &false)
        .unwrap()
        .reopen(&mut clock, &false)
        .unwrap();
    assert_eq!(
        read_all(&opened, 100, &mut clock, &true),
        Err(Code::Cancelled)
    );
    let mut bytes = [0; 5];
    assert_eq!(rustix::io::read(opened.fd(), &mut bytes).unwrap(), 5);
    assert_eq!(&bytes, b"owned");
}
