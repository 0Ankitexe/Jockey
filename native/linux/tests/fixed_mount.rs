//! Fixed-facility admission tests never open the developer's proc/sys mounts.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;

use jocky_forensic::collection::{ClockReading, InputSet, admit, clock::Clock};
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
};
use sources::inventory::{native_adapters, observed_facilities, selected_fixed};
use sources::procfs::{FixedMount, MountKind};

struct Frozen(ClockReading);
impl Clock for Frozen {
    fn read(&mut self) -> Result<ClockReading, Code> {
        Ok(self.0.clone())
    }
}
fn clock(utc: &str) -> Frozen {
    Frozen(ClockReading {
        utc: UtcTime::parse(utc).unwrap(),
        monotonic_ms: 0,
    })
}
fn inputs() -> InputSet<'static> {
    InputSet {
        designation: include_bytes!("../../../fixtures/valid/collection/endpoint-designation.json"),
        authorisation: Some(include_bytes!(
            "../../../fixtures/valid/collection/authorisation.json"
        )),
        policy: include_bytes!("../../../fixtures/valid/collection/policy.json"),
        request: include_bytes!("../../../fixtures/valid/collection/request.json"),
        indicators: None,
    }
}

#[test]
fn native_inventory_is_versioned_and_runtime_status_is_separate() {
    use jocky_shared::collection::outcomes::{Collector, Coverage, FacilityState};
    let entries = native_adapters();
    assert_eq!(entries.len(), 10);
    assert!(entries.iter().all(|entry| entry.version == "1.0.0"));
    assert!(
        entries
            .iter()
            .any(|entry| entry.collector == Collector::Indicators && entry.compiled)
    );
    let id = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    let observed = observed_facilities(&[Coverage {
        source_id: id.clone(),
        state: FacilityState::PermissionDenied,
        reason: Some(Code::PermissionDenied),
    }]);
    assert_eq!(observed[0].source_id, id);
    assert_eq!(observed[0].state, FacilityState::PermissionDenied);
    assert_eq!(observed[0].reason, Some(Code::PermissionDenied));
    assert!(
        entries
            .iter()
            .all(|entry| entry.version == observed[0].version)
    );
}

#[test]
fn wrong_source_and_expired_authority_fail_before_any_fixed_mount_open() {
    let ctx = admit(inputs(), clock("2020-01-01T00:00:10Z").0).unwrap();
    let selected = Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap();
    let other = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    let mut now = clock("2020-01-01T00:00:10Z");
    assert!(matches!(
        FixedMount::open(&ctx, &other, MountKind::Proc, &mut now, &false),
        Err(Code::ScopeDenied)
    ));
    assert!(matches!(
        FixedMount::open(&ctx, &selected, MountKind::Sys, &mut now, &false),
        Err(Code::ScopeDenied)
    ));
    let mut expired = clock("2020-01-01T01:00:00Z");
    assert!(matches!(
        FixedMount::open(&ctx, &selected, MountKind::Proc, &mut expired, &false),
        Err(Code::AuthorisationExpired)
    ));
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::Entries),
        Ok(0)
    );
}

#[test]
fn ordinary_descriptor_cannot_impersonate_an_admitted_proc_mount() {
    let ctx = admit(inputs(), clock("2020-01-01T00:00:10Z").0).unwrap();
    let selected = Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap();
    let owned_dir = support::scratch();
    let owned = std::fs::File::create(owned_dir.path().join("not-proc")).unwrap();
    let fd = std::os::fd::OwnedFd::from(owned);
    assert!(matches!(
        FixedMount::inherited(
            &ctx,
            &selected,
            MountKind::Proc,
            fd,
            &mut clock("2020-01-01T00:00:10Z"),
            &false
        ),
        Err(Code::Unsupported)
    ));
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}

#[test]
fn fixed_inventory_requires_current_selected_source_without_io() {
    let ctx = admit(inputs(), clock("2020-01-01T00:00:10Z").0).unwrap();
    let selected = Uuid::parse("10000000-0000-4000-8000-000000000008").unwrap();
    let other = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    let fixed =
        selected_fixed(&ctx, &selected, &mut clock("2020-01-01T00:00:10Z"), &false).unwrap();
    assert_eq!(fixed.primary, "/proc");
    assert_eq!(
        selected_fixed(&ctx, &other, &mut clock("2020-01-01T00:00:10Z"), &false),
        Err(Code::ScopeDenied)
    );
    assert_eq!(
        selected_fixed(&ctx, &selected, &mut clock("2020-01-01T01:00:00Z"), &false),
        Err(Code::AuthorisationExpired)
    );
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}
