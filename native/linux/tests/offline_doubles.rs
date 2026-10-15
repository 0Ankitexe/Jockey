mod support;

use support::collection::{
    EXPIRED_UNTIL, FixtureClock, FixtureFailure, FixtureSources, expired_authorisation,
    expired_designation,
};

#[test]
fn source_double_counts_only_injected_accesses() {
    let mut source = FixtureSources::default();
    source.insert("profile", Ok(b"synthetic".to_vec()));
    assert_eq!(source.calls, 0);
    assert_eq!(source.read("profile"), Ok(b"synthetic".as_slice()));
    assert_eq!(source.calls, 1);
    assert_eq!(source.read("not-injected"), Err(FixtureFailure::NotFound));
    assert_eq!(source.calls, 2);
}

#[test]
fn source_denial_remains_visible() {
    let mut source = FixtureSources::default();
    source.insert("profile", Err(FixtureFailure::PermissionDenied));
    assert_eq!(
        source.read("profile"),
        Err(FixtureFailure::PermissionDenied)
    );
    assert_eq!(source.calls, 1);
}

#[test]
fn clock_and_expired_designation_are_data_only() {
    let mut clock = FixtureClock::default();
    clock.advance(2);
    assert_eq!((clock.monotonic_ms, clock.utc_ms), (2, 2));
    assert_eq!(expired_designation()["valid_until"], EXPIRED_UNTIL);
    assert_eq!(expired_designation()["label"], "synthetic-test-only");
    assert_eq!(expired_authorisation()["valid_until"], EXPIRED_UNTIL);
    assert_eq!(
        expired_authorisation()["designation_id"],
        expired_designation()["designation_id"]
    );
    assert!(jocky_native_linux::bootstrap().is_err());
}
