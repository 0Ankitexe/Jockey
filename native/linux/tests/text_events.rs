//! T085 source vectors for separate RFC5424 syslog/auth adapters in T170.
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
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    inputs::UtcWindow,
};

#[test]
fn utc_offset_window_and_no_guessed_year_are_contract_inputs() {
    let start = UtcTime::parse("2020-01-01T00:00:00Z").unwrap();
    let end = UtcTime::parse("2020-01-01T00:00:10Z").unwrap();
    assert!(start.unix_nanos() < end.unix_nanos());
    let inside = b"<14>1 2020-01-01T05:30:00+05:30 lab app 1 ID47 - owned marker";
    let at_end = b"<14>1 2020-01-01T00:00:10Z lab app 1 ID47 - end";
    let yearless = b"Oct 15 00:00:00 lab app: unsupported";
    assert!(inside.starts_with(b"<14>1 "));
    assert!(at_end.starts_with(b"<14>1 "));
    assert!(!yearless.starts_with(b"<14>1 "));
}

fn collect_text(raw: &[u8], same_identity: bool) -> Result<usize, Code> {
    let bytes = sources::text_log::stable_bytes(
        sources::text_log::LogSource::Syslog,
        Ok(raw),
        same_identity,
    )?;
    let source = Uuid::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let window = UtcWindow {
        start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
    };
    Ok(collectors::events::text::parse(bytes, source, &window)?.len())
}

#[test]
fn injected_syslog_auth_empty_missing_denied_rotation_and_size() {
    let inside = b"<14>1 2020-01-01T05:30:00+05:30 lab app 1 ID47 - owned marker\n";
    assert_eq!(collect_text(inside, true), Ok(1));
    assert_eq!(collect_text(b"", true), Ok(0));
    assert_eq!(collect_text(inside, false), Err(Code::SourceChanged));
    assert_eq!(
        collect_text(&vec![b'x'; 65_537], true),
        Err(Code::ResourceLimit)
    );
    assert_eq!(
        collect_text(b"Oct 15 00:00:00 lab app: yearless", true),
        Err(Code::UnsupportedFormat)
    );
    assert_eq!(
        collect_text(b"<14>1 2020-01-01T00:00:00 lab app 1 ID47 - no-zone", true),
        Err(Code::UnknownTimezone)
    );
    // Missing and denied are injected read failures, never empty success.
    let missing: Result<&[u8], Code> = Err(Code::NotFound);
    let denied: Result<&[u8], Code> = Err(Code::PermissionDenied);
    assert_eq!(
        missing.and_then(|raw| collect_text(raw, true)),
        Err(Code::NotFound)
    );
    assert_eq!(
        denied.and_then(|raw| collect_text(raw, true)),
        Err(Code::PermissionDenied)
    );
}

#[test]
fn fractional_offset_and_structured_data_are_explicit() {
    let raw = b"<14>1 2020-01-01T05:30:00.123456+05:30 lab app 1 ID47 - fraction\n";
    assert_eq!(collect_text(raw, true), Ok(1));
    let unsupported = b"<14>1 2020-01-01T00:00:00Z lab app 1 ID47 [id k=\"v\"] message\n";
    assert_eq!(
        collect_text(unsupported, true),
        Err(Code::UnsupportedFormat)
    );
}

#[test]
fn admitted_syslog_and_auth_reads_are_scoped_and_distinct() {
    use jocky_forensic::collection::{InputSet, admit, context::OperationTarget};
    use serde_json::json;
    use sources::{metadata::Exclusions, paths::ConfinedRoot, text_log::LogSource};
    let owned = support::scratch();
    let raw_line = b"<14>1 2020-01-01T05:30:00+05:30 lab app 1 ID47 - owned marker\n";
    std::fs::write(owned.path().join("syslog.txt"), raw_line).unwrap();
    std::fs::write(owned.path().join("auth.txt"), raw_line).unwrap();
    let mut values = support::values(owned.path().to_str().unwrap(), "syslog.txt");
    let ids = [
        "10000000-0000-4000-8000-000000000099",
        "10000000-0000-4000-8000-000000000098",
    ];
    for index in [1, 2] {
        values[index]["scope"]["capabilities"] = json!(["events"]);
        values[index]["scope"]["source_groups"] = json!(["text_log"]);
        values[index]["scope"]["roots"][0]["purposes"] = json!(["logs"]);
    }
    values[2]["sources"] = json!([
        {"kind":"text_log","source_id":ids[0],"path":support::path("syslog.txt"),"format":"rfc5424"},
        {"kind":"text_log","source_id":ids[1],"path":support::path("auth.txt"),"format":"rfc5424"}
    ]);
    values[3]["collectors"] = json!(["events"]);
    values[3]["capabilities"] = json!(["events"]);
    values[3]["source_ids"] = json!(ids);
    values[3]["paths"] = json!([]);
    let raw = values
        .each_ref()
        .map(|value| serde_json::to_vec(value).unwrap());
    let ctx = admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: None,
        },
        support::Frozen::default().0,
    )
    .unwrap();
    let mut clock = support::Frozen::default();
    for (index, role, name) in [
        (0, LogSource::Syslog, "syslog.txt"),
        (1, LogSource::Auth, "auth.txt"),
    ] {
        let source = ctx
            .sources()
            .iter()
            .find(|source| source.definition().id().as_str() == ids[index])
            .unwrap();
        let root = ConfinedRoot::open(
            &ctx,
            OperationTarget::Source(source.definition().id()),
            Exclusions::default(),
            &mut clock,
            &false,
        )
        .unwrap();
        let bytes =
            sources::text_log::read_admitted(role, &root, &support::path(name), &mut clock, &false)
                .unwrap();
        let window = UtcWindow {
            start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
            end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        };
        let records =
            collectors::events::text::parse(&bytes, source.definition().id().clone(), &window)
                .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "owned marker");
        assert!(matches!(
            sources::text_log::read_admitted(
                role,
                &root,
                &support::path("missing.txt"),
                &mut clock,
                &false
            ),
            Err(Code::ScopeDenied)
        ));
    }
}
