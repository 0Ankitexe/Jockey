//! T084 contract vectors for the T170 journal adapter. No ambient journal I/O.
#![cfg(target_os = "linux")]
use jocky_shared::collection::{Code, identity::UtcTime, outcomes::Field};
use std::os::unix::fs::PermissionsExt;

#[derive(Clone)]
struct Event<'a> {
    at: &'a str,
    bytes: &'a [u8],
}

#[test]
fn half_open_window_and_distinct_unavailable_states_are_frozen() {
    let start = UtcTime::parse("2020-01-01T00:00:00Z").unwrap();
    let end = UtcTime::parse("2020-01-01T00:00:10Z").unwrap();
    let entries = [
        Event {
            at: "2019-12-31T23:59:59Z",
            bytes: b"before",
        },
        Event {
            at: "2020-01-01T00:00:00Z",
            bytes: b"inside",
        },
        Event {
            at: "2020-01-01T00:00:10Z",
            bytes: b"end",
        },
    ];
    let selected: Vec<_> = entries
        .iter()
        .filter(|event| {
            let at = UtcTime::parse(event.at).unwrap();
            at.unix_nanos() >= start.unix_nanos() && at.unix_nanos() < end.unix_nanos()
        })
        .map(|event| event.bytes)
        .collect();
    assert_eq!(selected, vec![b"inside".as_slice()]);
    assert_ne!(
        Field::<String>::Unavailable {
            reason: Code::PermissionDenied
        },
        Field::Unavailable {
            reason: Code::NotFound
        }
    );
    assert_ne!(
        Field::<String>::Unavailable {
            reason: Code::Unsupported
        },
        Field::Available {
            value: String::new()
        }
    );
}

#[cfg(feature = "journal")]
#[test]
fn optional_reader_exposes_only_the_safe_named_file_entrypoint() {
    // Type-check the actual optional API without opening any host journal.
    let _open =
        |options: &systemd::journal::OpenFilesOptions, files: Vec<&str>| options.open_files(files);
}

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

#[test]
fn admitted_snapshot_is_private_and_reader_has_no_discovery_fallback() {
    use jocky_forensic::collection::{InputSet, admit, context::OperationTarget};
    use jocky_shared::collection::{identity::Uuid, inputs::UtcWindow};
    use serde_json::json;
    use sources::{metadata::Exclusions, paths::ConfinedRoot};
    let owned = support::scratch();
    std::fs::write(
        owned.path().join("owned.journal"),
        b"inert journal test bytes",
    )
    .unwrap();
    let mut values = support::values(owned.path().to_str().unwrap(), "owned.journal");
    let id = "10000000-0000-4000-8000-000000000099";
    for index in [1, 2] {
        values[index]["scope"]["capabilities"] = json!(["events"]);
        values[index]["scope"]["source_groups"] = json!(["journal_file"]);
        values[index]["scope"]["roots"][0]["purposes"] = json!(["journal"]);
    }
    values[2]["sources"] =
        json!([{"kind":"journal_file","source_id":id,"path":support::path("owned.journal")}]);
    values[3]["collectors"] = json!(["events"]);
    values[3]["capabilities"] = json!(["events"]);
    values[3]["source_ids"] = json!([id]);
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
    let selected = &ctx.sources()[0];
    let mut clock = support::Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::Source(selected.definition().id()),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let stage = sources::journal_snapshot::snapshot_admitted(
        &root,
        &support::path("owned.journal"),
        &mut clock,
        &false,
    )
    .unwrap();
    assert_eq!(stage.copied(), 24);
    let staged_path = stage.named_path();
    assert!(staged_path.ends_with(".journal"));
    assert_eq!(
        std::fs::metadata(&staged_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let window = UtcWindow {
        start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
    };
    let fact = sources::journal::JournalFact {
        micros: 1_577_836_800_000_000,
        message: b"owned marker".to_vec(),
        priority: Some(b"6".to_vec()),
    };
    let events =
        collectors::events::journal::parse_facts(&[fact], Uuid::parse(id).unwrap(), &window)
            .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message, "owned marker");
    #[cfg(not(feature = "journal"))]
    assert!(matches!(
        sources::journal::read_staged(&stage, |_| Ok(())),
        Err(Code::Unsupported)
    ));
    #[cfg(feature = "journal")]
    assert!(sources::journal::read_staged(&stage, |_| Ok(())).is_err());
    drop(stage);
    assert!(!std::path::Path::new(&staged_path).exists());
}
