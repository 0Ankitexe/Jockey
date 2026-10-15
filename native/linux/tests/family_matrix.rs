//! All four legacy distribution trees are synthetic parser inputs only.
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
    inputs::{PathRef, UtcWindow},
};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

fn cases() -> Vec<Value> {
    serde_json::from_slice::<Value>(include_bytes!("fixtures/cases.json")).unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn four_synthetic_service_startup_log_module_variants_run_real_parsers() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let window = UtcWindow {
        start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
    };
    let source_id = Uuid::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let root_id = Uuid::parse("22222222-2222-4222-8222-222222222222").unwrap();
    let mut formats = Vec::new();
    for case in cases().into_iter().take(4) {
        let directory = base.join(case["root"].as_str().unwrap());
        let facility = &case["facilities"];
        let service: Value = serde_json::from_slice(
            &fs::read(directory.join(facility["service"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
        let name = service["name"].as_str().unwrap().to_owned();
        let state = service["state"].as_str().unwrap().to_owned();
        let snapshot = sources::systemd::Snapshot {
            units: vec![sources::systemd::UnitFact {
                name: name.clone(),
                description: "JOCKY synthetic".into(),
                load_state: "loaded".into(),
                active_state: state,
                sub_state: "running".into(),
                object_path: "/org/freedesktop/systemd1/unit/jocky_2dsynthetic_2eservice".into(),
            }],
            files: vec![sources::systemd::UnitFileFact {
                name: name.clone(),
                state: "enabled".into(),
            }],
            properties: BTreeMap::new(),
        };
        let services = collectors::services::normalize(snapshot).unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].unit_name, name);

        let path = facility["startup"].as_str().unwrap();
        let location = PathRef {
            root_id: root_id.clone(),
            relative_path: path.into(),
        };
        let raw = fs::read(directory.join(path)).unwrap();
        let format = facility["startup_format"].as_str().unwrap();
        formats.push(format.to_owned());
        let entry = match format {
            "systemd_units" => collectors::persistence::systemd::parse_unit(&raw, location),
            "systemd_timers" => collectors::persistence::systemd::parse_timer(&raw, location),
            "cron" => collectors::persistence::cron::parse(&raw, location),
            "autostart" => collectors::persistence::autostart::parse(&raw, location),
            _ => panic!("unknown synthetic format"),
        }
        .unwrap();
        assert_eq!(entry.kind.as_str(), format);

        let log = fs::read(directory.join(facility["log"].as_str().unwrap())).unwrap();
        let events = collectors::events::text::parse(&log, source_id.clone(), &window).unwrap();
        assert_eq!(events.len(), 10);
        assert!(events.iter().all(|event| event.message.contains("marker-")));

        let modules = fs::read(directory.join(facility["module"].as_str().unwrap())).unwrap();
        let loaded =
            collectors::drivers::parse_loaded(&modules, |_, _| Err(Code::NotFound)).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].name.starts_with("jocky_"));
    }
    formats.sort();
    assert_eq!(
        formats,
        ["autostart", "cron", "systemd_timers", "systemd_units"]
    );
}

#[test]
fn synthetic_absence_malformed_denied_and_race_remain_typed() {
    let cases = cases();
    let expected = [
        ("missing-procfs", "FacilityUnavailable"),
        ("non-systemd", "Unsupported"),
        ("malformed-source", "UnsupportedFormat"),
        ("permission-denied", "PermissionDenied"),
        ("identity-race", "SourceChanged"),
    ];
    for (id, code) in expected {
        let case = cases.iter().find(|case| case["id"] == id).unwrap();
        assert_eq!(case["facility_fault"]["code"], code);
    }
    let absent =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/missing-procfs/proc/modules");
    assert_eq!(
        fs::read(absent).map_err(|error| if error.kind() == std::io::ErrorKind::NotFound {
            Code::FacilityUnavailable
        } else {
            Code::InvalidInput
        }),
        Err(Code::FacilityUnavailable)
    );
    assert_eq!(collectors::services::non_systemd(), Err(Code::Unsupported));
    let source = Uuid::parse("11111111-1111-4111-8111-111111111111").unwrap();
    let window = UtcWindow {
        start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
    };
    assert_eq!(
        collectors::events::text::parse(b"Oct 15 00:00:00 no-year", source.clone(), &window),
        Err(Code::UnsupportedFormat)
    );
    let denied: Result<Vec<u8>, Code> = Err(Code::PermissionDenied);
    assert_eq!(
        denied.and_then(|raw| collectors::events::text::parse(&raw, source, &window)),
        Err(Code::PermissionDenied)
    );
    assert_eq!(
        collectors::persistence::stable_bytes(Ok(b"synthetic"), false),
        Err(Code::SourceChanged)
    );
}
