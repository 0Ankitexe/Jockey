//! T086 loaded-module-only fixtures. T170 supplies the actual proc/sys join.
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

use jocky_shared::collection::{Code, outcomes::Field, records::DriverRecord};

#[test]
fn module_contract_preserves_unavailable_version_without_address_field() {
    let record = DriverRecord {
        name: "labmod".into(),
        size_bytes: Field::Available { value: 4096 },
        reference_count: Field::Available { value: 1 },
        state: "Live".into(),
        version: Field::Unavailable {
            reason: Code::NotFound,
        },
        source_version: Field::Unavailable {
            reason: Code::PermissionDenied,
        },
    };
    let value = serde_json::to_value(record).unwrap();
    assert!(value.get("address").is_none());
    assert!(value.get("module_path").is_none());
    assert_eq!(value["version"]["reason"], "NotFound");
}

fn collect_modules(
    proc: &[u8],
    version: Result<&[u8], Code>,
    srcversion: Result<&[u8], Code>,
) -> Result<Vec<DriverRecord>, Code> {
    collectors::drivers::parse_loaded(proc, |_, key| {
        let result = if key == "version" {
            &version
        } else {
            &srcversion
        };
        (*result).map(|raw| raw.to_vec())
    })
}

#[test]
fn injected_join_ignores_address_and_refuses_module_loading_paths() {
    let raw = b"labmod 4096 1 - Live 0xffff000000000000\n";
    let found = collect_modules(raw, Ok(b"1.2"), Err(Code::NotFound)).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].version,
        Field::Available {
            value: "1.2".into()
        }
    );
    assert_eq!(
        found[0].source_version,
        Field::Unavailable {
            reason: Code::NotFound
        }
    );
    assert_eq!(
        collect_modules(b"../escape 4096 1 - Live 0x0\n", Ok(b"1"), Ok(b"1")),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        collect_modules(&vec![b'x'; 65_537], Ok(b"1"), Ok(b"1")),
        Err(Code::ResourceLimit)
    );
}
