//! Static synthetic source trees; no host facility is read or labelled evidence.
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
};

fn manifest() -> Value {
    serde_json::from_slice(include_bytes!("fixtures/cases.json")).unwrap()
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

#[test]
fn four_distribution_trees_and_fault_cases_are_complete_synthetic_inputs() {
    let manifest = manifest();
    assert_eq!(manifest["schema_version"], "jocky-v5-offline-cases-1");
    assert_eq!(manifest["evidence_kind"], "synthetic_test");
    let cases = manifest["cases"].as_array().unwrap();
    let expected: BTreeSet<_> = [
        "debian-13.7",
        "ubuntu-24.04.5",
        "fedora-44",
        "arch-2026.10.01",
        "missing-procfs",
        "non-systemd",
        "malformed-source",
        "permission-denied",
        "identity-race",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<_> = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(cases.len(), actual.len());
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for case in cases {
        let root = case["root"].as_str().unwrap();
        assert!(safe_relative(root));
        assert!(matches!(
            case["init"].as_str(),
            Some("systemd" | "other" | "unknown")
        ));
        let paths = case["available"].as_array().unwrap();
        assert!(!paths.is_empty());
        for path in paths {
            let path = path.as_str().unwrap();
            assert!(safe_relative(path), "unsafe fixture path: {path}");
            let target = base.join(root).join(path);
            let metadata = fs::symlink_metadata(&target).unwrap();
            assert!(metadata.file_type().is_file());
            assert!(metadata.len() <= 65_536);
            let bytes = fs::read(&target).unwrap();
            assert!(std::str::from_utf8(&bytes).is_ok());
        }
    }
    for id in [
        "debian-13.7",
        "ubuntu-24.04.5",
        "fedora-44",
        "arch-2026.10.01",
    ] {
        let case = cases.iter().find(|case| case["id"] == id).unwrap();
        assert_eq!(case["available"].as_array().unwrap().len(), 10);
        let os_release = fs::read_to_string(
            base.join(case["root"].as_str().unwrap())
                .join("etc/os-release"),
        )
        .unwrap();
        assert!(os_release.contains("JOCKY synthetic"));
    }
}

#[test]
fn fault_manifest_declares_denial_race_and_missing_facilities_without_chmod() {
    let cases = manifest()["cases"].as_array().unwrap().clone();
    let fault = |id: &str| cases.iter().find(|case| case["id"] == id).unwrap()["faults"][0].clone();
    assert_eq!(fault("missing-procfs")["code"], "FacilityUnavailable");
    assert_eq!(fault("non-systemd")["code"], "Unsupported");
    assert_eq!(fault("malformed-source")["code"], "UnsupportedFormat");
    assert_eq!(fault("permission-denied")["code"], "PermissionDenied");
    assert_eq!(fault("identity-race")["code"], "SourceChanged");
    assert_eq!(fault("identity-race")["at"], "after_read");
    assert!(!safe_relative("../host"));
    assert!(!safe_relative("/proc"));
    assert!(!safe_relative("a//b"));
}
