//! Only repository-owned files/directories; no endpoint facilities are probed.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;

use jocky_forensic::collection::context::OperationTarget;
use jocky_shared::collection::Code;
use sources::{
    capabilities::OutputDirectory,
    inventory::{Inventory, ResolvedCapabilities},
    metadata::Exclusions,
    paths::ConfinedRoot,
};
use support::{Frozen, context, path, scratch, values};

#[test]
fn admitted_inventory_retains_owned_output_and_selected_source_handles() {
    let owned = scratch();
    std::fs::create_dir(owned.path().join("evidence")).unwrap();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    std::fs::write(owned.path().join("evidence/selected"), b"owned input").unwrap();
    let evidence = owned.path().join("evidence");
    let destination = owned.path().join("output/report.json");
    let ctx = context(&values(evidence.to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let admitted =
        ResolvedCapabilities::admit(&ctx, &[], destination.to_str().unwrap(), &mut clock, &false)
            .unwrap();
    assert_eq!(admitted.output().name(), "report.json");
    assert_eq!(admitted.ordinary_roots().len(), 1);
    assert_eq!(admitted.ordinary_roots()[0].0, path("selected"));
    assert!(admitted.fixed_facilities().is_empty());
    assert!(!destination.exists());
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}

#[test]
fn admitted_inventory_rejects_configuration_inode_alias_before_content_read() {
    use sources::metadata::ObjectId;
    let owned = scratch();
    std::fs::create_dir(owned.path().join("evidence")).unwrap();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    let selected = owned.path().join("evidence/selected");
    std::fs::write(&selected, b"private configuration").unwrap();
    let file = std::fs::File::open(&selected).unwrap();
    let stat = rustix::fs::fstat(&file).unwrap();
    let configuration = [ObjectId {
        device: stat.st_dev,
        inode: stat.st_ino,
    }];
    let evidence = owned.path().join("evidence");
    let ctx = context(&values(evidence.to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let admitted = ResolvedCapabilities::admit(
        &ctx,
        &configuration,
        owned.path().join("output/report.json").to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    let root = &admitted.ordinary_roots()[0].1;
    assert!(matches!(
        root.pin_file("selected", &mut clock, &false),
        Err(Code::AliasDenied)
    ));
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}

#[test]
fn fixed_source_inventory_uses_only_the_selected_literal_facility() {
    use jocky_forensic::collection::{InputSet, admit};
    let owned = scratch();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    let ctx = admit(
        InputSet {
            designation: include_bytes!(
                "../../../fixtures/valid/collection/endpoint-designation.json"
            ),
            authorisation: Some(include_bytes!(
                "../../../fixtures/valid/collection/authorisation.json"
            )),
            policy: include_bytes!("../../../fixtures/valid/collection/policy.json"),
            request: include_bytes!("../../../fixtures/valid/collection/request.json"),
            indicators: None,
        },
        Frozen::default().0,
    )
    .unwrap();
    let mut clock = Frozen::default();
    let admitted = ResolvedCapabilities::admit(
        &ctx,
        &[],
        owned.path().join("output/report.json").to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    assert!(admitted.ordinary_roots().is_empty());
    assert_eq!(admitted.fixed_facilities().len(), 1);
    assert_eq!(admitted.fixed_facilities()[0].1.primary, "/proc");
    assert_eq!(
        admitted.fixed_facilities()[0].1.secondary,
        Some("/usr/lib/os-release")
    );
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}

#[test]
fn nested_roots_fail_logical_admission_before_native_source_access() {
    use jocky_forensic::collection::{InputSet, admit};
    use jocky_shared::collection::{identity::Uuid, inputs::PathRef};
    use serde_json::json;

    let first = path("selected");
    let second = PathRef::new(
        Uuid::parse("10000000-0000-4000-8000-000000000091").unwrap(),
        "selected",
    )
    .unwrap();
    let mut input = values("/synthetic/case", "selected");
    for index in [1, 2] {
        input[index]["scope"]["roots"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "root_id": second.root_id,
                "absolute_path": "/synthetic/case/sub",
                "purposes": ["files", "persistence"]
            }));
    }
    input[3]["paths"] = json!([first, second]);
    let raw = input
        .each_ref()
        .map(|value| serde_json::to_vec(value).unwrap());
    assert!(matches!(
        admit(
            InputSet {
                designation: &raw[0],
                authorisation: Some(&raw[1]),
                policy: &raw[2],
                request: &raw[3],
                indicators: None,
            },
            Frozen::default().0,
        ),
        Err(Code::InvalidInput)
    ));

    let sibling = "/synthetic/case-other";
    for index in [1, 2] {
        input[index]["scope"]["roots"][1]["absolute_path"] = json!(sibling);
    }
    let raw = input
        .each_ref()
        .map(|value| serde_json::to_vec(value).unwrap());
    assert!(
        admit(
            InputSet {
                designation: &raw[0],
                authorisation: Some(&raw[1]),
                policy: &raw[2],
                request: &raw[3],
                indicators: None,
            },
            Frozen::default().0,
        )
        .is_ok()
    );
}

#[test]
fn admitted_sibling_output_is_pinned_without_creation_or_evidence_reads() {
    let owned = scratch();
    for name in ["evidence", "output"] {
        std::fs::create_dir(owned.path().join(name)).unwrap();
    }
    let evidence = owned.path().join("evidence");
    let output = owned.path().join("output/report.json");
    let ctx = context(&values(evidence.to_str().unwrap(), "selected"));
    let reference = path("selected");
    let mut clock = Frozen::default();
    let target = OperationTarget::File(&reference);
    let cap =
        OutputDirectory::open(&ctx, target, output.to_str().unwrap(), &mut clock, &false).unwrap();
    assert_eq!(cap.name(), "report.json");
    let mut inventory = Inventory::new(&[], &cap).unwrap();
    let root =
        ConfinedRoot::open(&ctx, target, inventory.exclusions(), &mut clock, &false).unwrap();
    inventory.add(&root).unwrap();
    inventory.add(&root).unwrap(); // One admitted root can serve multiple requests.
    cap.check_unchanged(&mut clock, &false).unwrap();
    assert!(!output.exists());
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}

#[test]
fn output_collision_symlink_unsafe_parent_and_cancellation_fail_without_writes() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for variant in ["exists", "symlink", "unsafe", "cancel"] {
        let owned = scratch();
        let selected = path("selected");
        let ctx = context(&values(owned.path().to_str().unwrap(), "selected"));
        let destination = owned.path().join("report.json");
        match variant {
            "exists" => std::fs::write(&destination, b"preserve").unwrap(),
            "symlink" => symlink("never-read", &destination).unwrap(),
            "unsafe" => {
                std::fs::set_permissions(owned.path(), std::fs::Permissions::from_mode(0o777))
                    .unwrap()
            }
            _ => (),
        }
        let expected = match variant {
            "exists" => Code::OutputExists,
            "symlink" => Code::AliasDenied,
            "unsafe" => Code::PermissionDenied,
            _ => Code::Cancelled,
        };
        assert!(
            matches!(OutputDirectory::open(&ctx, OperationTarget::File(&selected), destination.to_str().unwrap(), &mut Frozen::default(), &(variant == "cancel")), Err(code) if code == expected)
        );
        if variant == "exists" {
            assert_eq!(std::fs::read(destination).unwrap(), b"preserve");
        }
    }
}

#[test]
fn evidence_and_output_roots_cannot_overlap_in_either_direction() {
    for nested_output in [true, false] {
        let owned = scratch();
        std::fs::create_dir(owned.path().join("nested")).unwrap();
        let evidence = if nested_output {
            owned.path().to_path_buf()
        } else {
            owned.path().join("nested")
        };
        let output = if nested_output {
            owned.path().join("nested/report.json")
        } else {
            owned.path().join("report.json")
        };
        let selected = path("selected");
        let ctx = context(&values(evidence.to_str().unwrap(), "selected"));
        let mut clock = Frozen::default();
        let cap = OutputDirectory::open(
            &ctx,
            OperationTarget::File(&selected),
            output.to_str().unwrap(),
            &mut clock,
            &false,
        )
        .unwrap();
        let mut inventory = Inventory::new(&[], &cap).unwrap();
        let root = ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&selected),
            Exclusions::default(),
            &mut clock,
            &false,
        )
        .unwrap();
        assert_eq!(inventory.add(&root), Err(Code::AliasDenied));
        assert!(!output.exists());
    }
}

#[test]
fn retained_output_directory_cannot_be_redirected_by_replacement() {
    let owned = scratch();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    let selected = path("selected");
    let ctx = context(&values(owned.path().to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let cap = OutputDirectory::open(
        &ctx,
        OperationTarget::File(&selected),
        owned.path().join("output/report.json").to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    std::fs::rename(owned.path().join("output"), owned.path().join("original")).unwrap();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    // An unchanged pinned inode may survive a rename; its FD never becomes the replacement.
    let result = cap.check_unchanged(&mut clock, &false);
    assert!(matches!(result, Ok(()) | Err(Code::SourceChanged)));
    assert_ne!(
        rustix::fs::fstat(cap.fd()).unwrap().st_ino,
        std::fs::metadata(owned.path().join("output"))
            .unwrap()
            .ino()
    );
    use std::os::unix::fs::MetadataExt;
}

#[test]
fn configuration_inodes_are_excluded_from_content_even_when_requested() {
    use sources::metadata::ObjectId;
    let owned = scratch();
    for name in ["evidence", "output"] {
        std::fs::create_dir(owned.path().join(name)).unwrap();
    }
    let evidence = owned.path().join("evidence");
    std::fs::write(
        evidence.join("selected"),
        b"test authority bytes must not become evidence",
    )
    .unwrap();
    let file = std::fs::File::open(evidence.join("selected")).unwrap();
    let stat = rustix::fs::fstat(&file).unwrap();
    let excluded = ObjectId {
        device: stat.st_dev,
        inode: stat.st_ino,
    };
    let selected = path("selected");
    let ctx = context(&values(evidence.to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let target = OperationTarget::File(&selected);
    let cap = OutputDirectory::open(
        &ctx,
        target,
        owned.path().join("output/report.json").to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    let mut inventory = Inventory::new(&[excluded], &cap).unwrap();
    let root =
        ConfinedRoot::open(&ctx, target, inventory.exclusions(), &mut clock, &false).unwrap();
    inventory.add(&root).unwrap();
    assert!(matches!(
        root.pin_file("selected", &mut clock, &false),
        Err(Code::AliasDenied)
    ));
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::SourceBytes),
        Ok(0)
    );
}

#[test]
fn expired_or_unselected_scope_cannot_even_probe_a_nonexistent_output_parent() {
    use jocky_shared::collection::identity::UtcTime;
    let owned = scratch();
    let selected = path("selected");
    let ctx = context(&values(owned.path().to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    clock.0.utc = UtcTime::parse("2026-10-12T00:00:00Z").unwrap();
    assert!(matches!(
        OutputDirectory::open(
            &ctx,
            OperationTarget::File(&selected),
            "/nonexistent/unapproved/report.json",
            &mut clock,
            &false
        ),
        Err(Code::AuthorisationExpired)
    ));
    let ctx = context(&values(owned.path().to_str().unwrap(), "selected"));
    let unselected = path("other");
    assert!(matches!(
        OutputDirectory::open(
            &ctx,
            OperationTarget::File(&unselected),
            "/nonexistent/unapproved/report.json",
            &mut Frozen::default(),
            &false
        ),
        Err(Code::ScopeDenied)
    ));
    assert_eq!(
        ctx.charged(jocky_forensic::collection::budget::Counter::Entries),
        Ok(0)
    );
}

#[test]
fn output_capability_can_be_rechecked_after_evidence_cutoff_but_not_deadline() {
    use jocky_shared::collection::identity::UtcTime;
    let owned = scratch();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    let selected = path("selected");
    let ctx = context(&values(owned.path().to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let output = owned.path().join("output/report.json");
    let cap = OutputDirectory::open(
        &ctx,
        OperationTarget::File(&selected),
        output.to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    clock.0.monotonic_ms = 55_000;
    clock.0.utc = UtcTime::parse("2020-01-01T00:01:05Z").unwrap();
    assert_eq!(
        ctx.permit(OperationTarget::File(&selected), &clock.0, false)
            .err(),
        Some(Code::Timeout)
    );
    assert_eq!(cap.check_for_publication(&mut clock), Ok(()));
    std::fs::write(&output, b"already published").unwrap();
    assert_eq!(
        cap.check_for_publication(&mut clock),
        Err(Code::OutputExists)
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"already published");
    clock.0.monotonic_ms = 60_000;
    clock.0.utc = UtcTime::parse("2020-01-01T00:01:10Z").unwrap();
    assert_eq!(cap.check_for_publication(&mut clock), Err(Code::Timeout));
}

#[test]
fn expired_authority_does_not_reopen_sources_during_output_finalization() {
    use jocky_shared::collection::identity::UtcTime;
    let owned = scratch();
    std::fs::create_dir(owned.path().join("output")).unwrap();
    let selected = path("selected");
    let mut input = values(owned.path().to_str().unwrap(), "selected");
    input[1]["valid_until"] = serde_json::json!("2020-01-01T00:00:30Z");
    let ctx = context(&input);
    let mut clock = Frozen::default();
    let cap = OutputDirectory::open(
        &ctx,
        OperationTarget::File(&selected),
        owned.path().join("output/report.json").to_str().unwrap(),
        &mut clock,
        &false,
    )
    .unwrap();
    clock.0.monotonic_ms = 21_000;
    clock.0.utc = UtcTime::parse("2020-01-01T00:00:31Z").unwrap();
    assert_eq!(
        ctx.permit(OperationTarget::File(&selected), &clock.0, false)
            .err(),
        Some(Code::AuthorisationExpired)
    );
    assert_eq!(cap.check_for_publication(&mut clock), Ok(()));
    assert_eq!(
        ctx.permit(OperationTarget::File(&selected), &clock.0, false)
            .err(),
        Some(Code::AuthorisationExpired)
    );
}
