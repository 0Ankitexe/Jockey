//! Supplied source bytes and owned temporary trees only.
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

use collectors::persistence::{autostart, cron, systemd};
use jocky_shared::collection::{Code, identity::Uuid, inputs::PathRef, outcomes::Field};

fn location(name: &str) -> PathRef {
    PathRef::new(
        Uuid::parse("10000000-0000-4000-8000-000000000091").unwrap(),
        name,
    )
    .unwrap()
}

#[test]
fn systemd_unit_timer_are_inventory_only_and_keep_declared_targets() {
    let raw = b"[Unit]\nDescription=Owned timer\n[Timer]\nOnCalendar=daily\nUnit=jocky-lab.service\n[Install]\nWantedBy=timers.target\n";
    let record = systemd::parse_timer(raw, location("jocky-lab.timer")).unwrap();
    assert_eq!(
        record.referenced_targets,
        Field::Available {
            value: vec!["jocky-lab.service".into(), "timers.target".into()]
        }
    );
    assert!(matches!(record.content_sha256, Field::Available { .. }));
    assert_eq!(
        record.kind,
        jocky_shared::collection::inputs::StartupFormat::SystemdTimers
    );
    let unit = systemd::parse_unit(
        b"[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRestart=no\n",
        location("jocky-lab.service"),
    )
    .unwrap();
    assert_eq!(
        unit.referenced_targets,
        Field::Available {
            value: vec!["/usr/bin/true".into()]
        }
    );
}

#[test]
fn cron_and_autostart_preserve_distinct_format_and_disabled_state() {
    let cron_record = cron::parse(b"0 1 * * * /usr/bin/true\n", location("crontab")).unwrap();
    assert_eq!(
        cron_record.kind,
        jocky_shared::collection::inputs::StartupFormat::Cron
    );
    assert_eq!(
        cron_record.referenced_targets,
        Field::Available {
            value: vec!["/usr/bin/true".into()]
        }
    );
    let desktop = autostart::parse(
        b"[Desktop Entry]\nType=Application\nExec=/usr/bin/true --flag\nHidden=true\nX-Lab-Only=yes\n",
        location("lab.desktop"),
    )
    .unwrap();
    assert_eq!(
        desktop.enabled_state,
        Field::Available {
            value: "disabled".into()
        }
    );
    assert_eq!(
        desktop.referenced_targets,
        Field::Available {
            value: vec!["/usr/bin/true --flag".into()]
        }
    );
}

#[test]
fn malformed_escape_denial_rotation_and_bounds_fail_closed() {
    assert_eq!(
        systemd::parse_unit(
            b"[Service]\nExecStart=bad\nExecStart=other\n",
            location("bad.service")
        ),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        cron::parse(b"@reboot /usr/bin/true\n", location("cron")),
        Err(Code::UnsupportedFormat)
    );
    assert_eq!(
        autostart::parse(b"[Desktop Entry]\nExec=\n", location("bad.desktop")),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        systemd::parse_unit(&vec![b'x'; 65_537], location("big.service")),
        Err(Code::ResourceLimit)
    );
    assert!(
        PathRef::new(
            Uuid::parse("10000000-0000-4000-8000-000000000091").unwrap(),
            "../outside"
        )
        .is_err()
    );
    assert_eq!(
        collectors::persistence::stable_bytes(Err(Code::PermissionDenied), true),
        Err(Code::PermissionDenied)
    );
    assert_eq!(
        collectors::persistence::stable_bytes(Ok(b"owned"), false),
        Err(Code::SourceChanged)
    );
    let outside = systemd::parse_unit(
        b"[Service]\nExecStart=../outside\n",
        location("outside.service"),
    )
    .unwrap();
    assert_eq!(
        outside.referenced_targets,
        Field::Available {
            value: vec!["../outside".into()]
        }
    );
    // A declared reference is an inert string, not a request to open it.
    assert!(
        !serde_json::to_string(&outside)
            .unwrap()
            .contains("outside sentinel")
    );
}

#[test]
fn selected_startup_directory_pins_only_owned_descendants() {
    use jocky_forensic::collection::{InputSet, admit, context::OperationTarget};
    use serde_json::json;
    use sources::{metadata::Exclusions, paths::ConfinedRoot};
    use std::os::unix::fs::symlink;
    let owned = support::scratch();
    std::fs::create_dir(owned.path().join("startup")).unwrap();
    std::fs::write(
        owned.path().join("startup/lab.service"),
        b"[Service]\nExecStart=/usr/bin/true\n",
    )
    .unwrap();
    std::fs::write(owned.path().join("outside"), b"outside sentinel").unwrap();
    symlink(
        owned.path().join("outside"),
        owned.path().join("startup/link.service"),
    )
    .unwrap();
    let mut v = support::values(owned.path().to_str().unwrap(), "startup");
    let id = "10000000-0000-4000-8000-000000000099";
    for index in [1, 2] {
        v[index]["scope"]["capabilities"] = json!(["persistence"]);
        v[index]["scope"]["source_groups"] = json!(["startup_directory"]);
        v[index]["scope"]["roots"][0]["purposes"] = json!(["persistence"]);
    }
    v[2]["sources"] = json!([{"kind":"startup_directory","source_id":id,"path":support::path("startup"),"format":"systemd_units"}]);
    v[3]["collectors"] = json!(["persistence"]);
    v[3]["capabilities"] = json!(["persistence"]);
    v[3]["source_ids"] = json!([id]);
    v[3]["paths"] = json!([]);
    let raw = v.each_ref().map(|value| serde_json::to_vec(value).unwrap());
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
    let target = OperationTarget::Source(selected.definition().id());
    let mut clock = support::Frozen::default();
    let root = ConfinedRoot::open(&ctx, target, Exclusions::default(), &mut clock, &false).unwrap();
    assert_eq!(
        root.list_children("startup", &mut clock, &false).unwrap(),
        vec!["lab.service", "link.service"]
    );
    assert!(
        root.pin_file("startup/lab.service", &mut clock, &false)
            .is_ok()
    );
    assert!(matches!(
        root.pin_file("startup/link.service", &mut clock, &false),
        Err(Code::AliasDenied)
    ));
    assert!(matches!(
        root.pin_file("outside", &mut clock, &false),
        Err(Code::ScopeDenied)
    ));
}
