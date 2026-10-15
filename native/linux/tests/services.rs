//! Injected systemd bus only. No host bus, service manager or endpoint access.
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

use jocky_shared::collection::{Code, outcomes::Field};
use sources::systemd::{BusCall, BusReply, BusTransport, Property, UnitFact, UnitFileFact};

#[derive(Default)]
struct FakeBus {
    calls: Vec<BusCall>,
    units: Vec<UnitFact>,
    files: Vec<UnitFileFact>,
    denied: bool,
    fail_on: Option<(BusCall, Code)>,
}
impl BusTransport for FakeBus {
    fn call(&mut self, call: BusCall) -> Result<BusReply, Code> {
        self.calls.push(call.clone());
        if self.denied {
            return Err(Code::PermissionDenied);
        }
        if let Some((selected, reason)) = &self.fail_on
            && selected == &call
        {
            return Err(*reason);
        }
        Ok(match call {
            BusCall::ListUnits => BusReply::Units(self.units.clone()),
            BusCall::ListUnitFiles => BusReply::UnitFiles(self.files.clone()),
            BusCall::Get { property, .. } => BusReply::Text(match property {
                Property::Description => "Lab service".into(),
                Property::LoadState => "loaded".into(),
                Property::ActiveState => "active".into(),
                Property::SubState => "running".into(),
            }),
        })
    }
}

fn unit() -> UnitFact {
    UnitFact {
        name: "jocky-lab.service".into(),
        description: "Lab service".into(),
        load_state: "loaded".into(),
        active_state: "active".into(),
        sub_state: "running".into(),
        object_path: "/org/freedesktop/systemd1/unit/jocky_2dlab_2eservice".into(),
    }
}

#[test]
fn fixed_bus_calls_and_union_normalize_without_mutation() {
    assert_eq!(sources::systemd::MAX_QUEUE, 8);
    assert_eq!(
        sources::systemd::CALL_TIMEOUT,
        std::time::Duration::from_secs(2)
    );
    let mut bus = FakeBus {
        units: vec![unit()],
        files: vec![
            UnitFileFact {
                name: "jocky-lab.service".into(),
                state: "enabled".into(),
            },
            UnitFileFact {
                name: "only-file.timer".into(),
                state: "disabled".into(),
            },
        ],
        ..Default::default()
    };
    let raw = sources::systemd::query(&mut bus).unwrap();
    let records = collectors::services::normalize(raw).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].unit_name, "jocky-lab.service");
    assert_eq!(
        records[0].unit_file_state,
        Field::Available {
            value: "enabled".into()
        }
    );
    assert_eq!(records[1].unit_name, "only-file.timer");
    assert_eq!(
        records[1].active_state,
        Field::Unavailable {
            reason: Code::NotFound
        }
    );
    assert!(
        bus.calls
            .starts_with(&[BusCall::ListUnits, BusCall::ListUnitFiles])
    );
    assert!(bus.calls.iter().all(|call| matches!(
        call,
        BusCall::ListUnits | BusCall::ListUnitFiles | BusCall::Get { .. }
    )));
    for call in &bus.calls {
        let route = sources::systemd::route(call).unwrap();
        assert_eq!(route.destination, "org.freedesktop.systemd1");
        assert!(route.path.starts_with("/org/freedesktop/systemd1"));
        assert!(matches!(
            route.member,
            "ListUnits" | "ListUnitFiles" | "Get"
        ));
        assert!(route.no_auto_start);
    }
    assert_eq!(bus.calls.len(), 6);
}

#[test]
fn native_inventory_selects_service_units_only() {
    let mut bus = FakeBus {
        units: vec![
            unit(),
            UnitFact {
                name: "bad/path.mount".into(),
                ..unit()
            },
            UnitFact {
                name: "bad/path.service".into(),
                ..unit()
            },
        ],
        files: vec![UnitFileFact {
            name: "jocky-lab.service".into(),
            state: "enabled".into(),
        }],
        ..Default::default()
    };
    let (snapshot, malformed) = sources::systemd::query_listed(&mut bus).unwrap();
    assert!(malformed);
    assert_eq!(snapshot.units.len(), 1);
    assert_eq!(snapshot.files.len(), 1);
    assert_eq!(bus.calls, vec![BusCall::ListUnits, BusCall::ListUnitFiles]);
}

#[test]
fn denial_oversize_and_non_systemd_are_typed_failures() {
    let mut denied = FakeBus {
        denied: true,
        ..Default::default()
    };
    assert_eq!(
        sources::systemd::query(&mut denied),
        Err(Code::PermissionDenied)
    );
    assert_eq!(denied.calls, vec![BusCall::ListUnits]);
    let mut oversized = FakeBus {
        units: vec![unit(); 513],
        ..Default::default()
    };
    assert_eq!(
        sources::systemd::query(&mut oversized),
        Err(Code::ResourceLimit)
    );
    assert_eq!(collectors::services::non_systemd(), Err(Code::Unsupported));
    let mut timeout = FakeBus {
        fail_on: Some((BusCall::ListUnitFiles, Code::Timeout)),
        ..Default::default()
    };
    assert_eq!(sources::systemd::query(&mut timeout), Err(Code::Timeout));
    assert_eq!(
        timeout.calls,
        vec![BusCall::ListUnits, BusCall::ListUnitFiles]
    );
    let mut property_denied = FakeBus {
        units: vec![unit()],
        fail_on: Some((
            BusCall::Get {
                object_path: unit().object_path,
                property: Property::ActiveState,
            },
            Code::PermissionDenied,
        )),
        ..Default::default()
    };
    let observed =
        collectors::services::normalize(sources::systemd::query(&mut property_denied).unwrap())
            .unwrap();
    assert_eq!(
        observed[0].active_state,
        Field::Unavailable {
            reason: Code::PermissionDenied
        }
    );
}

#[test]
fn forged_name_and_object_path_never_become_bus_calls() {
    let mut bad = unit();
    bad.object_path = "/org/freedesktop/systemd1/../evil".into();
    let mut bus = FakeBus {
        units: vec![bad],
        ..Default::default()
    };
    assert_eq!(
        sources::systemd::query(&mut bus),
        Err(Code::MalformedSource)
    );
    assert_eq!(bus.calls, vec![BusCall::ListUnits]);
    assert_eq!(
        sources::systemd::route(&BusCall::Get {
            object_path: "/org/freedesktop/systemd1/../evil".into(),
            property: Property::Description,
        }),
        Err(Code::MalformedSource)
    );
}

#[test]
fn unselected_bus_fails_before_any_native_connection() {
    let values = support::values("/synthetic/owned", "selected");
    let ctx = support::context(&values);
    let source_id =
        jocky_shared::collection::identity::Uuid::parse("10000000-0000-4000-8000-000000000099")
            .unwrap();
    let mut clock = support::Frozen::default();
    assert!(matches!(
        sources::systemd::connect_admitted(&ctx, &source_id, &mut clock, &false),
        Err(Code::ScopeDenied)
    ));
}
