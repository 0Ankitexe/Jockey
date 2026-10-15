//! T088 mixed facility outcomes and authority tests are entirely synthetic.
#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "support/confinement.rs"]
mod support;
use jocky_forensic::collection::{
    InputSet, admit, collector::CollectorRequest, context::OperationTarget, outcome,
};
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    outcomes::{Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState},
    report::{SummaryStatus, WorkerCleanup},
};
use serde_json::json;

fn admitted(
    values: &[serde_json::Value; 4],
) -> Result<jocky_forensic::collection::ValidatedCollectionContext, Code> {
    let raw = values.each_ref().map(|v| serde_json::to_vec(v).unwrap());
    admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: None,
        },
        support::Frozen::default().0,
    )
}

#[test]
fn services_require_system_capability_and_a_selected_systemd_source() {
    let mut v = support::values("/synthetic/owned", "file");
    let id = "10000000-0000-4000-8000-000000000099";
    for index in [1, 2] {
        v[index]["scope"]["capabilities"] = json!(["system", "files"]);
        v[index]["scope"]["source_groups"] = json!(["systemd_bus"]);
    }
    v[2]["sources"] =
        json!([{"kind":"systemd_bus","source_id":id,"unix_path":"/run/dbus/system_bus_socket"}]);
    v[3]["capabilities"] = json!(["system", "files"]);
    v[3]["collectors"] = json!(["services", "files"]);
    v[3]["source_ids"] = json!([id]);
    let ctx = admitted(&v).unwrap();
    assert_eq!(
        CollectorRequest::Services(&ctx.sources()[0]).validate(&ctx),
        Ok(())
    );
    v[3]["capabilities"] = json!(["files"]);
    assert!(admitted(&v).is_err());
    v[3]["capabilities"] = json!(["system", "files"]);
    v[3]["source_ids"] = json!([]);
    assert!(admitted(&v).is_err());
}

#[test]
fn unavailable_and_permission_denied_never_become_complete_empty() {
    let source = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    let complete = CollectorOutcome {
        collector: Collector::System,
        status: CollectorStatus::Complete,
        coverage: vec![Coverage {
            source_id: source.clone(),
            state: FacilityState::Supported,
            reason: None,
        }],
        accepted_records: 1,
        omitted_records: Some(0),
        omitted_reason: None,
        errors: 0,
        stop_reason: None,
    };
    let mut denied = outcome::unsupported(Collector::Services);
    denied.status = CollectorStatus::PermissionDenied;
    denied.coverage = vec![Coverage {
        source_id: source,
        state: FacilityState::PermissionDenied,
        reason: Some(Code::PermissionDenied),
    }];
    denied.omitted_reason = Some(Code::PermissionDenied);
    denied.stop_reason = Some(Code::PermissionDenied);
    let summary =
        outcome::summarize(&[complete, denied.clone()], None, WorkerCleanup::Complete).unwrap();
    assert_eq!(summary.status, SummaryStatus::Partial);
    assert_eq!(summary.accepted_records, 1);
    let mut false_empty = denied;
    false_empty.status = CollectorStatus::Complete;
    false_empty.stop_reason = None;
    false_empty.omitted_reason = None;
    assert_eq!(
        outcome::summarize(&[false_empty], None, WorkerCleanup::Complete),
        Err(Code::InvalidInput)
    );
}

#[test]
fn requested_facility_does_not_authorize_registry_execution() {
    let v = support::values("/synthetic/owned", "file");
    let ctx = admitted(&v).unwrap();
    // Source registry describes selectors; it is not an executable function map.
    assert!(ctx.sources().is_empty());
    let unselected = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    assert!(matches!(
        ctx.permit(
            OperationTarget::Source(&unselected),
            &support::Frozen::default().0,
            false
        ),
        Err(Code::ScopeDenied)
    ));
}
