//! T087 admitted four-kind exact-set vectors; T171 supplies matching.
use jocky_forensic::collection::{ClockReading, InputSet, admit};
use jocky_shared::collection::{Code, identity::UtcTime, inputs::Indicator};
use serde_json::{Value, json};

fn values() -> [Value; 5] {
    [
        include_str!("../../fixtures/valid/collection/endpoint-designation.json"),
        include_str!("../../fixtures/valid/collection/authorisation.json"),
        include_str!("../../fixtures/valid/collection/policy.json"),
        include_str!("../../fixtures/valid/collection/request.json"),
        include_str!("../../fixtures/valid/collection/indicator-set.json"),
    ]
    .map(|raw| serde_json::from_str(raw).unwrap())
}
fn selected() -> [Value; 5] {
    let mut v = values();
    for index in [1, 2] {
        v[index]["scope"]["capabilities"] = json!(["system", "indicators"]);
    }
    v[3]["capabilities"] = json!(["system", "indicators"]);
    v[3]["collectors"] = json!(["system", "indicators"]);
    v[3]["indicator_set_id"] = v[4]["indicator_set_id"].clone();
    for index in [1, 2] {
        v[index]["scope"]["roots"] = json!([{"root_id":"10000000-0000-4000-8000-000000000090","absolute_path":"/synthetic/indicator","purposes":["files"]}]);
    }
    v
}
fn attempt(v: &[Value; 5]) -> Result<jocky_forensic::collection::ValidatedCollectionContext, Code> {
    let raw = v.each_ref().map(|value| serde_json::to_vec(value).unwrap());
    admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: Some(&raw[4]),
        },
        ClockReading {
            utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
            monotonic_ms: 0,
        },
    )
}

#[test]
fn all_four_kinds_are_typed_case_bound_and_normalized_once() {
    let mut v = selected();
    v[4]["indicators"] = json!([
        {"indicator_id":"10000000-0000-4000-8000-000000000020","kind":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"indicator_id":"10000000-0000-4000-8000-000000000021","kind":"path","value":{"root_id":"10000000-0000-4000-8000-000000000090","relative_path":"owned.txt"}},
        {"indicator_id":"10000000-0000-4000-8000-000000000022","kind":"ip_address","value":"2001:0db8:0:0:0:0:0:1"},
        {"indicator_id":"10000000-0000-4000-8000-000000000023","kind":"domain","value":"LAB.Example.invalid."}
    ]);
    let ctx = attempt(&v).unwrap();
    let admitted = ctx.indicators().unwrap();
    let indicators = &admitted.definition().indicators;
    assert_eq!(indicators.len(), 4);
    assert!(matches!(&indicators[0],Indicator::Sha256{value,..} if value.len()==64));
    assert!(matches!(&indicators[1],Indicator::Path{value,..} if value.relative_path=="owned.txt"));
    assert!(matches!(&indicators[2],Indicator::IpAddress{value,..} if value=="2001:db8::1"));
    assert!(matches!(&indicators[3],Indicator::Domain{value,..} if value=="lab.example.invalid"));
    assert!(ctx.input_provenance().indicators.is_some());
    v[4]["case_id"] = json!("10000000-0000-4000-8000-000000000099");
    assert!(matches!(attempt(&v), Err(Code::AuthorisationDenied)));
}

#[test]
fn patterns_idna_cidr_zones_and_duplicate_ids_reject() {
    let mut v = selected();
    let base = json!({"indicator_id":"10000000-0000-4000-8000-000000000020","kind":"domain","value":"example.invalid"});
    for (kind, value) in [
        ("domain", "*.example.invalid"),
        ("domain", "éxample.invalid"),
        ("ip_address", "192.0.2.1/24"),
        ("ip_address", "fe80::1%eth0"),
        ("sha256", "A"),
        ("domain", "example..invalid"),
    ] {
        v[4]["indicators"] = json!([{"indicator_id":"10000000-0000-4000-8000-000000000020","kind":kind,"value":value}]);
        assert!(attempt(&v).is_err(), "{kind} {value}");
    }
    v[4]["indicators"] = json!([base.clone(), base]);
    assert!(attempt(&v).is_err());
}

#[test]
fn exact_family_near_miss_missing_and_provenance_contract() {
    use jocky_forensic::collection::indicator_match::{
        Comparison, Completeness, compare, evaluate,
    };
    use jocky_shared::collection::{
        identity::Uuid,
        records::{ForensicRecord, Payload},
    };
    let id = Uuid::parse("10000000-0000-4000-8000-000000000020").unwrap();
    let ip = Indicator::IpAddress {
        indicator_id: id.clone(),
        value: "192.0.2.1".into(),
    };
    assert_eq!(compare(&ip, Some("192.0.2.1")), Comparison::Match);
    assert_eq!(compare(&ip, Some("::ffff:192.0.2.1")), Comparison::NoMatch);
    let domain = Indicator::Domain {
        indicator_id: id.clone(),
        value: "example.invalid".into(),
    };
    assert_eq!(
        compare(&domain, Some("sub.example.invalid")),
        Comparison::NoMatch
    );
    assert_eq!(compare(&domain, None), Comparison::Unevaluated);

    let mut v = selected();
    v[4]["indicators"] = json!([
      {"indicator_id":"10000000-0000-4000-8000-000000000020","kind":"ip_address","value":"192.0.2.1"},
      {"indicator_id":"10000000-0000-4000-8000-000000000021","kind":"domain","value":"example.invalid"},
      {"indicator_id":"10000000-0000-4000-8000-000000000022","kind":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    ]);
    let ctx = attempt(&v).unwrap();
    let mut connection: ForensicRecord = serde_json::from_str(include_str!(
        "../../fixtures/valid/collection/forensic-record--connection.json"
    ))
    .unwrap();
    if let Payload::Connection(row) = &mut connection.payload {
        row.local_address = "192.0.2.1".into();
        row.remote_address = "192.0.2.2".into();
    }
    let record_id = connection.record_id.clone();
    let result = evaluate(
        ctx.indicators().unwrap(),
        &[connection],
        Completeness {
            addresses: true,
            domains: true,
            hashes: false,
            paths: false,
        },
        10,
        10,
    )
    .unwrap();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].indicator_id, id);
    assert_eq!(result.matches[0].matched_record_id, record_id);
    assert_eq!(result.matches[0].field_path, "/payload/local_address");
    assert_eq!(result.unevaluated.len(), 2);
    assert_eq!(result.comparisons, 2);
    assert_eq!(
        evaluate(
            ctx.indicators().unwrap(),
            &[],
            Completeness::default(),
            10,
            10
        )
        .unwrap()
        .unevaluated
        .len(),
        3
    );
    assert_eq!(
        evaluate(
            ctx.indicators().unwrap(),
            &[serde_json::from_str(include_str!(
                "../../fixtures/valid/collection/forensic-record--connection.json"
            ))
            .unwrap()],
            Completeness {
                addresses: true,
                ..Completeness::default()
            },
            1,
            10
        ),
        Err(Code::ResourceLimit)
    );
}
