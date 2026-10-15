//! Authored bytes only. No fixture is an authority or an endpoint observation.
use jocky_forensic::collection::{ClockReading, InputSet, admit};
use jocky_shared::collection::{Code, identity::UtcTime};
use jocky_shared::collection::{DecodeReason, DocumentKind, decode};
use serde_json::{Value, json};

fn fixture(kind: DocumentKind) -> &'static [u8] {
    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                "../../../../fixtures/valid/collection/",
                $name,
                ".json"
            ))
        };
    }
    match kind {
        DocumentKind::Types => fixture!("types"),
        DocumentKind::Designation => fixture!("endpoint-designation"),
        DocumentKind::Authorisation => fixture!("authorisation"),
        DocumentKind::Policy => fixture!("policy"),
        DocumentKind::Request => fixture!("request"),
        DocumentKind::Indicators => fixture!("indicator-set"),
        DocumentKind::Endpoint => fixture!("endpoint-observation"),
        DocumentKind::Report => fixture!("report"),
        DocumentKind::Status => fixture!("status"),
        DocumentKind::Worker => fixture!("worker"),
        DocumentKind::LabScenario => fixture!("lab-scenario"),
        DocumentKind::Record => fixture!("forensic-record"),
        DocumentKind::Manifest => fixture!("evidence-manifest"),
    }
}

pub fn exercise() {
    let launch = include_bytes!("../../../../fixtures/valid/collection/worker-launch.json");
    jocky_shared::collection::launch::decode_launch(launch).unwrap();
    let mut padded = launch.to_vec();
    padded.resize(65536, b' ');
    jocky_shared::collection::launch::decode_launch(&padded).unwrap();
    padded.push(b' ');
    assert_eq!(
        jocky_shared::collection::launch::decode_launch(&padded)
            .unwrap_err()
            .reason,
        DecodeReason::Size
    );
    println!("WorkerLaunchSchemaInitializedAndByteBoundariesPassed");
    for kind in DocumentKind::ALL {
        decode(kind, fixture(kind)).unwrap();
        println!("FullSchemaInitialized:{}", kind.name());
    }
    // Every document's exact wire byte ceiling, then ceiling+1. Whitespace
    // padding tests wire limits, not maximum evidence retention or LAB-SMALL.
    for kind in DocumentKind::ALL {
        let mut bytes = Vec::with_capacity(kind.maximum_bytes() + 1);
        bytes.extend_from_slice(fixture(kind));
        bytes.resize(kind.maximum_bytes(), b' ');
        decode(kind, &bytes).unwrap();
        bytes.push(b' ');
        assert_eq!(decode(kind, &bytes).unwrap_err().reason, DecodeReason::Size);
    }
    cardinalities();
    aggregate_admission();
    hostile();
    // Repeated validation must not grow a new validator tree for each input.
    for _ in 0..16 {
        for kind in DocumentKind::ALL {
            decode(kind, fixture(kind)).unwrap();
        }
    }
    println!("AllSchemasByteCardinalityHostileAndRepeatCasesPassed");
}

fn aggregate_admission() {
    let kinds = [
        DocumentKind::Designation,
        DocumentKind::Authorisation,
        DocumentKind::Policy,
        DocumentKind::Request,
        DocumentKind::Indicators,
    ];
    let mut values: Vec<Value> = kinds
        .iter()
        .map(|kind| serde_json::from_slice(fixture(*kind)).unwrap())
        .collect();
    for n in [1, 2] {
        values[n]["scope"]["capabilities"] = json!(["system", "indicators"]);
    }
    values[3]["capabilities"] = json!(["system", "indicators"]);
    values[3]["collectors"] = json!(["system", "indicators"]);
    values[3]["indicator_set_id"] = values[4]["indicator_set_id"].clone();
    values[4]["indicators"] = json!(
        (1..=1000)
            .map(|n| json!({
                "indicator_id":format!("10000000-0000-4000-8000-{n:012x}"),
                "kind":"sha256", "value":format!("{n:064x}")
            }))
            .collect::<Vec<_>>()
    );
    let mut bytes: Vec<_> = values
        .iter()
        .zip(kinds)
        .map(|(value, kind)| {
            let mut raw = serde_json::to_vec(value).unwrap();
            assert!(raw.len() <= kind.maximum_bytes());
            raw.resize(kind.maximum_bytes(), b' ');
            raw
        })
        .collect();
    let check = |bytes: &[Vec<u8>]| {
        admit(
            InputSet {
                designation: &bytes[0],
                authorisation: Some(&bytes[1]),
                policy: &bytes[2],
                request: &bytes[3],
                indicators: Some(&bytes[4]),
            },
            ClockReading {
                utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
                monotonic_ms: 0,
            },
        )
    };
    assert_eq!(bytes.iter().map(Vec::len).sum::<usize>(), 786432);
    assert!(check(&bytes).is_ok());
    bytes[4].push(b' ');
    assert_eq!(check(&bytes).err(), Some(Code::ResourceLimit));
    println!("Aggregate786432ByteAdmissionAndBoundaryPlusOnePassed");
}

fn cardinalities() {
    let mut request: Value = serde_json::from_slice(fixture(DocumentKind::Request)).unwrap();
    request["paths"] = json!(
        (0..256)
            .map(|n| json!({
                "root_id":"10000000-0000-4000-8000-000000000010",
                "relative_path":format!("{n}/{}", "a".repeat(128))
            }))
            .collect::<Vec<_>>()
    );
    let bytes = serde_json::to_vec(&request).unwrap();
    decode(DocumentKind::Request, &bytes).unwrap();
    request["paths"].as_array_mut().unwrap().push(json!({
        "root_id":"10000000-0000-4000-8000-000000000010", "relative_path":"one-more"
    }));
    assert_eq!(
        decode(
            DocumentKind::Request,
            &serde_json::to_vec(&request).unwrap()
        )
        .unwrap_err()
        .reason,
        DecodeReason::Schema
    );
    let mut set: Value = serde_json::from_slice(fixture(DocumentKind::Indicators)).unwrap();
    set["indicators"] = json!(
        (1..=1000)
            .map(|n| json!({
                "indicator_id":format!("10000000-0000-4000-8000-{n:012x}"),
                "kind":"sha256", "value":format!("{n:064x}")
            }))
            .collect::<Vec<_>>()
    );
    decode(DocumentKind::Indicators, &serde_json::to_vec(&set).unwrap()).unwrap();
    set["indicators"].as_array_mut().unwrap().push(json!({
        "indicator_id":"20000000-0000-4000-8000-000000000001", "kind":"sha256", "value":"a".repeat(64)
    }));
    assert_eq!(
        decode(DocumentKind::Indicators, &serde_json::to_vec(&set).unwrap())
            .unwrap_err()
            .reason,
        DecodeReason::Schema
    );
}

fn hostile() {
    let mut bytes = Vec::with_capacity(DocumentKind::Report.maximum_bytes());
    bytes.push(b'"');
    bytes.resize(DocumentKind::Report.maximum_bytes() - 1, b'x');
    bytes.push(b'"');
    assert_eq!(
        decode(DocumentKind::Report, &bytes).unwrap_err().reason,
        DecodeReason::Schema
    );
    drop(bytes);
    let nodes = format!("[{}0]", "0,".repeat(131071));
    assert_eq!(
        decode(DocumentKind::Report, nodes.as_bytes())
            .unwrap_err()
            .reason,
        DecodeReason::Allocation
    );
    let deep = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    assert_eq!(
        decode(DocumentKind::Report, deep.as_bytes())
            .unwrap_err()
            .reason,
        DecodeReason::Depth
    );
}
