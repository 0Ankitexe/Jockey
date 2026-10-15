#[path = "../src/worker/chunks.rs"]
mod chunks;
#[path = "../src/worker/inputs.rs"]
mod inputs;
use base64::{Engine, engine::general_purpose::STANDARD};
use inputs::InputTransfer;
use jocky_forensic::collection::{ClockReading, admit, identity::digest};
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    outcomes::Collector,
    worker::{Chunk, Commit, InputDescriptor, InputRole, Start},
};

fn id() -> Uuid {
    Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap()
}
fn data() -> (Start, Vec<u8>, Commit) {
    let docs = [
        (
            InputRole::Designation,
            include_bytes!("../../../fixtures/valid/collection/endpoint-designation.json")
                .as_slice(),
        ),
        (
            InputRole::Authorisation,
            include_bytes!("../../../fixtures/valid/collection/authorisation.json").as_slice(),
        ),
        (
            InputRole::Policy,
            include_bytes!("../../../fixtures/valid/collection/policy.json").as_slice(),
        ),
        (
            InputRole::Request,
            include_bytes!("../../../fixtures/valid/collection/request.json").as_slice(),
        ),
    ];
    let inputs = docs
        .iter()
        .map(|(role, raw)| InputDescriptor {
            role: *role,
            byte_length: raw.len() as u64,
            sha256: digest(raw).unwrap(),
        })
        .collect();
    let bytes: Vec<_> = docs
        .into_iter()
        .flat_map(|(_, raw)| raw.iter().copied())
        .collect();
    let done = Commit {
        byte_length: bytes.len() as u64,
        sha256: digest(&bytes).unwrap(),
    };
    (
        Start::Collect {
            collector: Collector::System,
            inputs,
            input_byte_length: done.byte_length,
            input_sha256: done.sha256.clone(),
        },
        bytes,
        done,
    )
}
fn send(transfer: &mut InputTransfer, bytes: &[u8]) {
    for (i, raw) in bytes.chunks(101).enumerate() {
        transfer
            .push(&Chunk {
                offset: (i * 101) as u64,
                data: STANDARD.encode(raw),
            })
            .unwrap();
    }
}

#[test]
fn verified_bundle_is_integrity_checked_then_requires_separate_authority_admission() {
    let (start, bytes, done) = data();
    let mut transfer = InputTransfer::new(id(), &start).unwrap();
    send(&mut transfer, &bytes);
    let bundle = transfer.commit(&done).unwrap();
    assert_eq!(bundle.collector(), Collector::System);
    assert_eq!(bundle.context().collection_id, id());
    assert_eq!(bundle.fingerprint().request.id, id());
    assert!(
        admit(
            bundle.inputs(),
            ClockReading {
                utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
                monotonic_ms: 0
            }
        )
        .is_ok()
    );
    assert!(matches!(
        admit(
            bundle.inputs(),
            ClockReading {
                utc: UtcTime::parse("2026-10-10T00:00:00Z").unwrap(),
                monotonic_ms: 0
            }
        ),
        Err(Code::AuthorisationExpired)
    ));
    assert!(matches!(transfer.commit(&done), Err(Code::WorkerProtocol)));
}

#[test]
fn descriptor_roles_lengths_and_hashes_are_validated_before_transfer() {
    for mutation in 0..6 {
        let (mut start, _, _) = data();
        let Start::Collect {
            inputs,
            input_byte_length,
            ..
        } = &mut start
        else {
            unreachable!()
        };
        match mutation {
            0 => {
                inputs.pop();
            }
            1 => inputs[0].role = InputRole::Request,
            2 => inputs[0].byte_length = 65537,
            3 => inputs[0].sha256 = "x".repeat(64),
            4 => *input_byte_length += 1,
            _ => inputs[0].byte_length = 0,
        }
        assert!(
            matches!(InputTransfer::new(id(), &start), Err(Code::WorkerProtocol)),
            "mutation {mutation}"
        );
    }
}

#[test]
fn per_document_hash_and_schema_fail_even_when_aggregate_digest_matches() {
    for malformed in [false, true] {
        let (mut start, mut bytes, mut done) = data();
        let Start::Collect {
            inputs,
            input_sha256,
            ..
        } = &mut start
        else {
            unreachable!()
        };
        if malformed {
            bytes[0] = b'!';
            inputs[0].sha256 = digest(&bytes[..inputs[0].byte_length as usize]).unwrap();
            done.sha256 = digest(&bytes).unwrap();
            *input_sha256 = done.sha256.clone();
        } else {
            inputs[0].sha256 = "0".repeat(64);
        }
        let mut transfer = InputTransfer::new(id(), &start).unwrap();
        send(&mut transfer, &bytes);
        assert!(matches!(transfer.commit(&done), Err(Code::WorkerProtocol)));
        assert!(matches!(transfer.commit(&done), Err(Code::WorkerProtocol)));
    }
}

#[test]
fn wrong_collection_or_unrequested_collector_cannot_release_a_bundle() {
    for wrong_id in [false, true] {
        let (mut start, bytes, done) = data();
        let mut collection = id();
        if wrong_id {
            collection = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
        } else if let Start::Collect { collector, .. } = &mut start {
            *collector = Collector::Files;
        }
        let mut transfer = InputTransfer::new(collection, &start).unwrap();
        send(&mut transfer, &bytes);
        assert!(matches!(transfer.commit(&done), Err(Code::WorkerProtocol)));
    }
}

#[test]
fn role_mapping_does_not_depend_on_descriptor_order_and_preserves_optional_input() {
    let (start, bytes, _) = data();
    let Start::Collect { inputs, .. } = start else {
        unreachable!()
    };
    let mut offset = 0;
    let mut parts: Vec<_> = inputs
        .into_iter()
        .map(|d| {
            let end = offset + d.byte_length as usize;
            let raw = bytes[offset..end].to_vec();
            offset = end;
            (d, raw)
        })
        .collect();
    let indicators =
        include_bytes!("../../../fixtures/valid/collection/indicator-set.json").to_vec();
    parts.push((
        InputDescriptor {
            role: InputRole::Indicators,
            byte_length: indicators.len() as u64,
            sha256: digest(&indicators).unwrap(),
        },
        indicators.clone(),
    ));
    parts.reverse();
    let bytes: Vec<_> = parts.iter().flat_map(|(_, v)| v.iter().copied()).collect();
    let done = Commit {
        byte_length: bytes.len() as u64,
        sha256: digest(&bytes).unwrap(),
    };
    let start = Start::Collect {
        collector: Collector::System,
        inputs: parts.into_iter().map(|(d, _)| d).collect(),
        input_byte_length: done.byte_length,
        input_sha256: done.sha256.clone(),
    };
    let mut transfer = InputTransfer::new(id(), &start).unwrap();
    send(&mut transfer, &bytes);
    let bundle = transfer.commit(&done).unwrap();
    assert_eq!(bundle.inputs().indicators, Some(indicators.as_slice()));
    assert_eq!(
        bundle.inputs().designation,
        include_bytes!("../../../fixtures/valid/collection/endpoint-designation.json")
    );
    assert_eq!(
        bundle.inputs().request,
        include_bytes!("../../../fixtures/valid/collection/request.json")
    );
}

#[test]
fn aggregate_input_ceiling_is_independent_of_per_role_limits() {
    let descriptors: Vec<_> = InputRole::ALL
        .iter()
        .map(|role| InputDescriptor {
            role: *role,
            byte_length: if *role == InputRole::Indicators {
                524288
            } else {
                65536
            },
            sha256: "0".repeat(64),
        })
        .collect();
    let mut start = Start::Collect {
        collector: Collector::System,
        inputs: descriptors,
        input_byte_length: 786432,
        input_sha256: "0".repeat(64),
    };
    assert!(InputTransfer::new(id(), &start).is_ok());
    if let Start::Collect {
        input_byte_length, ..
    } = &mut start
    {
        *input_byte_length += 1;
    }
    assert!(matches!(
        InputTransfer::new(id(), &start),
        Err(Code::WorkerProtocol)
    ));
}
