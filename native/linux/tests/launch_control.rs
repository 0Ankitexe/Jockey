//! In-memory framing only; ownership/current authority remain native-entry gates.
#[allow(dead_code)]
#[path = "../src/worker/mod.rs"]
mod worker;
use jocky_shared::collection::{Code, launch::decode_launch};
use worker::control::{LaunchDecoder, encode_launch};

fn packet() -> Vec<u8> {
    let value = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    encode_launch(&value).unwrap()
}

#[test]
fn every_fragmentation_boundary_delivers_exactly_one_launch() {
    let packet = packet();
    for split in 0..=packet.len() {
        let mut decoder = LaunchDecoder::new();
        let (n, first) = decoder.push(&packet[..split]).unwrap();
        assert_eq!(n, split);
        if first.is_some() {
            assert_eq!(split, packet.len());
        } else {
            let (n, launch) = decoder.push(&packet[split..]).unwrap();
            assert_eq!(n, packet.len() - split);
            assert!(launch.is_some());
        }
        assert_eq!(decoder.finish(), Ok(()));
    }
}

#[test]
fn every_truncated_prefix_and_oversize_header_fails_without_a_launch() {
    let packet = packet();
    for end in 0..packet.len() {
        let mut decoder = LaunchDecoder::new();
        assert!(decoder.push(&packet[..end]).unwrap().1.is_none());
        assert_eq!(decoder.finish(), Err(Code::WorkerProtocol));
    }
    for size in [0u32, 65537, u32::MAX] {
        let mut decoder = LaunchDecoder::new();
        assert!(matches!(
            decoder.push(&size.to_be_bytes()),
            Err(Code::WorkerProtocol)
        ));
        assert!(matches!(decoder.push(&packet), Err(Code::WorkerProtocol)));
    }
}

#[test]
fn a_coalesced_start_is_not_swallowed_and_repeated_launch_is_not_accepted() {
    let packet = packet();
    let mut combined = packet.clone();
    combined.extend_from_slice(b"v1-start-placeholder");
    let mut decoder = LaunchDecoder::new();
    let (n, value) = decoder.push(&combined).unwrap();
    assert_eq!(n, packet.len());
    assert!(value.is_some());
    assert!(matches!(
        decoder.push(&combined[n..]),
        Err(Code::WorkerProtocol)
    ));
}

#[test]
fn exact_wire_size_is_allowed_but_unknown_or_corrupt_documents_are_not() {
    let mut raw = include_bytes!("../../../fixtures/valid/collection/worker-launch.json").to_vec();
    raw.resize(65536, b' ');
    let mut packet = (raw.len() as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&raw);
    let mut decoder = LaunchDecoder::new();
    assert!(decoder.push(&packet).unwrap().1.is_some());
    for raw in [
        b"{}".as_slice(),
        b"not-json",
        include_bytes!("../../../fixtures/valid/collection/worker.json").as_slice(),
    ] {
        let mut packet = (raw.len() as u32).to_be_bytes().to_vec();
        packet.extend_from_slice(raw);
        assert!(matches!(
            LaunchDecoder::new().push(&packet),
            Err(Code::WorkerProtocol)
        ));
    }
}
