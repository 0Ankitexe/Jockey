//! The first private worker packet is bounded launch metadata, not authority.
#![forbid(unsafe_code)]

#[path = "../src/worker/entry.rs"]
#[allow(dead_code)]
mod entry;
#[cfg(target_os = "linux")]
#[path = "../src/worker/handles.rs"]
#[allow(dead_code)]
mod handles;
#[cfg(target_os = "linux")]
#[path = "../src/worker/peer.rs"]
#[allow(dead_code)]
mod peer;
#[cfg(target_os = "linux")]
#[path = "../src/worker/resource.rs"]
#[allow(dead_code)]
mod resource;

use jocky_shared::collection::Code;
use std::io::{Cursor, Read};

fn valid_packet() -> Vec<u8> {
    let raw = include_bytes!("../../../fixtures/valid/collection/worker-launch.json");
    let mut packet = Vec::with_capacity(raw.len() + 4);
    packet.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    packet.extend_from_slice(raw);
    packet
}

#[test]
fn valid_launch_consumes_one_packet_and_preserves_following_bytes() {
    let mut packet = valid_packet();
    packet.extend_from_slice(b"next");
    let mut reader = Cursor::new(packet);
    let launch = entry::receive_launch(&mut reader).unwrap();
    assert_eq!(launch.schema_version.as_str(), "1.1.0");
    let mut tail = [0; 4];
    reader.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"next");
}

#[test]
fn empty_oversized_truncated_and_invalid_documents_fail_closed() {
    for packet in [
        Vec::new(),
        vec![0, 0, 0],
        vec![0, 0, 0, 0],
        (65537u32).to_be_bytes().to_vec(),
        vec![0, 0, 0, 5, b'{', b'}'],
        vec![0, 0, 0, 2, b'{', b'}'],
    ] {
        assert_eq!(
            entry::receive_launch(&mut Cursor::new(packet)).err(),
            Some(Code::WorkerProtocol)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn same_process_socket_cannot_impersonate_owned_parent() {
    use std::{io::Write, os::unix::net::UnixStream};
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let mut launch = jocky_shared::collection::launch::decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.parent = peer::own_identity().unwrap();
    let raw = serde_json::to_vec(&launch).unwrap();
    sender.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
    sender.write_all(&raw).unwrap();
    let writer = receiver.try_clone().unwrap();
    assert_eq!(
        entry::receive_from_owned_parent(&mut receiver, writer).err(),
        Some(Code::WorkerProtocol)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_file_entry_is_denied_before_consuming_untrusted_launch() {
    use std::{fs, io::Seek, io::SeekFrom, os::fd::AsFd};
    let root = tempfile::tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target")).unwrap();
    let path = root.path().join("launch");
    fs::write(&path, valid_packet()).unwrap();
    let mut reader = fs::File::open(&path).unwrap();
    let writer = reader.as_fd().try_clone_to_owned().unwrap();
    assert_eq!(
        entry::receive_from_owned_parent(&mut reader, writer).err(),
        Some(Code::WorkerProtocol)
    );
    assert_eq!(reader.stream_position().unwrap(), 0);
    reader.seek(SeekFrom::Start(0)).unwrap();
}
