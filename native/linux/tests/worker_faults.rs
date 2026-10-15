//! Offline malformed IPC and direct-worker denial. No live source is opened.
#![cfg(target_os = "linux")]
#[path = "../src/worker/chunks.rs"]
mod chunks;
#[path = "../src/worker/protocol.rs"]
#[allow(dead_code)]
mod protocol;
use jocky_shared::collection::worker::{Chunk, Commit};
use jocky_shared::collection::{Code, identity::Uuid};
use protocol::FrameDecoder;
use std::{io::Cursor, process::Command};

fn decoder() -> FrameDecoder {
    FrameDecoder::new(Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap())
}

#[test]
fn oversized_forged_and_truncated_frames_close_the_decoder() {
    for bytes in [
        u32::MAX.to_be_bytes().to_vec(),
        vec![0, 0, 0, 2, b'{', b'}'],
        vec![0, 0, 0, 4, b'{'],
    ] {
        let mut state = decoder();
        let mut input = Cursor::new(bytes);
        assert!(protocol::read_frame(&mut input, &mut state).is_err());
        assert_eq!(state.push(&[0, 0, 0, 1, b'x']), Err(Code::WorkerProtocol));
    }
}

#[test]
fn worker_mode_without_parent_handshake_cannot_start_collection() {
    let result = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("__worker")
        .env_clear()
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.len() <= 8192 && result.stderr.len() <= 8192);
}

#[test]
fn replayed_chunk_cannot_commit_or_recover_after_terminal_protocol_fault() {
    let bytes = b"owned synthetic";
    let commit = Commit {
        byte_length: bytes.len() as u64,
        sha256: jocky_forensic::collection::identity::digest(bytes).unwrap(),
    };
    let mut transfer = chunks::ChunkTransfer::new(&commit, bytes.len() as u64).unwrap();
    let first = Chunk {
        offset: 0,
        data: "b3duZWQ=".into(),
    };
    transfer.push(&first).unwrap();
    assert_eq!(transfer.push(&first), Err(Code::WorkerProtocol));
    assert_eq!(
        transfer.push(&Chunk {
            offset: 5,
            data: "IHN5bnRoZXRpYw==".into()
        }),
        Err(Code::WorkerProtocol)
    );
    assert_eq!(transfer.commit(&commit), Err(Code::WorkerProtocol));
}
