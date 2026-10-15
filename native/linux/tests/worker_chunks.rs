//! Supplied byte buffers only. A verified transfer is not live authority.
#[path = "../src/worker/chunks.rs"]
mod chunks;
use chunks::ChunkTransfer;
use jocky_forensic::collection::identity::digest;
use jocky_shared::collection::{
    Code,
    worker::{Chunk, Commit},
};

fn commit(bytes: &[u8]) -> Commit {
    Commit {
        byte_length: bytes.len() as u64,
        sha256: digest(bytes).unwrap(),
    }
}
fn chunk(offset: u64, data: &str) -> Chunk {
    Chunk {
        offset,
        data: data.into(),
    }
}

#[test]
fn ordered_chunks_release_bytes_only_after_exact_commit() {
    let expected = commit(b"abcdef");
    let mut transfer = ChunkTransfer::new(&expected, 6).unwrap();
    transfer.push(&chunk(0, "YWJj")).unwrap();
    transfer.push(&chunk(3, "ZGVm")).unwrap();
    assert_eq!(transfer.commit(&expected).unwrap(), b"abcdef");
    assert_eq!(transfer.commit(&expected), Err(Code::WorkerProtocol));
    assert_eq!(transfer.push(&chunk(6, "YQ==")), Err(Code::WorkerProtocol));
}

#[test]
fn gaps_replays_bad_padding_empty_and_excess_chunks_are_terminal() {
    for bad in [
        chunk(1, "YQ=="),
        chunk(0, ""),
        chunk(0, "YQ"),
        chunk(0, "YR=="),
        chunk(0, "YQ==\n"),
        chunk(0, "____"),
        chunk(0, "YWJjZA=="),
    ] {
        let expected = commit(b"abc");
        let mut transfer = ChunkTransfer::new(&expected, 3).unwrap();
        assert_eq!(transfer.push(&bad), Err(Code::WorkerProtocol));
        assert_eq!(transfer.push(&chunk(0, "YWJj")), Err(Code::WorkerProtocol));
    }
    let mut transfer = ChunkTransfer::new(&commit(b"abcdef"), 6).unwrap();
    transfer.push(&chunk(0, "YWJj")).unwrap();
    assert_eq!(transfer.push(&chunk(0, "YWJj")), Err(Code::WorkerProtocol));
}

#[test]
fn short_wrong_length_wrong_digest_and_corrupt_bytes_never_commit() {
    let expected = commit(b"abc");
    for (data, done) in [
        ("YQ==", expected.clone()),
        ("YWJj", commit(b"ab")),
        ("YWJj", commit(b"xyz")),
        ("eHl6", expected.clone()),
    ] {
        let mut transfer = ChunkTransfer::new(&expected, 3).unwrap();
        transfer.push(&chunk(0, data)).unwrap();
        assert_eq!(transfer.commit(&done), Err(Code::WorkerProtocol));
        assert_eq!(transfer.commit(&expected), Err(Code::WorkerProtocol));
    }
}

#[test]
fn declared_limits_and_digest_encoding_are_validated_before_allocation() {
    for (length, max) in [(0, 1), (2, 1), (10485761, 10485761), (u64::MAX, 10485760)] {
        assert!(matches!(
            ChunkTransfer::new(
                &Commit {
                    byte_length: length,
                    sha256: "0".repeat(64)
                },
                max
            ),
            Err(Code::WorkerProtocol)
        ));
    }
    for hash in ["0".repeat(63), "A".repeat(64), "g".repeat(64)] {
        assert!(matches!(
            ChunkTransfer::new(
                &Commit {
                    byte_length: 1,
                    sha256: hash
                },
                1
            ),
            Err(Code::WorkerProtocol)
        ));
    }
}

#[test]
fn decoded_chunk_boundary_and_plus_one_are_enforced_independently_of_encoded_size() {
    // 65536 zero bytes encode as 21845 full groups plus one padded byte.
    let encoded = format!("{}AA==", "AAAA".repeat(21845));
    let bytes = vec![0; 65536];
    let expected = commit(&bytes);
    let mut transfer = ChunkTransfer::new(&expected, 65536).unwrap();
    transfer.push(&chunk(0, &encoded)).unwrap();
    assert_eq!(transfer.commit(&expected).unwrap(), bytes);
    for suffix in ["AAA=", "AAAA"] {
        let encoded = format!("{}{suffix}", "AAAA".repeat(21845));
        let mut transfer = ChunkTransfer::new(&commit(&vec![0; 65538]), 65538).unwrap();
        assert_eq!(
            transfer.push(&chunk(0, &encoded)),
            Err(Code::WorkerProtocol)
        );
    }
}
