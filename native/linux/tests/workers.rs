//! Offline private protocol seam; no worker or evidence source is launched.
#[cfg(target_os = "linux")]
#[path = "../src/worker/handles.rs"]
mod handles;
#[path = "../src/worker/protocol.rs"]
mod protocol;

use jocky_shared::collection::{Code, identity::Uuid};
use protocol::FrameDecoder;
use std::io::{Cursor, Read};

#[cfg(target_os = "linux")]
fn owned_directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("v5-worker-handles-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
        .unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn owned_descriptor_transfer_is_bounded_and_keeps_the_actual_open_object() {
    use rustix::fd::AsFd;
    use std::{fs, os::unix::net::UnixStream};
    let owned = owned_directory();
    let path = owned.path().join("object");
    fs::write(&path, b"owned").unwrap();
    let file = fs::File::open(&path).unwrap();
    let original = rustix::fs::fstat(&file).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    handles::send(&sender, &[file.as_fd()]).unwrap();
    fs::rename(&path, owned.path().join("renamed")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    let received = handles::receive(&receiver, 1).unwrap();
    let retained = rustix::fs::fstat(&received[0]).unwrap();
    assert_eq!(
        (retained.st_dev, retained.st_ino),
        (original.st_dev, original.st_ino)
    );
    assert_ne!(retained.st_ino, fs::metadata(&path).unwrap().ino());
    use std::os::unix::fs::MetadataExt;
}

#[cfg(target_os = "linux")]
#[test]
fn missing_extra_and_unattached_descriptor_messages_fail_closed() {
    use rustix::fd::AsFd;
    use std::{fs, io::Write, os::unix::net::UnixStream};
    let owned = owned_directory();
    let file = fs::File::create(owned.path().join("object")).unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    handles::send(&sender, &[file.as_fd(), file.as_fd()]).unwrap();
    assert_eq!(
        handles::receive(&receiver, 1).err(),
        Some(Code::WorkerProtocol)
    );
    let (sender, receiver) = UnixStream::pair().unwrap();
    handles::send(&sender, &[file.as_fd()]).unwrap();
    assert_eq!(
        handles::receive(&receiver, 2).err(),
        Some(Code::WorkerProtocol)
    );
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender.write_all(&[0xa5]).unwrap();
    assert_eq!(
        handles::receive(&receiver, 1).err(),
        Some(Code::WorkerProtocol)
    );
    assert_eq!(handles::send(&sender, &[]), Err(Code::WorkerProtocol));
    assert_eq!(
        handles::receive(&receiver, 0).err(),
        Some(Code::WorkerProtocol)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn transferred_binding_rechecks_kernel_identity_type_and_exclusions() {
    use jocky_shared::collection::launch::{DescriptorBinding, HandleKind, ObjectIdentity};
    use rustix::fs::{self, AtFlags, StatxFlags};
    let owned = owned_directory();
    let directory = std::fs::File::open(owned.path()).unwrap();
    let stat = fs::statx(
        &directory,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::INO | StatxFlags::MNT_ID,
    )
    .unwrap();
    let object = ObjectIdentity {
        device_id: fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
        inode: stat.stx_ino.to_string(),
        mount_id: Some(stat.stx_mnt_id.to_string()),
    };
    let binding = DescriptorBinding {
        kind: HandleKind::OutputDirectory,
        subject_id: None,
        fd: 3,
        object: object.clone(),
    };
    let handle = std::os::fd::OwnedFd::from(directory);
    assert_eq!(
        handles::verify_objects(
            std::slice::from_ref(&binding),
            &[handle.try_clone().unwrap()],
            &[]
        ),
        Ok(())
    );
    assert_eq!(
        handles::verify_objects(
            std::slice::from_ref(&binding),
            &[handle.try_clone().unwrap()],
            &[object]
        ),
        Err(Code::WorkerProtocol)
    );
    let mut wrong = binding.clone();
    wrong.object.inode = "0".into();
    assert_eq!(
        handles::verify_objects(&[wrong], &[handle.try_clone().unwrap()], &[]),
        Err(Code::WorkerProtocol)
    );
    let mut wrong = binding;
    wrong.kind = HandleKind::ProcMount;
    assert_eq!(
        handles::verify_objects(&[wrong], &[handle], &[]),
        Err(Code::WorkerProtocol)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn transferred_binding_purpose_must_match_the_committed_selected_source() {
    use jocky_forensic::collection::{InputSet, admit};
    use jocky_shared::collection::{
        launch::{HandleKind, decode_launch},
        worker::Job,
    };
    let ctx = admit(
        InputSet {
            designation: include_bytes!(
                "../../../fixtures/valid/collection/endpoint-designation.json"
            ),
            authorisation: Some(include_bytes!(
                "../../../fixtures/valid/collection/authorisation.json"
            )),
            policy: include_bytes!("../../../fixtures/valid/collection/policy.json"),
            request: include_bytes!("../../../fixtures/valid/collection/request.json"),
            indicators: None,
        },
        jocky_forensic::collection::ClockReading {
            utc: jocky_shared::collection::identity::UtcTime::parse("2020-01-01T00:00:10Z")
                .unwrap(),
            monotonic_ms: 0,
        },
    )
    .unwrap();
    let launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    assert_eq!(
        handles::verify_scope(&ctx, Job::Collect, &launch.descriptors),
        Ok(())
    );
    let mut wrong = launch.descriptors[0].clone();
    wrong.subject_id = Some(id());
    assert_eq!(
        handles::verify_scope(&ctx, Job::Collect, &[wrong]),
        Err(Code::ScopeDenied)
    );
    let mut wrong = launch.descriptors[0].clone();
    wrong.kind = HandleKind::SysMount;
    assert_eq!(
        handles::verify_scope(&ctx, Job::Collect, &[wrong]),
        Err(Code::ScopeDenied)
    );
    assert_eq!(
        handles::verify_scope(&ctx, Job::Publish, &launch.descriptors),
        Err(Code::ScopeDenied)
    );
}

fn id() -> Uuid {
    Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap()
}
fn body(sequence: u64) -> Vec<u8> {
    format!(r#"{{"schema_version":"1.0.0","frame_seq":{sequence},"collection_id":"{}","kind":"cancel","payload":{{"code":"Cancelled"}}}}"#, id().as_str()).into_bytes()
}
fn packet(bytes: &[u8]) -> Vec<u8> {
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(bytes);
    framed
}

#[test]
fn bounded_transport_reads_one_frame_and_preserves_the_next() {
    let mut input = packet(&body(0));
    input.extend(packet(&body(1)));
    let mut reader = Cursor::new(input);
    let mut decoder = FrameDecoder::new(id());
    assert_eq!(
        protocol::read_frame(&mut reader, &mut decoder)
            .unwrap()
            .frame_seq,
        0
    );
    assert_eq!(
        protocol::read_frame(&mut reader, &mut decoder)
            .unwrap()
            .frame_seq,
        1
    );
    assert_eq!(decoder.finish(), Ok(()));
}

#[test]
fn transport_eof_oversize_and_sequence_faults_never_yield_a_frame() {
    for bad in [
        packet(&body(0))[..8].to_vec(),
        131073u32.to_be_bytes().to_vec(),
        packet(&body(1)),
    ] {
        let mut decoder = FrameDecoder::new(id());
        assert!(protocol::read_frame(&mut Cursor::new(bad), &mut decoder).is_err());
        assert_eq!(
            decoder.push(&packet(&body(0))).unwrap_err(),
            Code::WorkerProtocol
        );
    }
    let mut decoder = FrameDecoder::new(id());
    assert_eq!(
        protocol::read_frame(&mut Cursor::new(Vec::<u8>::new()), &mut decoder),
        Err(Code::WorkerFailed)
    );
    assert_eq!(
        decoder.push(&packet(&body(0))).unwrap_err(),
        Code::WorkerProtocol
    );
}

#[test]
fn transport_writer_handles_short_writes_and_reports_failure() {
    use jocky_shared::collection::{Document, DocumentKind, decode};
    let Document::Worker(frame) = decode(DocumentKind::Worker, &body(0)).unwrap() else {
        unreachable!()
    };
    let mut output = Vec::new();
    protocol::write_frame(&mut output, &frame).unwrap();
    let mut decoder = FrameDecoder::new(id());
    assert_eq!(
        protocol::read_frame(&mut Cursor::new(output), &mut decoder).unwrap(),
        *frame
    );
    struct ShortFail(usize);
    impl std::io::Write for ShortFail {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let size = self.0.min(bytes.len()).min(3);
            self.0 -= size;
            Ok(size)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        protocol::write_frame(&mut ShortFail(3), &frame),
        Err(Code::WorkerFailed)
    );
}

#[test]
fn transport_reader_does_not_request_more_than_one_payload() {
    struct Metered(Cursor<Vec<u8>>, usize);
    impl Read for Metered {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.1 = self.1.max(buf.len());
            self.0.read(buf)
        }
    }
    let mut reader = Metered(Cursor::new(packet(&body(0))), 0);
    protocol::read_frame(&mut reader, &mut FrameDecoder::new(id())).unwrap();
    assert!(reader.1 <= 65536);
}

#[cfg(unix)]
#[test]
fn owned_socket_transport_observes_deadline_and_partial_peer_loss() {
    use std::{io::Write, net::Shutdown, os::unix::net::UnixStream, time::Duration};
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    sender.write_all(&packet(&body(0))[..7]).unwrap();
    sender.shutdown(Shutdown::Write).unwrap();
    let mut decoder = FrameDecoder::new(id());
    assert_eq!(
        protocol::read_frame(&mut receiver, &mut decoder),
        Err(Code::WorkerFailed)
    );
    assert_eq!(decoder.finish(), Err(Code::WorkerProtocol));

    let (_sender, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert_eq!(
        protocol::read_frame(&mut receiver, &mut FrameDecoder::new(id())),
        Err(Code::WorkerFailed)
    );
}

#[test]
fn every_fragment_boundary_preserves_one_frame_and_sequence() {
    let bytes = packet(&body(0));
    for split in 0..=bytes.len() {
        let mut decoder = FrameDecoder::new(id());
        let (used, first) = decoder.push(&bytes[..split]).unwrap();
        assert_eq!(used, split);
        let (used, second) = decoder.push(&bytes[split..]).unwrap();
        assert_eq!(used, bytes.len() - split);
        let frame = first.or(second).unwrap();
        assert_eq!(frame.frame_seq, 0);
        assert_eq!(frame.collection_id, id());
        assert_eq!(decoder.finish(), Ok(()));
    }
}

#[test]
fn coalesced_frames_leave_following_bytes_with_the_caller() {
    let one = packet(&body(0));
    let mut bytes = one.clone();
    bytes.extend(packet(&body(1)));
    let mut decoder = FrameDecoder::new(id());
    let (used, frame) = decoder.push(&bytes).unwrap();
    assert_eq!(used, one.len());
    assert_eq!(frame.unwrap().frame_seq, 0);
    let (next, frame) = decoder.push(&bytes[used..]).unwrap();
    assert_eq!(used + next, bytes.len());
    assert_eq!(frame.unwrap().frame_seq, 1);
    assert_eq!(decoder.finish(), Ok(()));
    assert_eq!(decoder.push(&[]).unwrap_err(), Code::WorkerProtocol);
}

#[test]
fn length_zero_and_boundary_plus_one_fail_from_header_alone() {
    for length in [0u32, 131073, u32::MAX] {
        let mut decoder = FrameDecoder::new(id());
        assert_eq!(
            decoder.push(&length.to_be_bytes()).unwrap_err(),
            Code::WorkerProtocol
        );
        assert_eq!(
            decoder.push(&packet(&body(0))).unwrap_err(),
            Code::WorkerProtocol
        );
    }
    let mut exact = body(0);
    exact.resize(131072, b' ');
    let mut decoder = FrameDecoder::new(id());
    assert!(decoder.push(&packet(&exact)).unwrap().1.is_some());
}

#[test]
fn every_truncated_prefix_fails_at_eof_and_cannot_resume() {
    let bytes = packet(&body(0));
    for end in 1..bytes.len() {
        let mut decoder = FrameDecoder::new(id());
        assert!(decoder.push(&bytes[..end]).unwrap().1.is_none());
        assert_eq!(decoder.finish(), Err(Code::WorkerProtocol));
        assert_eq!(
            decoder.push(&bytes[end..]).unwrap_err(),
            Code::WorkerProtocol
        );
    }
}

#[test]
fn duplicate_unknown_version_identity_sequence_and_encoding_fail_closed() {
    let good = String::from_utf8(body(0)).unwrap();
    let invalid = [
        good.replace("\"frame_seq\":0", "\"frame_seq\":0,\"frame_seq\":0"),
        good.replace("\"kind\":", "\"extra\":1,\"kind\":"),
        good.replace("1.0.0", "2.0.0"),
        good.replace("000000000007", "000000000008"),
        good.replace("\"frame_seq\":0", "\"frame_seq\":1"),
        good.replace("cancel", "execute"),
        format!("{good} null"),
    ];
    for bytes in invalid.iter().map(|s| s.as_bytes()).chain([&b"\xff"[..]]) {
        let mut decoder = FrameDecoder::new(id());
        assert_eq!(
            decoder.push(&packet(bytes)).unwrap_err(),
            Code::WorkerProtocol
        );
        assert_eq!(decoder.finish(), Err(Code::WorkerProtocol));
    }
    let mut decoder = FrameDecoder::new(id());
    decoder.push(&packet(&body(0))).unwrap();
    assert_eq!(
        decoder.push(&packet(&body(0))).unwrap_err(),
        Code::WorkerProtocol
    );
}

#[test]
fn arbitrary_bounded_input_never_panics_or_recovers_after_failure() {
    let mut seed = 42u64;
    for length in 0..512 {
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect();
        let mut decoder = FrameDecoder::new(id());
        for chunk in bytes.chunks(7) {
            if decoder.push(chunk).is_err() {
                assert_eq!(
                    decoder.push(&packet(&body(0))).unwrap_err(),
                    Code::WorkerProtocol
                );
                break;
            }
        }
        let _ = decoder.finish();
    }
}

#[test]
fn encoder_matches_independent_header_and_round_trips_typed_frames() {
    use jocky_shared::collection::{Document, DocumentKind, decode};
    let Document::Worker(frame) = decode(DocumentKind::Worker, &body(0)).unwrap() else {
        unreachable!()
    };
    let encoded = protocol::encode_frame(&frame).unwrap();
    assert_eq!(
        u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
        encoded.len() - 4
    );
    let mut decoder = FrameDecoder::new(id());
    assert_eq!(
        decoder.push(&encoded).unwrap().1.as_ref(),
        Some(frame.as_ref())
    );
    let mut invalid = *frame;
    invalid.frame_seq = u64::MAX;
    assert_eq!(protocol::encode_frame(&invalid), Err(Code::WorkerProtocol));
}

#[test]
fn encoder_rejects_invalid_payloads_and_oversize_without_emitting_a_prefix() {
    use jocky_shared::collection::{
        Document, DocumentKind, decode,
        worker::{Body, Cancel, Chunk},
    };
    let Document::Worker(frame) = decode(DocumentKind::Worker, &body(0)).unwrap() else {
        unreachable!()
    };
    let mut frame = *frame;
    frame.body = Body::Cancel(Cancel {
        code: Code::NotRequested,
    });
    assert_eq!(protocol::encode_frame(&frame), Err(Code::WorkerProtocol));
    frame.body = Body::StartChunk(Chunk {
        offset: 0,
        data: "x".repeat(131073),
    });
    assert!(matches!(
        protocol::encode_frame(&frame),
        Err(Code::ResourceLimit | Code::WorkerProtocol)
    ));
}

#[cfg(unix)]
#[test]
fn owned_socket_pair_fragmentation_and_peer_loss_are_detected() {
    use std::{
        io::{Read, Write},
        net::Shutdown,
        os::unix::net::UnixStream,
        time::Duration,
    };
    for truncated in [false, true] {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        sender
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let bytes = packet(&body(0));
        let end = bytes.len() - usize::from(truncated);
        sender.write_all(&bytes[..end]).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        let mut decoder = FrameDecoder::new(id());
        let mut emitted = 0;
        let mut buffer = [0; 3];
        loop {
            let n = receiver.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            let (used, frame) = decoder.push(&buffer[..n]).unwrap();
            assert_eq!(used, n);
            emitted += usize::from(frame.is_some());
        }
        assert_eq!(emitted, usize::from(!truncated));
        assert_eq!(
            decoder.finish(),
            if truncated {
                Err(Code::WorkerProtocol)
            } else {
                Ok(())
            }
        );
    }
}

#[test]
fn record_limit_is_independent_of_frame_limit_and_nested_identity_must_match() {
    use jocky_forensic::collection::canonical;
    use serde_json::{Value, json};
    let mut record: Value = serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/forensic-record.json"
    ))
    .unwrap();
    record["payload"]["kernel_release"]["value"] = json!("a".repeat(60000));
    record["payload"]["kernel_version"]["value"] = json!("");
    let base = canonical::encode(&record, 131072).unwrap().len();
    for excess in [false, true] {
        record["payload"]["kernel_version"]["value"] =
            json!("b".repeat(98304 - base + usize::from(excess)));
        let raw = json!({"schema_version":"1.0.0","frame_seq":0,"collection_id":id(),"kind":"record","payload":record});
        let bytes = canonical::encode(&raw, 131072).unwrap();
        let mut decoder = FrameDecoder::new(id());
        let result = decoder.push(&packet(&bytes));
        assert_eq!(result.is_err(), excess);
        let frame = serde_json::from_value(raw).unwrap();
        assert_eq!(protocol::encode_frame(&frame).is_err(), excess);
    }
    record["payload"]["kernel_version"]["value"] = json!("");
    record["context"]["collection_id"] = json!("10000000-0000-4000-8000-000000000099");
    let raw = json!({"schema_version":"1.0.0","frame_seq":0,"collection_id":id(),"kind":"record","payload":record});
    let mut decoder = FrameDecoder::new(id());
    assert_eq!(
        decoder
            .push(&packet(&serde_json::to_vec(&raw).unwrap()))
            .unwrap_err(),
        Code::WorkerProtocol
    );
}
