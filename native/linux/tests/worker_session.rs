#[allow(dead_code)]
#[path = "../src/worker/mod.rs"]
mod worker;
use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::identity::digest;
use jocky_shared::collection::{
    Code,
    identity::Uuid,
    inputs::{CollectionVersion, Limits},
    outcomes::Collector,
    records::LocalContext,
    worker::{
        Body, Chunk, Commit, Done, InputDescriptor, InputRole, Job, Ready, Start, WorkerFrame,
    },
};
use worker::{
    order::Direction,
    session::{Receipt, Session},
};

struct Frozen(jocky_forensic::collection::ClockReading);
impl jocky_forensic::collection::clock::Clock for Frozen {
    fn read(&mut self) -> Result<jocky_forensic::collection::ClockReading, Code> {
        Ok(self.0.clone())
    }
}

fn id() -> Uuid {
    Uuid::parse("10000000-0000-4000-8000-000000000007").unwrap()
}
fn limits() -> Limits {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/request.json"
    ))
    .unwrap();
    serde_json::from_value(v["limits"].clone()).unwrap()
}
fn frame(seq: u64, body: Body) -> WorkerFrame {
    WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: seq,
        collection_id: id(),
        body,
    }
}
fn input() -> (Start, Vec<u8>, Commit) {
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
    let descriptors = docs
        .iter()
        .map(|(role, bytes)| InputDescriptor {
            role: *role,
            byte_length: bytes.len() as u64,
            sha256: digest(bytes).unwrap(),
        })
        .collect();
    let bytes: Vec<u8> = docs
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    let commit = Commit {
        byte_length: bytes.len() as u64,
        sha256: digest(&bytes).unwrap(),
    };
    (
        Start::Collect {
            collector: Collector::System,
            inputs: descriptors,
            input_byte_length: commit.byte_length,
            input_sha256: commit.sha256.clone(),
        },
        bytes,
        commit,
    )
}
fn committed() -> (Session, Box<worker::inputs::VerifiedInputs>) {
    let (start, bytes, commit) = input();
    let mut session = Session::new(id(), limits());
    session
        .accept(Direction::Parent, &frame(0, Body::Start(start)))
        .unwrap();
    session
        .accept(
            Direction::Parent,
            &frame(
                1,
                Body::StartChunk(Chunk {
                    offset: 0,
                    data: STANDARD.encode(bytes),
                }),
            ),
        )
        .unwrap();
    let Receipt::Inputs(input) = session
        .accept(Direction::Parent, &frame(2, Body::StartCommit(commit)))
        .unwrap()
    else {
        panic!("input receipt required");
    };
    (session, input)
}
fn active() -> Session {
    let (mut session, input) = committed();
    let now = jocky_forensic::collection::ClockReading {
        utc: jocky_shared::collection::identity::UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        monotonic_ms: 0,
    };
    let context = jocky_forensic::collection::admit(input.inputs(), now.clone()).unwrap();
    session.confirm_admission(&context, &now, false).unwrap();
    session
        .accept(
            Direction::Worker,
            &frame(0, Body::Ready(Ready { job: Job::Collect })),
        )
        .unwrap();
    session
}

#[cfg(target_os = "linux")]
#[test]
fn committed_start_requires_digest_original_clock_and_selected_handle_purpose() {
    use jocky_forensic::collection::budget::Counter;
    use jocky_shared::collection::{identity::UtcTime, launch::decode_launch};
    use std::io::Cursor;
    let (start, bytes, commit) = input();
    let start_frame = frame(0, Body::Start(start));
    let mut launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    let encoded = worker::protocol::encode_frame(&start_frame).unwrap();
    launch.start_sha256 = digest(&encoded[4..]).unwrap();
    let mut stream = encoded;
    stream.extend(
        worker::protocol::encode_frame(&frame(
            1,
            Body::StartChunk(Chunk {
                offset: 0,
                data: STANDARD.encode(&bytes),
            }),
        ))
        .unwrap(),
    );
    stream.extend(worker::protocol::encode_frame(&frame(2, Body::StartCommit(commit))).unwrap());
    let valid_clock = jocky_forensic::collection::ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        monotonic_ms: 11_000,
    };
    let mut admitted = worker::start::receive_committed(
        &mut Cursor::new(&stream),
        &launch,
        &mut Frozen(valid_clock.clone()),
    )
    .unwrap();
    assert_eq!(admitted.collector, Collector::System);
    assert_eq!(admitted.context.charged(Counter::SourceBytes), Ok(0));
    admitted
        .session
        .accept(
            Direction::Worker,
            &frame(0, Body::Ready(Ready { job: Job::Collect })),
        )
        .unwrap();
    assert_eq!(admitted.decoder.finish(), Ok(()));

    let mut bad_digest = launch.clone();
    bad_digest.start_sha256 = "0".repeat(64);
    assert!(matches!(
        worker::start::receive_committed(
            &mut Cursor::new(&stream),
            &bad_digest,
            &mut Frozen(valid_clock.clone()),
        ),
        Err(Code::WorkerProtocol)
    ));
    let mut wrong_purpose = launch.clone();
    wrong_purpose.descriptors[0].kind = jocky_shared::collection::launch::HandleKind::SysMount;
    assert!(matches!(
        worker::start::receive_committed(
            &mut Cursor::new(&stream),
            &wrong_purpose,
            &mut Frozen(valid_clock.clone()),
        ),
        Err(Code::ScopeDenied)
    ));
    let expired = jocky_forensic::collection::ClockReading {
        utc: UtcTime::parse("2020-01-01T01:00:00Z").unwrap(),
        monotonic_ms: 3_601_000,
    };
    assert!(matches!(
        worker::start::receive_committed(&mut Cursor::new(&stream), &launch, &mut Frozen(expired)),
        Err(Code::AuthorisationExpired | Code::Timeout)
    ));

    struct Advancing {
        reads: usize,
    }
    impl jocky_forensic::collection::clock::Clock for Advancing {
        fn read(&mut self) -> Result<jocky_forensic::collection::ClockReading, Code> {
            self.reads += 1;
            Ok(jocky_forensic::collection::ClockReading {
                utc: UtcTime::parse(if self.reads == 1 {
                    "2020-01-01T00:00:10Z"
                } else {
                    "2020-01-01T00:01:00Z"
                })
                .unwrap(),
                monotonic_ms: if self.reads == 1 { 11_000 } else { 61_000 },
            })
        }
    }
    let mut cursor = Cursor::new(&stream);
    assert!(matches!(
        worker::start::receive_committed(&mut cursor, &launch, &mut Advancing { reads: 0 }),
        Err(Code::Timeout)
    ));
    assert!((cursor.position() as usize) < stream.len());

    struct Rollback(bool);
    impl jocky_forensic::collection::clock::Clock for Rollback {
        fn read(&mut self) -> Result<jocky_forensic::collection::ClockReading, Code> {
            let first = !self.0;
            self.0 = true;
            Ok(jocky_forensic::collection::ClockReading {
                utc: UtcTime::parse(if first {
                    "2020-01-01T00:00:20Z"
                } else {
                    "2020-01-01T00:00:10Z"
                })
                .unwrap(),
                monotonic_ms: if first { 21_000 } else { 11_000 },
            })
        }
    }
    let mut cursor = Cursor::new(&stream);
    assert!(matches!(
        worker::start::receive_committed(&mut cursor, &launch, &mut Rollback(false)),
        Err(Code::ClockUncertain)
    ));
    assert!((cursor.position() as usize) < stream.len());
}

#[test]
fn input_integrity_alone_cannot_admit_a_ready_collecting_worker() {
    let (mut session, _) = committed();
    assert!(matches!(
        session.accept(
            Direction::Worker,
            &frame(0, Body::Ready(Ready { job: Job::Collect }))
        ),
        Err(Code::WorkerProtocol)
    ));
}

#[test]
fn admission_failure_can_terminate_committed_inputs_without_ready_or_evidence() {
    let (mut session, _) = committed();
    let mut body = collect_done();
    if let Body::Done(Done::Collect { outcome, .. }) = &mut body {
        outcome.status = jocky_shared::collection::outcomes::CollectorStatus::Failed;
        outcome.stop_reason = Some(Code::AuthorisationExpired);
        outcome.omitted_reason = Some(Code::AuthorisationExpired);
    }
    assert!(matches!(
        session.accept(Direction::Worker, &frame(0, body)),
        Ok(Receipt::Done(Some(_)))
    ));
    assert_eq!(session.finish(), Ok(()));
}

#[test]
fn publisher_can_report_preflight_failure_but_not_premature_success() {
    let start = Start::Publish {
        context: record().context,
        output_descriptor: 3,
        output_name: "report.json".into(),
        report_byte_length: 1,
        report_sha256: "0".repeat(64),
    };
    for success in [false, true] {
        let mut session = Session::new(id(), limits());
        session
            .accept(Direction::Parent, &frame(0, Body::Start(start.clone())))
            .unwrap();
        let body = Body::Done(Done::Publish {
            code: if success {
                jocky_shared::collection::report::StatusCode::Success(
                    jocky_shared::collection::report::SuccessCode::PublishedComplete,
                )
            } else {
                jocky_shared::collection::report::StatusCode::Error(Code::PublicationFailed)
            },
            sha256: None,
            byte_length: None,
            created_identity: None,
        });
        let result = session.accept(Direction::Worker, &frame(0, body));
        if success {
            assert!(matches!(result, Err(Code::WorkerProtocol)));
        } else {
            assert!(matches!(result, Ok(Receipt::Done(None))));
            assert_eq!(session.finish(), Ok(()));
        }
    }
}

#[test]
fn admission_confirmation_is_current_one_shot_and_matches_all_input_digests() {
    use jocky_forensic::collection::{ClockReading, InputSet, admit};
    use jocky_shared::collection::identity::UtcTime;
    let now = ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
        monotonic_ms: 0,
    };
    for mode in 0..3 {
        let (mut session, bundle) = committed();
        let original = bundle.inputs();
        let mut policy: serde_json::Value = serde_json::from_slice(original.policy).unwrap();
        if mode == 0 {
            policy["valid_until"] = serde_json::json!("2020-01-01T00:30:00Z");
        }
        let policy = serde_json::to_vec(&policy).unwrap();
        let context = admit(
            InputSet {
                policy: &policy,
                ..original
            },
            now.clone(),
        )
        .unwrap();
        let at = if mode == 1 {
            ClockReading {
                utc: UtcTime::parse("2026-10-11T00:00:00Z").unwrap(),
                monotonic_ms: 1,
            }
        } else {
            now.clone()
        };
        let expected = match mode {
            0 => Code::WorkerProtocol,
            1 => Code::AuthorisationExpired,
            _ => Code::Cancelled,
        };
        assert_eq!(
            session.confirm_admission(&context, &at, mode == 2),
            Err(expected)
        );
        assert!(
            session
                .accept(
                    Direction::Worker,
                    &frame(0, Body::Ready(Ready { job: Job::Collect }))
                )
                .is_err()
        );
    }
    let (mut session, bundle) = committed();
    let context = admit(bundle.inputs(), now.clone()).unwrap();
    session.confirm_admission(&context, &now, false).unwrap();
    assert_eq!(
        session.confirm_admission(&context, &now, false),
        Err(Code::WorkerProtocol)
    );
}
fn collect_done() -> Body {
    let usage = serde_json::from_value(serde_json::json!({"entries":0,"indicator_comparisons":0,"errors":0,"source_bytes":0,"staging_bytes":0,"retained_bytes":0})).unwrap();
    Body::Done(Done::Collect {
        outcome: jocky_forensic::collection::outcome::unsupported(Collector::System),
        usage,
    })
}

#[test]
fn integrated_collect_transfer_and_terminal_failure_are_validated() {
    let mut session = active();
    assert!(matches!(
        session.accept(Direction::Worker, &frame(1, collect_done())),
        Ok(Receipt::Done(Some(_)))
    ));
    assert_eq!(session.finish(), Ok(()));
}

#[test]
fn corrupt_commit_never_reaches_ready_or_inputs_receipt() {
    let (start, bytes, mut commit) = input();
    commit.sha256 = "0".repeat(64);
    let mut session = Session::new(id(), limits());
    session
        .accept(Direction::Parent, &frame(0, Body::Start(start)))
        .unwrap();
    session
        .accept(
            Direction::Parent,
            &frame(
                1,
                Body::StartChunk(Chunk {
                    offset: 0,
                    data: STANDARD.encode(bytes),
                }),
            ),
        )
        .unwrap();
    assert!(matches!(
        session.accept(Direction::Parent, &frame(2, Body::StartCommit(commit))),
        Err(Code::WorkerProtocol)
    ));
    assert!(
        session
            .accept(
                Direction::Worker,
                &frame(0, Body::Ready(Ready { job: Job::Collect }))
            )
            .is_err()
    );
}

#[test]
fn each_direction_has_its_own_sequence_and_collection_binding() {
    let mut session = active();
    assert!(matches!(
        session.accept(Direction::Worker, &frame(0, collect_done())),
        Err(Code::WorkerProtocol)
    ));
    let mut wrong = frame(1, collect_done());
    wrong.collection_id = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap();
    assert!(matches!(
        active().accept(Direction::Worker, &wrong),
        Err(Code::WorkerProtocol)
    ));
}

#[test]
fn done_cannot_invent_records_errors_or_another_collector() {
    for mutation in 0..3 {
        let mut body = collect_done();
        if let Body::Done(Done::Collect { outcome, .. }) = &mut body {
            match mutation {
                0 => outcome.accepted_records = 1,
                1 => outcome.errors = 1,
                _ => outcome.collector = Collector::Files,
            }
        }
        assert!(matches!(
            active().accept(Direction::Worker, &frame(1, body)),
            Err(Code::WorkerProtocol)
        ));
    }
}

fn publish() -> (Session, Vec<u8>, Commit) {
    let raw = include_bytes!("../../../fixtures/valid/collection/report.json").to_vec();
    // The stored JSON fixture is pretty printed; generate the canonical report
    // through the tested finalizer before transport. Still explicitly synthetic.
    let report = serde_json::from_slice(&raw).unwrap();
    let raw = jocky_forensic::collection::report::finalize(report, 10485760).unwrap();
    let report: jocky_shared::collection::report::CollectionReport =
        serde_json::from_slice(&raw).unwrap();
    let context: LocalContext = report.context;
    let commit = Commit {
        byte_length: raw.len() as u64,
        sha256: digest(&raw).unwrap(),
    };
    let mut session = Session::new(id(), limits());
    session
        .accept(
            Direction::Parent,
            &frame(
                0,
                Body::Start(Start::Publish {
                    context,
                    output_descriptor: 3,
                    output_name: "report.json".into(),
                    report_byte_length: commit.byte_length,
                    report_sha256: commit.sha256.clone(),
                }),
            ),
        )
        .unwrap();
    session
        .accept(
            Direction::Worker,
            &frame(0, Body::Ready(Ready { job: Job::Publish })),
        )
        .unwrap();
    (session, raw, commit)
}

#[test]
fn publication_requires_verified_report_and_exact_acknowledgement() {
    let (mut session, raw, commit) = publish();
    session
        .accept(
            Direction::Parent,
            &frame(
                1,
                Body::PublishChunk(Chunk {
                    offset: 0,
                    data: STANDARD.encode(&raw),
                }),
            ),
        )
        .unwrap();
    assert!(
        matches!(session.accept(Direction::Parent,&frame(2,Body::PublishCommit(commit.clone()))),Ok(Receipt::Report(bytes)) if bytes == raw)
    );
    let body = Body::Done(Done::Publish {
        code: jocky_shared::collection::report::StatusCode::Success(
            jocky_shared::collection::report::SuccessCode::PublishedComplete,
        ),
        sha256: Some(commit.sha256),
        byte_length: Some(commit.byte_length),
        created_identity: Some(jocky_shared::collection::worker::CreatedIdentity {
            device_id: "1".into(),
            inode: "2".into(),
        }),
    });
    assert!(matches!(
        session.accept(Direction::Worker, &frame(1, body)),
        Ok(Receipt::Done(None))
    ));
    assert_eq!(session.finish(), Ok(()));
}

#[test]
fn syntactically_valid_but_non_report_bytes_never_become_publication_input() {
    let record: jocky_shared::collection::records::ForensicRecord = serde_json::from_str(
        include_str!("../../../fixtures/valid/collection/forensic-record.json"),
    )
    .unwrap();
    let commit = Commit {
        byte_length: 3,
        sha256: digest(b"{}\n").unwrap(),
    };
    let mut session = Session::new(id(), limits());
    session
        .accept(
            Direction::Parent,
            &frame(
                0,
                Body::Start(Start::Publish {
                    context: record.context,
                    output_descriptor: 3,
                    output_name: "report.json".into(),
                    report_byte_length: commit.byte_length,
                    report_sha256: commit.sha256.clone(),
                }),
            ),
        )
        .unwrap();
    session
        .accept(
            Direction::Worker,
            &frame(0, Body::Ready(Ready { job: Job::Publish })),
        )
        .unwrap();
    session
        .accept(
            Direction::Parent,
            &frame(
                1,
                Body::PublishChunk(Chunk {
                    offset: 0,
                    data: STANDARD.encode(b"{}\n"),
                }),
            ),
        )
        .unwrap();
    assert!(matches!(
        session.accept(Direction::Parent, &frame(2, Body::PublishCommit(commit))),
        Err(Code::WorkerProtocol)
    ));
}

fn record() -> jocky_shared::collection::records::ForensicRecord {
    serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/forensic-record.json"
    ))
    .unwrap()
}
#[test]
fn record_identity_context_digest_and_singleton_are_bound_to_session() {
    let mut session = active();
    session
        .accept(
            Direction::Worker,
            &frame(1, Body::Record(Box::new(record()))),
        )
        .unwrap();
    assert!(matches!(
        session.accept(
            Direction::Worker,
            &frame(2, Body::Record(Box::new(record())))
        ),
        Err(Code::WorkerProtocol)
    ));
    for mutation in 0..4 {
        let mut record = record();
        match mutation {
            0 => record.sequence = 1,
            1 => {
                record.context.case_id =
                    Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap()
            }
            2 => record.content_sha256 = "0".repeat(64),
            _ => record.record_id = Uuid::parse("10000000-0000-4000-8000-000000000099").unwrap(),
        }
        assert!(matches!(
            active().accept(Direction::Worker, &frame(1, Body::Record(Box::new(record)))),
            Err(Code::WorkerProtocol)
        ));
    }
}

#[test]
fn record_counts_cannot_be_hidden_by_zero_done_or_complete_omissions() {
    let mut session = active();
    session
        .accept(
            Direction::Worker,
            &frame(1, Body::Record(Box::new(record()))),
        )
        .unwrap();
    assert!(matches!(
        session.accept(Direction::Worker, &frame(2, collect_done())),
        Err(Code::WorkerProtocol)
    ));
}

#[test]
fn publication_acknowledgement_cannot_change_hash_length_or_hide_identity() {
    for mutation in 0..3 {
        let (mut session, raw, commit) = publish();
        session
            .accept(
                Direction::Parent,
                &frame(
                    1,
                    Body::PublishChunk(Chunk {
                        offset: 0,
                        data: STANDARD.encode(raw),
                    }),
                ),
            )
            .unwrap();
        session
            .accept(
                Direction::Parent,
                &frame(2, Body::PublishCommit(commit.clone())),
            )
            .unwrap();
        let mut body = Done::Publish {
            code: jocky_shared::collection::report::StatusCode::Success(
                jocky_shared::collection::report::SuccessCode::PublishedComplete,
            ),
            sha256: Some(commit.sha256),
            byte_length: Some(commit.byte_length),
            created_identity: Some(jocky_shared::collection::worker::CreatedIdentity {
                device_id: "1".into(),
                inode: "2".into(),
            }),
        };
        if let Done::Publish {
            sha256,
            byte_length,
            created_identity,
            ..
        } = &mut body
        {
            match mutation {
                0 => *sha256 = Some("0".repeat(64)),
                1 => *byte_length = Some(1),
                _ => *created_identity = None,
            }
        }
        assert!(matches!(
            session.accept(Direction::Worker, &frame(1, Body::Done(body))),
            Err(Code::WorkerProtocol)
        ));
    }
}
