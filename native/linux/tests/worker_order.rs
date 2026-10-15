#[path = "../src/worker/order.rs"]
mod order;
use jocky_shared::collection::{
    Code,
    outcomes::Collector,
    worker::{Body, Cancel, Chunk, Commit, Done, Job, Ready, Start},
};
use order::{Direction, JobOrder};

// Order tests deliberately isolate message ordering from the existing schema,
// byte-transfer and authority tests. These bodies are not execution permits.
fn start() -> Body {
    Body::Start(Start::Collect {
        collector: Collector::System,
        inputs: vec![],
        input_byte_length: 1,
        input_sha256: "0".repeat(64),
    })
}
fn chunk() -> Body {
    Body::StartChunk(Chunk {
        offset: 0,
        data: "AA==".into(),
    })
}
fn commit() -> Body {
    Body::StartCommit(Commit {
        byte_length: 1,
        sha256: "0".repeat(64),
    })
}
fn ready() -> Body {
    Body::Ready(Ready { job: Job::Collect })
}
fn done() -> Body {
    Body::Done(Done::Collect {
        outcome: jocky_forensic::collection::outcome::unsupported(Collector::System),
        usage: serde_json::from_str(r#"{"entries":0,"indicator_comparisons":0,"errors":0,"source_bytes":0,"staging_bytes":0,"retained_bytes":0}"#).unwrap(),
    })
}
fn active() -> JobOrder {
    let mut order = JobOrder::new();
    for body in [start(), chunk(), commit()] {
        order.accept(Direction::Parent, &body).unwrap();
    }
    order.accept(Direction::Worker, &ready()).unwrap();
    order
}

#[test]
fn collect_requires_commit_then_ready_then_one_done() {
    let mut order = active();
    order.accept(Direction::Worker, &done()).unwrap();
    assert_eq!(order.finish(), Ok(()));
    assert_eq!(
        order.accept(Direction::Worker, &done()),
        Err(Code::WorkerProtocol)
    );
}

#[test]
fn admission_window_exists_only_after_commit_and_before_ready_or_cancel() {
    let mut order = JobOrder::new();
    assert!(!order.awaiting_admission());
    order.accept(Direction::Parent, &start()).unwrap();
    order.accept(Direction::Parent, &chunk()).unwrap();
    assert!(!order.awaiting_admission());
    order.accept(Direction::Parent, &commit()).unwrap();
    assert!(order.awaiting_admission());
    order
        .accept(
            Direction::Parent,
            &Body::Cancel(Cancel {
                code: Code::Cancelled,
            }),
        )
        .unwrap();
    assert!(!order.awaiting_admission());
    assert!(!active().awaiting_admission());
}

#[test]
fn incomplete_stream_never_means_success() {
    for count in 0..4 {
        let mut order = JobOrder::new();
        let messages = [
            (Direction::Parent, start()),
            (Direction::Parent, chunk()),
            (Direction::Parent, commit()),
            (Direction::Worker, ready()),
        ];
        for (side, body) in messages.iter().take(count) {
            order.accept(*side, body).unwrap();
        }
        assert_eq!(order.finish(), Err(Code::WorkerFailed));
        assert_eq!(
            order.accept(Direction::Parent, &start()),
            Err(Code::WorkerProtocol)
        );
    }
    assert_eq!(active().finish(), Err(Code::WorkerFailed));
}

#[test]
fn wrong_direction_early_ready_and_early_done_poison_session() {
    for (side, body) in [
        (Direction::Worker, start()),
        (Direction::Worker, ready()),
        (Direction::Worker, done()),
        (Direction::Parent, chunk()),
        (Direction::Parent, commit()),
    ] {
        let mut order = JobOrder::new();
        assert_eq!(order.accept(side, &body), Err(Code::WorkerProtocol));
        assert_eq!(
            order.accept(Direction::Parent, &start()),
            Err(Code::WorkerProtocol)
        );
    }
    for body in [ready(), done()] {
        let mut order = JobOrder::new();
        order.accept(Direction::Parent, &start()).unwrap();
        assert_eq!(
            order.accept(Direction::Worker, &body),
            Err(Code::WorkerProtocol)
        );
    }
}

#[test]
fn no_restart_duplicate_ready_or_input_after_commit() {
    for (side, body) in [
        (Direction::Parent, start()),
        (Direction::Parent, chunk()),
        (Direction::Parent, commit()),
        (Direction::Worker, ready()),
        (Direction::Parent, done()),
    ] {
        assert_eq!(active().accept(side, &body), Err(Code::WorkerProtocol));
    }
}

#[test]
fn cancellation_blocks_new_input_but_allows_terminal_reply() {
    let cancel = Body::Cancel(Cancel {
        code: Code::Cancelled,
    });
    let mut order = active();
    order.accept(Direction::Parent, &cancel).unwrap();
    order.accept(Direction::Worker, &done()).unwrap();
    assert_eq!(order.finish(), Ok(()));
    let mut order = active();
    order.accept(Direction::Parent, &cancel).unwrap();
    assert_eq!(
        order.accept(Direction::Parent, &cancel),
        Err(Code::WorkerProtocol)
    );
    assert_eq!(
        active().accept(Direction::Worker, &cancel),
        Err(Code::WorkerProtocol)
    );
}

#[test]
fn ready_and_done_must_match_job() {
    let mut order = JobOrder::new();
    order.accept(Direction::Parent, &start()).unwrap();
    order.accept(Direction::Parent, &chunk()).unwrap();
    order.accept(Direction::Parent, &commit()).unwrap();
    assert_eq!(
        order.accept(Direction::Worker, &Body::Ready(Ready { job: Job::Publish })),
        Err(Code::WorkerProtocol)
    );
    let body = Body::Done(Done::Publish {
        code: jocky_shared::collection::report::StatusCode::Error(Code::PublicationFailed),
        sha256: None,
        byte_length: None,
        created_identity: None,
    });
    assert_eq!(
        active().accept(Direction::Worker, &body),
        Err(Code::WorkerProtocol)
    );
}

fn publish_start() -> Body {
    let record: jocky_shared::collection::records::ForensicRecord = serde_json::from_str(
        include_str!("../../../fixtures/valid/collection/forensic-record.json"),
    )
    .unwrap();
    Body::Start(Start::Publish {
        context: record.context,
        output_descriptor: 3,
        output_name: "report.json".into(),
        report_byte_length: 1,
        report_sha256: "0".repeat(64),
    })
}
fn publish_done() -> Body {
    Body::Done(Done::Publish {
        code: jocky_shared::collection::report::StatusCode::Error(Code::PublicationFailed),
        sha256: None,
        byte_length: None,
        created_identity: None,
    })
}

#[test]
fn publication_requires_ready_and_committed_report_before_done() {
    let success = Body::Done(Done::Publish {
        code: jocky_shared::collection::report::StatusCode::Success(
            jocky_shared::collection::report::SuccessCode::PublishedComplete,
        ),
        sha256: Some("0".repeat(64)),
        byte_length: Some(1),
        created_identity: Some(jocky_shared::collection::worker::CreatedIdentity {
            device_id: "1".into(),
            inode: "1".into(),
        }),
    });
    let sequence = [
        (Direction::Parent, publish_start()),
        (Direction::Worker, Body::Ready(Ready { job: Job::Publish })),
        (
            Direction::Parent,
            Body::PublishChunk(Chunk {
                offset: 0,
                data: "AA==".into(),
            }),
        ),
        (
            Direction::Parent,
            Body::PublishCommit(Commit {
                byte_length: 1,
                sha256: "0".repeat(64),
            }),
        ),
        (Direction::Worker, success),
    ];
    let mut order = JobOrder::new();
    for (side, body) in &sequence {
        order.accept(*side, body).unwrap();
    }
    // Ordering completion still requires independent publication verification.
    assert_eq!(order.finish(), Ok(()));
    for skip in 0..sequence.len() - 1 {
        let mut order = JobOrder::new();
        assert!(
            sequence
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .try_for_each(|(_, (side, body))| order.accept(*side, body))
                .is_err()
        );
    }
}

#[test]
fn schema_valid_transport_messages_still_require_valid_order() {
    #[allow(dead_code)]
    #[path = "../src/worker/protocol.rs"]
    mod protocol;
    let frame: jocky_shared::collection::worker::WorkerFrame = serde_json::from_str(include_str!(
        "../../../fixtures/valid/collection/worker.json"
    ))
    .unwrap();
    let packet = protocol::encode_frame(&frame).unwrap();
    let mut decoder = protocol::FrameDecoder::new(frame.collection_id.clone());
    let (_, decoded) = decoder.push(&packet).unwrap();
    assert_eq!(decoder.finish(), Ok(()));
    assert_eq!(
        JobOrder::new().accept(Direction::Parent, &decoded.unwrap().body),
        Err(Code::WorkerProtocol)
    );
}

#[test]
fn cancelling_an_incomplete_transfer_allows_only_terminal_worker_reply() {
    let cancel = Body::Cancel(Cancel {
        code: Code::Timeout,
    });
    for first in [start(), publish_start()] {
        let mut order = JobOrder::new();
        let last = if matches!(&first, Body::Start(Start::Collect { .. })) {
            done()
        } else {
            publish_done()
        };
        order.accept(Direction::Parent, &first).unwrap();
        order.accept(Direction::Parent, &cancel).unwrap();
        order.accept(Direction::Worker, &last).unwrap();
        assert_eq!(order.finish(), Ok(()));
    }
}
