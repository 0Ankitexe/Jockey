//! Pure launch/session binding; this test never spawns a worker or opens a source.
#[allow(dead_code)]
#[path = "../src/worker/mod.rs"]
mod worker;
use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::{ClockReading, admit_for_invocation, identity::digest};
use jocky_shared::collection::{
    Code,
    inputs::CollectionVersion,
    launch::{WorkerLaunch, decode_launch},
    outcomes::Collector,
    worker::{Body, Chunk, Commit, InputDescriptor, InputRole, Job, Ready, Start, WorkerFrame},
};
use worker::{
    order::Direction,
    protocol::encode_frame,
    session::{Receipt, Session},
};

fn setup() -> (WorkerLaunch, Vec<WorkerFrame>) {
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
    let mut launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    let bytes: Vec<u8> = docs.iter().flat_map(|(_, b)| b.iter().copied()).collect();
    let commit = Commit {
        byte_length: bytes.len() as u64,
        sha256: digest(&bytes).unwrap(),
    };
    let bodies = [
        Body::Start(Start::Collect {
            collector: Collector::System,
            inputs: docs
                .iter()
                .map(|(role, b)| InputDescriptor {
                    role: *role,
                    byte_length: b.len() as u64,
                    sha256: digest(b).unwrap(),
                })
                .collect(),
            input_byte_length: commit.byte_length,
            input_sha256: commit.sha256.clone(),
        }),
        Body::StartChunk(Chunk {
            offset: 0,
            data: STANDARD.encode(bytes),
        }),
        Body::StartCommit(commit),
    ];
    let frames: Vec<_> = bodies
        .into_iter()
        .enumerate()
        .map(|(n, body)| WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: n as u64,
            collection_id: launch.collection_id.clone(),
            body,
        })
        .collect();
    launch.start_sha256 = digest(&encode_frame(&frames[0]).unwrap()[4..]).unwrap();
    (launch, frames)
}
fn clock(launch: &WorkerLaunch, origin: bool) -> ClockReading {
    let pair = if origin {
        &launch.invocation_origin
    } else {
        &launch.launch_observed
    };
    ClockReading {
        utc: pair.utc.clone(),
        monotonic_ms: pair.monotonic_ms,
    }
}

#[test]
fn launch_binds_the_exact_start_and_original_admission_clock() {
    let (launch, frames) = setup();
    let mut session = Session::for_launch(&launch).unwrap();
    let mut input = None;
    for frame in &frames {
        if let Receipt::Inputs(bundle) = session.accept(Direction::Parent, frame).unwrap() {
            input = Some(bundle);
        }
    }
    let input = input.unwrap();
    let current = clock(&launch, false);
    let context =
        admit_for_invocation(input.inputs(), clock(&launch, true), current.clone()).unwrap();
    session
        .confirm_admission(&context, &current, false)
        .unwrap();
    let ready = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id,
        body: Body::Ready(Ready { job: Job::Collect }),
    };
    assert!(matches!(
        session.accept(Direction::Worker, &ready),
        Ok(Receipt::None)
    ));
}

#[test]
fn changed_start_or_job_never_reaches_input_transfer() {
    for mode in 0..2 {
        let (mut launch, frames) = setup();
        if mode == 0 {
            launch.start_sha256 = "0".repeat(64);
        } else {
            launch.job = Job::Publish;
            launch.descriptors[0].kind =
                jocky_shared::collection::launch::HandleKind::OutputDirectory;
            launch.descriptors[0].subject_id = None;
            launch.allowance.records = 0;
            launch.allowance.errors = 0;
            launch.allowance.source_bytes = 0;
            launch.allowance.entries = 0;
            launch.allowance.indicator_comparisons = 0;
        }
        let mut session = Session::for_launch(&launch).unwrap();
        assert!(matches!(
            session.accept(Direction::Parent, &frames[0]),
            Err(Code::WorkerProtocol)
        ));
    }
}

#[test]
fn fresh_worker_deadline_and_prelaunch_clock_cannot_confirm_admission() {
    for restarted in [true, false] {
        let (launch, frames) = setup();
        let mut session = Session::for_launch(&launch).unwrap();
        let mut input = None;
        for frame in &frames {
            if let Receipt::Inputs(bundle) = session.accept(Direction::Parent, frame).unwrap() {
                input = Some(bundle);
            }
        }
        let input = input.unwrap();
        let current = clock(&launch, false);
        let context = admit_for_invocation(
            input.inputs(),
            if restarted {
                current.clone()
            } else {
                clock(&launch, true)
            },
            current.clone(),
        )
        .unwrap();
        assert_eq!(
            session.confirm_admission(
                &context,
                &if restarted {
                    current
                } else {
                    clock(&launch, true)
                },
                false
            ),
            Err(if restarted {
                Code::WorkerProtocol
            } else {
                Code::ClockUncertain
            })
        );
    }
}

#[test]
fn narrowed_launch_progress_cannot_spend_the_global_request_quota() {
    let (mut launch, frames) = setup();
    launch.allowance.source_bytes = 1;
    let mut session = Session::for_launch(&launch).unwrap();
    let mut input = None;
    for frame in &frames {
        if let Receipt::Inputs(bundle) = session.accept(Direction::Parent, frame).unwrap() {
            input = Some(bundle);
        }
    }
    let input = input.unwrap();
    let current = clock(&launch, false);
    let context =
        admit_for_invocation(input.inputs(), clock(&launch, true), current.clone()).unwrap();
    session
        .confirm_admission(&context, &current, false)
        .unwrap();
    let mut frame = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Ready(Ready { job: Job::Collect }),
    };
    session.accept(Direction::Worker, &frame).unwrap();
    frame.frame_seq = 1;
    frame.body = Body::Progress(jocky_shared::collection::outcomes::WorkUsed {
        entries: 0,
        indicator_comparisons: 0,
        errors: 0,
        source_bytes: 2,
        staging_bytes: 0,
        retained_bytes: 0,
    });
    assert!(matches!(
        session.accept(Direction::Worker, &frame),
        Err(Code::WorkerProtocol)
    ));
}

#[test]
fn collect_launch_requires_one_retained_config_identity_per_input() {
    let (mut launch, frames) = setup();
    launch
        .config_exclusions
        .push(jocky_shared::collection::launch::ObjectIdentity {
            device_id: "1".into(),
            inode: "15".into(),
            mount_id: Some("1".into()),
        });
    let mut session = Session::for_launch(&launch).unwrap();
    assert!(matches!(
        session.accept(Direction::Parent, &frames[0]),
        Err(Code::WorkerProtocol)
    ));
}

#[test]
fn publisher_start_must_select_its_sole_bound_output_descriptor() {
    use jocky_shared::collection::launch::HandleKind;
    let (mut launch, _) = setup();
    launch.job = Job::Publish;
    launch.descriptors[0].kind = HandleKind::OutputDirectory;
    launch.descriptors[0].subject_id = None;
    launch.allowance.records = 0;
    launch.allowance.errors = 0;
    launch.allowance.source_bytes = 0;
    launch.allowance.entries = 0;
    launch.allowance.indicator_comparisons = 0;
    let report: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../fixtures/valid/collection/report.json"
    ))
    .unwrap();
    let context = serde_json::from_value(report["context"].clone()).unwrap();
    let frame = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Publish {
            context,
            output_descriptor: 4,
            output_name: "report.json".into(),
            report_byte_length: 2,
            report_sha256: digest(b"{}").unwrap(),
        }),
    };
    launch.start_sha256 = digest(&encode_frame(&frame).unwrap()[4..]).unwrap();
    let mut session = Session::for_launch(&launch).unwrap();
    assert!(matches!(
        session.accept(Direction::Parent, &frame),
        Err(Code::WorkerProtocol)
    ));
}
