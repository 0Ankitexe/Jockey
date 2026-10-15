//! Product-binary worker handshake on synthetic documents only. No evidence
//! descriptor is transferred and no source is read by this test.
#![cfg(target_os = "linux")]
#[path = "../src/cli/mod.rs"]
#[allow(dead_code)]
mod cli;
use cli::clock;
#[path = "../src/collection.rs"]
#[allow(dead_code)]
mod collection;
#[path = "../src/collectors/mod.rs"]
#[allow(dead_code)]
mod collectors;
#[path = "../src/sources/mod.rs"]
#[allow(dead_code)]
mod sources;
#[path = "support/confinement.rs"]
#[allow(dead_code)]
mod support;
#[path = "../src/worker/mod.rs"]
#[allow(dead_code)]
mod worker;
use worker::{handles, peer, protocol};

use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::{InputSet, admit, identity::digest, report};
use jocky_shared::collection::{
    inputs::CollectionVersion,
    launch::{ClockPair, DescriptorBinding, HandleKind, ObjectIdentity, decode_launch},
    outcomes::{Collector, CollectorStatus},
    report::{ReportKind, StatusCode, SuccessCode, WorkerCleanup},
    worker::{Body, Chunk, Commit, Done, InputDescriptor, InputRole, Job, Start, WorkerFrame},
};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    process::{Command, Stdio},
};

fn synthetic_docs() -> Vec<(InputRole, Vec<u8>)> {
    let now = clock::read().unwrap().utc.unix_nanos() / 1_000_000_000;
    let before = clock::unix_utc((now - 3600) as i64).unwrap();
    let after = clock::unix_utc((now + 3600) as i64).unwrap();
    let source = [
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
    source
        .into_iter()
        .map(|(role, raw)| {
            let mut document: serde_json::Value = serde_json::from_slice(raw).unwrap();
            if document.get("valid_from").is_some() {
                document["valid_from"] = before.as_str().into();
                document["valid_until"] = after.as_str().into();
            }
            if document.get("scope").is_some() {
                document["scope"]["event_window"]["start"] = before.as_str().into();
                document["scope"]["event_window"]["end"] = after.as_str().into();
            }
            if document.get("event_window").is_some() {
                document["event_window"]["start"] = before.as_str().into();
                document["event_window"]["end"] = after.as_str().into();
            }
            (role, serde_json::to_vec(&document).unwrap())
        })
        .collect()
}

#[path = "support/joined_pipeline.rs"]
mod joined_pipeline;

#[test]
fn sequential_product_children_publish_a_verified_failed_report() {
    joined_pipeline::exercise_joined_pipeline();
}

#[test]
fn sequential_product_children_publish_a_verified_partial_file_report() {
    joined_pipeline::exercise_partial_file_report();
}

#[test]
fn injected_profile_is_published_by_the_product_binary_as_complete() {
    joined_pipeline::exercise_injected_complete_profile();
}

#[test]
fn lost_collector_still_publishes_a_charged_failed_report() {
    joined_pipeline::exercise_lost_worker_report();
}

#[test]
fn parent_supervisor_drives_and_reaps_product_collect_child() {
    let docs = synthetic_docs();
    let descriptors = docs
        .iter()
        .map(|(role, bytes)| InputDescriptor {
            role: *role,
            byte_length: bytes.len() as u64,
            sha256: digest(bytes).unwrap(),
        })
        .collect();
    let joined: Vec<u8> = docs
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    let commit = Commit {
        byte_length: joined.len() as u64,
        sha256: digest(&joined).unwrap(),
    };
    let mut launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.parent = worker::peer::own_identity().unwrap();
    launch.descriptors.clear();
    let now = clock::read().unwrap();
    let pair = ClockPair {
        utc: now.utc,
        monotonic_ms: now.monotonic_ms,
    };
    launch.invocation_origin = pair.clone();
    launch.launch_observed = pair;
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Collect {
            collector: Collector::System,
            inputs: descriptors,
            input_byte_length: commit.byte_length,
            input_sha256: commit.sha256.clone(),
        }),
    };
    let start_packet = worker::protocol::encode_frame(&start).unwrap();
    launch.start_sha256 = digest(&start_packet[4..]).unwrap();
    let frames = [
        start,
        WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 1,
            collection_id: launch.collection_id.clone(),
            body: Body::StartChunk(Chunk {
                offset: 0,
                data: STANDARD.encode(&joined),
            }),
        },
        WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 2,
            collection_id: launch.collection_id.clone(),
            body: Body::StartCommit(commit),
        },
    ];
    let mut ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let mut native_clock = clock::read;
    struct ClockFn<F>(F);
    impl<
        F: FnMut() -> Result<jocky_forensic::collection::ClockReading, jocky_shared::collection::Code>,
    > jocky_forensic::collection::clock::Clock for ClockFn<F>
    {
        fn read(
            &mut self,
        ) -> Result<jocky_forensic::collection::ClockReading, jocky_shared::collection::Code>
        {
            self.0()
        }
    }
    let done = worker::supervisor::collect_with(
        &launch,
        &frames,
        &[],
        &mut ledger,
        &mut ClockFn(&mut native_clock),
        |_| panic!("unsupported child must emit no observation"),
        || false,
        || {
            let (parent, child) = UnixStream::pair().unwrap();
            parent
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            parent
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let child_out = child.try_clone().unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
                .arg("__worker")
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::from(OwnedFd::from(child)))
                .stdout(Stdio::from(OwnedFd::from(child_out)))
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Ok(worker::spawn::Spawned {
                child,
                channel: parent,
            })
        },
    )
    .unwrap();
    assert!(
        matches!(done, Done::Collect { outcome, .. } if outcome.status == CollectorStatus::Unsupported)
    );
    assert_eq!(ledger.remaining_records(), launch.global_limits.max_records);

    let mut forged = launch.clone();
    forged.start_sha256 = "0".repeat(64);
    let started = std::cell::Cell::new(false);
    let mut denied_ledger =
        worker::accounting::ReservationLedger::new(forged.global_limits.clone()).unwrap();
    assert!(matches!(
        worker::supervisor::collect_with(
            &forged,
            &frames,
            &[],
            &mut denied_ledger,
            &mut ClockFn(&mut native_clock),
            |_| Ok(()),
            || false,
            || {
                started.set(true);
                Err(jocky_shared::collection::Code::WorkerFailed)
            },
        ),
        Err(jocky_shared::collection::Code::WorkerProtocol)
    ));
    assert!(!started.get());
    assert_eq!(
        denied_ledger.remaining_records(),
        launch.global_limits.max_records
    );

    let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut cancel_ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let cancellation = cancel_flag.clone();
    let signal_after_spawn = cancel_flag.clone();
    let cancelled = worker::supervisor::collect_with(
        &launch,
        &frames,
        &[],
        &mut cancel_ledger,
        &mut ClockFn(&mut native_clock),
        |_| Ok(()),
        move || cancellation.load(std::sync::atomic::Ordering::SeqCst),
        move || {
            let (parent, child) = UnixStream::pair().unwrap();
            parent
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let child_out = child.try_clone().unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
                .arg("__worker")
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::from(OwnedFd::from(child)))
                .stdout(Stdio::from(OwnedFd::from(child_out)))
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            signal_after_spawn.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(worker::spawn::Spawned {
                child,
                channel: parent,
            })
        },
    );
    assert!(matches!(
        cancelled,
        Err(jocky_shared::collection::Code::Cancelled)
    ));
    assert!(cancel_ledger.remaining_records() < launch.global_limits.max_records);

    // The fixed benign sleeper is a test-only blocked-worker fault double.
    // The supervisor must kill/reap the exact owned process and burn its
    // unacknowledged reservation after the bounded private-channel timeout.
    let mut lost_ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let failed = worker::supervisor::collect_with(
        &launch,
        &frames,
        &[],
        &mut lost_ledger,
        &mut ClockFn(&mut native_clock),
        |_| Ok(()),
        || false,
        || {
            let (parent, child) = UnixStream::pair().unwrap();
            parent
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            parent
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let child_out = child.try_clone().unwrap();
            let child = Command::new("/usr/bin/sleep")
                .arg("5")
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::from(OwnedFd::from(child)))
                .stdout(Stdio::from(OwnedFd::from(child_out)))
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Ok(worker::spawn::Spawned {
                child,
                channel: parent,
            })
        },
    );
    assert!(matches!(
        failed,
        Err(jocky_shared::collection::Code::WorkerFailed)
    ));
    assert!(lost_ledger.remaining_records() < launch.global_limits.max_records);
}

#[test]
fn output_only_product_publisher_installs_once_without_reading_a_source() {
    let docs = synthetic_docs();
    let context = admit(
        InputSet {
            designation: &docs[0].1,
            authorisation: Some(&docs[1].1),
            policy: &docs[2].1,
            request: &docs[3].1,
            indicators: None,
        },
        clock::read().unwrap(),
    )
    .unwrap();
    let failed = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        jocky_shared::collection::Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let report = report::finalize(failed, 65_536).unwrap();
    let root = tempfile::Builder::new()
        .prefix("v5-owned-publisher-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
        .unwrap();
    let output_path = root.path().join("output");
    fs::create_dir(&output_path).unwrap();
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o700)).unwrap();
    let output = fs::File::open(&output_path).unwrap();
    let stat = rustix::fs::statx(
        &output,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::TYPE
            | rustix::fs::StatxFlags::MODE
            | rustix::fs::StatxFlags::INO
            | rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap();
    let mut launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.job = Job::Publish;
    launch.parent = peer::own_identity().unwrap();
    launch.descriptors = vec![DescriptorBinding {
        kind: HandleKind::OutputDirectory,
        subject_id: None,
        fd: 3,
        object: ObjectIdentity {
            device_id: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
            inode: stat.stx_ino.to_string(),
            mount_id: Some(stat.stx_mnt_id.to_string()),
        },
    }];
    launch.allowance.records = 0;
    launch.allowance.source_bytes = 0;
    launch.allowance.errors = 0;
    launch.allowance.entries = 0;
    launch.allowance.indicator_comparisons = 0;
    let now = clock::read().unwrap();
    let pair = ClockPair {
        utc: now.utc,
        monotonic_ms: now.monotonic_ms,
    };
    launch.invocation_origin = pair.clone();
    launch.launch_observed = pair;
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Publish {
            context: context.identity().clone(),
            output_descriptor: 3,
            output_name: "report.json".to_owned(),
            report_byte_length: report.len() as u64,
            report_sha256: digest(&report).unwrap(),
        }),
    };
    let start_packet = protocol::encode_frame(&start).unwrap();
    launch.start_sha256 = digest(&start_packet[4..]).unwrap();
    let raw_launch = serde_json::to_vec(&launch).unwrap();
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let child_output = child.try_clone().unwrap();
    let mut owned = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("__worker")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    parent
        .write_all(&(raw_launch.len() as u32).to_be_bytes())
        .unwrap();
    parent.write_all(&raw_launch).unwrap();
    handles::send(&parent, &[output.as_fd()]).unwrap();
    parent.write_all(&start_packet).unwrap();
    let mut decoder = protocol::FrameDecoder::new(launch.collection_id.clone());
    let ready = protocol::read_frame(&mut parent, &mut decoder).unwrap();
    assert!(matches!(ready.body, Body::Ready(ref value) if value.job == Job::Publish));
    // More than the former max_report_bytes / 65536 + 2 frame cap, while
    // every chunk and the aggregate report remain within their wire limits.
    let mut next_seq = 1;
    for (offset, bytes) in report.chunks(8).enumerate() {
        protocol::write_frame(
            &mut parent,
            &WorkerFrame {
                schema_version: CollectionVersion::V1,
                frame_seq: next_seq,
                collection_id: launch.collection_id.clone(),
                body: Body::PublishChunk(Chunk {
                    offset: (offset * 8) as u64,
                    data: STANDARD.encode(bytes),
                }),
            },
        )
        .unwrap();
        next_seq += 1;
    }
    assert!(next_seq > launch.global_limits.max_report_bytes / 65_536 + 2);
    protocol::write_frame(
        &mut parent,
        &WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: next_seq,
            collection_id: launch.collection_id.clone(),
            body: Body::PublishCommit(Commit {
                byte_length: report.len() as u64,
                sha256: digest(&report).unwrap(),
            }),
        },
    )
    .unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    let done = protocol::read_frame(&mut parent, &mut decoder).unwrap_or_else(|error| {
        let status = owned.wait().unwrap();
        let mut stderr = String::new();
        owned
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        panic!(
            "publisher reply {error:?}, exit {:?}, stderr {stderr:?}",
            status.code()
        );
    });
    assert!(matches!(
        done.body,
        Body::Done(Done::Publish {
            code: StatusCode::Success(SuccessCode::PublishedComplete),
            created_identity: Some(_),
            ..
        })
    ));
    decoder.finish().unwrap();
    assert_eq!(owned.wait().unwrap().code(), Some(0));
    assert_eq!(fs::read(output_path.join("report.json")).unwrap(), report);
    assert_eq!(
        fs::metadata(output_path.join("report.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let child_output = child.try_clone().unwrap();
    let mut collision = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("__worker")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    parent
        .write_all(&(raw_launch.len() as u32).to_be_bytes())
        .unwrap();
    parent.write_all(&raw_launch).unwrap();
    handles::send(&parent, &[output.as_fd()]).unwrap();
    parent.write_all(&start_packet).unwrap();
    let mut decoder = protocol::FrameDecoder::new(launch.collection_id.clone());
    assert!(matches!(
        protocol::read_frame(&mut parent, &mut decoder)
            .unwrap()
            .body,
        Body::Ready(_)
    ));
    protocol::write_frame(
        &mut parent,
        &WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 1,
            collection_id: launch.collection_id.clone(),
            body: Body::PublishChunk(Chunk {
                offset: 0,
                data: STANDARD.encode(&report),
            }),
        },
    )
    .unwrap();
    protocol::write_frame(
        &mut parent,
        &WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 2,
            collection_id: launch.collection_id.clone(),
            body: Body::PublishCommit(Commit {
                byte_length: report.len() as u64,
                sha256: digest(&report).unwrap(),
            }),
        },
    )
    .unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    let denied = protocol::read_frame(&mut parent, &mut decoder).unwrap();
    assert!(matches!(
        denied.body,
        Body::Done(Done::Publish {
            code: StatusCode::Error(jocky_shared::collection::Code::OutputExists),
            created_identity: None,
            ..
        })
    ));
    assert_eq!(collision.wait().unwrap().code(), Some(0));
    assert_eq!(fs::read(output_path.join("report.json")).unwrap(), report);
}

#[test]
fn parent_supervisor_drives_output_only_publisher_and_reaps_it() {
    let docs = synthetic_docs();
    let context = admit(
        InputSet {
            designation: &docs[0].1,
            authorisation: Some(&docs[1].1),
            policy: &docs[2].1,
            request: &docs[3].1,
            indicators: None,
        },
        clock::read().unwrap(),
    )
    .unwrap();
    let failure = report::failure(
        &context,
        ReportKind::LiveLab,
        context.started_at().clone(),
        jocky_shared::collection::Code::Unsupported,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    let raw = report::finalize(failure, 65_536).unwrap();
    let root = tempfile::Builder::new()
        .prefix("v5-supervised-publisher-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
        .unwrap();
    let output_path = root.path().join("output");
    fs::create_dir(&output_path).unwrap();
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o700)).unwrap();
    let output = fs::File::open(&output_path).unwrap();
    let stat = rustix::fs::statx(
        &output,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::TYPE
            | rustix::fs::StatxFlags::MODE
            | rustix::fs::StatxFlags::INO
            | rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap();
    let mut launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.job = Job::Publish;
    launch.parent = peer::own_identity().unwrap();
    launch.descriptors = vec![DescriptorBinding {
        kind: HandleKind::OutputDirectory,
        subject_id: None,
        fd: 3,
        object: ObjectIdentity {
            device_id: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
            inode: stat.stx_ino.to_string(),
            mount_id: Some(stat.stx_mnt_id.to_string()),
        },
    }];
    launch.allowance.records = 0;
    launch.allowance.source_bytes = 0;
    launch.allowance.errors = 0;
    launch.allowance.entries = 0;
    launch.allowance.indicator_comparisons = 0;
    let now = clock::read().unwrap();
    let pair = ClockPair {
        utc: now.utc,
        monotonic_ms: now.monotonic_ms,
    };
    launch.invocation_origin = pair.clone();
    launch.launch_observed = pair;
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Publish {
            context: context.identity().clone(),
            output_descriptor: 3,
            output_name: "report.json".to_owned(),
            report_byte_length: raw.len() as u64,
            report_sha256: digest(&raw).unwrap(),
        }),
    };
    launch.start_sha256 = digest(&protocol::encode_frame(&start).unwrap()[4..]).unwrap();
    let frames = [
        start,
        WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 1,
            collection_id: launch.collection_id.clone(),
            body: Body::PublishChunk(Chunk {
                offset: 0,
                data: STANDARD.encode(&raw),
            }),
        },
        WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 2,
            collection_id: launch.collection_id.clone(),
            body: Body::PublishCommit(Commit {
                byte_length: raw.len() as u64,
                sha256: digest(&raw).unwrap(),
            }),
        },
    ];
    struct NativeClock;
    impl jocky_forensic::collection::clock::Clock for NativeClock {
        fn read(
            &mut self,
        ) -> Result<jocky_forensic::collection::ClockReading, jocky_shared::collection::Code>
        {
            clock::read()
        }
    }
    let mut ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let started = std::cell::Cell::new(false);
    let mut bad = frames.clone();
    if let Body::PublishCommit(ref mut commit) = bad[2].body {
        commit.sha256 = "0".repeat(64);
    }
    assert_eq!(
        worker::supervisor::publish_with(
            &launch,
            &bad,
            output.as_fd(),
            &mut ledger,
            &mut NativeClock,
            || false,
            || {
                started.set(true);
                Err(jocky_shared::collection::Code::WorkerFailed)
            }
        ),
        Err(jocky_shared::collection::Code::WorkerProtocol)
    );
    assert!(!started.get());
    let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancelled = cancel_flag.clone();
    let signal_after_spawn = cancel_flag.clone();
    let mut cancelled_ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let cancelled_result = worker::supervisor::publish_with(
        &launch,
        &frames,
        output.as_fd(),
        &mut cancelled_ledger,
        &mut NativeClock,
        move || cancelled.load(std::sync::atomic::Ordering::SeqCst),
        move || {
            let (parent, child) = UnixStream::pair().unwrap();
            parent
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let child_out = child.try_clone().unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
                .arg("__worker")
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::from(OwnedFd::from(child)))
                .stdout(Stdio::from(OwnedFd::from(child_out)))
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            signal_after_spawn.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(worker::spawn::Spawned {
                child,
                channel: parent,
            })
        },
    );
    assert_eq!(
        cancelled_result,
        Err(jocky_shared::collection::Code::Cancelled)
    );
    assert_eq!(cancelled_ledger.remaining_report_bytes(), 0);
    assert!(!output_path.join("report.json").exists());
    let crashed_stage = output_path.join(format!(".jocky-{}.stage", launch.collection_id.as_str()));
    let mut crash_ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let crashed = worker::supervisor::publish_with(
        &launch,
        &frames,
        output.as_fd(),
        &mut crash_ledger,
        &mut NativeClock,
        || false,
        || {
            fs::create_dir(&crashed_stage).unwrap();
            fs::set_permissions(&crashed_stage, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(crashed_stage.join("report.json"), b"partial").unwrap();
            fs::set_permissions(
                crashed_stage.join("report.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let (parent, child) = UnixStream::pair().unwrap();
            let child = Command::new("/bin/true")
                .env_clear()
                .stdin(Stdio::from(OwnedFd::from(child)))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Ok(worker::spawn::Spawned {
                child,
                channel: parent,
            })
        },
    );
    assert!(crashed.is_err());
    assert!(!crashed_stage.exists());
    assert_eq!(crash_ledger.remaining_report_bytes(), 0);
    let spawn = || {
        let (parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        parent
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let child_out = child.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
            .arg("__worker")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::from(OwnedFd::from(child_out)))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Ok(worker::spawn::Spawned {
            child,
            channel: parent,
        })
    };
    let done = worker::supervisor::publish_with(
        &launch,
        &frames,
        output.as_fd(),
        &mut ledger,
        &mut NativeClock,
        || false,
        spawn,
    )
    .unwrap();
    assert!(matches!(
        done,
        Done::Publish {
            code: StatusCode::Success(SuccessCode::PublishedComplete),
            created_identity: Some(_),
            ..
        }
    ));
    assert_eq!(fs::read(output_path.join("report.json")).unwrap(), raw);
    let mut denied_ledger =
        worker::accounting::ReservationLedger::new(launch.global_limits.clone()).unwrap();
    let denied = worker::supervisor::publish_with(
        &launch,
        &frames,
        output.as_fd(),
        &mut denied_ledger,
        &mut NativeClock,
        || false,
        spawn,
    )
    .unwrap();
    assert!(matches!(
        denied,
        Done::Publish {
            code: StatusCode::Error(jocky_shared::collection::Code::OutputExists),
            ..
        }
    ));
    assert_eq!(denied_ledger.remaining_report_bytes(), 0);
    assert_eq!(fs::read(output_path.join("report.json")).unwrap(), raw);
}

#[test]
fn private_product_worker_receives_committed_inputs_and_reports_unsupported() {
    let docs = synthetic_docs();
    let descriptors = docs
        .iter()
        .map(|(role, bytes)| InputDescriptor {
            role: *role,
            byte_length: bytes.len() as u64,
            sha256: digest(bytes).unwrap(),
        })
        .collect();
    let joined: Vec<u8> = docs
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    let commit = Commit {
        byte_length: joined.len() as u64,
        sha256: digest(&joined).unwrap(),
    };
    let mut launch = decode_launch(include_bytes!(
        "../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.parent = peer::own_identity().unwrap();
    launch.descriptors.clear();
    let now = clock::read().unwrap();
    let pair = ClockPair {
        utc: now.utc,
        monotonic_ms: now.monotonic_ms,
    };
    launch.invocation_origin = pair.clone();
    launch.launch_observed = pair;
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Collect {
            collector: Collector::System,
            inputs: descriptors,
            input_byte_length: commit.byte_length,
            input_sha256: commit.sha256.clone(),
        }),
    };
    let start_packet = protocol::encode_frame(&start).unwrap();
    launch.start_sha256 = digest(&start_packet[4..]).unwrap();
    let raw_launch = serde_json::to_vec(&launch).unwrap();
    let next_seq = 1 + joined.chunks(8).count() as u64;
    assert!(next_seq > 14);
    let committed = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: next_seq,
        collection_id: launch.collection_id.clone(),
        body: Body::StartCommit(commit),
    };
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let child_output = child.try_clone().unwrap();
    let mut owned = Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("__worker")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    parent
        .write_all(&(raw_launch.len() as u32).to_be_bytes())
        .unwrap();
    parent.write_all(&raw_launch).unwrap();
    parent.write_all(&start_packet).unwrap();
    for (index, bytes) in joined.chunks(8).enumerate() {
        protocol::write_frame(
            &mut parent,
            &WorkerFrame {
                schema_version: CollectionVersion::V1,
                frame_seq: 1 + index as u64,
                collection_id: launch.collection_id.clone(),
                body: Body::StartChunk(Chunk {
                    offset: (index * 8) as u64,
                    data: STANDARD.encode(bytes),
                }),
            },
        )
        .unwrap();
    }
    protocol::write_frame(&mut parent, &committed).unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    let mut decoder = protocol::FrameDecoder::new(launch.collection_id);
    let ready = protocol::read_frame(&mut parent, &mut decoder).unwrap();
    assert!(matches!(ready.body, Body::Ready(ref value) if value.job == Job::Collect));
    let done = protocol::read_frame(&mut parent, &mut decoder).unwrap();
    assert!(
        matches!(done.body, Body::Done(Done::Collect { ref outcome, .. })
        if outcome.status == CollectorStatus::Unsupported && outcome.accepted_records == 0)
    );
    decoder.finish().unwrap();
    assert_eq!(owned.wait().unwrap().code(), Some(0));
}
