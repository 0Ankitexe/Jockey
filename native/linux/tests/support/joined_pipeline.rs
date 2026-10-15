//! Reusable synthetic two-child pipeline for normal and harness-free memory tests.
use crate::{clock, collection, sources, support, worker};
use base64::{Engine, engine::general_purpose::STANDARD};
use jocky_forensic::collection::{InputSet, admit, identity::digest};
use jocky_shared::collection::{
    inputs::CollectionVersion,
    launch::{ClockPair, DescriptorBinding, HandleKind, ObjectIdentity, decode_launch},
    outcomes::Collector,
    report::{ReportKind, StatusCode, SuccessCode},
    worker::{Body, Chunk, Commit, Done, InputDescriptor, InputRole, Job, Start, WorkerFrame},
};
use std::{
    fs,
    os::{
        fd::OwnedFd,
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    process::{Command, Stdio},
};
use worker::{peer, protocol};

fn synthetic_file_docs(root: &str) -> Vec<(InputRole, Vec<u8>)> {
    let now = clock::read().unwrap().utc.unix_nanos() / 1_000_000_000;
    let before = clock::unix_utc((now - 3600) as i64).unwrap();
    let after = clock::unix_utc((now + 3600) as i64).unwrap();
    support::values(root, "selected")
        .into_iter()
        .zip([
            InputRole::Designation,
            InputRole::Authorisation,
            InputRole::Policy,
            InputRole::Request,
        ])
        .map(|(mut document, role)| {
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

fn spawn_product() -> Result<worker::spawn::Spawned, jocky_shared::collection::Code> {
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
}

pub(crate) fn exercise_joined_pipeline() {
    exercise_joined_pipeline_mode(false, false);
}

pub(crate) fn exercise_lost_worker_report() {
    exercise_joined_pipeline_mode(true, false);
}
pub(crate) fn exercise_partial_file_report() {
    exercise_joined_pipeline_mode(false, true);
}

pub(crate) fn exercise_injected_complete_profile() {
    use jocky_forensic::collection::{ClockReading, clock::Clock, context::OperationTarget};
    use sources::capabilities::OutputDirectory;
    struct NativeClock;
    impl Clock for NativeClock {
        fn read(&mut self) -> Result<ClockReading, jocky_shared::collection::Code> {
            clock::read()
        }
    }
    let root = support::scratch();
    let output_path = root.path().join("output");
    fs::create_dir(&output_path).unwrap();
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = output_path.join("report.json");
    let now = clock::read().unwrap();
    let seconds = now.utc.unix_nanos() / 1_000_000_000;
    let before = clock::unix_utc((seconds - 3600) as i64).unwrap();
    let after = clock::unix_utc((seconds + 3600) as i64).unwrap();
    let mut docs: Vec<serde_json::Value> = [
        include_bytes!("../../../../fixtures/valid/collection/endpoint-designation.json")
            .as_slice(),
        include_bytes!("../../../../fixtures/valid/collection/authorisation.json").as_slice(),
        include_bytes!("../../../../fixtures/valid/collection/policy.json").as_slice(),
        include_bytes!("../../../../fixtures/valid/collection/request.json").as_slice(),
    ]
    .into_iter()
    .map(|bytes| serde_json::from_slice(bytes).unwrap())
    .collect();
    for doc in &mut docs {
        if doc.get("valid_from").is_some() {
            doc["valid_from"] = before.as_str().into();
            doc["valid_until"] = after.as_str().into();
        }
        if doc.get("scope").is_some() {
            doc["scope"]["event_window"]["start"] = before.as_str().into();
            doc["scope"]["event_window"]["end"] = after.as_str().into();
        }
        if doc.get("event_window").is_some() {
            doc["event_window"]["start"] = before.as_str().into();
            doc["event_window"]["end"] = after.as_str().into();
        }
    }
    let raw: Vec<Vec<u8>> = docs
        .iter()
        .map(|doc| serde_json::to_vec(doc).unwrap())
        .collect();
    let context = admit(
        InputSet {
            designation: &raw[0],
            authorisation: Some(&raw[1]),
            policy: &raw[2],
            request: &raw[3],
            indicators: None,
        },
        now.clone(),
    )
    .unwrap();
    let source_id = context.sources()[0].definition().id().clone();
    let output = OutputDirectory::open(
        &context,
        OperationTarget::Source(&source_id),
        destination.to_str().unwrap(),
        &mut NativeClock,
        &false,
    )
    .unwrap();
    let model: jocky_shared::collection::report::CollectionReport = serde_json::from_slice(
        include_bytes!("../../../../fixtures/valid/collection/report.json"),
    )
    .unwrap();
    let record = crate::collectors::record::make(
        &context,
        Collector::System,
        jocky_shared::collection::records::Adapter::KernelProfile,
        jocky_shared::collection::records::Category::System,
        jocky_shared::collection::records::ProvenanceKind::KernelProfile,
        source_id.clone(),
        crate::collectors::record::facility_scope(source_id.clone()),
        model.records[0].payload.clone(),
        0,
        context.started_at().clone(),
    )
    .unwrap();
    let mut launch = decode_launch(include_bytes!(
        "../../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    launch.parent = peer::own_identity().unwrap();
    launch.descriptors.clear();
    launch.allowance.report_bytes = 0;
    launch.allowance.staging_bytes = 64 * 1024 * 1024;
    launch.invocation_origin = ClockPair {
        utc: now.utc.clone(),
        monotonic_ms: now.monotonic_ms,
    };
    launch.launch_observed = launch.invocation_origin.clone();
    let input_roles = [
        InputRole::Designation,
        InputRole::Authorisation,
        InputRole::Policy,
        InputRole::Request,
    ];
    let inputs: Vec<_> = input_roles
        .into_iter()
        .zip(&raw)
        .map(|(role, bytes)| InputDescriptor {
            role,
            byte_length: bytes.len() as u64,
            sha256: digest(bytes).unwrap(),
        })
        .collect();
    let joined: Vec<u8> = raw.iter().flat_map(|bytes| bytes.iter().copied()).collect();
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: Body::Start(Start::Collect {
            collector: Collector::System,
            inputs,
            input_byte_length: joined.len() as u64,
            input_sha256: digest(&joined).unwrap(),
        }),
    };
    launch.start_sha256 = digest(&protocol::encode_frame(&start).unwrap()[4..]).unwrap();
    let stat = rustix::fs::statx(
        output.sync_fd(),
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::TYPE
            | rustix::fs::StatxFlags::MODE
            | rustix::fs::StatxFlags::INO
            | rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap();
    let mut publisher = launch.clone();
    publisher.job = Job::Publish;
    publisher.descriptors = vec![DescriptorBinding {
        kind: HandleKind::OutputDirectory,
        subject_id: None,
        fd: 3,
        object: ObjectIdentity {
            device_id: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
            inode: stat.stx_ino.to_string(),
            mount_id: Some(stat.stx_mnt_id.to_string()),
        },
    }];
    publisher.allowance.records = 0;
    publisher.allowance.source_bytes = 0;
    publisher.allowance.errors = 0;
    publisher.allowance.entries = 0;
    publisher.allowance.indicator_comparisons = 0;
    publisher.allowance.report_bytes = 10 * 1024 * 1024;
    publisher.allowance.staging_bytes = 16 * 1024 * 1024;
    publisher.allowance.retained_bytes = 64 * 1024 * 1024;
    let frames = [start];
    let job = collection::CollectJob {
        launch: &launch,
        frames: &frames,
        descriptors: &[],
    };
    let done = collection::run_with(
        &context,
        &[job],
        &output,
        publisher,
        &mut NativeClock,
        || false,
        |_, _, _, observe, _| {
            observe(&WorkerFrame {
                schema_version: CollectionVersion::V1,
                frame_seq: 1,
                collection_id: context.identity().collection_id.clone(),
                body: Body::Record(Box::new(record.clone())),
            })?;
            Ok(Done::Collect {
                outcome: model.collectors[0].clone(),
                usage: model.summary.work_used.clone(),
            })
        },
        |launch, frames, output, ledger, clock, cancelled| {
            worker::supervisor::publish_with(
                launch,
                frames,
                output,
                ledger,
                clock,
                cancelled,
                spawn_product,
            )
        },
    )
    .unwrap();
    assert!(
        matches!(
            done,
            Done::Publish {
                code: StatusCode::Success(SuccessCode::PublishedComplete),
                ..
            }
        ),
        "{done:?}"
    );
    let report =
        jocky_forensic::collection::verify::verify_report(&fs::read(destination).unwrap()).unwrap();
    assert_eq!(
        report.summary.status,
        jocky_shared::collection::report::SummaryStatus::Complete
    );
    assert_eq!(report.records.len(), 1);
}

fn exercise_joined_pipeline_mode(lost: bool, positive: bool) {
    use jocky_forensic::collection::{ClockReading, clock::Clock, context::OperationTarget};
    use sources::capabilities::OutputDirectory;
    struct NativeClock;
    impl Clock for NativeClock {
        fn read(&mut self) -> Result<ClockReading, jocky_shared::collection::Code> {
            clock::read()
        }
    }
    let root = tempfile::Builder::new()
        .prefix("v5-joined-worker-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
        .unwrap();
    let owned_path = root.path().canonicalize().unwrap();
    let source_path = owned_path.join("source");
    fs::create_dir(&source_path).unwrap();
    if positive {
        fs::write(
            source_path.join("selected"),
            b"offline synthetic evidence\n",
        )
        .unwrap();
    }
    let mut docs = synthetic_file_docs(source_path.to_str().unwrap());
    if positive {
        let mut request: serde_json::Value = serde_json::from_slice(&docs[3].1).unwrap();
        request["paths"] = serde_json::json!([support::path("selected"), support::path("missing")]);
        docs[3].1 = serde_json::to_vec(&request).unwrap();
    }
    let now = clock::read().unwrap();
    let context = admit(
        InputSet {
            designation: &docs[0].1,
            authorisation: Some(&docs[1].1),
            policy: &docs[2].1,
            request: &docs[3].1,
            indicators: None,
        },
        now.clone(),
    )
    .unwrap();
    let output_path = owned_path.join("output");
    fs::create_dir(&output_path).unwrap();
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = output_path.join("report.json");
    let selected = support::path("selected");
    let output = OutputDirectory::open(
        &context,
        OperationTarget::File(&selected),
        destination.to_str().unwrap(),
        &mut NativeClock,
        &false,
    )
    .unwrap();
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
    let mut collect_launch = decode_launch(include_bytes!(
        "../../../../fixtures/valid/collection/worker-launch.json"
    ))
    .unwrap();
    collect_launch.parent = peer::own_identity().unwrap();
    collect_launch.descriptors.clear();
    collect_launch.allowance.report_bytes = 0;
    collect_launch.allowance.staging_bytes = 64 * 1024 * 1024;
    collect_launch.invocation_origin = ClockPair {
        utc: now.utc.clone(),
        monotonic_ms: now.monotonic_ms,
    };
    collect_launch.launch_observed = collect_launch.invocation_origin.clone();
    let start = WorkerFrame {
        schema_version: CollectionVersion::V1,
        frame_seq: 0,
        collection_id: collect_launch.collection_id.clone(),
        body: Body::Start(Start::Collect {
            collector: Collector::Files,
            inputs: descriptors,
            input_byte_length: commit.byte_length,
            input_sha256: commit.sha256.clone(),
        }),
    };
    collect_launch.start_sha256 = digest(&protocol::encode_frame(&start).unwrap()[4..]).unwrap();
    let frames = [
        start,
        WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 1,
            collection_id: collect_launch.collection_id.clone(),
            body: Body::StartChunk(Chunk {
                offset: 0,
                data: STANDARD.encode(&joined),
            }),
        },
        WorkerFrame {
            schema_version: CollectionVersion::V1,
            frame_seq: 2,
            collection_id: collect_launch.collection_id.clone(),
            body: Body::StartCommit(commit),
        },
    ];
    let root_handle = if positive {
        Some(
            sources::paths::ConfinedRoot::open(
                &context,
                OperationTarget::File(&selected),
                sources::metadata::Exclusions::new(&[]).unwrap(),
                &mut NativeClock,
                &false,
            )
            .unwrap(),
        )
    } else {
        None
    };
    let source_handle = root_handle.as_ref().map(|root| root.fd());
    if let Some(fd) = source_handle {
        let source_stat = rustix::fs::statx(
            fd,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::TYPE
                | rustix::fs::StatxFlags::MODE
                | rustix::fs::StatxFlags::INO
                | rustix::fs::StatxFlags::MNT_ID,
        )
        .unwrap();
        collect_launch.descriptors.push(DescriptorBinding {
            kind: HandleKind::OrdinaryRoot,
            subject_id: Some(selected.root_id.clone()),
            fd: 3,
            object: ObjectIdentity {
                device_id: rustix::fs::makedev(
                    source_stat.stx_dev_major,
                    source_stat.stx_dev_minor,
                )
                .to_string(),
                inode: source_stat.stx_ino.to_string(),
                mount_id: Some(source_stat.stx_mnt_id.to_string()),
            },
        });
    }
    let stat = rustix::fs::statx(
        output.sync_fd(),
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::TYPE
            | rustix::fs::StatxFlags::MODE
            | rustix::fs::StatxFlags::INO
            | rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap();
    let mut publish_launch = collect_launch.clone();
    publish_launch.job = Job::Publish;
    publish_launch.descriptors = vec![DescriptorBinding {
        kind: HandleKind::OutputDirectory,
        subject_id: None,
        fd: 3,
        object: ObjectIdentity {
            device_id: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
            inode: stat.stx_ino.to_string(),
            mount_id: Some(stat.stx_mnt_id.to_string()),
        },
    }];
    publish_launch.allowance.records = 0;
    publish_launch.allowance.source_bytes = 0;
    publish_launch.allowance.errors = 0;
    publish_launch.allowance.entries = 0;
    publish_launch.allowance.indicator_comparisons = 0;
    publish_launch.allowance.report_bytes = 10 * 1024 * 1024;
    publish_launch.allowance.staging_bytes = 16 * 1024 * 1024;
    publish_launch.allowance.retained_bytes = 64 * 1024 * 1024;
    let job = collection::CollectJob {
        launch: &collect_launch,
        frames: &frames,
        descriptors: source_handle.as_slice(),
    };
    let done = collection::run_with(
        &context,
        &[job],
        &output,
        publish_launch,
        &mut NativeClock,
        || false,
        |job, ledger, clock, observation, cancelled| {
            if lost {
                ledger.reserve(&job.launch.allowance)?;
                ledger.lost()?;
                return Err(jocky_shared::collection::Code::WorkerFailed);
            }
            worker::supervisor::collect_with(
                job.launch,
                job.frames,
                job.descriptors,
                ledger,
                clock,
                observation,
                cancelled,
                spawn_product,
            )
        },
        |launch, frames, output, ledger, clock, cancelled| {
            worker::supervisor::publish_with(
                launch,
                frames,
                output,
                ledger,
                clock,
                cancelled,
                spawn_product,
            )
        },
    )
    .unwrap();
    let expected_code = if positive {
        StatusCode::Success(SuccessCode::PublishedPartial)
    } else if lost {
        StatusCode::Success(SuccessCode::PublishedFailed)
    } else {
        StatusCode::Error(jocky_shared::collection::Code::Unsupported)
    };
    assert!(
        matches!(&done, Done::Publish { code, .. } if *code == expected_code),
        "{done:?}"
    );
    let raw = fs::read(&destination).unwrap();
    let verified = jocky_forensic::collection::verify::verify_report(&raw).unwrap();
    assert_eq!(verified.report_kind, ReportKind::LiveLab);
    assert_eq!(
        verified.summary.status,
        if positive {
            jocky_shared::collection::report::SummaryStatus::Partial
        } else {
            jocky_shared::collection::report::SummaryStatus::Failed
        }
    );
    assert_eq!(verified.records.len(), usize::from(positive));
    if lost {
        assert_eq!(verified.summary.work_used.source_bytes, 64 * 1024 * 1024);
        assert_eq!(
            verified.summary.stop_reason,
            Some(jocky_shared::collection::Code::WorkerFailed)
        );
    }
    assert_eq!(fs::read_dir(&output_path).unwrap().count(), 1);
}
