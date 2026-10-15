//! Owned-self spawn contract smoke; no source or endpoint is opened.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../src/worker/mod.rs"]
#[allow(dead_code, unused_imports)]
mod worker;
#[cfg(target_os = "linux")]
use worker::{entry, handles, owned, peer, resource, spawn, supervisor};

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("WorkerSpawnUnsupported: Linux-only, not lab acceptance");
}

#[cfg(target_os = "linux")]
fn main() {
    use jocky_shared::collection::Code;
    use std::{
        io::{Read, Write},
        os::fd::AsFd,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    if std::env::args().nth(1).as_deref() == Some("__worker") {
        // std::io::Stdin is buffered and could consume the SCM_RIGHTS token
        // while reading the launch document. Use an unbuffered owned duplicate.
        let mut stdin = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
        let (_launch, _received) = match entry::receive_owned_launch(&mut stdin, std::io::stdout())
        {
            Ok(value) => value,
            Err(_) => std::process::exit(3),
        };
        if std::env::var_os("PATH").is_some() {
            std::process::exit(3);
        }
        let observed = rustix::process::getrlimit(rustix::process::Resource::As);
        if observed
            .current
            .is_none_or(|limit| limit > 192 * 1024 * 1024)
            || observed
                .maximum
                .is_none_or(|limit| limit > 192 * 1024 * 1024)
        {
            std::process::exit(5);
        }
        let mut raw = Vec::new();
        stdin.take(4096).read_to_end(&mut raw).unwrap();
        if raw == b"crash" {
            std::process::exit(9);
        }
        if raw.starts_with(b"stall") {
            std::thread::sleep(Duration::from_secs(5));
            std::process::exit(9);
        }
        std::process::exit(if raw.is_empty() { 0 } else { 3 });
    }
    let claim = peer::own_identity().unwrap();
    assert_eq!(
        resource::split_address_space(256 * 1024 * 1024),
        Ok((64 * 1024 * 1024, 192 * 1024 * 1024))
    );
    assert_eq!(
        resource::split_address_space(128 * 1024 * 1024),
        Ok((32 * 1024 * 1024, 96 * 1024 * 1024))
    );
    assert_eq!(resource::split_address_space(0), Err(Code::InvalidInput));
    assert_eq!(
        resource::split_address_space(256 * 1024 * 1024 + 1),
        Err(Code::InvalidInput)
    );
    assert_eq!(resource::split_address_space(3), Err(Code::ResourceLimit));
    assert_eq!(
        resource::limit_worker_address_space(0),
        Err(Code::InvalidInput)
    );
    assert_eq!(
        resource::limit_worker_address_space(192 * 1024 * 1024 + 1),
        Err(Code::InvalidInput)
    );
    let mut launch: jocky_shared::collection::launch::WorkerLaunch =
        jocky_shared::collection::launch::decode_launch(include_bytes!(
            "../../../fixtures/valid/collection/worker-launch.json"
        ))
        .unwrap();
    launch.parent = claim;
    let owned = tempfile::Builder::new()
        .prefix("v5-owned-spawn-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"))
        .unwrap();
    let source = std::fs::File::open(owned.path()).unwrap();
    let stat = rustix::fs::statx(
        &source,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::TYPE
            | rustix::fs::StatxFlags::MODE
            | rustix::fs::StatxFlags::INO
            | rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap();
    launch.descriptors = vec![jocky_shared::collection::launch::DescriptorBinding {
        kind: jocky_shared::collection::launch::HandleKind::OrdinaryRoot,
        subject_id: Some(
            jocky_shared::collection::identity::Uuid::parse("10000000-0000-4000-8000-000000000090")
                .unwrap(),
        ),
        fd: 3,
        object: jocky_shared::collection::launch::ObjectIdentity {
            device_id: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
            inode: stat.stx_ino.to_string(),
            mount_id: Some(stat.stx_mnt_id.to_string()),
        },
    }];
    let raw = serde_json::to_vec(&launch).unwrap();
    let mut packet = Vec::with_capacity(raw.len() + 4);
    packet.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    packet.extend_from_slice(&raw);
    for (kind, expected) in [
        (std::io::ErrorKind::PermissionDenied, Code::PermissionDenied),
        (std::io::ErrorKind::OutOfMemory, Code::ResourceLimit),
        (std::io::ErrorKind::NotFound, Code::Unsupported),
    ] {
        assert_eq!(spawn::map_error(std::io::Error::from(kind)), expected);
    }
    let mut spawned = spawn::fixed_self().unwrap();
    let mut child = owned::OwnedWorker::capture(spawned.child).unwrap_or_else(|mut failure| {
        failure.child.kill().unwrap();
        failure.child.wait().unwrap();
        panic!("OwnedWorkerCaptureFailed:{:?}", failure.code)
    });
    spawned.channel.write_all(&packet).unwrap();
    handles::send(&spawned.channel, &[source.as_fd()]).unwrap();
    spawn::close_write(&spawned.channel).unwrap();
    assert!(child.id() > 0);
    let until = Instant::now();
    loop {
        if let Some(status) = child.poll().unwrap() {
            assert_eq!(status.code(), Some(0));
            break;
        }
        if until.elapsed() >= Duration::from_secs(3) {
            assert_eq!(child.kill_owned(), Ok(()));
            panic!("CleanupIncomplete: owned self-worker did not exit");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(child.kill_owned(), Err(Code::WorkerProtocol));
    assert_eq!(
        supervisor::stop_owned(&mut child, &spawned.channel, 0, Code::Cancelled).err(),
        Some(Code::InvalidInput)
    );
    assert_eq!(
        supervisor::stop_owned(&mut child, &spawned.channel, 6000, Code::NotImplemented).err(),
        Some(Code::InvalidInput)
    );
    let mut forged = launch.clone();
    forged.parent.pid = forged.parent.pid.saturating_add(1);
    let forged_raw = serde_json::to_vec(&forged).unwrap();
    let mut forged_packet = Vec::with_capacity(forged_raw.len() + 4);
    forged_packet.extend_from_slice(&(forged_raw.len() as u32).to_be_bytes());
    forged_packet.extend_from_slice(&forged_raw);
    let mut spawned = spawn::fixed_self().unwrap();
    let mut denied = owned::OwnedWorker::capture(spawned.child).unwrap_or_else(|mut failure| {
        failure.child.kill().unwrap();
        failure.child.wait().unwrap();
        panic!("OwnedWorkerCaptureFailed:{:?}", failure.code)
    });
    spawned.channel.write_all(&forged_packet).unwrap();
    spawn::close_write(&spawned.channel).unwrap();
    let until = Instant::now();
    loop {
        if let Some(status) = denied.poll().unwrap() {
            assert_eq!(status.code(), Some(3));
            break;
        }
        if until.elapsed() >= Duration::from_secs(3) {
            denied.kill_owned().unwrap();
            panic!("CleanupIncomplete: forged-launch child did not exit");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut forged_object = launch.clone();
    forged_object.descriptors[0].object.inode = "0".into();
    let raw = serde_json::to_vec(&forged_object).unwrap();
    let mut forged_packet = Vec::with_capacity(raw.len() + 4);
    forged_packet.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    forged_packet.extend_from_slice(&raw);
    let mut spawned = spawn::fixed_self().unwrap();
    let mut denied = owned::OwnedWorker::capture(spawned.child).unwrap_or_else(|mut failure| {
        failure.child.kill().unwrap();
        failure.child.wait().unwrap();
        panic!("OwnedWorkerCaptureFailed:{:?}", failure.code)
    });
    spawned.channel.write_all(&forged_packet).unwrap();
    handles::send(&spawned.channel, &[source.as_fd()]).unwrap();
    spawn::close_write(&spawned.channel).unwrap();
    let until = Instant::now();
    loop {
        if let Some(status) = denied.poll().unwrap() {
            assert_eq!(status.code(), Some(3));
            break;
        }
        if until.elapsed() >= Duration::from_secs(3) {
            denied.kill_owned().unwrap();
            panic!("CleanupIncomplete: forged-object child did not exit");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    for (payload, expected_status) in [(b"crash".as_slice(), Some(9)), (b"stall", None)] {
        let mut spawned = spawn::fixed_self().unwrap();
        let mut owned = owned::OwnedWorker::capture(spawned.child).unwrap_or_else(|mut failure| {
            failure.child.kill().unwrap();
            failure.child.wait().unwrap();
            panic!("OwnedWorkerCaptureFailed:{:?}", failure.code)
        });
        spawned.channel.write_all(&packet).unwrap();
        handles::send(&spawned.channel, &[source.as_fd()]).unwrap();
        spawned.channel.write_all(payload).unwrap();
        if expected_status.is_some() {
            spawn::close_write(&spawned.channel).unwrap();
        }
        let until = Instant::now();
        if let Some(code) = expected_status {
            loop {
                if let Some(status) = owned.poll().unwrap() {
                    assert_eq!(status.code(), Some(code));
                    break;
                }
                assert!(until.elapsed() < Duration::from_secs(3));
                std::thread::sleep(Duration::from_millis(5));
            }
        } else {
            let status =
                supervisor::stop_owned(&mut owned, &spawned.channel, 6000, Code::Cancelled)
                    .unwrap();
            assert!(!status.success());
            assert!(until.elapsed() < Duration::from_secs(4));
        }
    }
    let mut spawned = spawn::fixed_self().unwrap();
    let mut stalled = owned::OwnedWorker::capture(spawned.child).unwrap_or_else(|mut failure| {
        failure.child.kill().unwrap();
        failure.child.wait().unwrap();
        panic!("OwnedWorkerCaptureFailed:{:?}", failure.code)
    });
    spawned.channel.write_all(&packet).unwrap();
    handles::send(&spawned.channel, &[source.as_fd()]).unwrap();
    spawned.channel.write_all(b"stall").unwrap();
    assert_eq!(
        supervisor::stop_owned_with(&mut stalled, 6000, Code::Cancelled, || {
            Err(Code::WorkerFailed)
        })
        .err(),
        Some(Code::WorkerFailed)
    );
    assert!(stalled.poll().unwrap().is_some());
    let mut spawned = spawn::fixed_self().unwrap();
    let mut stalled = owned::OwnedWorker::capture(spawned.child).unwrap_or_else(|mut failure| {
        failure.child.kill().unwrap();
        failure.child.wait().unwrap();
        panic!("OwnedWorkerCaptureFailed:{:?}", failure.code)
    });
    spawned.channel.write_all(&packet).unwrap();
    handles::send(&spawned.channel, &[source.as_fd()]).unwrap();
    spawned.channel.write_all(b"stall").unwrap();
    let mut cancel = jocky_shared::collection::worker::WorkerFrame {
        schema_version: jocky_shared::collection::inputs::CollectionVersion::V1,
        frame_seq: 0,
        collection_id: launch.collection_id.clone(),
        body: jocky_shared::collection::worker::Body::Cancel(
            jocky_shared::collection::worker::Cancel {
                code: Code::Cancelled,
            },
        ),
    };
    cancel.body =
        jocky_shared::collection::worker::Body::Cancel(jocky_shared::collection::worker::Cancel {
            code: Code::Timeout,
        });
    assert_eq!(
        supervisor::cancel_owned(
            &mut stalled,
            &spawned.channel,
            &cancel,
            6000,
            Code::Cancelled
        )
        .err(),
        Some(Code::WorkerProtocol)
    );
    cancel.body =
        jocky_shared::collection::worker::Body::Cancel(jocky_shared::collection::worker::Cancel {
            code: Code::Cancelled,
        });
    let status = supervisor::cancel_owned(
        &mut stalled,
        &spawned.channel,
        &cancel,
        6000,
        Code::Cancelled,
    )
    .unwrap();
    assert!(!status.success());
    assert!(stalled.poll().unwrap().is_some());
    let mut direct = Command::new("/proc/self/exe")
        .arg("__worker")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    direct.stdin.take().unwrap().write_all(&packet).unwrap();
    let until = Instant::now();
    loop {
        if let Some(status) = direct.try_wait().unwrap() {
            assert_eq!(status.code(), Some(3));
            break;
        }
        if until.elapsed() >= Duration::from_secs(3) {
            direct.kill().unwrap();
            direct.wait().unwrap();
            panic!("CleanupIncomplete: direct-entry test child did not exit");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("WorkerSpawnPassed: fixed self image, cleared environment, owned Unix channel");
}
