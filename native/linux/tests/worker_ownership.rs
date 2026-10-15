//! Owned-self process/channel tests only. No endpoint, collector or source inventory.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../src/worker/owned.rs"]
mod owned;
#[cfg(target_os = "linux")]
#[path = "../src/worker/peer.rs"]
#[allow(dead_code)]
mod peer;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("WorkerOwnershipUnsupported: Linux-only, not lab acceptance");
}

#[cfg(target_os = "linux")]
fn main() {
    use std::{
        io::Read,
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut args = std::env::args();
    args.next();
    let mode = args.next();
    if mode.as_deref() == Some("--owned-stall") {
        std::thread::sleep(Duration::from_secs(5));
        return;
    }
    if mode.as_deref() == Some("--owned-child") {
        let mut raw = Vec::new();
        std::io::stdin().take(4096).read_to_end(&mut raw).unwrap();
        let claim: jocky_shared::collection::launch::ParentIdentity =
            serde_json::from_slice(&raw).unwrap();
        let result = peer::require_parent(std::io::stdin(), &claim);
        std::process::exit(if result.is_ok() { 0 } else { 3 });
    }
    let claim = peer::own_identity().unwrap();
    for kind in ["valid", "wrong-pid", "wrong-uid", "stale-start", "pipe"] {
        let mut expected = claim.clone();
        match kind {
            "wrong-pid" => expected.pid = 1,
            "wrong-uid" => expected.uid = expected.uid.wrapping_add(1),
            "stale-start" => expected.start_ticks = "0".into(),
            _ => (),
        }
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.arg("--owned-child")
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.stdin(if kind == "pipe" {
            Stdio::piped()
        } else {
            Stdio::from(OwnedFd::from(receiver))
        });
        let mut child = cmd.spawn().unwrap();
        let bytes = serde_json::to_vec(&expected).unwrap();
        use std::io::Write;
        if kind == "pipe" {
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
        } else {
            sender.write_all(&bytes).unwrap();
            sender.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() >= Duration::from_secs(3) {
                child.kill().unwrap();
                let reap = Instant::now();
                loop {
                    if child.try_wait().unwrap().is_some() {
                        panic!("OwnedWorkerTestTimeout: owned child reaped");
                    }
                    if reap.elapsed() >= Duration::from_secs(1) {
                        panic!("CleanupIncomplete: owned child could not be reaped");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            status.code(),
            Some(if kind == "valid" { 0 } else { 3 }),
            "{kind}"
        );
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.arg("--owned-stall")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match owned::OwnedWorker::capture(cmd.spawn().unwrap()) {
        Ok(child) => child,
        Err(mut failed) => {
            // No start handshake or source I/O exists in this fixed test. Close
            // capture failure honestly; retaining the Child permits bounded poll.
            let until = Instant::now();
            while failed.child.try_wait().unwrap().is_none() {
                if until.elapsed() >= Duration::from_secs(6) {
                    panic!("CleanupIncomplete: capture failed");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("OwnedWorkerCaptureFailed:{:?}", failed.code);
        }
    };
    assert!(child.id() > 0);
    child.kill_owned().unwrap();
    let until = Instant::now();
    while child.poll().unwrap().is_none() {
        if until.elapsed() >= Duration::from_secs(1) {
            panic!("CleanupIncomplete: owned pidfd kill was not reaped");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        child.kill_owned(),
        Err(jocky_shared::collection::Code::WorkerProtocol)
    );
    println!(
        "WorkerOwnershipPassed: owned parent/child metadata only, not collection or full T027"
    );
}
