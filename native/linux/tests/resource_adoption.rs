//! Early dependency-adoption gate, not a collection or full worker test.
//! Harness-free: libtest threads/allocator arenas would contaminate RLIMIT_AS.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
#[path = "resource_adoption/inputs.rs"]
mod inputs;
#[cfg(target_os = "linux")]
#[path = "../src/worker/resource.rs"]
#[allow(dead_code)]
mod resource;
#[cfg(target_os = "linux")]
#[path = "../src/worker/signals.rs"]
#[allow(dead_code)]
mod signals;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("ResourceAdoptionUnsupported: Linux-only, not native acceptance");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use jocky_forensic::collection::{
        ClockReading, InputSet, admit, canonical, verify::verify_report,
    };
    use jocky_shared::collection::identity::UtcTime;
    use rustix::process::{Resource, Rlimit, setrlimit};
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    pub fn main() {
        match std::env::args().nth(1).as_deref() {
            Some("--parent-probe") => probe(64 * 1024 * 1024, false),
            Some("--worker-probe") => probe(192 * 1024 * 1024, true),
            _ => {
                // Only this owned executable is spawned; no host source, bus,
                // journal discovery, shell, PATH lookup or external endpoint.
                let mut passed = true;
                for role in ["--parent-probe", "--worker-probe"] {
                    passed &= run(role);
                }
                assert!(
                    passed,
                    "ResourceAdoptionFailed: design review required, no threshold waiver"
                );
                println!("ResourceAdoptionPassed: dependency initialization under 64/192 MiB");
            }
        }
    }

    fn run(role: &str) -> bool {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg(role)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() >= Duration::from_secs(15) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("ResourceAdoptionFailed: owned probe timeout {role}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(16384)
            .read_to_string(&mut output)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .take(16384)
            .read_to_string(&mut output)
            .unwrap();
        // Output is only this fixed test's stage markers and synthetic failures.
        println!("{role}: {status}\n{output}");
        status.success()
    }

    fn probe(bytes: u64, worker: bool) {
        // This test intentionally exercises allocation failure. Prevent the
        // owned probe from leaving crash dumps via a system-wide pipe handler;
        // RLIMIT_CORE alone does not cover that case. No global setting changes.
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap();
        usage("before-limit");
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        if worker {
            super::resource::limit_worker_address_space(bytes).unwrap();
        } else {
            super::resource::limit_parent_address_space(bytes, 192 * 1024 * 1024).unwrap();
        }
        let _signals = if worker {
            None
        } else {
            Some(super::signals::SignalWatch::start().unwrap())
        };
        if !worker {
            assert!(run("--worker-probe"), "inherited 64/192 MiB split failed");
            println!("InheritedParentToWorkerSplitPassed");
        }
        println!("AddressSpaceLimitApplied:{bytes}");
        let input = InputSet {
            designation: include_bytes!(
                "../../../fixtures/valid/collection/endpoint-designation.json"
            ),
            authorisation: Some(include_bytes!(
                "../../../fixtures/valid/collection/authorisation.json"
            )),
            policy: include_bytes!("../../../fixtures/valid/collection/policy.json"),
            request: include_bytes!("../../../fixtures/valid/collection/request.json"),
            indicators: None,
        };
        for (kind, bytes) in [
            (
                jocky_shared::collection::DocumentKind::Designation,
                input.designation,
            ),
            (
                jocky_shared::collection::DocumentKind::Authorisation,
                input.authorisation.unwrap(),
            ),
            (jocky_shared::collection::DocumentKind::Policy, input.policy),
            (
                jocky_shared::collection::DocumentKind::Request,
                input.request,
            ),
        ] {
            println!("Initializing:{}", kind.name());
            jocky_shared::collection::decode(kind, bytes).unwrap();
            usage(kind.name());
        }
        let _context = admit(
            input,
            ClockReading {
                utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
                monotonic_ms: 0,
            },
        )
        .unwrap();
        println!("AdmissionAndSchemaInitializationPassed");
        usage("after-admission");
        let value: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/valid/collection/report.json"
        ))
        .unwrap();
        let mut report = canonical::encode(&value, 10485759).unwrap();
        report.push(b'\n');
        verify_report(&report).unwrap();
        println!("SyntheticReportVerificationPassed");
        usage("after-report");
        super::inputs::exercise();
        usage("after-all-schemas-and-boundaries");
        if worker {
            dependencies();
        }
        usage("finished");
        println!("ProbePassed");
    }

    fn usage(stage: &str) {
        // Only the probe's own address-space statistics, not endpoint evidence.
        let mut raw = String::new();
        std::fs::File::open("/proc/self/statm")
            .unwrap()
            .take(128)
            .read_to_string(&mut raw)
            .unwrap();
        let counts: Vec<u64> = raw
            .split_ascii_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        let page = rustix::param::page_size() as u64;
        println!(
            "ProbeMemory:{stage}:virtual_bytes={}:rss_bytes={}",
            counts[0] * page,
            counts[1] * page
        );
        let mut status = String::new();
        std::fs::File::open("/proc/self/status")
            .unwrap()
            .take(8192)
            .read_to_string(&mut status)
            .unwrap();
        for (key, label) in [
            ("VmPeak:", "peak_virtual_bytes"),
            ("VmHWM:", "peak_rss_bytes"),
        ] {
            let line = status.lines().find(|line| line.starts_with(key)).unwrap();
            let mut fields = line.split_ascii_whitespace().skip(1);
            let kib: u64 = fields.next().unwrap().parse().unwrap();
            assert_eq!(fields.next(), Some("kB"));
            println!("ProbePeak:{stage}:{label}={}", kib * 1024);
        }
    }

    fn dependencies() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (client, _owned_peer) = tokio::net::UnixStream::pair().unwrap();
            // The in-memory test peer is pre-authenticated only for this probe;
            // this does not assert system-bus auth or service inventory works.
            let builder = zbus::connection::Builder::authenticated_socket(
                client,
                "0123456789abcdef0123456789abcdef",
            )
            .unwrap()
            .max_queued(8)
            .method_timeout(Duration::from_secs(2));
            let connection = tokio::time::timeout(Duration::from_secs(2), builder.build())
                .await
                .unwrap()
                .unwrap();
            connection.close().await.unwrap();
        });
        println!("TokioAndZbusInitializedOnOwnedSocketPair");
        #[cfg(feature = "journal")]
        {
            use std::io::Write;
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
            let dir = tempfile::Builder::new()
                .prefix("v5-adoption-")
                .tempdir_in(root)
                .unwrap();
            let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            file.write_all(b"synthetic-invalid-journal-header").unwrap();
            // Real libsystemd path on an explicitly owned invalid file. Failure
            // is expected; no ambient journal directory is ever supplied.
            let opened = systemd::journal::OpenFilesOptions::default()
                .open_files([file.path().to_str().unwrap()]);
            assert!(
                opened.is_err(),
                "malformed journal must not become valid evidence"
            );
            println!("LibsystemdInitializedAndRejectedOwnedMalformedFile");
        }
    }
}
