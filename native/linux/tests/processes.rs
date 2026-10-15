//! Process parser assertions over authored procfs text only.
#![cfg(target_os = "linux")]
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
use collectors::processes;
#[path = "../src/cli/mod.rs"]
#[allow(dead_code)]
mod cli;
use jocky_shared::collection::Code;

#[test]
fn parent_command_uid_and_start_join_by_exact_pid() {
    let stat = b"4242 (test worker) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0 0\n";
    let parsed = processes::parse_stat(stat, 4242).unwrap();
    assert_eq!(parsed.pid, 4242);
    assert_eq!(parsed.parent_pid, 1);
    assert_eq!(parsed.command, "test worker");
    assert_eq!(parsed.start_ticks, "12345");
    assert_eq!(
        processes::parse_uid(b"Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n").unwrap(),
        1000
    );
}

#[test]
fn disappearing_reused_and_malformed_pids_fail_closed() {
    let stat = b"4242 (test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0 0";
    assert_eq!(processes::parse_stat(stat, 999), Err(Code::SourceChanged));
    assert_eq!(
        processes::parse_stat(b"4242 (unfinished", 4242),
        Err(Code::MalformedSource)
    );
    let before = processes::parse_stat(stat, 4242).unwrap();
    let after = processes::parse_stat(
        b"4242 (test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 54321 0 0",
        4242,
    )
    .unwrap();
    assert_eq!(
        processes::same_start(&before, &after),
        Err(Code::SourceChanged)
    );
    assert_eq!(processes::parse_uid(b"Name:\ttest\n"), Err(Code::NotFound));
}

#[test]
fn rejected_content_does_not_expose_environment_or_credentials() {
    assert_eq!(
        processes::parse_uid(b"Uid:\tSECRET\n"),
        Err(Code::MalformedSource)
    );
}

#[test]
fn private_join_preserves_identity_and_attributable_denied_fields() {
    use jocky_shared::collection::outcomes::Field;
    let stat = b"4242 (test worker) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0 0";
    let record = processes::join_process(
        4242,
        stat,
        stat,
        Ok(b"10000000-0000-4000-8000-000000000011\n"),
        Ok(b"Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n"),
        Ok(b"/usr/bin/test-worker"),
    )
    .unwrap();
    assert_eq!(record.pid, 4242);
    assert!(matches!(record.parent_pid, Field::Available { value: 1 }));
    assert!(matches!(record.uid, Field::Available { value: 1000 }));
    assert!(matches!(record.command, Field::Available { ref value } if value == "test worker"));
    assert!(
        matches!(record.executable, Field::Available { ref value } if value == "/usr/bin/test-worker")
    );
    assert!(
        matches!(record.start_identity, Field::Available { ref value } if value.start_ticks == "12345")
    );

    let denied = processes::join_process(
        4242,
        stat,
        stat,
        Err(Code::PermissionDenied),
        Err(Code::PermissionDenied),
        Err(Code::SourceDisappeared),
    )
    .unwrap();
    assert!(matches!(
        denied.uid,
        Field::Unavailable {
            reason: Code::PermissionDenied
        }
    ));
    assert!(matches!(
        denied.executable,
        Field::Unavailable {
            reason: Code::SourceDisappeared
        }
    ));
    assert!(matches!(
        denied.start_identity,
        Field::Unavailable {
            reason: Code::PermissionDenied
        }
    ));
    let with_ignored_status = processes::join_process(
        4242,
        stat,
        stat,
        Ok(b"10000000-0000-4000-8000-000000000011"),
        Ok(b"Uid:\t1000\nVmRSS:\t999 kB\nEnviron:\tSECRET_TOKEN\n"),
        Ok(b"/bin/test"),
    )
    .unwrap();
    assert!(
        !serde_json::to_string(&with_ignored_status)
            .unwrap()
            .contains("SECRET_TOKEN")
    );
    let reused = b"4242 (test worker) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 54321 0 0";
    assert_eq!(
        processes::join_process(
            4242,
            stat,
            reused,
            Ok(b"10000000-0000-4000-8000-000000000011"),
            Ok(b"Uid:\t1000"),
            Ok(b"/bin/test")
        ),
        Err(Code::SourceChanged)
    );
}
