//! Offline argument and status assertions for the standalone CLI.
#![cfg(target_os = "linux")]
#[path = "../src/cli/mod.rs"]
#[allow(dead_code)]
mod cli;
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
use cli::args;
use jocky_shared::collection::Code;

fn parse(values: &[&str]) -> Result<args::Command, Code> {
    args::parse(&values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>())
}

#[test]
fn help_and_version_are_pure_and_duplicate_collect_flags_deny() {
    assert!(matches!(parse(&["--help"]), Ok(args::Command::Help)));
    assert!(matches!(parse(&["--version"]), Ok(args::Command::Version)));
    assert!(matches!(
        parse(&["collect", "--allow-live-lab", "--allow-live-lab"]),
        Err(Code::InvalidInput)
    ));
    assert!(matches!(
        parse(&["collect", "--designation", "/not-read"]),
        Err(Code::InvalidInput)
    ));
    assert!(matches!(
        parse(&["__worker", "--allow-live-lab"]),
        Err(Code::InvalidInput)
    ));
}

#[test]
fn every_config_flag_is_required_once_and_indicators_is_optional() {
    let required = ["--designation", "--authorisation", "--policy", "--request"];
    let mut complete = vec!["validate-inputs"];
    for flag in required {
        complete.extend([flag, "/owned/input"]);
    }
    assert!(matches!(
        parse(&complete),
        Ok(args::Command::Validate {
            indicators: None,
            ..
        })
    ));
    let mut with_indicators = complete.clone();
    with_indicators.extend(["--indicators", "/owned/indicators"]);
    assert!(matches!(
        parse(&with_indicators),
        Ok(args::Command::Validate {
            indicators: Some(_),
            ..
        })
    ));
    for missing in required {
        let mut incomplete = vec!["validate-inputs"];
        for flag in required {
            if flag != missing {
                incomplete.extend([flag, "/owned/input"]);
            }
        }
        assert!(
            matches!(parse(&incomplete), Err(Code::InvalidInput)),
            "{missing}"
        );
    }
    for duplicate in required.into_iter().chain(["--indicators"]) {
        let mut repeated = with_indicators.clone();
        repeated.extend([duplicate, "/owned/other"]);
        assert!(
            matches!(parse(&repeated), Err(Code::InvalidInput)),
            "{duplicate}"
        );
    }
}

#[test]
fn collect_requires_explicit_opt_in_output_and_exact_paths() {
    let valid = [
        "collect",
        "--allow-live-lab",
        "--designation",
        "/d",
        "--authorisation",
        "/a",
        "--policy",
        "/p",
        "--request",
        "/r",
        "--output",
        "/owned/new-report.json",
    ];
    assert!(matches!(parse(&valid), Ok(args::Command::Collect { .. })));
    let reordered = [
        "collect",
        "--designation",
        "/d",
        "--authorisation",
        "/a",
        "--policy",
        "/p",
        "--request",
        "/r",
        "--output",
        "/owned/new-report.json",
        "--allow-live-lab",
    ];
    assert!(matches!(
        parse(&reordered),
        Ok(args::Command::Collect { .. })
    ));
    for missing in [
        "--allow-live-lab",
        "--designation",
        "--authorisation",
        "--policy",
        "--request",
        "--output",
    ] {
        let mut bad = Vec::new();
        let mut index = 0;
        while index < valid.len() {
            if valid[index] == missing {
                index += if missing == "--allow-live-lab" { 1 } else { 2 };
            } else {
                bad.push(valid[index]);
                index += 1;
            }
        }
        assert!(matches!(parse(&bad), Err(Code::InvalidInput)), "{missing}");
    }
    for duplicate in [
        "--designation",
        "--authorisation",
        "--policy",
        "--request",
        "--output",
    ] {
        let mut bad = valid.to_vec();
        bad.extend([duplicate, "/another"]);
        assert!(
            matches!(parse(&bad), Err(Code::InvalidInput)),
            "{duplicate}"
        );
    }
    let mut with_indicators = valid.to_vec();
    with_indicators.extend(["--indicators", "/i"]);
    assert!(matches!(
        parse(&with_indicators),
        Ok(args::Command::Collect {
            indicators: Some(_),
            ..
        })
    ));
}

#[test]
fn each_available_command_has_a_typed_status_and_exit() {
    let cases: &[(&[&str], u8, &str)] = &[
        (&["--help"], 0, "Help"),
        (&["--version"], 0, "Version"),
        (&["collect", "--allow-live-lab"], 3, "InvalidInput"),
        (&["__worker"], 4, "NotImplemented"),
        (&["collect"], 3, "InvalidInput"),
        (&["unknown"], 3, "InvalidInput"),
        (&["verify-report"], 3, "InvalidInput"),
        (&["validate-inputs"], 3, "InvalidInput"),
    ];
    for (argv, expected_exit, expected_code) in cases {
        let output = cli::status::run(&argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_eq!(output.exit, *expected_exit, "{argv:?}");
        assert_eq!(output.stderr, *expected_exit != 0, "{argv:?}");
        assert!(output.bytes.len() <= 8192, "{argv:?}");
        assert_eq!(output.bytes.last(), Some(&b'\n'));
        let status: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert!(status.to_string().contains(expected_code), "{argv:?}");
    }
}

#[test]
fn invalid_report_and_duplicate_or_unknown_flags_fail_closed() {
    for argv in [
        vec!["verify-report", "/not-an-owned-report"],
        vec!["verify-report", ""],
        vec!["collect", "--allow-live-lab", "--allow-live-lab"],
        vec!["validate-inputs", "--designation", "/a"],
        vec![
            "validate-inputs",
            "--designation",
            "/a",
            "--authorisation",
            "/b",
            "--policy",
            "/c",
            "--request",
            "/d",
            "--unknown",
            "/e",
        ],
    ] {
        let output = cli::status::run(&argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_ne!(output.exit, 0, "{argv:?}");
        assert!(output.stderr);
    }
}

#[test]
fn failed_status_stream_cannot_return_success() {
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_jocky-collect-linux"))
        .arg("--help")
        .stdout(sink)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(5));
}

#[test]
fn private_status_seam_maps_collision_signal_mixed_failure_and_publication() {
    use jocky_shared::collection::report::{Stage, StatusCode, SuccessCode};
    for (code, exit) in [
        (Code::OutputExists, 3),
        (Code::Cancelled, 5),
        (Code::WorkerFailed, 5),
        (Code::WorkerProtocol, 5),
        (Code::ResourceLimit, 5),
    ] {
        let output = cli::status::render(cli::commands::Reply {
            code: StatusCode::Error(code),
            stage: Stage::Publication,
            identifiers: None,
            report: None,
            interrupted: false,
        });
        assert_eq!(output.exit, exit);
        assert!(output.stderr);
        let status: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert_eq!(status["stage"], "publication");
    }
    for success in [
        SuccessCode::PublishedComplete,
        SuccessCode::PublishedPartial,
        SuccessCode::PublishedFailed,
    ] {
        let missing_digest = cli::status::render(cli::commands::Reply {
            code: StatusCode::Success(success),
            stage: Stage::Publication,
            identifiers: None,
            report: None,
            interrupted: false,
        });
        assert_eq!(missing_digest.exit, 5);
        assert!(missing_digest.stderr);
        assert!(
            String::from_utf8(missing_digest.bytes)
                .unwrap()
                .contains("WorkerProtocol")
        );
    }
    let mixed_published = cli::status::render(cli::commands::Reply {
        code: StatusCode::Success(SuccessCode::PublishedPartial),
        stage: Stage::Publication,
        identifiers: None,
        report: Some(("a".repeat(64), 128)),
        interrupted: false,
    });
    assert_eq!(mixed_published.exit, 2);
    assert!(!mixed_published.stderr);
    let status: serde_json::Value = serde_json::from_slice(&mixed_published.bytes).unwrap();
    assert_eq!(status["code"], "PublishedPartial");
    assert_eq!(status["report_digest"], "a".repeat(64));
    for malformed in ["short".to_owned(), "A".repeat(64), "z".repeat(64)] {
        let output = cli::status::render(cli::commands::Reply {
            code: StatusCode::Success(SuccessCode::PublishedComplete),
            stage: Stage::Publication,
            identifiers: None,
            report: Some((malformed, 128)),
            interrupted: false,
        });
        assert_eq!(output.exit, 5);
    }
    let signal = cli::status::render(cli::commands::Reply {
        code: StatusCode::Error(Code::Cancelled),
        stage: Stage::Finalization,
        identifiers: None,
        report: None,
        interrupted: true,
    });
    assert_eq!(signal.exit, 130);
    let failed_publication = cli::status::render(cli::commands::Reply {
        code: StatusCode::Error(Code::PublicationFailed),
        stage: Stage::Publication,
        identifiers: None,
        report: None,
        interrupted: true,
    });
    assert_eq!(failed_publication.exit, 5);
}
