//! Portable static obligations, including uncalled source functions.
#[path = "support/artifacts.rs"]
mod artifacts;
use artifacts::OwnedDir;
use std::process::Command;
fn check(target: &str, body: &str) -> std::process::Output {
    let dir = OwnedDir::new("portable-semantic");
    let source = format!(
        "module demo\ntarget {target}\nfn inspect(t: endpoint) -> forensic_result {{ {body} }}\nrun inspect on selected_endpoints\n"
    );
    let file = dir.write("source.jky", source);
    Command::new(env!("CARGO_BIN_EXE_jockyc"))
        .args([
            "check",
            file.to_str().unwrap(),
            "--language-version",
            "3.0.0",
            "--diagnostic-format",
            "json",
        ])
        .output()
        .unwrap()
}
#[test]
fn every_selected_target_must_be_supported() {
    for (targets, call, expected) in [
        (
            "linux",
            "forensic.event.ubuntu_journal(t, since, until, limit)",
            false,
        ),
        (
            "linux",
            "forensic.event.windows_log(t, channel, since, until, limit)",
            false,
        ),
        ("windows", "forensic.service.list(t)", false),
        ("windows | linux", "forensic.service.list(t)", false),
        ("linux", "forensic.system.profile(t)", true),
    ] {
        let dir = OwnedDir::new("portable-targets");
        let source = format!(
            "module demo\ntarget {targets}\nfn probe(t: endpoint, since: timestamp, until: timestamp, limit: int, channel: string) -> forensic_result {{ let observed = {call} return forensic.system.profile(t) }}\nfn inspect(t: endpoint) -> forensic_result {{ return forensic.system.profile(t) }}\nrun inspect on selected_endpoints\n"
        );
        let file = dir.write("source.jky", source);
        let output = Command::new(env!("CARGO_BIN_EXE_jockyc"))
            .args([
                "check",
                file.to_str().unwrap(),
                "--language-version",
                "3.0.0",
                "--diagnostic-format",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            expected,
            "{targets}/{call}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !expected {
            assert!(!output.stderr.is_empty() || !output.stdout.is_empty());
        }
    }
}
#[test]
fn dead_code_still_has_static_target_obligations_and_privilege_is_not_authority() {
    let dir = OwnedDir::new("portable-dead-code");
    let file = dir.write("source.jky", "module demo\ntarget linux\nfn unused(t: endpoint) -> list<event_record> { return forensic.event.ubuntu_journal(t) }\nfn inspect(t: endpoint) -> forensic_result { return forensic.system.profile(t) }\nrun inspect on selected_endpoints\n");
    let output = Command::new(env!("CARGO_BIN_EXE_jockyc"))
        .args([
            "check",
            file.to_str().unwrap(),
            "--language-version",
            "3.0.0",
            "--diagnostic-format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("unsupported-target"));
    let output = check("linux", "return forensic.system.profile(t)");
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["registry"]["schema_version"], "2.0.0");
    assert_eq!(report["language_version"], "3.0.0");
}
