//! Direct v3 APIs are active before T175 adds CLI dispatch.
use jocky_forensic::contracts::v2::builtin_registry;
use jocky_language::{SourceFile, parse_source_v3, report::v2, semantic::v3::analyze};
use serde_json::Value;
fn source(target: &str, body: &str) -> String {
    format!(
        "module demo\ntarget {target}\nfn inspect(t: endpoint) -> forensic_result {{ {body} }}\nrun inspect on selected_endpoints\n"
    )
}
#[test]
fn portable_parser_preserves_context_and_byte_spans() {
    for target in [
        "linux",
        "windows | linux",
        "ubuntu | linux",
        "windows | ubuntu",
    ] {
        for text in [
            source(target, "return forensic.system.profile(t)"),
            source(target, "return forensic.system.profile(t)").replace('\n', "\r\n"),
        ] {
            let parsed = parse_source_v3(SourceFile::new("x", &text)).unwrap();
            assert_eq!(parsed.program.span.end, text.len());
            let emitted: Value = serde_json::from_slice(&parsed.to_pretty_json().unwrap()).unwrap();
            assert_eq!(emitted["schema_version"], "3.0.0");
            assert_eq!(
                emitted["program"]["target"]["platforms"]
                    .as_array()
                    .unwrap()
                    .len(),
                target.split(" | ").count()
            );
        }
    }
    let text = source("linux", "return forensic.system.profile(t)").replace("inspect", "linux");
    assert!(parse_source_v3(SourceFile::new("x", &text)).is_ok());
}
#[test]
fn bad_portable_targets_and_old_parser_reject_without_fallback() {
    for target in [
        "linux | linux",
        "linux | ubuntu",
        "ubuntu | windows",
        "linux | windows",
        "windows | ubuntu | linux",
        "macos",
        "",
    ] {
        assert!(
            parse_source_v3(SourceFile::new(
                "x",
                &source(target, "return forensic.system.profile(t)")
            ))
            .is_err(),
            "{target}"
        );
    }
    assert!(
        jocky_language::parse_source(SourceFile::new(
            "x",
            &source("linux", "return forensic.system.profile(t)")
        ))
        .is_err()
    );
}
#[test]
fn portable_semantics_require_every_declared_target_even_in_dead_code() {
    let registry = builtin_registry().unwrap();
    for (target, name) in [
        ("linux", "forensic.event.ubuntu_journal"),
        ("linux", "forensic.event.windows_log"),
        ("windows", "forensic.service.list"),
        ("windows | linux", "forensic.service.list"),
    ] {
        let text = format!(
            "module demo\ntarget {target}\nfn unused(t: endpoint) -> forensic_result {{ let observation = {name}(t) return forensic.system.profile(t) }}\nfn inspect(t: endpoint) -> forensic_result {{ return forensic.system.profile(t) }}\nrun inspect on selected_endpoints\n"
        );
        let error = analyze(SourceFile::new("x", &text), registry).unwrap_err();
        let jocky_language::semantic::CheckFailure::Semantic(diagnostics) = error else {
            panic!("expected semantic error")
        };
        assert!(
            diagnostics
                .items()
                .iter()
                .any(|d| d.code().as_str() == "unsupported-target"),
            "{target}/{name}"
        );
    }
    let text = source("linux", "return forensic.system.profile(t)");
    let checked = analyze(SourceFile::new("x", &text), registry).unwrap();
    assert_eq!(
        checked.selected_targets().collect::<Vec<_>>(),
        [jocky_shared::compiler::v2::Platform::Linux]
    );
    let report: Value =
        serde_json::from_slice(&v2::from_checked(SourceFile::new("x", &text), &checked).unwrap())
            .unwrap();
    assert_eq!(report["schema_version"], "2.0.0");
    assert_eq!(report["language_version"], "3.0.0");
    assert_eq!(report["registry"]["schema_version"], "2.0.0");
    assert_eq!(
        report["metadata"]["selected_targets"],
        serde_json::json!(["linux"])
    );
}

#[test]
fn portable_lowering_is_deterministic_and_verifies_without_collection() {
    let registry = builtin_registry().unwrap();
    for target in ["linux", "windows | linux", "ubuntu | linux"] {
        let text = source(target, "return forensic.system.profile(t)");
        let checked = analyze(SourceFile::new("portable", &text), registry).unwrap();
        let first = jocky_language::lowering::v3::lower(&checked, Default::default()).unwrap();
        let second = jocky_language::lowering::v3::lower(&checked, Default::default()).unwrap();
        let bytes = first.to_json().unwrap();
        assert_eq!(bytes, second.to_json().unwrap());
        let decoded = jocky_ir::v2::decode_ir(&bytes).unwrap();
        assert_eq!(decoded.language_version, "3.0.0");
        assert_eq!(decoded.registry.schema_version, "2.0.0");
        jocky_ir::v2::verify(decoded, registry).unwrap();
    }
}
