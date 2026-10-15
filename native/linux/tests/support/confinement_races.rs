use super::*;
use jocky_forensic::collection::budget::Counter;

#[test]
fn replacing_a_pinned_name_cannot_redirect_the_readable_handle() {
    for replacement in ["symlink", "fifo", "regular", "unlink", "hardlink"] {
        let dir = scratch();
        let selected = dir.path().join("selected");
        fs::write(&selected, b"original").unwrap();
        let reference = path("selected");
        let ctx = context(&values(dir.path().to_str().unwrap(), "selected"));
        let mut clock = Frozen::default();
        let root = ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut clock,
            &false,
        )
        .unwrap();
        let pinned = root.pin_file("selected", &mut clock, &false).unwrap();
        if replacement == "hardlink" {
            fs::hard_link(&selected, dir.path().join("alias")).unwrap();
        } else if replacement == "unlink" {
            fs::remove_file(&selected).unwrap(); // Test-owned object only.
        } else {
            fs::rename(&selected, dir.path().join("retained")).unwrap();
            match replacement {
                "symlink" => symlink("retained", &selected).unwrap(),
                "fifo" => rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &selected,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap(),
                "regular" => fs::write(&selected, b"replacement").unwrap(),
                _ => unreachable!(),
            }
        }
        // Renames can have indistinguishable timestamps on coarse filesystems.
        // In that case only the retained original may be read, never replacement.
        match pinned.reopen(&mut clock, &false) {
            Err(Code::SourceChanged | Code::SourceDisappeared | Code::AliasDenied) => {}
            Ok(opened) if !matches!(replacement, "unlink" | "hardlink") => {
                let mut bytes = [0; 32];
                let n = rustix::io::read(opened.fd(), &mut bytes).unwrap();
                assert_eq!(&bytes[..n], b"original");
            }
            _ => panic!("unsafe or unexpected result for {replacement}"),
        }
    }
}

#[test]
fn cancellation_expiry_and_exhaustion_between_pin_and_reopen_remain_terminal() {
    for cause in [
        Code::Cancelled,
        Code::AuthorisationExpired,
        Code::ResourceLimit,
    ] {
        let dir = scratch();
        fs::write(dir.path().join("selected"), b"test").unwrap();
        let reference = path("selected");
        let ctx = context(&values(dir.path().to_str().unwrap(), "selected"));
        let target = OperationTarget::File(&reference);
        let mut clock = Frozen::default();
        let root =
            ConfinedRoot::open(&ctx, target, Exclusions::default(), &mut clock, &false).unwrap();
        let pinned = root.pin_file("selected", &mut clock, &false).unwrap();
        match cause {
            Code::AuthorisationExpired => {
                clock.0.utc = UtcTime::parse("2020-01-01T01:00:00Z").unwrap()
            }
            Code::ResourceLimit => assert_eq!(
                ctx.permit(target, &clock.0, false)
                    .unwrap()
                    .charge(Counter::Entries, u64::MAX),
                Err(cause)
            ),
            _ => {}
        }
        assert!(
            matches!(pinned.reopen(&mut clock, &(cause == Code::Cancelled)), Err(c) if c == cause)
        );
        assert!(matches!(pinned.reopen(&mut clock, &false), Err(c) if c == cause));
    }
}

#[test]
fn entries_are_charged_before_resolution_including_missing_names() {
    use jocky_forensic::collection::report::failure;
    use jocky_shared::collection::report::{ReportKind, WorkerCleanup};
    let dir = scratch();
    let reference = path("missing");
    let mut input = values(dir.path().to_str().unwrap(), "missing");
    let ancestors = dir.path().components().count() as u64 - 1;
    input[3]["limits"]["max_entries"] = serde_json::json!(ancestors + 1);
    let ctx = context(&input);
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::File(&reference),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    assert!(matches!(
        root.pin_file("missing", &mut clock, &false),
        Err(Code::NotFound)
    ));
    assert!(matches!(
        root.pin_file("missing", &mut clock, &false),
        Err(Code::ResourceLimit)
    ));
    let report = failure(
        &ctx,
        ReportKind::SyntheticTest,
        ctx.started_at().clone(),
        Code::ResourceLimit,
        WorkerCleanup::NotStarted,
    )
    .unwrap();
    assert_eq!(report.summary.work_used.entries, ancestors + 1);
}
