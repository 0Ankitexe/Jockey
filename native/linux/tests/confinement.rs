//! Direct private-module integration seam. Only test-owned repository files are touched.
#![cfg(target_os = "linux")]
#[path = "support/confinement_races.rs"]
mod races;
#[path = "support/confinement_scope.rs"]
mod scopes;
// This direct-module seam intentionally exercises confinement, not every
// private output/worker helper; the dedicated capability suite covers those.
#[allow(dead_code)]
#[path = "../src/sources/mod.rs"]
mod sources;
#[path = "support/confinement.rs"]
mod support;

use jocky_forensic::collection::context::OperationTarget;
use jocky_shared::collection::{Code, identity::UtcTime};
use sources::{metadata::Exclusions, paths::ConfinedRoot, reads::read_all};
use std::{
    fs,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
};
use support::{Frozen, context, path, scratch, values};

#[test]
fn only_selected_regular_files_get_readonly_handles_and_stability_checks() {
    let dir = scratch();
    fs::create_dir(dir.path().join("inside")).unwrap();
    let selected = dir.path().join("inside/file");
    fs::write(&selected, b"known synthetic bytes").unwrap();
    let reference = path("inside/file");
    let ctx = context(&values(
        dir.path().to_str().unwrap(),
        &reference.relative_path,
    ));
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::File(&reference),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    let pinned = root.pin_file("inside/file", &mut clock, &false).unwrap();
    let opened = pinned.reopen(&mut clock, &false).unwrap();
    assert!(
        rustix::io::fcntl_getfd(opened.fd())
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    let flags = rustix::fs::fcntl_getfl(opened.fd()).unwrap();
    assert_eq!(
        flags & rustix::fs::OFlags::ACCMODE,
        rustix::fs::OFlags::RDONLY
    );
    let bytes = read_all(&opened, 64, &mut clock, &false).unwrap();
    assert_eq!(bytes, b"known synthetic bytes");
    assert_eq!(
        rustix::io::write(opened.fd(), b"mutation"),
        Err(rustix::io::Errno::BADF)
    );
    opened.check_unchanged(&mut clock, &false).unwrap();
    fs::write(&selected, b"changed").unwrap();
    assert_eq!(
        opened.check_unchanged(&mut clock, &false),
        Err(Code::SourceChanged)
    );
}

#[test]
fn traversal_and_unrequested_siblings_fail_before_path_resolution() {
    let dir = scratch();
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
    for bad in [
        "../outside",
        "/absolute",
        "a/../selected",
        "./selected",
        "selected/",
        "a//b",
        "nul\0",
        "",
        "sibling",
    ] {
        assert!(
            matches!(
                root.pin_file(bad, &mut clock, &false),
                Err(Code::ScopeDenied | Code::InvalidInput)
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        root.pin_file("selected", &mut clock, &false),
        Err(Code::NotFound)
    ));
}

#[test]
fn symlinks_hardlinks_and_special_files_never_become_content_handles() {
    for kind in [
        "symlink",
        "parent-symlink",
        "magic-link",
        "hardlink",
        "fifo",
        "socket",
        "directory",
    ] {
        let dir = scratch();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("target"), b"must not become evidence").unwrap();
        let root_path = dir.path().join("root");
        fs::create_dir(&root_path).unwrap();
        let name = if kind == "parent-symlink" {
            "link/target"
        } else {
            "selected"
        };
        let selected = root_path.join("selected");
        let mut socket = None;
        let mut owned = None;
        match kind {
            "symlink" => symlink(outside.join("target"), &selected).unwrap(),
            "parent-symlink" => symlink(&outside, root_path.join("link")).unwrap(),
            "magic-link" => {
                use std::os::fd::AsRawFd;
                let file = fs::File::open(outside.join("target")).unwrap();
                symlink(format!("/proc/self/fd/{}", file.as_raw_fd()), &selected).unwrap();
                owned = Some(file);
            }
            "hardlink" => fs::hard_link(outside.join("target"), &selected).unwrap(),
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                &selected,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR,
                0,
            )
            .unwrap(),
            "socket" => socket = Some(UnixListener::bind(&selected).unwrap()),
            "directory" => fs::create_dir(&selected).unwrap(),
            _ => unreachable!(),
        }
        let reference = path(name);
        let ctx = context(&values(root_path.to_str().unwrap(), name));
        let mut clock = Frozen::default();
        let root = ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut clock,
            &false,
        )
        .unwrap();
        assert!(
            matches!(
                root.pin_file(name, &mut clock, &false),
                Err(Code::AliasDenied | Code::Unsupported)
            ),
            "{kind}"
        );
        assert_eq!(
            fs::read(outside.join("target")).unwrap(),
            b"must not become evidence"
        );
        drop((socket, owned));
    }
}

#[test]
fn expired_cancelled_or_wrong_target_contexts_cannot_open_even_a_missing_root() {
    let dir = scratch();
    let absent = dir.path().join("not-created");
    let reference = path("selected");
    let input = values(absent.to_str().unwrap(), "selected");
    let ctx = context(&input);
    let mut clock = Frozen::default();
    assert!(matches!(
        ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&path("other")),
            Exclusions::default(),
            &mut clock,
            &false
        ),
        Err(Code::ScopeDenied)
    ));
    assert!(matches!(
        ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut clock,
            &true
        ),
        Err(Code::Cancelled)
    ));
    let ctx = context(&input);
    clock.0.utc = UtcTime::parse("2020-01-01T01:00:00Z").unwrap();
    assert!(matches!(
        ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut clock,
            &false
        ),
        Err(Code::AuthorisationExpired)
    ));
}

#[test]
fn root_replacement_does_not_redirect_the_retained_descriptor() {
    let dir = scratch();
    let original = dir.path().join("root");
    fs::create_dir(&original).unwrap();
    fs::write(original.join("selected"), b"original").unwrap();
    let reference = path("selected");
    let ctx = context(&values(original.to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::File(&reference),
        Exclusions::default(),
        &mut clock,
        &false,
    )
    .unwrap();
    fs::rename(&original, dir.path().join("retained")).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join("selected"), b"replacement").unwrap();
    let pinned = root.pin_file("selected", &mut clock, &false).unwrap();
    let opened = pinned.reopen(&mut clock, &false).unwrap();
    let mut bytes = [0; 32];
    let n = rustix::io::read(opened.fd(), &mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"original");
}

#[test]
fn root_modes_and_parent_symlinks_are_rejected_not_repaired() {
    let dir = scratch();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    let alias = dir.path().join("alias");
    symlink(&real, &alias).unwrap();
    let reference = path("selected");
    for root_path in [&alias, &real] {
        if root_path == &real {
            fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
        }
        let ctx = context(&values(root_path.to_str().unwrap(), "selected"));
        let result = ConfinedRoot::open(
            &ctx,
            OperationTarget::File(&reference),
            Exclusions::default(),
            &mut Frozen::default(),
            &false,
        );
        assert!(matches!(
            result,
            Err(Code::AliasDenied | Code::PermissionDenied)
        ));
    }
    assert_eq!(
        fs::metadata(&real).unwrap().permissions().mode() & 0o777,
        0o777
    );
}

#[test]
fn excluded_inode_aliases_are_rejected_even_after_a_name_change() {
    use sources::metadata::ObjectId;
    use std::os::unix::fs::MetadataExt;
    let dir = scratch();
    let config = dir.path().join("configuration");
    fs::write(&config, b"authority not evidence").unwrap();
    let stat = fs::metadata(&config).unwrap();
    let excluded = Exclusions::new(&[ObjectId {
        device: stat.dev(),
        inode: stat.ino(),
    }])
    .unwrap();
    fs::rename(&config, dir.path().join("selected")).unwrap();
    let reference = path("selected");
    let ctx = context(&values(dir.path().to_str().unwrap(), "selected"));
    let mut clock = Frozen::default();
    let root = ConfinedRoot::open(
        &ctx,
        OperationTarget::File(&reference),
        excluded,
        &mut clock,
        &false,
    )
    .unwrap();
    assert!(matches!(
        root.pin_file("selected", &mut clock, &false),
        Err(Code::AliasDenied)
    ));
}
