//! Input-file tests only, inside repository-owned temporary directories. No endpoint reads.
#![cfg(target_os = "linux")]
use jocky_forensic::collection::ClockReading;
use jocky_native_linux::cli::config::{ConfigPaths, read_configuration};
use jocky_shared::collection::{Code, identity::UtcTime};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    path::PathBuf,
};

fn scratch() -> tempfile::TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()
        .unwrap();
    tempfile::Builder::new()
        .prefix("v5-config-test-")
        .tempdir_in(root)
        .unwrap()
}
fn fixtures(root: &std::path::Path) -> ConfigPaths {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/valid/collection");
    let names = ["endpoint-designation", "authorisation", "policy", "request"];
    let paths = names.map(|name| {
        let path = root.join(format!("{name}.json"));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        output
            .write_all(&fs::read(source.join(format!("{name}.json"))).unwrap())
            .unwrap();
        path.to_str().unwrap().to_owned()
    });
    ConfigPaths::new(paths.each_ref().map(String::as_str), None).unwrap()
}
fn clock() -> ClockReading {
    ClockReading {
        utc: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        monotonic_ms: 0,
    }
}

#[test]
fn explicit_owned_regular_inputs_validate_without_a_live_permit() {
    let dir = scratch();
    let paths = fixtures(dir.path());
    let inputs = read_configuration(&paths).unwrap();
    let status = inputs.validate(clock()).unwrap();
    assert_eq!(
        status.endpoint_id.as_str(),
        "10000000-0000-4000-8000-000000000002"
    );
    assert_eq!(inputs.identities().count(), 4);
    assert!(jocky_native_linux::bootstrap().is_err());
    assert!(matches!(
        inputs.validate(ClockReading {
            utc: UtcTime::parse("2026-10-09T00:00:00Z").unwrap(),
            monotonic_ms: 0
        }),
        Err(Code::AuthorisationExpired)
    ));
}

#[test]
fn lexical_duplicates_traversal_and_relative_names_fail_before_open() {
    for invalid in [
        "relative.json",
        "/tmp/../data",
        "/tmp//data",
        "/tmp/./data",
        "/tmp/data/",
        "/",
        "/tmp/nu\0l",
    ] {
        assert!(matches!(
            ConfigPaths::new([invalid, "/b", "/c", "/d"], None),
            Err(Code::InvalidInput)
        ));
    }
    assert!(matches!(
        ConfigPaths::new(["/a", "/b", "/a", "/d"], None),
        Err(Code::AliasDenied)
    ));
    assert!(matches!(
        ConfigPaths::new(["/a", "/b", "/c", "/d"], Some("/b")),
        Err(Code::AliasDenied)
    ));
}

#[test]
fn authority_modes_parent_permissions_and_symlinks_are_not_repaired() {
    let dir = scratch();
    let paths = fixtures(dir.path());
    let grant = dir.path().join("authorisation.json");
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        read_configuration(&paths),
        Err(Code::PermissionDenied)
    ));
    assert_eq!(
        fs::metadata(&grant).unwrap().permissions().mode() & 0o777,
        0o644
    );
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        read_configuration(&paths),
        Err(Code::PermissionDenied)
    ));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let saved = dir.path().join("saved-grant");
    fs::rename(&grant, &saved).unwrap();
    symlink(&saved, &grant).unwrap();
    assert!(matches!(read_configuration(&paths), Err(Code::AliasDenied)));
}

#[test]
fn directory_fifo_socket_and_hardlink_inputs_never_become_regular_reads() {
    for kind in ["directory", "fifo", "socket", "hardlink"] {
        let dir = scratch();
        let paths = fixtures(dir.path());
        let path = dir.path().join("request.json");
        fs::remove_file(&path).unwrap();
        let socket = match kind {
            "directory" => {
                fs::create_dir(&path).unwrap();
                None
            }
            "fifo" => {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
                None
            }
            "socket" => Some(UnixListener::bind(&path).unwrap()),
            "hardlink" => {
                fs::hard_link(dir.path().join("policy.json"), &path).unwrap();
                None
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(
                read_configuration(&paths),
                Err(Code::AliasDenied | Code::InvalidInput)
            ),
            "{kind}"
        );
        drop(socket);
    }
}

#[test]
fn byte_boundary_duplicate_keys_and_mutated_config_fail_explicitly() {
    let dir = scratch();
    let paths = fixtures(dir.path());
    let path = dir.path().join("request.json");
    // A bounded file is readable, but not thereby a valid document or authority.
    fs::write(&path, vec![b' '; 65536]).unwrap();
    assert!(read_configuration(&paths).is_ok());
    assert_eq!(
        read_configuration(&paths)
            .unwrap()
            .validate(clock())
            .unwrap_err(),
        Code::InvalidInput
    );
    fs::write(&path, vec![b' '; 65537]).unwrap();
    assert!(matches!(
        read_configuration(&paths),
        Err(Code::ResourceLimit)
    ));
    fs::write(
        &path,
        br#"{"schema_version":"1.0.0","schema_version":"1.0.0"}"#,
    )
    .unwrap();
    assert_eq!(
        read_configuration(&paths)
            .unwrap()
            .validate(clock())
            .unwrap_err(),
        Code::InvalidInput
    );
}

#[test]
fn missing_file_is_not_an_empty_configuration_and_errors_are_redacted() {
    let dir = scratch();
    let paths = fixtures(dir.path());
    fs::remove_file(dir.path().join("policy.json")).unwrap();
    let Err(code) = read_configuration(&paths) else {
        panic!("missing policy accepted")
    };
    assert_eq!(code, Code::NotFound);
    assert!(!format!("{code:?}").contains(dir.path().to_str().unwrap()));
}

#[test]
fn parent_symlink_and_optional_indicator_alias_are_rejected() {
    let dir = scratch();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    let _ = fixtures(&real);
    let alias = dir.path().join("alias");
    symlink(&real, &alias).unwrap();
    let names = ["endpoint-designation", "authorisation", "policy", "request"]
        .map(|n| alias.join(format!("{n}.json")).to_str().unwrap().to_owned());
    let paths = ConfigPaths::new(names.each_ref().map(String::as_str), None).unwrap();
    assert!(read_configuration(&paths).is_err());
    let names = ["endpoint-designation", "authorisation", "policy", "request"]
        .map(|n| real.join(format!("{n}.json")).to_str().unwrap().to_owned());
    let copy = real.join("indicators.json");
    fs::hard_link(real.join("request.json"), &copy).unwrap();
    let paths = ConfigPaths::new(names.each_ref().map(String::as_str), copy.to_str()).unwrap();
    assert!(matches!(read_configuration(&paths), Err(Code::AliasDenied)));
}
