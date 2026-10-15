//! Synthetic profile facts only; no host endpoint reads.
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
use collectors::system;
#[path = "../src/cli/mod.rs"]
#[allow(dead_code)]
mod cli;

use jocky_shared::collection::Code;

#[test]
fn four_distro_profiles_parse_only_supplied_release_facts() {
    for (name, id) in [
        ("debian", "debian"),
        ("ubuntu", "ubuntu"),
        ("fedora", "fedora"),
        ("arch", "arch"),
    ] {
        let raw = std::fs::read(format!(
            "{}/tests/fixtures/{name}/etc/os-release",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let facts = system::parse_os_release(&raw).unwrap();
        assert_eq!(facts.id, id);
        assert!(!facts.version.is_empty());
        let profile = system::decode_profile(system::ProfileRaw {
            kernel_version: Ok(b"Linux version 6.12.1 (builder) #1 SMP\n"),
            hostname: Ok(b"owned-vm\n"),
            boot_id: Ok(b"10000000-0000-4000-8000-000000000011\n"),
            primary_release: Ok(&raw),
            fallback_release: Err(Code::NotFound),
            architecture: Ok("x86_64"),
        });
        assert!(profile.failures.is_empty(), "{name}");
        assert!(
            matches!(profile.payload.distribution_id, jocky_shared::collection::outcomes::Field::Available { ref value } if value == id)
        );
        assert!(
            matches!(profile.payload.hostname, jocky_shared::collection::outcomes::Field::Available { ref value } if value == "owned-vm")
        );
    }
}

#[test]
fn malformed_missing_and_fallback_remain_distinct() {
    assert_eq!(
        system::parse_os_release(b"ID=debian\nID=arch\n"),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        system::parse_os_release(b"ID=\"debian\nVERSION_ID=13\n"),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        system::parse_os_release(b"NAME=Example\n"),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        system::select_release(
            Err(Code::PermissionDenied),
            Ok(b"ID=debian\nVERSION_ID=13\n")
        ),
        Err(Code::PermissionDenied)
    );
    assert_eq!(
        system::select_release(Err(Code::NotFound), Ok(b"ID=debian\nVERSION_ID=13\n"))
            .unwrap()
            .id,
        "debian"
    );
    assert_eq!(
        system::select_release(Err(Code::NotFound), Err(Code::NotFound)),
        Err(Code::NotFound)
    );
}

#[test]
fn kernel_fields_do_not_infer_abi_or_permissions_from_distro() {
    assert_eq!(
        system::parse_kernel_line(b"Linux version 6.12.1 (builder) #1 SMP\n")
            .unwrap()
            .release,
        "6.12.1"
    );
    assert_eq!(
        system::parse_kernel_line(b"not a kernel line"),
        Err(Code::MalformedSource)
    );
}

#[test]
fn decoded_profile_carries_real_supplied_fields_and_typed_partial_failures() {
    use jocky_shared::collection::outcomes::Field;
    let snapshot = system::decode_profile(system::ProfileRaw {
        kernel_version: Ok(b"Linux version 6.12.1 (builder) #1 SMP\n"),
        hostname: Err(Code::PermissionDenied),
        boot_id: Ok(b"10000000-0000-4000-8000-000000000011\n"),
        primary_release: Ok(b"ID=debian\nVERSION_ID=13\n"),
        fallback_release: Err(Code::NotFound),
        architecture: Ok("x86_64"),
    });
    assert!(
        matches!(snapshot.payload.kernel_release, Field::Available { ref value } if value == "6.12.1")
    );
    assert!(matches!(
        snapshot.payload.hostname,
        Field::Unavailable {
            reason: Code::PermissionDenied
        }
    ));
    assert_eq!(
        snapshot.failures,
        vec![("hostname", Code::PermissionDenied)]
    );
}

#[test]
fn distro_label_does_not_turn_denied_kernel_facts_into_available_values() {
    use jocky_shared::collection::outcomes::Field;
    for id in ["debian", "ubuntu", "fedora", "arch"] {
        let release = format!("ID={id}\nVERSION_ID=1\n");
        let snapshot = system::decode_profile(system::ProfileRaw {
            kernel_version: Err(Code::PermissionDenied),
            hostname: Err(Code::PermissionDenied),
            boot_id: Err(Code::PermissionDenied),
            primary_release: Ok(release.as_bytes()),
            fallback_release: Err(Code::NotFound),
            architecture: Err(Code::PermissionDenied),
        });
        assert!(matches!(
            snapshot.payload.kernel_release,
            Field::Unavailable {
                reason: Code::PermissionDenied
            }
        ));
        assert!(matches!(
            snapshot.payload.architecture,
            Field::Unavailable {
                reason: Code::PermissionDenied
            }
        ));
        assert!(matches!(
            snapshot.payload.boot_id,
            Field::Unavailable {
                reason: Code::PermissionDenied
            }
        ));
        assert_eq!(snapshot.failures.len(), 5);
    }
}
