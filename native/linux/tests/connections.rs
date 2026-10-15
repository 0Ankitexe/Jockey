//! Network table decoding never creates a socket or performs DNS.
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
use collectors::connections;
use jocky_shared::collection::Code;

const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

#[test]
fn ipv4_ipv6_tcp_udp_rows_decode_with_explicit_family() {
    let v4 = format!("{HEADER}   0: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 1000 0 12345\n");
    let row = connections::parse_table(v4.as_bytes(), connections::Family::Ipv4)
        .unwrap()
        .remove(0);
    assert_eq!(row.local_address, "127.0.0.1");
    assert_eq!(row.local_port, 8080);
    assert_eq!(row.inode, "12345");
    let v6 = format!(
        "{HEADER} 0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 0:0 00:0 0 0 0 7\n"
    );
    assert_eq!(
        connections::parse_table(v6.as_bytes(), connections::Family::Ipv6).unwrap()[0]
            .local_address,
        "::1"
    );
    for (family, raw, expected) in [
        (connections::Family::Ipv4, v4.as_bytes(), "127.0.0.1"),
        (connections::Family::Ipv6, v6.as_bytes(), "::1"),
    ] {
        // TCP and UDP use the same documented address layout; table selection
        // supplies the protocol and never opens a socket.
        for _protocol in ["tcp", "udp"] {
            let rows = connections::parse_table(raw, family).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].local_address, expected);
        }
    }
}

#[test]
fn malformed_oversized_or_ambiguous_owners_never_become_unique() {
    assert_eq!(
        connections::parse_table(b"bad", connections::Family::Ipv4),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        connections::parse_table(b"", connections::Family::Ipv4),
        Err(Code::MalformedSource)
    );
    assert_eq!(
        connections::unique_owner(&[42, 43]),
        Err(Code::AmbiguousOwner)
    );
    assert_eq!(connections::unique_owner(&[]), Err(Code::NotFound));
    assert_eq!(connections::unique_owner(&[42]).unwrap(), 42);
    assert_eq!(
        connections::socket_inode_link(b"socket:[12345]").unwrap(),
        Some("12345".into())
    );
    assert_eq!(connections::socket_inode_link(b"/dev/null").unwrap(), None);
    assert_eq!(
        connections::socket_inode_link(b"socket:[1/2]"),
        Err(Code::MalformedSource)
    );
    let mut oversized = HEADER.as_bytes().to_vec();
    oversized.resize(65_537, b' ');
    assert_eq!(
        connections::parse_table(&oversized, connections::Family::Ipv4),
        Err(Code::ResourceLimit)
    );
}

#[test]
fn private_join_keeps_namespace_denial_and_pid_race_attributable() {
    use jocky_shared::collection::{
        outcomes::Field,
        records::{AddressFamily, Protocol},
    };
    let table = format!("{HEADER}   0: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 1000 0 12345\n");
    let row = connections::parse_table(table.as_bytes(), connections::Family::Ipv4)
        .unwrap()
        .remove(0);
    let owners = std::collections::BTreeMap::new();
    let (raced, reason) = connections::connection(
        row.clone(),
        Protocol::Tcp,
        AddressFamily::Ipv4,
        &owners,
        Some(Code::SourceChanged),
        &Err(Code::PermissionDenied),
    );
    assert_eq!(reason, Some(Code::SourceChanged));
    assert!(matches!(
        raced.owners,
        Field::Unavailable {
            reason: Code::SourceChanged
        }
    ));
    assert!(matches!(
        raced.namespace,
        Field::Unavailable {
            reason: Code::PermissionDenied
        }
    ));
    let (missing, reason) = connections::connection(
        row,
        Protocol::Udp,
        AddressFamily::Ipv4,
        &owners,
        None,
        &Ok("net:[7]".into()),
    );
    assert_eq!(reason, Some(Code::NotFound));
    assert!(matches!(missing.namespace, Field::Available { value } if value == "net:[7]"));
}
