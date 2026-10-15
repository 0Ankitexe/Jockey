//! Bounded /proc/net text decoding; no socket creation or DNS.
use crate::{
    collection::Collected,
    sources::procfs::{FixedMount, MountKind, Query, links::LinkQuery},
};
use jocky_forensic::collection::{
    ValidatedCollectionContext,
    budget::Counter,
    clock::Clock,
    context::OperationTarget,
    identity::{IdentityKind, derive_id},
};
use jocky_shared::collection::{
    Code,
    identity::{ClockBasis, TimeObservation, Uuid},
    inputs::SourceKind,
    launch::{HandleKind, WorkerLaunch},
    outcomes::{
        Collector, CollectorOutcome, CollectorStatus, Coverage, FacilityState, Field, ItemError,
    },
    records::{
        Adapter, AddressFamily, Category, ConnectionRecord, Payload, ProcessIdentity, Protocol,
        ProvenanceKind,
    },
};
use rustix::fd::{AsFd, OwnedFd};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SocketRow {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub uid: u32,
    pub inode: String,
}

fn endpoint(value: &str, family: Family) -> Result<(String, u16), Code> {
    let (hex, port) = value.split_once(':').ok_or(Code::MalformedSource)?;
    let port = u16::from_str_radix(port, 16).map_err(|_| Code::MalformedSource)?;
    let address = match family {
        Family::Ipv4 if hex.len() == 8 => {
            let word = u32::from_str_radix(hex, 16).map_err(|_| Code::MalformedSource)?;
            Ipv4Addr::from(word.to_le_bytes()).to_string()
        }
        Family::Ipv6 if hex.len() == 32 => {
            let mut bytes = [0; 16];
            for (i, chunk) in hex.as_bytes().as_chunks::<8>().0.iter().enumerate() {
                let text = std::str::from_utf8(chunk).map_err(|_| Code::MalformedSource)?;
                let word = u32::from_str_radix(text, 16).map_err(|_| Code::MalformedSource)?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Ipv6Addr::from(bytes).to_string()
        }
        _ => return Err(Code::MalformedSource),
    };
    Ok((address, port))
}

fn sort_rows(rows: &mut [(SocketRow, Protocol, AddressFamily)]) {
    rows.sort_by(|a, b| {
        let key = |(row, protocol, family): &(SocketRow, Protocol, AddressFamily)| {
            (
                *protocol,
                *family,
                row.local_address.parse::<IpAddr>().ok(),
                row.local_port,
                row.remote_address.parse::<IpAddr>().ok(),
                row.remote_port,
                row.inode.parse::<u128>().ok(),
            )
        };
        key(a).cmp(&key(b))
    });
}

pub(crate) fn parse_table(raw: &[u8], family: Family) -> Result<Vec<SocketRow>, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    let mut lines = text.lines();
    let header = lines.next().ok_or(Code::MalformedSource)?;
    if !header.contains("local_address") || !header.contains("inode") {
        return Err(Code::MalformedSource);
    }
    let mut rows = Vec::new();
    for line in lines {
        if rows.len() >= 20_000 {
            return Err(Code::ResourceLimit);
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 10 || !fields[0].ends_with(':') {
            return Err(Code::MalformedSource);
        }
        let (local_address, local_port) = endpoint(fields[1], family)?;
        let (remote_address, remote_port) = endpoint(fields[2], family)?;
        let uid = fields[7].parse().map_err(|_| Code::MalformedSource)?;
        if fields[9].parse::<u64>().is_err() {
            return Err(Code::MalformedSource);
        }
        rows.push(SocketRow {
            local_address,
            local_port,
            remote_address,
            remote_port,
            state: fields[3].to_owned(),
            uid,
            inode: fields[9].to_owned(),
        });
    }
    Ok(rows)
}

pub(crate) fn unique_owner(owners: &[u32]) -> Result<u32, Code> {
    match owners {
        [] => Err(Code::NotFound),
        [one] => Ok(*one),
        _ => Err(Code::AmbiguousOwner),
    }
}

pub(crate) fn socket_inode_link(raw: &[u8]) -> Result<Option<String>, Code> {
    if raw.len() > 4096 {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    let Some(number) = text
        .strip_prefix("socket:[")
        .and_then(|tail| tail.strip_suffix(']'))
    else {
        return Ok(None);
    };
    if number.is_empty()
        || number.len() > 20
        || !number.bytes().all(|b| b.is_ascii_digit())
        || number.len() > 1 && number.starts_with('0')
    {
        return Err(Code::MalformedSource);
    }
    number.parse::<u64>().map_err(|_| Code::MalformedSource)?;
    Ok(Some(number.to_owned()))
}

fn boot_id(raw: &[u8]) -> Result<Uuid, Code> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| Code::UnsupportedEncoding)?
        .trim_end();
    Uuid::parse(text).map_err(|_| Code::MalformedSource)
}

fn owner_identity(
    source: &FixedMount<'_>,
    pid: u32,
    boot: &Uuid,
    clock: &mut dyn Clock,
) -> Result<Vec<(String, ProcessIdentity)>, Code> {
    let before =
        super::processes::parse_stat(&source.read(Query::OwnerStat(pid), clock, &false)?, pid)?;
    let fds = source.list_fds(pid, clock, &false)?;
    let mut links = Vec::new();
    for fd in fds {
        let raw = match source.read_link(LinkQuery::Fd(pid, fd), clock, &false) {
            Ok(raw) => raw,
            Err(Code::SourceDisappeared | Code::NotFound) => continue,
            Err(code) => return Err(code),
        };
        if let Some(inode) = socket_inode_link(&raw)? {
            links.push((
                inode,
                ProcessIdentity {
                    boot_id: boot.clone(),
                    pid: u64::from(pid),
                    start_ticks: before.start_ticks.clone(),
                },
            ));
        }
    }
    let after =
        super::processes::parse_stat(&source.read(Query::OwnerStat(pid), clock, &false)?, pid)?;
    super::processes::same_start(&before, &after)?;
    Ok(links)
}

pub(crate) fn connection(
    row: SocketRow,
    protocol: Protocol,
    family: AddressFamily,
    owners: &BTreeMap<String, Vec<ProcessIdentity>>,
    owner_uncertain: Option<Code>,
    namespace: &Result<String, Code>,
) -> (ConnectionRecord, Option<Code>) {
    let candidates = owners.get(&row.inode).map(Vec::as_slice).unwrap_or(&[]);
    let owner = match candidates {
        [one] if owner_uncertain.is_none() => Field::Available {
            value: vec![one.clone()],
        },
        [_] => Field::Unavailable {
            reason: owner_uncertain.unwrap_or(Code::SourceChanged),
        },
        [] => Field::Unavailable {
            reason: owner_uncertain.unwrap_or(Code::NotFound),
        },
        _ => Field::Unavailable {
            reason: Code::AmbiguousOwner,
        },
    };
    let reason = match &owner {
        Field::Unavailable { reason } => Some(*reason),
        _ => None,
    };
    (
        ConnectionRecord {
            protocol,
            family,
            local_address: row.local_address,
            local_port: row.local_port,
            remote_address: row.remote_address,
            remote_port: row.remote_port,
            state: row.state,
            uid: Field::Available {
                value: u64::from(row.uid),
            },
            socket_inode: row.inode,
            owners: owner,
            namespace: match namespace {
                Ok(value) => Field::Available {
                    value: value.clone(),
                },
                Err(reason) => Field::Unavailable { reason: *reason },
            },
        },
        reason,
    )
}

/// Read only fixed proc-net tables in this worker's current namespace and
/// bound owner identities by before/after PID start ticks.
pub(crate) fn collect_owned(
    context: &ValidatedCollectionContext,
    launch: &WorkerLaunch,
    handles: &[OwnedFd],
    clock: &mut dyn Clock,
) -> Result<Collected, Code> {
    let source_id = context
        .sources()
        .iter()
        .find(|source| source.definition().kind() == SourceKind::ProcNet)
        .ok_or(Code::ScopeDenied)?
        .definition()
        .id()
        .clone();
    let proc = launch
        .descriptors
        .iter()
        .zip(handles)
        .find_map(|(binding, handle)| {
            (binding.kind == HandleKind::ProcMount
                && binding.subject_id.as_ref() == Some(&source_id))
            .then_some(handle)
        })
        .ok_or(Code::WorkerProtocol)?;
    let mount = FixedMount::inherited(
        context,
        &source_id,
        MountKind::Proc,
        proc.as_fd()
            .try_clone_to_owned()
            .map_err(|_| Code::WorkerProtocol)?,
        clock,
        &false,
    )?;
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for (query, protocol, family, decode_family) in [
        (Query::Tcp, Protocol::Tcp, AddressFamily::Ipv4, Family::Ipv4),
        (
            Query::Tcp6,
            Protocol::Tcp,
            AddressFamily::Ipv6,
            Family::Ipv6,
        ),
        (Query::Udp, Protocol::Udp, AddressFamily::Ipv4, Family::Ipv4),
        (
            Query::Udp6,
            Protocol::Udp,
            AddressFamily::Ipv6,
            Family::Ipv6,
        ),
    ] {
        match mount
            .read(query, clock, &false)
            .and_then(|raw| parse_table(&raw, decode_family))
        {
            Ok(table) => rows.extend(table.into_iter().map(|row| (row, protocol, family))),
            Err(code) => failures.push(code),
        }
    }
    let boot = mount
        .read(Query::ConnectionBootId, clock, &false)
        .and_then(|raw| boot_id(&raw));
    let namespace = mount
        .read_link(LinkQuery::NetNamespace(std::process::id()), clock, &false)
        .and_then(|raw| String::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding));
    let mut owners = BTreeMap::<String, Vec<ProcessIdentity>>::new();
    let mut owner_uncertain = boot.as_ref().err().copied();
    if let Ok(boot) = &boot {
        match mount.list_pids(clock, &false) {
            Ok(pids) => {
                for pid in pids {
                    match owner_identity(&mount, pid, boot, clock) {
                        Ok(entries) => {
                            for (inode, identity) in entries {
                                owners.entry(inode).or_default().push(identity);
                            }
                        }
                        Err(code) => {
                            owner_uncertain = Some(match code {
                                Code::SourceDisappeared | Code::NotFound | Code::SourceChanged => {
                                    Code::SourceChanged
                                }
                                other => other,
                            });
                        }
                    }
                }
            }
            Err(code) => {
                owner_uncertain = Some(code);
                failures.push(code);
            }
        }
    }
    for identities in owners.values_mut() {
        identities.sort_by(|a, b| a.pid.cmp(&b.pid).then(a.start_ticks.cmp(&b.start_ticks)));
        identities.dedup();
    }
    // Wire verification requires canonical socket order. Proc-net tables are
    // grouped by family and their rows can change order between observations.
    sort_rows(&mut rows);
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut error_limit_hit = false;
    let mut omissions = rows.len().saturating_sub(launch.allowance.records as usize) as u64;
    for (row, protocol, family) in rows.into_iter().take(launch.allowance.records as usize) {
        let (payload, owner_error) =
            connection(row, protocol, family, &owners, owner_uncertain, &namespace);
        let namespace_error = match &payload.namespace {
            Field::Unavailable { reason } => Some(*reason),
            Field::Available { .. } => None,
        };
        let ordinal = launch.record_base + records.len() as u64;
        let now = clock.read()?;
        let observed = TimeObservation {
            value: now.utc,
            basis: ClockBasis::LocalClock,
            uncertainty_ms: None,
            clock_uncertain: false,
        };
        records.push(super::record::make(
            context,
            Collector::Connections,
            Adapter::Network,
            Category::Network,
            ProvenanceKind::ProcNet,
            source_id.clone(),
            super::record::facility_scope(source_id.clone()),
            Payload::Connection(payload),
            ordinal,
            observed,
        )?);
        let mut permit =
            context.permit(OperationTarget::Source(&source_id), &clock.read()?, false)?;
        permit.charge(Counter::Records, 1)?;
        if let Some(code) = owner_error {
            if errors.len() as u64 >= launch.allowance.errors {
                error_limit_hit = true;
            } else {
                let error_ordinal = launch.error_base + errors.len() as u64;
                permit.charge(Counter::Errors, 1)?;
                errors.push(ItemError {
                    error_id: derive_id(
                        IdentityKind::Error,
                        &context.identity().collection_id,
                        error_ordinal,
                    )?,
                    collector: Collector::Connections,
                    source_id: Some(source_id.clone()),
                    item_ref: ordinal,
                    field_path: Some("/payload/owners".into()),
                    code,
                    retryable: false,
                    counted_omission: false,
                });
            }
        }
        if let Some(code) = namespace_error {
            if errors.len() as u64 >= launch.allowance.errors {
                error_limit_hit = true;
            } else {
                let error_ordinal = launch.error_base + errors.len() as u64;
                permit.charge(Counter::Errors, 1)?;
                errors.push(ItemError {
                    error_id: derive_id(
                        IdentityKind::Error,
                        &context.identity().collection_id,
                        error_ordinal,
                    )?,
                    collector: Collector::Connections,
                    source_id: Some(source_id.clone()),
                    item_ref: ordinal,
                    field_path: Some("/payload/namespace".into()),
                    code,
                    retryable: false,
                    counted_omission: false,
                });
            }
        }
    }
    for code in failures {
        if errors.len() as u64 >= launch.allowance.errors {
            error_limit_hit = true;
            omissions += 1;
            continue;
        }
        let ordinal = launch.error_base + errors.len() as u64;
        let mut permit =
            context.permit(OperationTarget::Source(&source_id), &clock.read()?, false)?;
        permit.charge(Counter::Errors, 1)?;
        errors.push(ItemError {
            error_id: derive_id(
                IdentityKind::Error,
                &context.identity().collection_id,
                ordinal,
            )?,
            collector: Collector::Connections,
            source_id: Some(source_id.clone()),
            item_ref: 0,
            field_path: None,
            code,
            retryable: false,
            counted_omission: true,
        });
        omissions += 1;
    }
    let partial = !errors.is_empty() || omissions != 0 || error_limit_hit;
    let reason = if error_limit_hit || omissions != 0 {
        Some(Code::ResourceLimit)
    } else {
        errors.first().map(|error| error.code)
    };
    let usage = super::usage(context)?;
    Ok(Collected {
        outcome: CollectorOutcome {
            collector: Collector::Connections,
            status: if partial {
                if records.is_empty() {
                    CollectorStatus::Failed
                } else {
                    CollectorStatus::Partial
                }
            } else {
                CollectorStatus::Complete
            },
            coverage: vec![Coverage {
                source_id,
                state: if partial {
                    FacilityState::Partial
                } else {
                    FacilityState::Supported
                },
                reason,
            }],
            accepted_records: records.len() as u64,
            omitted_records: Some(omissions),
            omitted_reason: reason,
            errors: errors.len() as u64,
            stop_reason: reason,
        },
        usage,
        records,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> SocketRow {
        SocketRow {
            local_address: "127.0.0.1".into(),
            local_port: 8080,
            remote_address: "0.0.0.0".into(),
            remote_port: 0,
            state: "0A".into(),
            uid: 1000,
            inode: "123".into(),
        }
    }

    #[test]
    fn proc_table_order_is_normalized_before_record_ids_are_assigned() {
        let mut rows = vec![
            (
                SocketRow {
                    local_port: 9000,
                    ..row()
                },
                Protocol::Tcp,
                AddressFamily::Ipv4,
            ),
            (
                SocketRow {
                    local_port: 1000,
                    ..row()
                },
                Protocol::Tcp,
                AddressFamily::Ipv4,
            ),
        ];
        sort_rows(&mut rows);
        assert_eq!(
            rows.iter()
                .map(|(r, _, _)| r.local_port)
                .collect::<Vec<_>>(),
            vec![1000, 9000]
        );
        rows.reverse();
        assert_eq!(rows[0].0.local_port, 9000);
        sort_rows(&mut rows);
        assert_eq!(rows[0].0.local_port, 1000);
    }

    #[test]
    fn owner_join_distinguishes_unique_missing_ambiguous_and_denied() {
        let mut owners = BTreeMap::new();
        let one = ProcessIdentity {
            boot_id: Uuid::parse("10000000-0000-4000-8000-000000000001").unwrap(),
            pid: 42,
            start_ticks: "7".into(),
        };
        owners.insert("123".into(), vec![one.clone()]);
        let namespace = Ok("net:[7]".into());
        let (found, code) = connection(
            row(),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            &owners,
            None,
            &namespace,
        );
        assert_eq!(
            found.owners,
            Field::Available {
                value: vec![one.clone()]
            }
        );
        assert_eq!(code, None);
        let (incomplete, reason) = connection(
            row(),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            &owners,
            Some(Code::PermissionDenied),
            &namespace,
        );
        assert_eq!(
            incomplete.owners,
            Field::Unavailable {
                reason: Code::PermissionDenied
            }
        );
        assert_eq!(reason, Some(Code::PermissionDenied));
        owners.clear();
        let (_, missing) = connection(
            row(),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            &owners,
            None,
            &namespace,
        );
        assert_eq!(missing, Some(Code::NotFound));
        let (_, denied) = connection(
            row(),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            &owners,
            Some(Code::PermissionDenied),
            &namespace,
        );
        assert_eq!(denied, Some(Code::PermissionDenied));
        let (_, raced) = connection(
            row(),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            &owners,
            Some(Code::SourceChanged),
            &Err(Code::PermissionDenied),
        );
        assert_eq!(raced, Some(Code::SourceChanged));
        owners.insert("123".into(), vec![one.clone(), one]);
        let (_, ambiguous) = connection(
            row(),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            &owners,
            None,
            &namespace,
        );
        assert_eq!(ambiguous, Some(Code::AmbiguousOwner));
    }
}
