use std::{cmp::Ordering, collections::BTreeMap, net::IpAddr};

pub(crate) fn inputs(input: &mut super::inputs::DecodedInputs) -> Result<(), Code> {
    fn scope(scope: &mut jocky_shared::collection::inputs::Scope) {
        scope.capabilities.sort_by_key(|c| c.as_str());
        scope.source_groups.sort_by_key(|s| s.as_str());
        scope.roots.sort_by(|a, b| a.root_id.cmp(&b.root_id));
        for root in &mut scope.roots {
            root.purposes.sort_by_key(|p| p.as_str());
        }
    }
    input.designation.approved_operator_ids.sort();
    scope(&mut input.authorisation.scope);
    scope(&mut input.policy.scope);
    input.policy.sources.sort_by(|a, b| a.id().cmp(b.id()));
    input.request.capabilities.sort_by_key(|c| c.as_str());
    input.request.source_ids.sort();
    input
        .request
        .paths
        .sort_by(|a, b| (&a.root_id, &a.relative_path).cmp(&(&b.root_id, &b.relative_path)));
    if let Some(set) = &mut input.indicators {
        super::indicators::normalize(set)?;
    }
    Ok(())
}
use jocky_shared::collection::{
    Code,
    outcomes::Field,
    records::{ForensicRecord, Payload},
};

/// Stable collector and source-key order, with source ordinal preserving equal-time events.
fn compare(a: &ForensicRecord, b: &ForensicRecord) -> Ordering {
    let first = a.collector.name.cmp(&b.collector.name);
    if first != Ordering::Equal {
        return first;
    }
    match (&a.payload, &b.payload) {
        (Payload::System(_), Payload::System(_)) => {
            a.provenance.source_id.cmp(&b.provenance.source_id)
        }
        (Payload::Process(a), Payload::Process(b)) => a.pid.cmp(&b.pid).then_with(|| {
            let ticks = |v: &Field<jocky_shared::collection::records::ProcessIdentity>| match v {
                Field::Available { value } => value.start_ticks.parse::<u128>().ok(),
                _ => None,
            };
            ticks(&a.start_identity).cmp(&ticks(&b.start_identity))
        }),
        (Payload::Service(a), Payload::Service(b)) => a.unit_name.cmp(&b.unit_name),
        (Payload::Connection(a), Payload::Connection(b)) => (
            a.protocol,
            a.family,
            a.local_address.parse::<IpAddr>().ok(),
            a.local_port,
            a.remote_address.parse::<IpAddr>().ok(),
            a.remote_port,
            a.socket_inode.parse::<u128>().ok(),
        )
            .cmp(&(
                b.protocol,
                b.family,
                b.local_address.parse::<IpAddr>().ok(),
                b.local_port,
                b.remote_address.parse::<IpAddr>().ok(),
                b.remote_port,
                b.socket_inode.parse::<u128>().ok(),
            )),
        (Payload::Persistence(a), Payload::Persistence(b)) => {
            (&a.location.root_id, &a.location.relative_path)
                .cmp(&(&b.location.root_id, &b.location.relative_path))
        }
        (Payload::File(a), Payload::File(b)) => (&a.location.root_id, &a.location.relative_path)
            .cmp(&(&b.location.root_id, &b.location.relative_path)),
        (Payload::Event(a), Payload::Event(b)) => {
            let time = |v: &Field<jocky_shared::collection::identity::UtcTime>| match v {
                Field::Available { value } => Some(value.unix_nanos()),
                _ => None,
            };
            time(&a.event_time)
                .cmp(&time(&b.event_time))
                .then_with(|| a.source_id.cmp(&b.source_id))
        }
        (Payload::Driver(a), Payload::Driver(b)) => a.name.cmp(&b.name),
        (Payload::Indicator(a), Payload::Indicator(b)) => (
            &a.indicator_id,
            &a.matched_record_id,
            &a.field_path,
        )
            .cmp(&(&b.indicator_id, &b.matched_record_id, &b.field_path)),
        _ => a.record_type.cmp(&b.record_type),
    }
}

pub fn records(records: &mut [ForensicRecord]) -> Result<(), Code> {
    if records.len() > 10000 {
        return Err(Code::ResourceLimit);
    }
    let sequences = sequences(records)?;
    records.sort_by(|a, b| ordered_compare(a, b, &sequences));
    Ok(())
}

fn sequences(records: &[ForensicRecord]) -> Result<BTreeMap<String, u64>, Code> {
    if records.len() > 10000 {
        return Err(Code::ResourceLimit);
    }
    let mut result = BTreeMap::new();
    for record in records {
        validate_key(record)?;
        if result
            .insert(record.record_id.as_str().to_owned(), record.sequence)
            .is_some()
        {
            return Err(Code::InvalidInput);
        }
    }
    for record in records {
        if let Payload::Indicator(i) = &record.payload
            && !result.contains_key(i.matched_record_id.as_str())
        {
            return Err(Code::InvalidInput);
        }
    }
    Ok(result)
}

fn decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|c| c.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}
fn validate_key(record: &ForensicRecord) -> Result<(), Code> {
    use jocky_shared::collection::records::AddressFamily;
    let valid = match &record.payload {
        Payload::Connection(c) => {
            let address = |text: &str| {
                text.parse::<IpAddr>().is_ok_and(|ip| match c.family {
                    AddressFamily::Ipv4 => ip.is_ipv4(),
                    AddressFamily::Ipv6 => ip.is_ipv6(),
                })
            };
            address(&c.local_address) && address(&c.remote_address) && decimal(&c.socket_inode)
        }
        Payload::Process(c) => match &c.start_identity {
            Field::Available { value } => decimal(&value.start_ticks) && value.pid == c.pid,
            Field::Unavailable { .. } => true,
        },
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Code::InvalidInput)
    }
}
fn ordered_compare(
    a: &ForensicRecord,
    b: &ForensicRecord,
    sequences: &BTreeMap<String, u64>,
) -> Ordering {
    if let (Payload::Indicator(a), Payload::Indicator(b)) = (&a.payload, &b.payload) {
        return (
            &a.indicator_id,
            sequences.get(a.matched_record_id.as_str()),
            &a.field_path,
        )
            .cmp(&(
                &b.indicator_id,
                sequences.get(b.matched_record_id.as_str()),
                &b.field_path,
            ));
    }
    compare(a, b)
}
pub fn is_ordered(records: &[ForensicRecord]) -> Result<bool, Code> {
    let sequences = sequences(records)?;
    Ok(records
        .windows(2)
        .all(|pair| ordered_compare(&pair[0], &pair[1], &sequences) != Ordering::Greater))
}
