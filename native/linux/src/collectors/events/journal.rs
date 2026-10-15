//! Event normalization from an explicitly opened, staged journal copy.
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    inputs::UtcWindow,
    outcomes::Field,
    records::{EventRecord, TimeBasis},
};

pub(crate) fn event(
    micros: u64,
    message: &[u8],
    priority: Option<&[u8]>,
    source_id: Uuid,
    window: &UtcWindow,
) -> Result<Option<EventRecord>, Code> {
    if message.len() > 4096 || priority.is_some_and(|v| v.len() > 8) {
        return Err(Code::ResourceLimit);
    }
    let whole = crate::cli::clock::unix_utc(
        i64::try_from(micros / 1_000_000).map_err(|_| Code::MalformedSource)?,
    )?;
    let at = if micros.is_multiple_of(1_000_000) {
        whole
    } else {
        let base = whole
            .as_str()
            .strip_suffix('Z')
            .ok_or(Code::MalformedSource)?;
        UtcTime::parse(&format!("{base}.{:06}Z", micros % 1_000_000))
            .map_err(|_| Code::MalformedSource)?
    };
    if at.unix_nanos() < window.start.unix_nanos() || at.unix_nanos() >= window.end.unix_nanos() {
        return Ok(None);
    }
    let message = std::str::from_utf8(message).map_err(|_| Code::UnsupportedEncoding)?;
    if message.contains('\0') {
        return Err(Code::MalformedSource);
    }
    let severity = match priority {
        Some(raw) => {
            let value = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
            let number = value.parse::<u8>().map_err(|_| Code::MalformedSource)?;
            if number > 7 {
                return Err(Code::MalformedSource);
            }
            Field::Available {
                value: value.to_owned(),
            }
        }
        None => Field::Unavailable {
            reason: Code::NotFound,
        },
    };
    Ok(Some(EventRecord {
        source_id,
        event_time: Field::Available { value: at },
        time_basis: TimeBasis::SourceUtc,
        severity,
        message: message.to_owned(),
        domain: Field::Unavailable {
            reason: Code::NotRequested,
        },
    }))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    #[test]
    fn half_open_and_field_bounds() {
        let id = Uuid::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let window = UtcWindow {
            start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
            end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        };
        assert_eq!(
            event(
                1_577_836_800_000_000,
                b"marker",
                Some(b"6"),
                id.clone(),
                &window
            )
            .unwrap()
            .unwrap()
            .message,
            "marker"
        );
        assert_eq!(
            event(1_577_836_810_000_000, b"end", None, id.clone(), &window),
            Ok(None)
        );
        assert_eq!(
            event(1_577_836_800_000_000, &vec![b'x'; 4097], None, id, &window),
            Err(Code::ResourceLimit)
        );
    }
}

/// Pure normalization of bounded facts from the optional staged reader.
pub(crate) fn parse_facts(
    facts: &[crate::sources::journal::JournalFact],
    source_id: Uuid,
    window: &UtcWindow,
) -> Result<Vec<EventRecord>, Code> {
    if facts.len() > 10_000 {
        return Err(Code::ResourceLimit);
    }
    let mut out = Vec::new();
    for fact in facts {
        if let Some(row) = event(
            fact.micros,
            &fact.message,
            fact.priority.as_deref(),
            source_id.clone(),
            window,
        )? {
            out.push(row);
        }
    }
    Ok(out)
}
