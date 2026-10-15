//! RFC5424 records from an explicitly selected, stable log snapshot.
use jocky_shared::collection::{
    Code,
    identity::{UtcTime, Uuid},
    inputs::UtcWindow,
    outcomes::Field,
    records::{EventRecord, TimeBasis},
};

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += i64::from(m <= 2);
    (y, m, d)
}
fn timestamp(input: &str) -> Result<(UtcTime, TimeBasis), Code> {
    if !input.is_ascii() {
        return Err(Code::UnsupportedFormat);
    }
    let (base, offset, basis) = if let Some(base) = input.strip_suffix('Z') {
        (base, 0i64, TimeBasis::SourceUtc)
    } else if input.len() >= 25 {
        let sign_at = input.len() - 6;
        let (base, zone) = input.split_at(sign_at);
        if !matches!(&zone[..1], "+" | "-") || zone.as_bytes()[3] != b':' {
            return Err(Code::UnknownTimezone);
        }
        let hours = zone[1..3]
            .parse::<i64>()
            .map_err(|_| Code::UnknownTimezone)?;
        let mins = zone[4..6]
            .parse::<i64>()
            .map_err(|_| Code::UnknownTimezone)?;
        if hours > 23 || mins > 59 {
            return Err(Code::UnknownTimezone);
        }
        let seconds = (hours * 60 + mins) * 60 * if zone.starts_with('+') { 1 } else { -1 };
        (base, seconds, TimeBasis::SourceOffset)
    } else {
        return Err(Code::UnknownTimezone);
    };
    let (whole, fraction) = match base.split_once('.') {
        Some((whole, digits))
            if (1..=9).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            (whole, Some(digits))
        }
        Some(_) => return Err(Code::UnsupportedFormat),
        None => (base, None),
    };
    let bytes = whole.as_bytes();
    if bytes.len() != 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(Code::UnsupportedFormat);
    }
    let number = |a: usize, b: usize| {
        whole[a..b]
            .parse::<i64>()
            .map_err(|_| Code::UnsupportedFormat)
    };
    let (y, m, d, h, min, sec) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    // Shared UtcTime validates real civil dates; first validate the local wall time.
    UtcTime::parse(&format!("{base}Z")).map_err(|_| Code::UnsupportedFormat)?;
    let epoch = days_from_civil(y, m, d) * 86400 + h * 3600 + min * 60 + sec - offset;
    let days = epoch.div_euclid(86400);
    let seconds = epoch.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    if !(1..=9999).contains(&y) {
        return Err(Code::UnsupportedFormat);
    }
    let suffix = fraction
        .map(|digits| format!(".{digits}"))
        .unwrap_or_default();
    let utc = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}{suffix}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    );
    Ok((
        UtcTime::parse(&utc).map_err(|_| Code::UnsupportedFormat)?,
        basis,
    ))
}

pub(crate) fn parse(
    raw: &[u8],
    source_id: Uuid,
    window: &UtcWindow,
) -> Result<Vec<EventRecord>, Code> {
    if raw.len() > 65_536 {
        return Err(Code::ResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::UnsupportedEncoding)?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.len() > 4096 || out.len() >= 512 {
            return Err(Code::ResourceLimit);
        }
        if !line.starts_with('<') {
            return Err(Code::UnsupportedFormat);
        }
        let end = line.find('>').ok_or(Code::MalformedSource)?;
        let pri = line[1..end]
            .parse::<u8>()
            .map_err(|_| Code::MalformedSource)?;
        if pri > 191 {
            return Err(Code::MalformedSource);
        }
        let rest = line[end + 1..]
            .strip_prefix("1 ")
            .ok_or(Code::UnsupportedFormat)?;
        let mut parts = rest.splitn(7, ' ');
        let at = parts.next().ok_or(Code::MalformedSource)?;
        let (at, basis) = timestamp(at)?;
        let host = parts.next().ok_or(Code::MalformedSource)?;
        for _ in 0..3 {
            if parts.next().is_none() {
                return Err(Code::MalformedSource);
            }
        }
        let structured_data = parts.next().ok_or(Code::MalformedSource)?;
        if structured_data != "-" {
            return Err(Code::UnsupportedFormat);
        }
        let message = parts.next().ok_or(Code::MalformedSource)?;
        if host.is_empty() || message.is_empty() || message.contains('\0') {
            return Err(Code::MalformedSource);
        }
        if at.unix_nanos() >= window.start.unix_nanos() && at.unix_nanos() < window.end.unix_nanos()
        {
            out.push(EventRecord {
                source_id: source_id.clone(),
                event_time: Field::Available { value: at },
                time_basis: basis,
                severity: Field::Available {
                    value: (pri % 8).to_string(),
                },
                message: message.to_owned(),
                domain: Field::Unavailable {
                    reason: Code::NotRequested,
                },
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn window() -> UtcWindow {
        UtcWindow {
            start: UtcTime::parse("2020-01-01T00:00:00Z").unwrap(),
            end: UtcTime::parse("2020-01-01T00:00:10Z").unwrap(),
        }
    }
    fn source() -> Uuid {
        Uuid::parse("11111111-1111-4111-8111-111111111111").unwrap()
    }
    #[test]
    fn offset_and_half_open_window() {
        let raw = b"<14>1 2020-01-01T05:30:00+05:30 lab app 1 ID47 - owned marker\n<14>1 2020-01-01T00:00:10Z lab app 1 ID47 - excluded\n";
        let rows = parse(raw, source(), &window()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "owned marker");
        assert_eq!(
            rows[0].event_time,
            Field::Available {
                value: window().start
            }
        );
        assert_eq!(rows[0].time_basis, TimeBasis::SourceOffset);
        assert!(parse(b"", source(), &window()).unwrap().is_empty());
    }
    #[test]
    fn yearless_zone_less_and_size_are_errors() {
        assert_eq!(
            parse(b"Oct 15 00:00:00 lab app: unsupported", source(), &window()),
            Err(Code::UnsupportedFormat)
        );
        assert_eq!(
            parse(
                b"<14>1 2020-01-01T00:00:00 lab app 1 ID47 - no-zone",
                source(),
                &window()
            ),
            Err(Code::UnknownTimezone)
        );
        assert_eq!(
            parse(&vec![b'x'; 65_537], source(), &window()),
            Err(Code::ResourceLimit)
        );
    }
}
