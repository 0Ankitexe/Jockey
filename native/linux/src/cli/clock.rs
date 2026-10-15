//! A paired Linux clock observation for logical admission and later workers.
use jocky_forensic::collection::ClockReading;
use jocky_shared::collection::{Code, identity::UtcTime};

pub(crate) fn read() -> Result<ClockReading, Code> {
    use rustix::time::{ClockId, clock_gettime};
    let monotonic = clock_gettime(ClockId::Monotonic);
    let utc = clock_gettime(ClockId::Realtime);
    if monotonic.tv_sec < 0 || utc.tv_sec < 0 {
        return Err(Code::ClockUncertain);
    }
    let monotonic_ms = u64::try_from(monotonic.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .and_then(|s| s.checked_add(u64::try_from(monotonic.tv_nsec / 1_000_000).ok()?))
        .ok_or(Code::ClockUncertain)?;
    Ok(ClockReading {
        monotonic_ms,
        utc: unix_utc(utc.tv_sec)?,
    })
}

pub(crate) fn unix_utc(seconds: i64) -> Result<UtcTime, Code> {
    if seconds < 0 {
        return Err(Code::ClockUncertain);
    }
    let days = seconds / 86_400;
    let seconds_in_day = seconds % 86_400;
    // Gregorian civil date from Unix days; all arithmetic is bounded for the
    // UtcTime wire range (years 0001..9999).
    let z = days.checked_add(719_468).ok_or(Code::ClockUncertain)?;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    UtcTime::parse(&format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_in_day / 3600,
        seconds_in_day / 60 % 60,
        seconds_in_day % 60
    ))
    .map_err(|_| Code::ClockUncertain)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_conversion_handles_epoch_leap_days_and_wire_range() {
        assert_eq!(unix_utc(0).unwrap().as_str(), "1970-01-01T00:00:00Z");
        assert_eq!(
            unix_utc(951_782_400).unwrap().as_str(),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(
            unix_utc(1_704_067_199).unwrap().as_str(),
            "2023-12-31T23:59:59Z"
        );
        assert_eq!(unix_utc(-1), Err(Code::ClockUncertain));
    }
}
