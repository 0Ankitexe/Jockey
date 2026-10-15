//! Canonical IDs and Gregorian UTC instants, without platform or clock access.
use super::{DecodeReason, InputError};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct Uuid(String);

impl Uuid {
    pub fn parse(value: &str) -> Result<Self, InputError> {
        if value.len() != 36
            || value == "00000000-0000-0000-0000-000000000000"
            || !value.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
        {
            return Err(InputError::new(DecodeReason::Identifier));
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn bytes(&self) -> [u8; 16] {
        let mut out = [0; 16];
        for (index, b) in self.0.bytes().filter(|b| *b != b'-').enumerate() {
            let digit = if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            };
            out[index / 2] = (out[index / 2] << 4) | digit;
        }
        out
    }
}
impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UtcTime(String);

impl UtcTime {
    pub fn parse(value: &str) -> Result<Self, InputError> {
        nanos(value).ok_or_else(|| InputError::new(DecodeReason::Timestamp))?;
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn unix_nanos(&self) -> i128 {
        // Private representation and custom deserialization guarantee validity.
        nanos(&self.0).expect("UtcTime construction invariant")
    }
}
impl<'de> Deserialize<'de> for UtcTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

fn nanos(value: &str) -> Option<i128> {
    let b = value.as_bytes();
    if !(20..=30).contains(&b.len())
        || !b.is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return None;
    }
    let number = |s: &[u8]| -> Option<i128> {
        s.iter().try_fold(0i128, |n, c| {
            c.is_ascii_digit().then(|| n * 10 + i128::from(c - b'0'))
        })
    };
    let y = number(&b[..4])?;
    let m = number(&b[5..7])?;
    let d = number(&b[8..10])?;
    let h = number(&b[11..13])?;
    let min = number(&b[14..16])?;
    let sec = number(&b[17..19])?;
    if y == 0 || !(1..=12).contains(&m) || h > 23 || min > 59 || sec > 59 {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d < 1 || d > months[(m - 1) as usize] {
        return None;
    }
    let fraction = if b.len() == 20 {
        0
    } else {
        if b[19] != b'.' || b.len() == 21 {
            return None;
        }
        let digits = &b[20..b.len() - 1];
        number(digits)? * 10i128.pow((9 - digits.len()) as u32)
    };
    let previous = y - 1;
    let days = 365 * previous + previous / 4 - previous / 100 + previous / 400 - 719162
        + months[..(m - 1) as usize].iter().sum::<i128>()
        + d
        - 1;
    Some((((days * 24 + h) * 60 + min) * 60 + sec) * 1_000_000_000 + fraction)
}

wire!(TimeObservation { value: UtcTime, basis: ClockBasis, uncertainty_ms: Option<u64>, clock_uncertain: bool });
vocabulary!(ClockBasis { LocalClock => "local_clock" });

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_bytes_are_exact_and_invalid_serde_cannot_construct() {
        let id = Uuid::parse("10000000-0000-4000-8000-000000000001").unwrap();
        assert_eq!(id.as_str(), "10000000-0000-4000-8000-000000000001");
        assert_eq!(
            id.bytes(),
            [16, 0, 0, 0, 0, 0, 64, 0, 128, 0, 0, 0, 0, 0, 0, 1]
        );
        assert!(serde_json::from_str::<Uuid>("\"invalid\"").is_err());
    }

    #[test]
    fn calendar_extremes_precision_and_leap_rules() {
        for (text, expected) in [
            ("0001-01-01T00:00:00Z", -62135596800i128 * 1_000_000_000),
            ("1969-12-31T23:59:59.999999999Z", -1),
            ("1970-01-01T00:00:00.000000001Z", 1),
            (
                "9999-12-31T23:59:59.999999999Z",
                253402300800i128 * 1_000_000_000 - 1,
            ),
        ] {
            let time = UtcTime::parse(text).unwrap();
            assert_eq!(time.as_str(), text);
            assert_eq!(time.unix_nanos(), expected);
        }
        for text in [
            "2020-01-01T00:00:00.Z",
            "2020-01-01T00:00:00.0000000000Z",
            "2100-02-29T00:00:00Z",
            "2020-04-31T00:00:00Z",
            "2020-01-01T24:00:00Z",
        ] {
            assert!(UtcTime::parse(text).is_err());
        }
        assert!(UtcTime::parse("2400-02-29T00:00:00Z").is_ok());
    }
}
