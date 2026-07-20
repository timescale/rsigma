//! Timestamp types for STIX objects and TAXII-compatible RFC 3339 wire values.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::core::error::TimestampError;

fn parse_fraction_digits(input: &str) -> u8 {
    let Some((_, tail)) = input.split_once('T') else {
        return 0;
    };
    let Some((time_part, _)) = tail.rsplit_once('Z') else {
        return 0;
    };
    let Some((_, frac)) = time_part.split_once('.') else {
        return 0;
    };
    u8::try_from(frac.len()).unwrap_or(u8::MAX)
}

fn parse_utc(input: &str) -> Result<OffsetDateTime, TimestampError> {
    if !input.ends_with('Z') {
        return Err(TimestampError::Invalid(input.to_owned()));
    }
    OffsetDateTime::parse(input, &Rfc3339).map_err(|_| TimestampError::Invalid(input.to_owned()))
}

/// STIX timestamp preserving fractional precision.
#[derive(Clone, Debug)]
pub struct StixTimestamp {
    inner: OffsetDateTime,
    subsec_digits: u8,
}

impl PartialEq for StixTimestamp {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for StixTimestamp {}

impl PartialOrd for StixTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StixTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl Hash for StixTimestamp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl StixTimestamp {
    /// Current UTC timestamp.
    pub fn now() -> Self {
        let dt = OffsetDateTime::now_utc();
        Self {
            inner: dt,
            subsec_digits: 3,
        }
    }

    /// Construct from datetime.
    pub fn from_datetime(dt: OffsetDateTime) -> Self {
        Self {
            inner: dt,
            subsec_digits: 3,
        }
    }

    /// Parse STIX timestamp from RFC3339 UTC input.
    pub fn parse(s: &str) -> Result<Self, TimestampError> {
        let inner = parse_utc(s)?;
        Ok(Self {
            inner,
            subsec_digits: parse_fraction_digits(s),
        })
    }

    /// Access underlying datetime.
    pub const fn as_datetime(&self) -> OffsetDateTime {
        self.inner
    }

    /// Format preserving parsed fractional precision when possible.
    pub fn to_rfc3339(&self) -> String {
        let date = self.inner.date();
        let time = self.inner.time();
        let (year, month, day) = date.to_calendar_date();
        let month = u8::from(month);
        if self.subsec_digits == 0 {
            return format!(
                "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
                time.hour(),
                time.minute(),
                time.second()
            );
        }

        let nanos = time.nanosecond();
        let digits = usize::from(self.subsec_digits).min(9);
        let mut frac = format!("{nanos:09}");
        frac.truncate(digits);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{frac}Z",
            time.hour(),
            time.minute(),
            time.second()
        )
    }
}

/// TAXII timestamp normalized to six fractional digits.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaxiiTimestamp(OffsetDateTime);

impl TaxiiTimestamp {
    /// Current UTC timestamp.
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Construct from datetime.
    pub const fn from_datetime(dt: OffsetDateTime) -> Self {
        Self(dt)
    }

    /// Parse TAXII timestamp from RFC3339 UTC input.
    pub fn parse(s: &str) -> Result<Self, TimestampError> {
        parse_utc(s).map(Self)
    }

    /// Format with exactly six fractional digits.
    pub fn to_rfc3339(&self) -> String {
        let date = self.0.date();
        let time = self.0.time();
        let (year, month, day) = date.to_calendar_date();
        let month = u8::from(month);
        let micros = time.nanosecond() / 1_000;
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
            time.hour(),
            time.minute(),
            time.second()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stix_timestamp_round_trip_fraction() {
        let ts = StixTimestamp::parse("2014-02-20T09:16:08.989000Z").expect("valid");
        assert_eq!(ts.to_rfc3339(), "2014-02-20T09:16:08.989000Z");
    }

    #[test]
    fn stix_timestamp_round_trip_bare_z() {
        let ts = StixTimestamp::parse("2016-01-20T12:31:12Z").expect("valid");
        assert_eq!(ts.to_rfc3339(), "2016-01-20T12:31:12Z");
    }

    #[test]
    fn taxii_timestamp_normalizes_to_six_digits() {
        let ts = TaxiiTimestamp::parse("2024-01-01T00:00:00.000Z").expect("valid");
        assert_eq!(ts.to_rfc3339(), "2024-01-01T00:00:00.000000Z");
    }

    #[test]
    fn stix_timestamp_preserves_common_fraction_widths() {
        let cases = [
            ("2024-01-01T00:00:00.1Z", "2024-01-01T00:00:00.1Z"),
            ("2024-01-01T00:00:00.123Z", "2024-01-01T00:00:00.123Z"),
            ("2024-01-01T00:00:00.123456Z", "2024-01-01T00:00:00.123456Z"),
            (
                "2024-01-01T00:00:00.123456789Z",
                "2024-01-01T00:00:00.123456789Z",
            ),
            ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
        ];
        for (input, expected) in cases {
            let parsed = StixTimestamp::parse(input).expect("valid timestamp");
            assert_eq!(parsed.to_rfc3339(), expected);
        }
    }

    #[test]
    fn stix_timestamp_compares_by_instant_only() {
        let bare = StixTimestamp::parse("2016-01-20T12:31:12Z").expect("valid");
        let padded = StixTimestamp::parse("2016-01-20T12:31:12.000Z").expect("valid");
        assert_eq!(bare, padded);
        assert_eq!(bare.cmp(&padded), Ordering::Equal);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn stix_timestamp_serde_preserves_precision() {
        let ts = StixTimestamp::parse("2017-05-31T21:32:29.203Z").expect("valid");
        let encoded = serde_json::to_string(&ts).expect("serialize");
        assert_eq!(encoded, "\"2017-05-31T21:32:29.203Z\"");
        let decoded: StixTimestamp = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, ts);
        assert!(serde_json::from_str::<StixTimestamp>("\"2017-05-31 21:32:29\"").is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn taxii_timestamp_serde_uses_six_digits() {
        let ts = TaxiiTimestamp::parse("2024-01-01T00:00:00Z").expect("valid");
        let encoded = serde_json::to_string(&ts).expect("serialize");
        assert_eq!(encoded, "\"2024-01-01T00:00:00.000000Z\"");
        let decoded: TaxiiTimestamp = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, ts);
    }
}
