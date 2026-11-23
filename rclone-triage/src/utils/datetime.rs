//! Timestamp boundaries shared by exports, remote listings and OAuth state.

use anyhow::{bail, Result};
use jiff::{tz::Offset, Timestamp, ZonedDateTime};
use regex::Regex;
use std::sync::OnceLock;

/// Remote metadata accepts RFC 3339 only, without zone annotations or truncation.
/// Reject leap seconds rather than silently clamping them to the preceding second.
pub fn parse_rfc3339(value: &str) -> Result<Timestamp> {
    static RFC3339: OnceLock<Regex> = OnceLock::new();
    let syntax = RFC3339.get_or_init(|| {
        Regex::new(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-5][0-9](?:\.[0-9]{1,9})?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\z")
            .expect("static RFC3339 expression")
    });
    if !syntax.is_match(value) {
        bail!("invalid RFC3339 timestamp");
    }
    Ok(value.parse()?)
}

/// Keep the explicit UTC offset used in CSV/XLSX exports and OAuth token JSON.
pub fn rfc3339_utc(value: Timestamp) -> String {
    value.display_with_offset(Offset::UTC).to_string()
}

/// Local export metadata keeps its numeric offset without an IANA annotation.
pub fn rfc3339_local_now() -> String {
    let now = ZonedDateTime::now();
    now.timestamp()
        .display_with_offset(now.offset())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_fractional_precision_and_normalizes_offsets() {
        let value = parse_rfc3339("2024-01-02T03:04:05.123456789+11:00").unwrap();
        assert_eq!(rfc3339_utc(value), "2024-01-01T16:04:05.123456789+00:00");
        assert_eq!(
            rfc3339_utc(Timestamp::UNIX_EPOCH),
            "1970-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn reads_existing_json_timestamps_and_writes_rfc3339() {
        for text in [
            "2024-01-02T03:04:05Z",
            "2024-01-02T03:04:05.123456789+11:00",
        ] {
            let json = serde_json::to_string(text).unwrap();
            let value: Timestamp = serde_json::from_str(&json).unwrap();
            assert_eq!(value, parse_rfc3339(text).unwrap());
            let roundtrip: Timestamp =
                serde_json::from_str(&serde_json::to_string(&value).unwrap()).unwrap();
            assert_eq!(roundtrip, value);
        }
    }

    #[test]
    fn rejects_ambiguous_truncated_or_lossy_remote_times() {
        for text in [
            "2024-01-02 03:04:05Z",
            "2024-01-02T03:04Z",
            "2024-01-02T03:04:05",
            "2024-01-02T03:04:05Z[UTC]",
            "2024-01-02T03:04:60Z",
            "2024-01-02T03:04:05.1234567891Z",
            "2024-02-30T03:04:05Z",
            "2024-01-02T03:04:05+25:00",
            "2024-01-02T03:04:05+23:60",
            "2024-01-02T24:04:05Z",
        ] {
            assert!(parse_rfc3339(text).is_err(), "{text}");
        }
    }

    #[test]
    fn run_ids_and_forensic_milliseconds_keep_their_layout() {
        let value = parse_rfc3339("2024-01-02T03:04:05.123456789Z").unwrap();
        assert_eq!(
            value.strftime("%Y%m%dT%H%M%S%.f").to_string(),
            "20240102T030405.123456789"
        );
        assert_eq!(
            value.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            "2024-01-02T03:04:05.123Z"
        );
    }

    #[test]
    fn local_serialization_has_an_offset_and_no_zone_annotation() {
        let text = rfc3339_local_now();
        assert!(parse_rfc3339(&text).is_ok());
        assert!(!text.contains('['));
    }
}
