//! Disposition records: the analyst verdict carried back to the rule that fired.
//!
//! A disposition is a single JSON object. The wire shape is deliberately
//! minimal: a rule identity, a verdict, and a few optional fields for
//! traceability and rolling-window placement. Parsing accepts either a single
//! object or an array (a `POST` body), and validation produces a normalized
//! [`Disposition`] with a pointed error pointing at the offending field.

use serde::{Deserialize, Serialize};

/// The analyst's verdict on an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// A real detection of the targeted behavior.
    TruePositive,
    /// A misfire: the rule fired on benign or unrelated activity.
    FalsePositive,
    /// The activity is real and correctly detected, but benign in context
    /// (still triage noise that a tuning program may want to count).
    BenignTruePositive,
}

impl Verdict {
    /// Parse a verdict from its wire string, returning a pointed error.
    pub fn parse(s: &str) -> Result<Self, DispositionError> {
        match s {
            "true_positive" => Ok(Self::TruePositive),
            "false_positive" => Ok(Self::FalsePositive),
            "benign_true_positive" => Ok(Self::BenignTruePositive),
            other => Err(DispositionError::field(
                "verdict",
                format!(
                    "unknown verdict '{other}' (expected 'true_positive', 'false_positive', or \
                     'benign_true_positive')"
                ),
            )),
        }
    }

    /// The wire string for this verdict.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TruePositive => "true_positive",
            Self::FalsePositive => "false_positive",
            Self::BenignTruePositive => "benign_true_positive",
        }
    }
}

/// Whether a disposition is keyed to a single detection or a whole incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionScope {
    /// The verdict applies to one rule's detection (the default).
    #[default]
    Detection,
    /// The verdict applies to an incident; the daemon resolves the incident to
    /// its contributing rules through the live alert-pipeline incident map.
    Incident,
}

impl DispositionScope {
    fn parse(s: &str) -> Result<Self, DispositionError> {
        match s {
            "detection" => Ok(Self::Detection),
            "incident" => Ok(Self::Incident),
            other => Err(DispositionError::field(
                "scope",
                format!("unknown scope '{other}' (expected 'detection' or 'incident')"),
            )),
        }
    }
}

/// The raw disposition as it arrives on the wire, before validation.
#[derive(Debug, Clone, Deserialize)]
pub struct RawDisposition {
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub incident_id: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub analyst: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Maximum accepted length of the free-text `note` field, in bytes.
pub const MAX_NOTE_BYTES: usize = 2048;

/// A validated, normalized disposition ready for the store.
///
/// `rule_id` is `None` only for an `incident`-scoped record that the daemon has
/// not yet resolved to its contributing rules; the store rejects such a record
/// until a `rule_id` is supplied.
#[derive(Debug, Clone, PartialEq)]
pub struct Disposition {
    /// The rule identity the verdict accounts against (the rule's id, with the
    /// title as the fallback the per-rule metrics already use).
    pub rule_id: Option<String>,
    /// The analyst verdict.
    pub verdict: Verdict,
    /// Detection- or incident-scoped.
    pub scope: DispositionScope,
    /// The alert-pipeline dedup fingerprint, when carried.
    pub fingerprint: Option<String>,
    /// The alert-pipeline incident id, required for `incident` scope.
    pub incident_id: Option<String>,
    /// Epoch seconds for rolling-window placement (defaults to ingest time).
    pub timestamp: i64,
    /// Optional analyst identity, recorded for traceability.
    pub analyst: Option<String>,
    /// Optional bounded free-text note, recorded for traceability.
    pub note: Option<String>,
}

impl Disposition {
    /// Validate and normalize a [`RawDisposition`], using `now` (epoch seconds)
    /// as the default timestamp when none is supplied.
    pub fn from_raw(raw: RawDisposition, now: i64) -> Result<Self, DispositionError> {
        let verdict = match raw.verdict.as_deref() {
            Some(v) => Verdict::parse(v)?,
            None => return Err(DispositionError::field("verdict", "missing required field")),
        };

        let scope = match raw.scope.as_deref() {
            Some(s) => DispositionScope::parse(s)?,
            None => DispositionScope::Detection,
        };

        let rule_id = raw.rule_id.filter(|s| !s.is_empty());
        let incident_id = raw.incident_id.filter(|s| !s.is_empty());
        let fingerprint = raw.fingerprint.filter(|s| !s.is_empty());

        match scope {
            DispositionScope::Detection => {
                if rule_id.is_none() {
                    return Err(DispositionError::field(
                        "rule_id",
                        "missing required field for a 'detection'-scoped disposition",
                    ));
                }
            }
            DispositionScope::Incident => {
                if incident_id.is_none() {
                    return Err(DispositionError::field(
                        "incident_id",
                        "required when 'scope' is 'incident'",
                    ));
                }
            }
        }

        let timestamp = match raw.timestamp.as_deref() {
            Some(ts) => parse_rfc3339(ts)?,
            None => now,
        };

        if let Some(note) = raw.note.as_deref()
            && note.len() > MAX_NOTE_BYTES
        {
            return Err(DispositionError::field(
                "note",
                format!("exceeds the {MAX_NOTE_BYTES}-byte limit"),
            ));
        }

        Ok(Self {
            rule_id,
            verdict,
            scope,
            fingerprint,
            incident_id,
            timestamp,
            analyst: raw.analyst.filter(|s| !s.is_empty()),
            note: raw.note,
        })
    }

    /// The idempotency key for redelivery dedup: `(fingerprint or incident_id,
    /// verdict, rule_id)` when an alert identity is present, otherwise
    /// `(rule_id, timestamp, analyst)`.
    ///
    /// The `rule_id` is always part of the key. It is redundant for a
    /// fingerprint (which already identifies a single rule's alert) but
    /// essential for an `incident_id`, which fans out to every contributing
    /// rule: without it, the per-rule records an incident expands into would
    /// collapse to one and only the first rule would be counted.
    pub fn dedup_key(&self) -> String {
        let rule = self.rule_id.as_deref().unwrap_or("");
        if let Some(id) = self.fingerprint.as_deref().or(self.incident_id.as_deref()) {
            format!("id\u{1}{id}\u{1}{}\u{1}{rule}", self.verdict.as_str())
        } else {
            format!(
                "rt\u{1}{rule}\u{1}{}\u{1}{}",
                self.timestamp,
                self.analyst.as_deref().unwrap_or(""),
            )
        }
    }
}

/// Parse an RFC 3339 timestamp into epoch seconds.
fn parse_rfc3339(ts: &str) -> Result<i64, DispositionError> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp())
        .map_err(|e| {
            DispositionError::field("timestamp", format!("not a valid RFC 3339 time: {e}"))
        })
}

/// Parse a `POST` body or source payload into a vector of raw dispositions.
///
/// Accepts a single JSON object, a JSON array of objects, or newline-delimited
/// JSON (one object per line; blank lines are skipped). This is the single
/// untrusted-input surface and never panics on malformed input.
pub fn parse_dispositions(input: &str) -> Result<Vec<RawDisposition>, DispositionError> {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // A leading `[` is a JSON array; a single-line leading `{` is one JSON
    // object; anything else is NDJSON (one object per non-blank line).
    if trimmed.starts_with('[') {
        return serde_json::from_str::<Vec<RawDisposition>>(trimmed)
            .map_err(|e| DispositionError::parse(format!("invalid disposition array: {e}")));
    }
    if trimmed.starts_with('{') && !trimmed.contains('\n') {
        return serde_json::from_str::<RawDisposition>(trimmed)
            .map(|d| vec![d])
            .map_err(|e| DispositionError::parse(format!("invalid disposition object: {e}")));
    }

    let mut out = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec = serde_json::from_str::<RawDisposition>(line).map_err(|e| {
            DispositionError::parse(format!("invalid disposition on line {}: {e}", i + 1))
        })?;
        out.push(rec);
    }
    Ok(out)
}

/// An error parsing or validating a disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispositionError {
    /// The JSON could not be parsed.
    Parse(String),
    /// A field was missing or invalid; carries the field name and reason.
    Field { field: String, reason: String },
}

impl DispositionError {
    fn field(field: &str, reason: impl Into<String>) -> Self {
        Self::Field {
            field: field.to_string(),
            reason: reason.into(),
        }
    }

    fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }
}

impl std::fmt::Display for DispositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "{msg}"),
            Self::Field { field, reason } => write!(f, "field '{field}': {reason}"),
        }
    }
}

impl std::error::Error for DispositionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(json: &str) -> RawDisposition {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn verdict_round_trips() {
        for v in [
            Verdict::TruePositive,
            Verdict::FalsePositive,
            Verdict::BenignTruePositive,
        ] {
            assert_eq!(Verdict::parse(v.as_str()).unwrap(), v);
        }
        assert!(Verdict::parse("nope").is_err());
    }

    #[test]
    fn detection_requires_rule_id() {
        let err = Disposition::from_raw(raw(r#"{"verdict": "false_positive"}"#), 100).unwrap_err();
        assert!(matches!(err, DispositionError::Field { ref field, .. } if field == "rule_id"));
    }

    #[test]
    fn incident_requires_incident_id() {
        let err = Disposition::from_raw(
            raw(r#"{"verdict": "true_positive", "scope": "incident"}"#),
            100,
        )
        .unwrap_err();
        assert!(matches!(err, DispositionError::Field { ref field, .. } if field == "incident_id"));
    }

    #[test]
    fn incident_scope_allows_missing_rule_id() {
        let d = Disposition::from_raw(
            raw(r#"{"verdict": "true_positive", "scope": "incident", "incident_id": "abc"}"#),
            100,
        )
        .unwrap();
        assert_eq!(d.rule_id, None);
        assert_eq!(d.scope, DispositionScope::Incident);
        assert_eq!(d.incident_id.as_deref(), Some("abc"));
    }

    #[test]
    fn missing_verdict_is_rejected() {
        let err = Disposition::from_raw(raw(r#"{"rule_id": "r1"}"#), 100).unwrap_err();
        assert!(matches!(err, DispositionError::Field { ref field, .. } if field == "verdict"));
    }

    #[test]
    fn timestamp_defaults_to_now_else_parses_rfc3339() {
        let d = Disposition::from_raw(raw(r#"{"rule_id": "r", "verdict": "true_positive"}"#), 42)
            .unwrap();
        assert_eq!(d.timestamp, 42);

        let d = Disposition::from_raw(
            raw(r#"{"rule_id": "r", "verdict": "true_positive", "timestamp": "2026-01-01T00:00:00Z"}"#),
            42,
        )
        .unwrap();
        assert_eq!(d.timestamp, 1_767_225_600);

        let err = Disposition::from_raw(
            raw(r#"{"rule_id": "r", "verdict": "true_positive", "timestamp": "not-a-time"}"#),
            42,
        )
        .unwrap_err();
        assert!(matches!(err, DispositionError::Field { ref field, .. } if field == "timestamp"));
    }

    #[test]
    fn oversized_note_is_rejected() {
        let note = "x".repeat(MAX_NOTE_BYTES + 1);
        let json = format!(r#"{{"rule_id": "r", "verdict": "true_positive", "note": "{note}"}}"#);
        let err = Disposition::from_raw(raw(&json), 1).unwrap_err();
        assert!(matches!(err, DispositionError::Field { ref field, .. } if field == "note"));
    }

    #[test]
    fn dedup_key_prefers_alert_identity() {
        let with_fp = Disposition::from_raw(
            raw(r#"{"rule_id": "r", "verdict": "false_positive", "fingerprint": "fp1"}"#),
            1,
        )
        .unwrap();
        assert!(with_fp.dedup_key().contains("fp1"));

        // Same fingerprint + verdict collapses regardless of timestamp/analyst.
        let again = Disposition::from_raw(
            raw(r#"{"rule_id": "r", "verdict": "false_positive", "fingerprint": "fp1", "analyst": "x"}"#),
            999,
        )
        .unwrap();
        assert_eq!(with_fp.dedup_key(), again.dedup_key());

        // Without an alert identity, the key falls back to rule/time/analyst.
        let no_id =
            Disposition::from_raw(raw(r#"{"rule_id": "r", "verdict": "false_positive"}"#), 5)
                .unwrap();
        assert!(no_id.dedup_key().contains("\u{1}5\u{1}"));
    }

    #[test]
    fn parse_accepts_object_array_and_ndjson() {
        assert_eq!(parse_dispositions("").unwrap().len(), 0);
        assert_eq!(
            parse_dispositions(r#"{"rule_id":"r","verdict":"true_positive"}"#)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            parse_dispositions(
                r#"[{"rule_id":"r","verdict":"true_positive"},{"rule_id":"s","verdict":"false_positive"}]"#
            )
            .unwrap()
            .len(),
            2
        );
        let ndjson = "{\"rule_id\":\"r\",\"verdict\":\"true_positive\"}\n\n{\"rule_id\":\"s\",\"verdict\":\"false_positive\"}\n";
        assert_eq!(parse_dispositions(ndjson).unwrap().len(), 2);
    }

    #[test]
    fn parse_reports_malformed_input() {
        assert!(matches!(
            parse_dispositions("[not json"),
            Err(DispositionError::Parse(_))
        ));
        assert!(matches!(
            parse_dispositions("{bad}\n{also bad}"),
            Err(DispositionError::Parse(_))
        ));
    }
}
