//! TAXII envelope and status resources.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::TaxiiTimestamp;
use crate::model::ParseOptions;
use crate::model::StixObject;
use crate::model::stix_object::deserialize_stix_object_from_value;
use crate::model::validate_value_limits;

use super::TaxiiError;
use super::filter::ObjectVersion;

/// TAXII envelope wire format (spec section 3.7) — not a STIX Bundle.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TaxiiEnvelope {
    /// Whether additional pages exist.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub more: bool,
    /// Opaque pagination cursor when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// STIX objects in this page.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<StixObject>,
    /// Custom envelope properties (`x_*`) preserved for TXC/TXS interoperability (CSD01 §3.15).
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

impl TaxiiEnvelope {
    /// Create an envelope for POST requests.
    pub fn new(objects: Vec<StixObject>) -> Self {
        Self {
            more: false,
            next: None,
            objects,
            custom: BTreeMap::new(),
        }
    }

    /// Attach a custom `x_*` property (CSD01 §3.15.1).
    pub fn with_custom(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.custom.insert(key.into(), value);
        self
    }
}

/// Raw envelope JSON prior to STIX object dispatch.
#[derive(Deserialize)]
struct RawEnvelope {
    #[serde(default)]
    more: bool,
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    objects: Vec<serde_json::Value>,
    /// Unmodeled envelope properties (including `x_*` custom properties).
    #[serde(flatten)]
    custom: BTreeMap<String, serde_json::Value>,
}

impl RawEnvelope {
    fn into_envelope(self, opts: &ParseOptions) -> Result<TaxiiEnvelope, TaxiiError> {
        let mut objects = Vec::with_capacity(self.objects.len());
        for value in self.objects {
            let (object, _) = deserialize_stix_object_from_value(value, opts)?;
            objects.push(object);
        }
        Ok(TaxiiEnvelope {
            more: self.more,
            next: self.next,
            objects,
            custom: self.custom,
        })
    }
}

/// Parse a TAXII envelope, applying the same JSON limits as [`crate::Bundle::parse_with_options`].
///
/// Nesting depth and string length use [`ParseOptions::max_nesting_depth`] and
/// [`ParseOptions::max_string_length`]. The `objects` array is rejected when it is longer
/// than [`ParseOptions::max_object_count`]. Limit failures are [`crate::ParseError`] values
/// wrapped in [`TaxiiError::StixParseError`]. JSON that is not an object fails as
/// [`TaxiiError::MalformedResponse`].
pub fn parse_envelope(bytes: &[u8], opts: &ParseOptions) -> Result<TaxiiEnvelope, TaxiiError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|err| TaxiiError::MalformedResponse {
            reason: err.to_string(),
        })?;
    validate_value_limits(&value, opts)?;
    let object_count = value
        .get("objects")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if object_count > opts.max_object_count {
        return Err(crate::ParseError::ObjectLimitExceeded {
            count: object_count,
            max: opts.max_object_count,
        }
        .into());
    }
    let raw: RawEnvelope =
        serde_json::from_value(value).map_err(|err| TaxiiError::MalformedResponse {
            reason: err.to_string(),
        })?;
    raw.into_envelope(opts)
}

/// Status resource processing state (spec section 4.3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusState {
    /// Request still processing.
    Pending,
    /// Request finished.
    Complete,
}

/// Per-object status detail entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusDetail {
    /// Object identifier.
    pub id: String,
    /// Object version string when present.
    #[serde(default)]
    pub version: Option<String>,
    /// Optional detail message.
    #[serde(default)]
    pub message: Option<String>,
}

impl StatusDetail {
    /// Parse the version field into [`ObjectVersion`] when present.
    pub fn object_version(&self) -> Option<ObjectVersion> {
        self.version.as_deref().map(ObjectVersion::from_wire)
    }
}

/// Status resource returned for POST 202 and status polling.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaxiiStatus {
    /// Status identifier.
    pub id: String,
    /// Processing state.
    pub status: StatusState,
    /// Request timestamp (TAXII transport precision).
    #[serde(default)]
    pub request_timestamp: Option<TaxiiTimestamp>,
    /// Total objects in the status summary.
    pub total_count: u32,
    /// Successfully processed object count.
    pub success_count: u32,
    /// Successfully processed objects.
    #[serde(default)]
    pub successes: Vec<StatusDetail>,
    /// Failed object count.
    pub failure_count: u32,
    /// Failed objects.
    #[serde(default)]
    pub failures: Vec<StatusDetail>,
    /// Pending object count.
    pub pending_count: u32,
    /// Objects still pending processing.
    #[serde(default)]
    pub pendings: Vec<StatusDetail>,
    /// Custom status properties preserved verbatim.
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

/// Manifest record entry (spec section 5.3.1).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ManifestRecord {
    /// Object identifier.
    pub id: String,
    /// When the object version was added to the collection.
    pub date_added: TaxiiTimestamp,
    /// Object version string.
    pub version: String,
    /// Optional media type for this version.
    #[serde(default)]
    pub media_type: Option<String>,
}

/// Manifest resource wrapper.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ManifestResponse {
    /// Whether more manifest records are available.
    #[serde(default)]
    pub more: bool,
    /// Opaque pagination cursor when present.
    #[serde(default)]
    pub next: Option<String>,
    /// Manifest records when present.
    #[serde(default)]
    pub objects: Vec<ManifestRecord>,
    /// Unmodeled manifest properties.
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParseError;

    fn limited(max_objects: usize, max_depth: usize, max_string: usize) -> ParseOptions {
        ParseOptions {
            max_object_count: max_objects,
            max_nesting_depth: max_depth,
            max_string_length: max_string,
            ..ParseOptions::default()
        }
    }

    #[test]
    fn empty_envelope_parses() {
        let envelope = parse_envelope(br#"{"objects":[]}"#, &ParseOptions::default()).unwrap();
        assert!(envelope.objects.is_empty());
    }

    #[test]
    fn rejects_too_many_objects() {
        let err = parse_envelope(br#"{"objects":[{},{}]}"#, &limited(1, 64, 1024)).unwrap_err();
        assert!(matches!(
            err,
            TaxiiError::StixParseError(ParseError::ObjectLimitExceeded { count: 2, max: 1 })
        ));
    }

    #[test]
    fn rejects_nesting_past_the_limit() {
        let err =
            parse_envelope(br#"{"objects":[{"a":{"b":1}}]}"#, &limited(8, 2, 1024)).unwrap_err();
        assert!(matches!(
            err,
            TaxiiError::StixParseError(ParseError::JsonNestingTooDeep { max: 2 })
        ));
    }

    #[test]
    fn rejects_a_string_past_the_limit() {
        let body = format!(r#"{{"next":"{}","objects":[]}}"#, "n".repeat(8));
        let err = parse_envelope(body.as_bytes(), &limited(8, 64, 4)).unwrap_err();
        assert!(matches!(
            err,
            TaxiiError::StixParseError(ParseError::JsonStringTooLong { len: 8, max: 4 })
        ));
    }
}
