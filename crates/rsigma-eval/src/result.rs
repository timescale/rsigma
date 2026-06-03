//! Unified result type for rule evaluation and correlation.
//!
//! `EvaluationResult` is the single output type produced by both detection
//! and correlation. Fields shared across kinds (rule metadata, custom
//! attributes, optional enrichments) live in [`RuleHeader`]; kind-specific
//! fields live in [`ResultBody`]. Both are merged into one flat top-level
//! JSON object via `#[serde(flatten)]` on the struct and `#[serde(untagged)]`
//! on the body enum.
//!
//! Downstream JSON consumers distinguish detection from correlation by the
//! presence of `correlation_type` (correlation-only) and `matched_fields`
//! (detection-only). The field set, values, and `skip_serializing_if`
//! behavior match the pre-unification `MatchResult` / `CorrelationResult`
//! layout; the only visible difference is that a non-empty
//! `custom_attributes` map is now emitted between header and body fields
//! rather than at the end of the line, which is invisible to compliant
//! JSON consumers (objects are unordered per spec). The wire-shape golden
//! tests under `crates/rsigma-eval/tests/wire_shape_golden.rs` pin the
//! new ordering for both kinds.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_parser::{CorrelationType, Level};
use serde::Serialize;

use crate::correlation::EventRef;

/// A single evaluation result.
///
/// Wraps a detection match ([`ResultBody::Detection`]) or a correlation
/// firing ([`ResultBody::Correlation`]) behind one shared [`RuleHeader`].
/// Serialize emits a single flat JSON object combining header and body
/// fields.
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationResult {
    #[serde(flatten)]
    pub header: RuleHeader,
    #[serde(flatten)]
    pub body: ResultBody,
}

impl EvaluationResult {
    /// True when this result was produced by detection rule matching.
    pub fn is_detection(&self) -> bool {
        matches!(self.body, ResultBody::Detection(_))
    }

    /// True when this result was produced by a correlation firing.
    pub fn is_correlation(&self) -> bool {
        matches!(self.body, ResultBody::Correlation(_))
    }

    /// Read the detection-specific body, if this result is a detection.
    pub fn as_detection(&self) -> Option<&DetectionBody> {
        match &self.body {
            ResultBody::Detection(d) => Some(d),
            ResultBody::Correlation(_) => None,
        }
    }

    /// Read the correlation-specific body, if this result is a correlation.
    pub fn as_correlation(&self) -> Option<&CorrelationBody> {
        match &self.body {
            ResultBody::Correlation(c) => Some(c),
            ResultBody::Detection(_) => None,
        }
    }

    /// Mutable accessor for the detection-specific body.
    pub fn as_detection_mut(&mut self) -> Option<&mut DetectionBody> {
        match &mut self.body {
            ResultBody::Detection(d) => Some(d),
            ResultBody::Correlation(_) => None,
        }
    }

    /// Mutable accessor for the correlation-specific body.
    pub fn as_correlation_mut(&mut self) -> Option<&mut CorrelationBody> {
        match &mut self.body {
            ResultBody::Correlation(c) => Some(c),
            ResultBody::Detection(_) => None,
        }
    }
}

/// Fields shared between detection and correlation results.
///
/// The optional `enrichments` map is `None` for results emitted directly
/// by the engine; downstream middleware can populate it with arbitrary
/// JSON values to ride along with each result.
#[derive(Debug, Clone, Serialize)]
pub struct RuleHeader {
    /// Title of the matched rule.
    pub rule_title: String,
    /// ID of the matched rule (if present).
    pub rule_id: Option<String>,
    /// Severity level.
    pub level: Option<Level>,
    /// Tags from the matched rule.
    pub tags: Vec<String>,
    /// Custom attributes from the rule (merged with pipeline overrides).
    ///
    /// Wrapped in `Arc` so per-match cloning is a pointer bump.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
    /// Optional map of arbitrary enrichment values, written by downstream
    /// middleware. `None` for engine-emitted results; skipped on serialize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichments: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Kind-specific payload of an [`EvaluationResult`].
///
/// Serialized as an untagged enum so the variant fields flatten directly
/// into the parent JSON object. Downstream consumers disambiguate variants
/// by the kind-unique fields each variant carries (`matched_fields` for
/// detection, `correlation_type` for correlation).
///
/// Invariant: each variant must keep at least one required, kind-unique
/// field. This is what lets the untagged enum disambiguate on a future
/// `Deserialize` and keeps the `correlation_type`-presence rule reliable
/// for existing consumers.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ResultBody {
    /// Detection rule match (stateless, immediate).
    Detection(DetectionBody),
    /// Correlation rule firing (stateful, time-windowed).
    Correlation(CorrelationBody),
}

/// Detection-specific result fields.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionBody {
    /// Which named detections (selections) matched.
    pub matched_selections: Vec<String>,
    /// Specific field matches that triggered the detection.
    pub matched_fields: Vec<FieldMatch>,
    /// The full event that triggered the match, included when the rule
    /// sets `rsigma.include_event: "true"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<serde_json::Value>,
}

/// Correlation-specific result fields.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationBody {
    /// Type of correlation.
    pub correlation_type: CorrelationType,
    /// Group-by field names and their values for this match.
    pub group_key: Vec<(String, String)>,
    /// The aggregated value that triggered the condition (count, sum, avg, ...).
    pub aggregated_value: f64,
    /// The time window in seconds.
    pub timespan_secs: u64,
    /// Tenant/organization that produced this correlation.
    /// `None` in single-tenant mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Full event bodies, included when `correlation_event_mode` is `Full`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<serde_json::Value>>,
    /// Lightweight event references, included when `correlation_event_mode` is `Refs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_refs: Option<Vec<EventRef>>,
}

/// A specific field match within a detection.
#[derive(Debug, Clone, Serialize)]
pub struct FieldMatch {
    /// The field name that matched.
    pub field: String,
    /// The event value that triggered the match.
    pub value: serde_json::Value,
}

/// Convenience iterators over a slice of [`EvaluationResult`].
///
/// `ProcessResult` is a flat `Vec<EvaluationResult>` (detections then
/// correlations, in evaluation order); this trait exposes by-kind views
/// without forcing every caller to write `.iter().filter(|r| r.is_*())`.
/// Implemented on `[EvaluationResult]` so it works for `Vec`, slices, and
/// boxed slices alike.
pub trait ProcessResultExt {
    /// Iterate over detection results.
    fn detections(&self) -> impl Iterator<Item = &EvaluationResult>;
    /// Iterate over correlation results.
    fn correlations(&self) -> impl Iterator<Item = &EvaluationResult>;
    /// Number of detection results.
    fn detection_count(&self) -> usize {
        self.detections().count()
    }
    /// Number of correlation results.
    fn correlation_count(&self) -> usize {
        self.correlations().count()
    }
}

impl ProcessResultExt for [EvaluationResult] {
    fn detections(&self) -> impl Iterator<Item = &EvaluationResult> {
        self.iter().filter(|r| r.is_detection())
    }
    fn correlations(&self) -> impl Iterator<Item = &EvaluationResult> {
        self.iter().filter(|r| r.is_correlation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(title: &str) -> RuleHeader {
        RuleHeader {
            rule_title: title.to_string(),
            rule_id: Some(format!("{title}-id")),
            level: Some(Level::High),
            tags: vec!["attack.t1059".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        }
    }

    /// Wire-shape snapshot: a detection serializes to a flat JSON object
    /// with detection-only fields and no `correlation_type` key.
    #[test]
    fn detection_wire_shape_is_flat() {
        let result = EvaluationResult {
            header: header("Suspicious PowerShell"),
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["selection".to_string()],
                matched_fields: vec![FieldMatch {
                    field: "CommandLine".to_string(),
                    value: serde_json::json!("powershell -enc ..."),
                }],
                event: None,
            }),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(
            json,
            r#"{"rule_title":"Suspicious PowerShell","rule_id":"Suspicious PowerShell-id","level":"high","tags":["attack.t1059"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"powershell -enc ..."}]}"#
        );

        // Downstream-disambiguation contract: detections must not carry
        // a `correlation_type` key.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("correlation_type").is_none());
        assert!(parsed.get("matched_fields").is_some());
    }

    /// Wire-shape snapshot: a correlation serializes to a flat JSON object
    /// with correlation-only fields and no `matched_fields` key.
    #[test]
    fn correlation_wire_shape_is_flat() {
        let result = EvaluationResult {
            header: header("SSH brute force"),
            body: ResultBody::Correlation(CorrelationBody {
                correlation_type: CorrelationType::EventCount,
                group_key: vec![("SourceIP".to_string(), "203.0.113.4".to_string())],
                aggregated_value: 73.0,
                timespan_secs: 300,
                tenant_id: None,
                events: None,
                event_refs: None,
            }),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(
            json,
            r#"{"rule_title":"SSH brute force","rule_id":"SSH brute force-id","level":"high","tags":["attack.t1059"],"correlation_type":"event_count","group_key":[["SourceIP","203.0.113.4"]],"aggregated_value":73.0,"timespan_secs":300}"#
        );

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("matched_fields").is_none());
        assert!(parsed.get("correlation_type").is_some());
    }

    #[test]
    fn accessors_dispatch_on_body_variant() {
        let det = EvaluationResult {
            header: header("Det"),
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![],
                event: None,
            }),
        };
        assert!(det.is_detection());
        assert!(!det.is_correlation());
        assert!(det.as_detection().is_some());
        assert!(det.as_correlation().is_none());

        let corr = EvaluationResult {
            header: header("Corr"),
            body: ResultBody::Correlation(CorrelationBody {
                correlation_type: CorrelationType::EventCount,
                group_key: vec![],
                aggregated_value: 0.0,
                timespan_secs: 0,
                tenant_id: None,
                events: None,
                event_refs: None,
            }),
        };
        assert!(corr.is_correlation());
        assert!(!corr.is_detection());
        assert!(corr.as_correlation().is_some());
        assert!(corr.as_detection().is_none());
    }
}
