//! Schema classification: recognize the structure of a parsed event.
//!
//! Real-world streams mix log schemas: one feed can carry ECS-normalized
//! events, raw (rendered) Windows Event Log, flat Sysmon JSON, CEF, OCSF, or
//! vendor-specific shapes, and the wire format is often still JSON while only
//! the field names differ. This module recognizes which schema a parsed event
//! belongs to from its *content* (marker fields and values), not from the
//! input format, so it works regardless of how the event arrived.
//!
//! Classification is declarative: each [`SchemaSignature`] is a set of
//! [`SchemaPredicate`]s that must all hold (logical AND). The
//! [`SchemaClassifier`] returns the highest-[`specificity`](SchemaSignature::specificity)
//! signature that matches, breaking ties by name for determinism. Returning
//! `None` means the event matched no signature ("unknown"), which is the
//! actionable signal for surfacing unsupported schemas.
//!
//! Built-in signatures cover `ecs`, `ocsf`, `windows_eventlog`, `sysmon`,
//! `cef`, and a low-specificity `generic_json` fallback for structured events
//! that match no specific security schema. Users extend the set with their own
//! signatures loaded from YAML (see [`parse_schema_signatures`]).
//!
//! Detection-side only: this recognizes events so callers can route them to the
//! right field-mapping pipeline. It does not collect, transport, or normalize
//! events.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use regex::Regex;
use serde::Deserialize;

use crate::event::Event;

/// A single condition over a parsed event used to recognize a schema.
///
/// Field names use the same dot-notation as [`Event::get_field`], so nested
/// shapes like `Event.System.EventID` or `ecs.version` work whether the event
/// is nested or carries flattened dotted keys.
#[derive(Debug, Clone)]
pub enum SchemaPredicate {
    /// The named field is present (any non-absent value, including null).
    FieldPresent(String),
    /// The named field is absent.
    FieldAbsent(String),
    /// At least one of the named fields is present.
    AnyOf(Vec<String>),
    /// The field is present and its string-coerced value equals `value`
    /// (ASCII case-insensitive).
    Equals { field: String, value: String },
    /// The field is present and its string-coerced value matches `regex`.
    Matches { field: String, regex: Regex },
    /// The event has at least one structured field. Used by the
    /// `generic_json` fallback to distinguish structured events from
    /// field-less ones (raw text, empty objects), which stay "unknown".
    HasAnyField,
}

impl SchemaPredicate {
    fn eval<E: Event + ?Sized>(&self, event: &E) -> bool {
        match self {
            SchemaPredicate::FieldPresent(f) => event.get_field(f).is_some(),
            SchemaPredicate::FieldAbsent(f) => event.get_field(f).is_none(),
            SchemaPredicate::AnyOf(fields) => fields.iter().any(|f| event.get_field(f).is_some()),
            SchemaPredicate::Equals { field, value } => event
                .get_field(field)
                .and_then(|v| v.as_str().map(|s| s.as_ref().eq_ignore_ascii_case(value)))
                .unwrap_or(false),
            SchemaPredicate::Matches { field, regex } => event
                .get_field(field)
                .and_then(|v| v.as_str().map(|s| regex.is_match(s.as_ref())))
                .unwrap_or(false),
            SchemaPredicate::HasAnyField => !event.field_keys().is_empty(),
        }
    }
}

/// A named schema recognizer: every predicate must hold for the signature to
/// match. Higher `specificity` wins when several signatures match the same
/// event. Multiple signatures may share a `name` (for example several distinct
/// ways to recognize Sysmon); the classifier reports the name.
#[derive(Debug, Clone)]
pub struct SchemaSignature {
    /// Schema label reported on a match (for example `ecs`, `sysmon`).
    pub name: String,
    /// Conditions that must all hold (logical AND). An empty predicate set
    /// matches every event; prefer [`SchemaPredicate::HasAnyField`] for a
    /// structured-event fallback.
    pub predicates: Vec<SchemaPredicate>,
    /// Tie-breaking weight; the highest-specificity matching signature wins.
    pub specificity: u32,
}

impl SchemaSignature {
    fn matches<E: Event + ?Sized>(&self, event: &E) -> bool {
        self.predicates.iter().all(|p| p.eval(event))
    }
}

/// The result of classifying an event: the matched schema name and the
/// specificity of the signature that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMatch {
    pub name: String,
    pub specificity: u32,
}

/// Recognizes the schema of parsed events from a set of signatures.
///
/// Signatures are sorted once at construction (specificity descending, then
/// name ascending) so [`classify`](Self::classify) returns the best match with
/// a single in-order scan.
#[derive(Debug, Clone)]
pub struct SchemaClassifier {
    signatures: Vec<SchemaSignature>,
}

impl SchemaClassifier {
    /// Build a classifier from an explicit signature set.
    pub fn new(mut signatures: Vec<SchemaSignature>) -> Self {
        signatures.sort_by(|a, b| {
            b.specificity
                .cmp(&a.specificity)
                .then_with(|| a.name.cmp(&b.name))
        });
        Self { signatures }
    }

    /// Build a classifier from the built-in signatures only.
    pub fn builtin() -> Self {
        Self::new(builtin_signatures())
    }

    /// Build a classifier from the built-ins plus user-supplied signatures.
    /// User signatures are added to (not replacing) the built-ins; a user
    /// signature with a higher specificity than a built-in wins on overlap.
    pub fn with_user_signatures(user: Vec<SchemaSignature>) -> Self {
        let mut signatures = builtin_signatures();
        signatures.extend(user);
        Self::new(signatures)
    }

    /// Classify an event. Returns the highest-specificity matching schema, or
    /// `None` when the event matches no signature ("unknown").
    pub fn classify<E: Event + ?Sized>(&self, event: &E) -> Option<SchemaMatch> {
        self.signatures
            .iter()
            .find(|s| s.matches(event))
            .map(|s| SchemaMatch {
                name: s.name.clone(),
                specificity: s.specificity,
            })
    }

    /// All matching schema names for an event, most specific first. Useful for
    /// tuning signatures (seeing what else an event could match). Deduplicated
    /// by name while preserving order.
    pub fn classify_all<E: Event + ?Sized>(&self, event: &E) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for sig in self.signatures.iter().filter(|s| s.matches(event)) {
            if !out.iter().any(|n| n == &sig.name) {
                out.push(sig.name.clone());
            }
        }
        out
    }

    /// Distinct schema names this classifier can produce, most specific first.
    pub fn schema_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for sig in &self.signatures {
            if !out.contains(&sig.name.as_str()) {
                out.push(sig.name.as_str());
            }
        }
        out
    }
}

impl Default for SchemaClassifier {
    fn default() -> Self {
        Self::builtin()
    }
}

/// The built-in schema signatures, derived from the public schema specs:
/// Elastic Common Schema, OCSF, the Windows event XML model, Microsoft
/// Sysmon, and the ArcSight CEF spec.
fn builtin_signatures() -> Vec<SchemaSignature> {
    vec![
        // ECS (Elastic Common Schema): `ecs.version` is the canonical marker.
        SchemaSignature {
            name: "ecs".to_string(),
            specificity: 100,
            predicates: vec![SchemaPredicate::FieldPresent("ecs.version".to_string())],
        },
        // OCSF: class_uid plus metadata.version are mandatory discriminators.
        SchemaSignature {
            name: "ocsf".to_string(),
            specificity: 95,
            predicates: vec![
                SchemaPredicate::FieldPresent("class_uid".to_string()),
                SchemaPredicate::FieldPresent("metadata.version".to_string()),
            ],
        },
        // Rendered Windows Event Log (EVTX decoded to JSON): Event.System.*.
        SchemaSignature {
            name: "windows_eventlog".to_string(),
            specificity: 90,
            predicates: vec![SchemaPredicate::AnyOf(vec![
                "Event.System.EventID".to_string(),
                "Event.System.Provider".to_string(),
            ])],
        },
        // Sysmon (flat) via the operational channel marker.
        SchemaSignature {
            name: "sysmon".to_string(),
            specificity: 88,
            predicates: vec![SchemaPredicate::Equals {
                field: "Channel".to_string(),
                value: "Microsoft-Windows-Sysmon/Operational".to_string(),
            }],
        },
        // Sysmon (flat) via the provider marker.
        SchemaSignature {
            name: "sysmon".to_string(),
            specificity: 88,
            predicates: vec![SchemaPredicate::Equals {
                field: "Provider_Name".to_string(),
                value: "Microsoft-Windows-Sysmon".to_string(),
            }],
        },
        // Sysmon (flat) via field shape when no provider/channel tag is present.
        SchemaSignature {
            name: "sysmon".to_string(),
            specificity: 80,
            predicates: vec![
                SchemaPredicate::FieldPresent("EventID".to_string()),
                SchemaPredicate::FieldPresent("ProcessGuid".to_string()),
                SchemaPredicate::AnyOf(vec!["Image".to_string(), "CommandLine".to_string()]),
            ],
        },
        // CEF: structured header fields produced by the CEF parser or carried
        // in JSON (deviceVendor / deviceProduct / signatureId).
        SchemaSignature {
            name: "cef".to_string(),
            specificity: 85,
            predicates: vec![
                SchemaPredicate::FieldPresent("deviceVendor".to_string()),
                SchemaPredicate::FieldPresent("deviceProduct".to_string()),
                SchemaPredicate::FieldPresent("signatureId".to_string()),
            ],
        },
        // Generic JSON: any structured event that matched no specific schema.
        SchemaSignature {
            name: "generic_json".to_string(),
            specificity: 0,
            predicates: vec![SchemaPredicate::HasAnyField],
        },
    ]
}

/// Distinct built-in schema names, most specific first.
pub fn builtin_schema_names() -> Vec<&'static str> {
    vec![
        "ecs",
        "ocsf",
        "windows_eventlog",
        "sysmon",
        "cef",
        "generic_json",
    ]
}

// =============================================================================
// User-supplied signatures (YAML config)
// =============================================================================

/// Errors raised while loading user schema signatures.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// The signatures file could not be read.
    #[error("cannot read schema signatures file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The signatures YAML failed to parse.
    #[error("schema signatures YAML parse error: {0}")]
    Parse(String),
    /// A predicate carried an invalid regular expression.
    #[error("invalid regex in schema '{name}': {error}")]
    InvalidRegex { name: String, error: String },
}

/// A `{ field: ..., value: ... }` pair used by the `equals` and `matches`
/// predicate forms.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValueConfig {
    pub field: String,
    pub value: String,
}

/// A predicate as written in YAML: a single-key map, for example
/// `field_present: ecs.version` or `equals: { field: type, value: alert }`.
/// Exactly one form must be set per list entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaPredicateConfig {
    /// `field_present: <field>`
    #[serde(default)]
    pub field_present: Option<String>,
    /// `field_absent: <field>`
    #[serde(default)]
    pub field_absent: Option<String>,
    /// `any_of: [<field>, ...]`
    #[serde(default)]
    pub any_of: Option<Vec<String>>,
    /// `equals: { field: <field>, value: <value> }`
    #[serde(default)]
    pub equals: Option<FieldValueConfig>,
    /// `matches: { field: <field>, value: <regex> }`
    #[serde(default)]
    pub matches: Option<FieldValueConfig>,
}

impl SchemaPredicateConfig {
    fn build(self, schema_name: &str) -> Result<SchemaPredicate, SchemaError> {
        let mut chosen: Option<SchemaPredicate> = None;
        let mut set = 0u32;
        if let Some(f) = self.field_present {
            set += 1;
            chosen = Some(SchemaPredicate::FieldPresent(f));
        }
        if let Some(f) = self.field_absent {
            set += 1;
            chosen = Some(SchemaPredicate::FieldAbsent(f));
        }
        if let Some(fields) = self.any_of {
            set += 1;
            chosen = Some(SchemaPredicate::AnyOf(fields));
        }
        if let Some(fv) = self.equals {
            set += 1;
            chosen = Some(SchemaPredicate::Equals {
                field: fv.field,
                value: fv.value,
            });
        }
        if let Some(fv) = self.matches {
            set += 1;
            chosen = Some(SchemaPredicate::Matches {
                field: fv.field,
                regex: Regex::new(&fv.value).map_err(|e| SchemaError::InvalidRegex {
                    name: schema_name.to_string(),
                    error: e.to_string(),
                })?,
            });
        }
        match (set, chosen) {
            (1, Some(p)) => Ok(p),
            (0, _) => Err(SchemaError::Parse(format!(
                "schema '{schema_name}': a predicate has no condition (expected one of \
                 field_present, field_absent, any_of, equals, matches)"
            ))),
            _ => Err(SchemaError::Parse(format!(
                "schema '{schema_name}': a predicate sets multiple conditions; use one per list item"
            ))),
        }
    }
}

/// A signature as written in YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaSignatureConfig {
    /// Schema label reported on a match.
    pub name: String,
    /// Tie-breaking weight (default 50, above `generic_json` and below the
    /// strong built-ins by default).
    #[serde(default = "default_user_specificity")]
    pub specificity: u32,
    /// Conditions that must all hold.
    #[serde(default, rename = "match")]
    pub predicates: Vec<SchemaPredicateConfig>,
}

fn default_user_specificity() -> u32 {
    50
}

/// Top-level YAML document holding a `schemas:` list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SchemaSignaturesFile {
    #[serde(default)]
    pub schemas: Vec<SchemaSignatureConfig>,
}

impl SchemaSignatureConfig {
    fn build(self) -> Result<SchemaSignature, SchemaError> {
        let name = self.name;
        let predicates = self
            .predicates
            .into_iter()
            .map(|p| p.build(&name))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SchemaSignature {
            name,
            predicates,
            specificity: self.specificity,
        })
    }
}

/// Parse user schema signatures from a YAML string.
pub fn parse_schema_signatures(yaml: &str) -> Result<Vec<SchemaSignature>, SchemaError> {
    let file: SchemaSignaturesFile =
        yaml_serde::from_str(yaml).map_err(|e| SchemaError::Parse(e.to_string()))?;
    file.schemas.into_iter().map(|s| s.build()).collect()
}

/// Load user schema signatures from a YAML file path.
pub fn load_schema_signatures(path: &Path) -> Result<Vec<SchemaSignature>, SchemaError> {
    let content = fs::read_to_string(path).map_err(|e| SchemaError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    parse_schema_signatures(&content)
}

// =============================================================================
// SchemaObserver: opt-in per-schema counting for reporting
// =============================================================================

/// One per-schema counter as exposed via [`SchemaObserver::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaCountEntry {
    /// Recognized schema name.
    pub schema: String,
    /// Number of events classified as this schema since the last reset.
    pub count: u64,
}

/// Immutable snapshot of a [`SchemaObserver`] at one moment.
#[derive(Debug, Clone, Default)]
pub struct SchemaObservation {
    /// Per-schema counts, sorted by descending count then ascending name.
    pub by_schema: Vec<SchemaCountEntry>,
    /// Events classified into a known schema since the last reset.
    pub classified: u64,
    /// Events that matched no signature since the last reset.
    pub unknown: u64,
    /// Total events observed since the last reset (`classified + unknown`).
    pub events_observed: u64,
    /// Lifetime total of classified events, ignoring resets. Monotonic, so it
    /// can drive Prometheus counters across observer resets.
    pub lifetime_classified: u64,
    /// Lifetime total of unknown events, ignoring resets. Monotonic.
    pub lifetime_unknown: u64,
    /// Seconds since the observer was created (or last reset).
    pub uptime_seconds: f64,
}

/// Opt-in counter that classifies each observed event and tallies per-schema
/// (and unknown) totals. Mirrors the design of [`FieldObserver`](crate::FieldObserver):
/// shared behind an `Arc`, cheap repeated snapshots, monotonic lifetime
/// counters for a Prometheus bridge. The schema set is small and bounded, so
/// there is no key cap.
pub struct SchemaObserver {
    classifier: SchemaClassifier,
    counts: Mutex<HashMap<String, u64>>,
    unknown: AtomicU64,
    events_observed: AtomicU64,
    lifetime_classified: AtomicU64,
    lifetime_unknown: AtomicU64,
    start: Mutex<Instant>,
}

impl SchemaObserver {
    /// Create an observer backed by the given classifier.
    pub fn new(classifier: SchemaClassifier) -> Self {
        Self {
            classifier,
            counts: Mutex::new(HashMap::new()),
            unknown: AtomicU64::new(0),
            events_observed: AtomicU64::new(0),
            lifetime_classified: AtomicU64::new(0),
            lifetime_unknown: AtomicU64::new(0),
            start: Mutex::new(Instant::now()),
        }
    }

    /// Create an observer using the built-in classifier.
    pub fn builtin() -> Self {
        Self::new(SchemaClassifier::builtin())
    }

    /// Classify an event and update the counters. Takes `&self` so the
    /// observer can be shared behind an `Arc`.
    pub fn observe<E: Event + ?Sized>(&self, event: &E) {
        self.events_observed.fetch_add(1, Ordering::Relaxed);
        match self.classifier.classify(event) {
            Some(m) => {
                self.lifetime_classified.fetch_add(1, Ordering::Relaxed);
                let mut counts = self.counts.lock().expect("schema observer mutex poisoned");
                *counts.entry(m.name).or_insert(0) += 1;
            }
            None => {
                self.unknown.fetch_add(1, Ordering::Relaxed);
                self.lifetime_unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot the current counts, sorted by descending count then name.
    pub fn snapshot(&self) -> SchemaObservation {
        let counts = self.counts.lock().expect("schema observer mutex poisoned");
        let mut by_schema: Vec<SchemaCountEntry> = counts
            .iter()
            .map(|(schema, count)| SchemaCountEntry {
                schema: schema.clone(),
                count: *count,
            })
            .collect();
        let classified: u64 = counts.values().sum();
        drop(counts);
        by_schema.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.schema.cmp(&b.schema)));
        let unknown = self.unknown.load(Ordering::Relaxed);
        SchemaObservation {
            by_schema,
            classified,
            unknown,
            events_observed: self.events_observed.load(Ordering::Relaxed),
            lifetime_classified: self.lifetime_classified.load(Ordering::Relaxed),
            lifetime_unknown: self.lifetime_unknown.load(Ordering::Relaxed),
            uptime_seconds: self
                .start
                .lock()
                .expect("schema observer start mutex poisoned")
                .elapsed()
                .as_secs_f64(),
        }
    }

    /// Reset the since-last-reset counters (lifetime totals are preserved).
    /// Returns the previous `(classified, unknown)` pair.
    pub fn reset(&self) -> (u64, u64) {
        let mut counts = self.counts.lock().expect("schema observer mutex poisoned");
        let previous_classified: u64 = counts.values().sum();
        counts.clear();
        drop(counts);
        let previous_unknown = self.unknown.swap(0, Ordering::Relaxed);
        self.events_observed.store(0, Ordering::Relaxed);
        *self
            .start
            .lock()
            .expect("schema observer start mutex poisoned") = Instant::now();
        (previous_classified, previous_unknown)
    }

    /// Lifetime classified total, ignoring resets. Monotonic.
    pub fn lifetime_classified(&self) -> u64 {
        self.lifetime_classified.load(Ordering::Relaxed)
    }

    /// Lifetime unknown total, ignoring resets. Monotonic.
    pub fn lifetime_unknown(&self) -> u64 {
        self.lifetime_unknown.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use serde_json::json;

    fn classify(value: &serde_json::Value) -> Option<String> {
        SchemaClassifier::builtin()
            .classify(&JsonEvent::borrow(value))
            .map(|m| m.name)
    }

    #[test]
    fn recognizes_ecs_by_version_marker() {
        let v = json!({"ecs": {"version": "8.11.0"}, "process": {"command_line": "whoami"}});
        assert_eq!(classify(&v).as_deref(), Some("ecs"));
    }

    #[test]
    fn recognizes_ecs_with_flattened_keys() {
        let v = json!({"ecs.version": "8.11.0", "process.command_line": "whoami"});
        assert_eq!(classify(&v).as_deref(), Some("ecs"));
    }

    #[test]
    fn recognizes_ocsf_by_class_and_metadata() {
        let v = json!({"class_uid": 1001, "category_uid": 1, "metadata": {"version": "1.1.0"}});
        assert_eq!(classify(&v).as_deref(), Some("ocsf"));
    }

    #[test]
    fn recognizes_rendered_windows_event_log() {
        let v = json!({"Event": {"System": {"EventID": 4688, "Provider": "Microsoft-Windows-Security-Auditing"}}});
        assert_eq!(classify(&v).as_deref(), Some("windows_eventlog"));
    }

    #[test]
    fn recognizes_sysmon_by_channel() {
        let v = json!({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:/cmd.exe"});
        assert_eq!(classify(&v).as_deref(), Some("sysmon"));
    }

    #[test]
    fn recognizes_sysmon_by_provider() {
        let v = json!({"Provider_Name": "Microsoft-Windows-Sysmon", "EventID": 3});
        assert_eq!(classify(&v).as_deref(), Some("sysmon"));
    }

    #[test]
    fn recognizes_flat_sysmon_by_field_shape() {
        let v = json!({"EventID": 1, "ProcessGuid": "{abc}", "CommandLine": "cmd /c whoami"});
        assert_eq!(classify(&v).as_deref(), Some("sysmon"));
    }

    #[test]
    fn recognizes_cef_structured_fields() {
        let v = json!({"deviceVendor": "Security", "deviceProduct": "IDS", "signatureId": "100", "src": "10.0.0.1"});
        assert_eq!(classify(&v).as_deref(), Some("cef"));
    }

    #[test]
    fn falls_back_to_generic_json_for_unrecognized_structured_events() {
        let v = json!({"some_vendor_field": "x", "another": 1});
        assert_eq!(classify(&v).as_deref(), Some("generic_json"));
    }

    #[test]
    fn fieldless_events_are_unknown() {
        // Empty object: no fields, no signature matches (not even generic_json).
        assert_eq!(classify(&json!({})), None);
        // JSON scalar/array carries no named fields either.
        assert_eq!(classify(&json!("just a string")), None);
    }

    #[test]
    fn specificity_prefers_specific_schema_over_generic() {
        // Carries both an ECS marker and arbitrary extra fields; ECS wins.
        let v = json!({"ecs.version": "8.0.0", "vendor_blob": {"x": 1}});
        let cls = SchemaClassifier::builtin();
        let m = cls.classify(&JsonEvent::borrow(&v)).unwrap();
        assert_eq!(m.name, "ecs");
        assert_eq!(m.specificity, 100);
        // generic_json is still a candidate, just lower priority.
        let all = cls.classify_all(&JsonEvent::borrow(&v));
        assert_eq!(all.first().map(String::as_str), Some("ecs"));
        assert!(all.iter().any(|n| n == "generic_json"));
    }

    #[test]
    fn schema_names_lists_builtins_most_specific_first() {
        let classifier = SchemaClassifier::builtin();
        let names = classifier.schema_names();
        assert_eq!(names.first(), Some(&"ecs"));
        assert!(names.contains(&"generic_json"));
        // generic_json is the lowest-specificity, so it sorts last.
        assert_eq!(names.last(), Some(&"generic_json"));
    }

    #[test]
    fn parses_user_signatures_from_yaml() {
        let yaml = r#"
schemas:
  - name: my_vendor
    specificity: 70
    match:
      - field_present: vendor.product
      - equals:
          field: event_type
          value: alert
      - any_of: [a, b]
"#;
        let sigs = parse_schema_signatures(yaml).expect("parse");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "my_vendor");
        assert_eq!(sigs[0].specificity, 70);
        assert_eq!(sigs[0].predicates.len(), 3);

        let cls = SchemaClassifier::with_user_signatures(sigs);
        let v = json!({"vendor": {"product": "X"}, "event_type": "ALERT", "a": 1});
        assert_eq!(
            cls.classify(&JsonEvent::borrow(&v))
                .map(|m| m.name)
                .as_deref(),
            Some("my_vendor")
        );
    }

    #[test]
    fn user_signature_with_invalid_regex_is_rejected() {
        let yaml = r#"
schemas:
  - name: bad
    match:
      - matches:
          field: msg
          value: "([unclosed"
"#;
        let err = parse_schema_signatures(yaml).unwrap_err();
        assert!(matches!(err, SchemaError::InvalidRegex { .. }));
    }

    #[test]
    fn user_regex_signature_matches_field_value() {
        let yaml = r#"
schemas:
  - name: cef_raw
    specificity: 60
    match:
      - matches:
          field: message
          value: "^CEF:\\d"
"#;
        let sigs = parse_schema_signatures(yaml).expect("parse");
        let cls = SchemaClassifier::with_user_signatures(sigs);
        let v = json!({"message": "CEF:0|Vendor|Product|1.0|100|Name|9|src=1.2.3.4"});
        assert_eq!(
            cls.classify(&JsonEvent::borrow(&v))
                .map(|m| m.name)
                .as_deref(),
            Some("cef_raw")
        );
    }

    #[test]
    fn observer_counts_per_schema_and_unknown() {
        let observer = SchemaObserver::builtin();
        observer.observe(&JsonEvent::borrow(&json!({"ecs.version": "8.0.0"})));
        observer.observe(&JsonEvent::borrow(&json!({"ecs.version": "8.1.0"})));
        observer.observe(&JsonEvent::borrow(
            &json!({"class_uid": 1001, "metadata": {"version": "1.1.0"}}),
        ));
        observer.observe(&JsonEvent::borrow(&json!({})));

        let snap = observer.snapshot();
        assert_eq!(snap.events_observed, 4);
        assert_eq!(snap.classified, 3);
        assert_eq!(snap.unknown, 1);
        // Sorted by descending count, so ecs (2) comes first.
        assert_eq!(snap.by_schema[0].schema, "ecs");
        assert_eq!(snap.by_schema[0].count, 2);
        let ocsf = snap.by_schema.iter().find(|e| e.schema == "ocsf").unwrap();
        assert_eq!(ocsf.count, 1);
    }

    #[test]
    fn observer_reset_preserves_lifetime_counters() {
        let observer = SchemaObserver::builtin();
        observer.observe(&JsonEvent::borrow(&json!({"ecs.version": "8.0.0"})));
        observer.observe(&JsonEvent::borrow(&json!({})));
        let (classified, unknown) = observer.reset();
        assert_eq!(classified, 1);
        assert_eq!(unknown, 1);

        let snap = observer.snapshot();
        assert_eq!(snap.classified, 0);
        assert_eq!(snap.unknown, 0);
        assert_eq!(snap.events_observed, 0);
        // Lifetime totals survive the reset for the Prometheus bridge.
        assert_eq!(snap.lifetime_classified, 1);
        assert_eq!(snap.lifetime_unknown, 1);
    }
}
