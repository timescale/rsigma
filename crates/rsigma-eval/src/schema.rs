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
use rsigma_parser::LogSource;
use serde::{Deserialize, Serialize};

use crate::event::Event;

/// Numeric comparison operator for [`SchemaPredicate::Compare`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// Strictly greater than.
    Gt,
    /// Greater than or equal.
    Gte,
    /// Strictly less than.
    Lt,
    /// Less than or equal.
    Lte,
}

impl CompareOp {
    fn apply(self, lhs: f64, rhs: f64) -> bool {
        match self {
            CompareOp::Gt => lhs > rhs,
            CompareOp::Gte => lhs >= rhs,
            CompareOp::Lt => lhs < rhs,
            CompareOp::Lte => lhs <= rhs,
        }
    }

    fn symbol(self) -> &'static str {
        match self {
            CompareOp::Gt => ">",
            CompareOp::Gte => ">=",
            CompareOp::Lt => "<",
            CompareOp::Lte => "<=",
        }
    }
}

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
    /// The field is present, numeric-coercible, and compares to `value` under
    /// `op`. A non-numeric or absent field fails closed (no match).
    Compare {
        field: String,
        op: CompareOp,
        value: f64,
    },
    /// The field is present and its string-coerced value equals one of
    /// `values` (ASCII case-insensitive). The multi-value form of `Equals`.
    In { field: String, values: Vec<String> },
    /// Both fields are present, string-coercible, and equal (case-insensitive).
    FieldEqualsField { left: String, right: String },
    /// Logical negation of the inner predicate.
    Not(Box<SchemaPredicate>),
    /// At least one of the inner predicates holds (logical OR).
    Any(Vec<SchemaPredicate>),
    /// All of the inner predicates hold (logical AND). Useful as a group under
    /// `Not` or `Any`.
    All(Vec<SchemaPredicate>),
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
            SchemaPredicate::Compare { field, op, value } => event
                .get_field(field)
                .and_then(|v| v.as_f64())
                .map(|n| op.apply(n, *value))
                .unwrap_or(false),
            SchemaPredicate::In { field, values } => event
                .get_field(field)
                .and_then(|v| {
                    v.as_str().map(|s| {
                        values
                            .iter()
                            .any(|val| s.as_ref().eq_ignore_ascii_case(val))
                    })
                })
                .unwrap_or(false),
            SchemaPredicate::FieldEqualsField { left, right } => {
                let l = event
                    .get_field(left)
                    .and_then(|v| v.as_str().map(|s| s.into_owned()));
                let r = event
                    .get_field(right)
                    .and_then(|v| v.as_str().map(|s| s.into_owned()));
                matches!((l, r), (Some(a), Some(b)) if a.eq_ignore_ascii_case(&b))
            }
            SchemaPredicate::Not(inner) => !inner.eval(event),
            SchemaPredicate::Any(preds) => preds.iter().any(|p| p.eval(event)),
            SchemaPredicate::All(preds) => preds.iter().all(|p| p.eval(event)),
            SchemaPredicate::HasAnyField => !event.field_keys().is_empty(),
        }
    }

    /// A compact human description of the predicate, for `explain` output.
    fn describe(&self) -> String {
        match self {
            SchemaPredicate::FieldPresent(f) => format!("field_present({f})"),
            SchemaPredicate::FieldAbsent(f) => format!("field_absent({f})"),
            SchemaPredicate::AnyOf(fs) => format!("any_of([{}])", fs.join(", ")),
            SchemaPredicate::Equals { field, value } => format!("{field} == \"{value}\""),
            SchemaPredicate::Matches { field, regex } => {
                format!("{field} matches /{}/", regex.as_str())
            }
            SchemaPredicate::Compare { field, op, value } => {
                format!("{field} {} {value}", op.symbol())
            }
            SchemaPredicate::In { field, values } => format!("{field} in [{}]", values.join(", ")),
            SchemaPredicate::FieldEqualsField { left, right } => format!("{left} == {right}"),
            SchemaPredicate::Not(inner) => format!("not({})", inner.describe()),
            SchemaPredicate::Any(ps) => format!(
                "any({})",
                ps.iter()
                    .map(|p| p.describe())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            SchemaPredicate::All(ps) => format!(
                "all({})",
                ps.iter()
                    .map(|p| p.describe())
                    .collect::<Vec<_>>()
                    .join(" & ")
            ),
            SchemaPredicate::HasAnyField => "has_any_field".to_string(),
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

    fn explain<E: Event + ?Sized>(&self, event: &E) -> SignatureExplanation {
        let predicates: Vec<PredicateOutcome> = self
            .predicates
            .iter()
            .map(|p| PredicateOutcome {
                predicate: p.describe(),
                matched: p.eval(event),
            })
            .collect();
        let predicates_matched = predicates.iter().all(|p| p.matched);
        SignatureExplanation {
            name: self.name.clone(),
            specificity: self.specificity,
            predicates_matched,
            predicates,
        }
    }
}

/// The outcome of one predicate within a [`SignatureExplanation`].
#[derive(Debug, Clone, Serialize)]
pub struct PredicateOutcome {
    /// Human description of the predicate (for example `field_present(ecs.version)`).
    pub predicate: String,
    /// Whether the predicate held for the event.
    pub matched: bool,
}

/// Per-signature detail produced by [`SchemaClassifier::explain`].
#[derive(Debug, Clone, Serialize)]
pub struct SignatureExplanation {
    /// The signature's schema name.
    pub name: String,
    /// The signature's tie-breaking specificity.
    pub specificity: u32,
    /// Whether every predicate held (the signature matched).
    pub predicates_matched: bool,
    /// Per-predicate outcomes, in signature order.
    pub predicates: Vec<PredicateOutcome>,
}

/// Why an event classified (or did not) as reported by
/// [`SchemaClassifier::explain`]: the winning schema (if any) plus the
/// signature that explains the outcome (the winning signature, or for an
/// unknown event the closest near-miss).
#[derive(Debug, Clone, Serialize)]
pub struct SchemaExplanation {
    /// The classified schema name, or `None` when the event matched none.
    pub matched: Option<String>,
    /// The winning signature's specificity, when matched.
    pub specificity: Option<u32>,
    /// The explaining signature: the winner when matched, otherwise the
    /// highest-scoring near-miss (most predicates passing).
    pub signature: Option<SignatureExplanation>,
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

    /// Explain how an event classifies: the winning schema (if any) plus the
    /// signature that explains it (the winning signature, or for an unknown
    /// event the closest near-miss, the non-matching signature with the most
    /// passing predicates). For tuning signatures.
    pub fn explain<E: Event + ?Sized>(&self, event: &E) -> SchemaExplanation {
        let mut best_near: Option<SignatureExplanation> = None;
        let mut best_near_passing = 0usize;
        for sig in &self.signatures {
            let ex = sig.explain(event);
            if ex.predicates_matched {
                return SchemaExplanation {
                    matched: Some(ex.name.clone()),
                    specificity: Some(ex.specificity),
                    signature: Some(ex),
                };
            }
            // Signatures are sorted specificity-descending, so the first
            // signature reaching a given passing count wins the tie-break.
            let passing = ex.predicates.iter().filter(|p| p.matched).count();
            if best_near.is_none() || passing > best_near_passing {
                best_near_passing = passing;
                best_near = Some(ex);
            }
        }
        SchemaExplanation {
            matched: None,
            specificity: None,
            signature: best_near,
        }
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

/// A `{ field: ..., value: <number> }` pair used by the numeric comparison
/// predicate forms (`gt`, `gte`, `lt`, `lte`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldNumberConfig {
    pub field: String,
    pub value: f64,
}

/// A `{ field: ..., values: [...] }` pair used by the `in` predicate form.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValuesConfig {
    pub field: String,
    pub values: Vec<String>,
}

/// A `{ left: ..., right: ... }` pair used by the `field_equals_field` form.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldPairConfig {
    pub left: String,
    pub right: String,
}

/// A predicate as written in YAML: a single-key map, for example
/// `field_present: ecs.version` or `equals: { field: type, value: alert }`.
/// Exactly one form must be set per list entry. The `not`/`any`/`all` group
/// forms nest predicate lists to express OR and NOT within one signature.
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
    /// `gt: { field: <field>, value: <number> }`
    #[serde(default)]
    pub gt: Option<FieldNumberConfig>,
    /// `gte: { field: <field>, value: <number> }`
    #[serde(default)]
    pub gte: Option<FieldNumberConfig>,
    /// `lt: { field: <field>, value: <number> }`
    #[serde(default)]
    pub lt: Option<FieldNumberConfig>,
    /// `lte: { field: <field>, value: <number> }`
    #[serde(default)]
    pub lte: Option<FieldNumberConfig>,
    /// `in: { field: <field>, values: [...] }`
    #[serde(default, rename = "in")]
    pub in_set: Option<FieldValuesConfig>,
    /// `field_equals_field: { left: <field>, right: <field> }`
    #[serde(default)]
    pub field_equals_field: Option<FieldPairConfig>,
    /// `not: <predicate>`
    #[serde(default)]
    pub not: Option<Box<SchemaPredicateConfig>>,
    /// `any: [<predicate>, ...]`
    #[serde(default)]
    pub any: Option<Vec<SchemaPredicateConfig>>,
    /// `all: [<predicate>, ...]`
    #[serde(default)]
    pub all: Option<Vec<SchemaPredicateConfig>>,
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
        for (op, cfg) in [
            (CompareOp::Gt, self.gt),
            (CompareOp::Gte, self.gte),
            (CompareOp::Lt, self.lt),
            (CompareOp::Lte, self.lte),
        ] {
            if let Some(fv) = cfg {
                set += 1;
                chosen = Some(SchemaPredicate::Compare {
                    field: fv.field,
                    op,
                    value: fv.value,
                });
            }
        }
        if let Some(fv) = self.in_set {
            set += 1;
            chosen = Some(SchemaPredicate::In {
                field: fv.field,
                values: fv.values,
            });
        }
        if let Some(fp) = self.field_equals_field {
            set += 1;
            chosen = Some(SchemaPredicate::FieldEqualsField {
                left: fp.left,
                right: fp.right,
            });
        }
        if let Some(inner) = self.not {
            set += 1;
            chosen = Some(SchemaPredicate::Not(Box::new(inner.build(schema_name)?)));
        }
        if let Some(list) = self.any {
            set += 1;
            chosen = Some(SchemaPredicate::Any(build_group(list, schema_name, "any")?));
        }
        if let Some(list) = self.all {
            set += 1;
            chosen = Some(SchemaPredicate::All(build_group(list, schema_name, "all")?));
        }
        match (set, chosen) {
            (1, Some(p)) => Ok(p),
            (0, _) => Err(SchemaError::Parse(format!(
                "schema '{schema_name}': a predicate has no condition (expected one of \
                 field_present, field_absent, any_of, equals, matches, gt, gte, lt, lte, \
                 in, field_equals_field, not, any, all)"
            ))),
            _ => Err(SchemaError::Parse(format!(
                "schema '{schema_name}': a predicate sets multiple conditions; use one per list item"
            ))),
        }
    }
}

/// Build a non-empty list of sub-predicates for the `any`/`all` group forms.
fn build_group(
    list: Vec<SchemaPredicateConfig>,
    schema_name: &str,
    kind: &str,
) -> Result<Vec<SchemaPredicate>, SchemaError> {
    if list.is_empty() {
        return Err(SchemaError::Parse(format!(
            "schema '{schema_name}': '{kind}' needs at least one sub-predicate"
        )));
    }
    list.into_iter().map(|p| p.build(schema_name)).collect()
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

/// Top-level YAML document holding a `schemas:` list and an optional
/// `routing:` section.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SchemaSignaturesFile {
    #[serde(default)]
    pub schemas: Vec<SchemaSignatureConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
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

/// Parse both the user signatures and the optional routing section from a YAML
/// string.
pub fn parse_schema_config(
    yaml: &str,
) -> Result<(Vec<SchemaSignature>, Option<RoutingConfig>), SchemaError> {
    let file: SchemaSignaturesFile =
        yaml_serde::from_str(yaml).map_err(|e| SchemaError::Parse(e.to_string()))?;
    let signatures = file
        .schemas
        .into_iter()
        .map(|s| s.build())
        .collect::<Result<Vec<_>, _>>()?;
    Ok((signatures, file.routing))
}

/// Load both the user signatures and the optional routing section from a YAML
/// file path.
pub fn load_schema_config(
    path: &Path,
) -> Result<(Vec<SchemaSignature>, Option<RoutingConfig>), SchemaError> {
    let content = fs::read_to_string(path).map_err(|e| SchemaError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    parse_schema_config(&content)
}

/// Validate a parsed schema config for common authoring mistakes, returning a
/// list of human-readable findings (empty means clean). Static checks only, no
/// event data:
///
/// - duplicate user signatures (same name and identical predicates);
/// - unreachable signatures shadowed by a strictly-higher-specificity
///   signature whose predicates are a subset (so the shadowed one can never be
///   the top match);
/// - routing bindings referencing a schema no signature can produce;
/// - duplicate routing bindings for the same schema.
///
/// Pipeline-name resolvability is checked by the caller (the CLI), which owns
/// pipeline resolution.
pub fn validate_schema_config(
    user_signatures: &[SchemaSignature],
    routing: Option<&RoutingConfig>,
) -> Vec<String> {
    let mut findings = Vec::new();

    // The full effective signature set (built-ins plus user).
    let mut all = builtin_signatures();
    all.extend(user_signatures.iter().cloned());
    let preds = |s: &SchemaSignature| -> Vec<String> {
        s.predicates.iter().map(|p| p.describe()).collect()
    };

    // Duplicate user signatures (same name, identical predicate set).
    for i in 0..user_signatures.len() {
        for j in (i + 1)..user_signatures.len() {
            if user_signatures[i].name == user_signatures[j].name
                && preds(&user_signatures[i]) == preds(&user_signatures[j])
            {
                findings.push(format!(
                    "duplicate signature '{}' with identical predicates",
                    user_signatures[i].name
                ));
            }
        }
    }

    // Unreachable (shadowed) signatures.
    for b in &all {
        let b_preds = preds(b);
        for a in &all {
            if a.name != b.name
                && a.specificity > b.specificity
                && !a.predicates.is_empty()
                && preds(a).iter().all(|p| b_preds.contains(p))
            {
                findings.push(format!(
                    "signature '{}' (specificity {}) is unreachable: shadowed by '{}' (specificity {}) whose predicates are a subset",
                    b.name, b.specificity, a.name, a.specificity
                ));
                break;
            }
        }
    }

    // Routing binding checks.
    if let Some(routing) = routing {
        let mut known: std::collections::HashSet<&str> =
            builtin_schema_names().into_iter().collect();
        for s in user_signatures {
            known.insert(s.name.as_str());
        }
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for binding in &routing.bindings {
            if !known.contains(binding.schema.as_str()) {
                findings.push(format!(
                    "routing binding references unknown schema '{}' (no built-in or user signature produces it)",
                    binding.schema
                ));
            }
            if !seen.insert(binding.schema.as_str()) {
                findings.push(format!(
                    "duplicate routing binding for schema '{}'",
                    binding.schema
                ));
            }
        }
    }

    findings
}

// =============================================================================
// Routing: schema -> pipeline-set bindings and the dispatch plan
// =============================================================================

/// What to do with an event whose schema matched no signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnUnknown {
    /// Evaluate against the default pipeline-set and log a warning.
    #[default]
    Warn,
    /// Drop the event without evaluating.
    Drop,
    /// Evaluate against the default pipeline-set without logging.
    Passthrough,
    /// Drop the event and flag it as an error (non-zero exit / error counter).
    Error,
}

/// The logsource a recognized schema implies, used to fill gaps in an event's
/// logsource for conflict-based pruning when the event carries no explicit
/// `product`/`service`/`category` field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaLogsource {
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub custom: HashMap<String, String>,
}

impl SchemaLogsource {
    fn to_logsource(&self) -> LogSource {
        LogSource {
            product: self.product.clone(),
            service: self.service.clone(),
            category: self.category.clone(),
            custom: self.custom.clone(),
            ..LogSource::default()
        }
    }
}

/// A `schema -> pipelines` binding: events recognized as `schema` are
/// evaluated against the engine built from `pipelines`.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaBinding {
    pub schema: String,
    /// Pipeline names or file paths, resolved by the caller.
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Optional logsource this schema implies. Overrides any built-in default
    /// for the schema and fills gaps in an event's logsource at pruning time.
    #[serde(default)]
    pub logsource: Option<SchemaLogsource>,
}

/// Built-in schema-to-logsource defaults for the platform-locked schemas.
///
/// Only schemas that unambiguously imply a platform are listed. Cross-platform
/// schemas (`ecs`, `ocsf`, `cef`, `generic_json`) are intentionally omitted:
/// they must not imply a product, since doing so would prune correct rules for
/// the other platforms those schemas also carry.
fn builtin_schema_logsource() -> HashMap<String, LogSource> {
    fn ls(product: &str, service: Option<&str>) -> LogSource {
        LogSource {
            product: Some(product.to_string()),
            service: service.map(str::to_string),
            ..LogSource::default()
        }
    }
    HashMap::from([
        ("sysmon".to_string(), ls("windows", Some("sysmon"))),
        ("windows_eventlog".to_string(), ls("windows", None)),
    ])
}

/// The `routing:` section of a schema config file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub on_unknown: OnUnknown,
    #[serde(default)]
    pub bindings: Vec<SchemaBinding>,
    /// Pipelines applied to known-but-unbound schemas and to the
    /// unknown-fallback path. Empty means "rules with no pipeline".
    #[serde(default)]
    pub default_pipelines: Vec<String>,
}

/// The decision for one event, produced by [`RoutingPlan::decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// Evaluate against the pipeline-set at this index. `unknown` is true when
    /// the event matched no signature and fell through to the default set.
    Evaluate { set: usize, unknown: bool },
    /// Drop the event without evaluating (`on_unknown: drop`).
    Drop,
    /// Drop and flag as an error (`on_unknown: error`).
    Error,
}

/// A resolved routing plan: the deduplicated pipeline-sets to build one engine
/// each, plus the schema-to-set mapping and the unknown-handling policy.
///
/// Pure data: it decides *which* pipeline-set an event routes to, leaving the
/// engine construction and dispatch to the caller. The default set (index 0)
/// is always present, so there is always a fallback target.
#[derive(Debug, Clone)]
pub struct RoutingPlan {
    /// Deduplicated pipeline-sets. Index 0 is always the default set.
    pipeline_sets: Vec<Vec<String>>,
    /// Recognized schema name -> pipeline-set index.
    schema_to_set: HashMap<String, usize>,
    /// Recognized schema name -> the logsource it implies (built-in defaults
    /// plus per-binding overrides). Used to fill gaps in an event's logsource
    /// for conflict-based pruning.
    schema_logsource: HashMap<String, LogSource>,
    on_unknown: OnUnknown,
}

impl RoutingPlan {
    /// Build a plan from a routing config, deduplicating identical
    /// pipeline-sets so the caller compiles each distinct set once.
    pub fn from_config(config: &RoutingConfig) -> Self {
        // Index 0 is always the default set.
        let mut pipeline_sets: Vec<Vec<String>> = vec![config.default_pipelines.clone()];
        let mut schema_to_set: HashMap<String, usize> = HashMap::new();
        // Seed the built-in platform-locked defaults, then let bindings
        // override or add per-schema logsources.
        let mut schema_logsource = builtin_schema_logsource();

        for binding in &config.bindings {
            let idx = pipeline_sets
                .iter()
                .position(|s| s == &binding.pipelines)
                .unwrap_or_else(|| {
                    pipeline_sets.push(binding.pipelines.clone());
                    pipeline_sets.len() - 1
                });
            schema_to_set.insert(binding.schema.clone(), idx);
            if let Some(ls) = &binding.logsource {
                schema_logsource.insert(binding.schema.clone(), ls.to_logsource());
            }
        }

        RoutingPlan {
            pipeline_sets,
            schema_to_set,
            schema_logsource,
            on_unknown: config.on_unknown,
        }
    }

    /// The deduplicated pipeline-sets, in index order (set 0 is the default).
    /// The caller builds one engine per entry.
    pub fn pipeline_sets(&self) -> &[Vec<String>] {
        &self.pipeline_sets
    }

    /// The configured unknown-handling policy.
    pub fn on_unknown(&self) -> OnUnknown {
        self.on_unknown
    }

    /// The logsource a recognized schema implies, if any (built-in default or
    /// binding override). Used by the router to fill gaps in an event's
    /// logsource before conflict-based pruning.
    pub fn schema_logsource(&self, schema: &str) -> Option<&LogSource> {
        self.schema_logsource.get(schema)
    }

    /// The recognized schema names that carry an implied logsource (built-in
    /// defaults plus binding overrides), sorted for deterministic output.
    pub fn schemas_with_logsource(&self) -> Vec<String> {
        let mut names: Vec<String> = self.schema_logsource.keys().cloned().collect();
        names.sort();
        names
    }

    /// Decide how to route an event given its classified schema (or `None`
    /// when nothing matched).
    pub fn decide(&self, schema: Option<&str>) -> RouteDecision {
        match schema {
            // Recognized and bound: its own set.
            Some(s) if self.schema_to_set.contains_key(s) => RouteDecision::Evaluate {
                set: self.schema_to_set[s],
                unknown: false,
            },
            // Recognized but unbound: the default set, not flagged unknown.
            Some(_) => RouteDecision::Evaluate {
                set: 0,
                unknown: false,
            },
            // Unrecognized: per the unknown policy.
            None => match self.on_unknown {
                OnUnknown::Warn | OnUnknown::Passthrough => RouteDecision::Evaluate {
                    set: 0,
                    unknown: true,
                },
                OnUnknown::Drop => RouteDecision::Drop,
                OnUnknown::Error => RouteDecision::Error,
            },
        }
    }
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

    /// Build a single-signature classifier from a `match:` YAML body.
    fn classifier_from_match(match_body: &str) -> SchemaClassifier {
        let yaml = format!("schemas:\n  - name: t\n    specificity: 70\n    match:\n{match_body}");
        let sigs = parse_schema_signatures(&yaml).expect("parse");
        SchemaClassifier::new(sigs)
    }

    fn matches_t(match_body: &str, event: &serde_json::Value) -> bool {
        classifier_from_match(match_body)
            .classify(&JsonEvent::borrow(event))
            .is_some()
    }

    #[test]
    fn numeric_comparisons() {
        let body = "      - gte: { field: EventID, value: 4000 }\n";
        assert!(matches_t(body, &json!({"EventID": 4688})));
        assert!(matches_t(body, &json!({"EventID": 4000})));
        assert!(!matches_t(body, &json!({"EventID": 1})));
        // String-coercible numeric values work too.
        assert!(matches_t(body, &json!({"EventID": "4688"})));
        // A non-numeric field fails closed.
        assert!(!matches_t(body, &json!({"EventID": "not-a-number"})));
        // lt / gt / lte round out the operators.
        assert!(matches_t(
            "      - lt: { field: score, value: 10 }\n",
            &json!({"score": 9.5})
        ));
        assert!(matches_t(
            "      - gt: { field: score, value: 10 }\n",
            &json!({"score": 10.1})
        ));
    }

    #[test]
    fn in_set_membership_is_case_insensitive() {
        let body = "      - in: { field: event_type, values: [alert, alarm] }\n";
        assert!(matches_t(body, &json!({"event_type": "ALERT"})));
        assert!(matches_t(body, &json!({"event_type": "alarm"})));
        assert!(!matches_t(body, &json!({"event_type": "info"})));
        assert!(!matches_t(body, &json!({})));
    }

    #[test]
    fn field_equals_field_compares_two_fields() {
        let body = "      - field_equals_field: { left: a, right: b }\n";
        assert!(matches_t(body, &json!({"a": "X", "b": "x"})));
        assert!(!matches_t(body, &json!({"a": "X", "b": "y"})));
        // A missing side fails closed.
        assert!(!matches_t(body, &json!({"a": "X"})));
    }

    #[test]
    fn recursive_not_any_all_groups() {
        // any: OR of two field-presence predicates.
        let any_body = "      - any:\n          - field_present: winlog.channel\n          - equals: { field: host.os.type, value: windows }\n";
        assert!(matches_t(
            any_body,
            &json!({"winlog": {"channel": "Security"}})
        ));
        assert!(matches_t(
            any_body,
            &json!({"host": {"os": {"type": "windows"}}})
        ));
        assert!(!matches_t(any_body, &json!({"unrelated": 1})));

        // not: negation of a presence predicate.
        let not_body = "      - not: { field_present: ecs.version }\n";
        assert!(matches_t(not_body, &json!({"CommandLine": "whoami"})));
        assert!(!matches_t(not_body, &json!({"ecs.version": "8.0.0"})));

        // all: nested AND, usable under not/any.
        let all_body = "      - all:\n          - field_present: a\n          - field_present: b\n";
        assert!(matches_t(all_body, &json!({"a": 1, "b": 2})));
        assert!(!matches_t(all_body, &json!({"a": 1})));
    }

    #[test]
    fn empty_group_is_rejected() {
        let yaml = "schemas:\n  - name: t\n    match:\n      - any: []\n";
        let err = parse_schema_signatures(yaml).unwrap_err();
        assert!(
            matches!(&err, SchemaError::Parse(m) if m.contains("'any' needs at least one")),
            "got: {err}"
        );
    }

    #[test]
    fn predicate_with_two_conditions_is_rejected() {
        let yaml = "schemas:\n  - name: t\n    match:\n      - field_present: a\n        field_absent: b\n";
        let err = parse_schema_signatures(yaml).unwrap_err();
        assert!(
            matches!(&err, SchemaError::Parse(m) if m.contains("multiple conditions")),
            "got: {err}"
        );
    }

    #[test]
    fn explain_reports_matched_signature() {
        let cls = SchemaClassifier::builtin();
        let v = json!({"ecs.version": "8.0.0"});
        let ex = cls.explain(&JsonEvent::borrow(&v));
        assert_eq!(ex.matched.as_deref(), Some("ecs"));
        let sig = ex.signature.expect("signature");
        assert!(sig.predicates_matched);
        assert!(sig.predicates.iter().all(|p| p.matched));
    }

    #[test]
    fn explain_reports_near_miss_for_unknown() {
        // Drop generic_json so a structured non-match is genuinely unknown.
        let sigs = builtin_signatures()
            .into_iter()
            .filter(|s| s.name != "generic_json")
            .collect();
        let cls = SchemaClassifier::new(sigs);
        // Sysmon-ish but missing ProcessGuid: unknown, near-miss is sysmon.
        let v = json!({"EventID": 1, "Image": "C:/cmd.exe"});
        let ex = cls.explain(&JsonEvent::borrow(&v));
        assert_eq!(ex.matched, None);
        let sig = ex.signature.expect("near-miss");
        assert_eq!(sig.name, "sysmon");
        assert!(!sig.predicates_matched);
        assert!(sig.predicates.iter().any(|p| !p.matched));
    }

    #[test]
    fn validate_flags_unknown_binding_and_shadow() {
        let yaml = r#"
schemas:
  - name: shadowed
    specificity: 40
    match:
      - field_present: ecs.version
      - field_present: extra.marker
routing:
  bindings:
    - schema: ecs
      pipelines: [ecs_windows]
    - schema: nonexistent
      pipelines: [x]
"#;
        let (sigs, routing) = parse_schema_config(yaml).unwrap();
        let findings = validate_schema_config(&sigs, routing.as_ref());
        assert!(
            findings
                .iter()
                .any(|f| f.contains("unknown schema 'nonexistent'")),
            "findings: {findings:?}"
        );
        // `shadowed` needs ecs.version + extra.marker; the built-in ecs (spec
        // 100) needs only ecs.version (a subset), so `shadowed` is unreachable.
        assert!(
            findings
                .iter()
                .any(|f| f.contains("'shadowed'") && f.contains("unreachable")),
            "findings: {findings:?}"
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
    fn routing_plan_dedups_pipeline_sets() {
        let config = RoutingConfig {
            on_unknown: OnUnknown::Warn,
            default_pipelines: vec![],
            bindings: vec![
                SchemaBinding {
                    schema: "ecs".to_string(),
                    pipelines: vec!["ecs_windows".to_string()],
                    logsource: None,
                },
                SchemaBinding {
                    schema: "winlogbeat".to_string(),
                    pipelines: vec!["ecs_windows".to_string()],
                    logsource: None,
                },
                SchemaBinding {
                    schema: "sysmon".to_string(),
                    pipelines: vec!["sysmon".to_string()],
                    logsource: None,
                },
            ],
        };
        let plan = RoutingPlan::from_config(&config);
        // Default set (0) + ecs_windows set + sysmon set = 3 distinct sets.
        assert_eq!(plan.pipeline_sets().len(), 3);
        // ecs and winlogbeat share the same deduped set.
        let ecs = plan.decide(Some("ecs"));
        let win = plan.decide(Some("winlogbeat"));
        assert_eq!(ecs, win);
        assert!(matches!(
            ecs,
            RouteDecision::Evaluate { unknown: false, .. }
        ));
        // sysmon is a different set.
        assert_ne!(plan.decide(Some("sysmon")), ecs);
    }

    #[test]
    fn routing_decides_bound_unbound_and_unknown() {
        let config = RoutingConfig {
            on_unknown: OnUnknown::Warn,
            default_pipelines: vec![],
            bindings: vec![SchemaBinding {
                schema: "ecs".to_string(),
                pipelines: vec!["ecs_windows".to_string()],
                logsource: None,
            }],
        };
        let plan = RoutingPlan::from_config(&config);
        // Bound schema -> its own set, not flagged unknown.
        assert!(matches!(
            plan.decide(Some("ecs")),
            RouteDecision::Evaluate { unknown: false, .. }
        ));
        // Recognized but unbound -> default set (0), not flagged unknown.
        assert_eq!(
            plan.decide(Some("cef")),
            RouteDecision::Evaluate {
                set: 0,
                unknown: false
            }
        );
        // Unknown -> default set, flagged unknown (Warn).
        assert_eq!(
            plan.decide(None),
            RouteDecision::Evaluate {
                set: 0,
                unknown: true
            }
        );
    }

    #[test]
    fn routing_on_unknown_policies() {
        let base = |policy| RoutingConfig {
            on_unknown: policy,
            default_pipelines: vec![],
            bindings: vec![],
        };
        assert_eq!(
            RoutingPlan::from_config(&base(OnUnknown::Drop)).decide(None),
            RouteDecision::Drop
        );
        assert_eq!(
            RoutingPlan::from_config(&base(OnUnknown::Error)).decide(None),
            RouteDecision::Error
        );
        assert_eq!(
            RoutingPlan::from_config(&base(OnUnknown::Passthrough)).decide(None),
            RouteDecision::Evaluate {
                set: 0,
                unknown: true
            }
        );
    }

    #[test]
    fn parses_routing_section_from_yaml() {
        let yaml = r#"
schemas:
  - name: my_vendor
    match:
      - field_present: vendor.id
routing:
  on_unknown: drop
  default_pipelines: [base]
  bindings:
    - schema: ecs
      pipelines: [ecs_windows]
    - schema: my_vendor
      pipelines: [vendor_map, base]
"#;
        let (sigs, routing) = parse_schema_config(yaml).expect("parse");
        assert_eq!(sigs.len(), 1);
        let routing = routing.expect("routing present");
        assert_eq!(routing.on_unknown, OnUnknown::Drop);
        assert_eq!(routing.default_pipelines, vec!["base".to_string()]);
        assert_eq!(routing.bindings.len(), 2);
        let plan = RoutingPlan::from_config(&routing);
        // default [base], ecs [ecs_windows], my_vendor [vendor_map, base] = 3.
        assert_eq!(plan.pipeline_sets().len(), 3);
        assert_eq!(plan.decide(None), RouteDecision::Drop);
    }

    #[test]
    fn schema_logsource_builtin_defaults_and_overrides() {
        // Built-in platform-locked defaults apply even without bindings.
        let plan = RoutingPlan::from_config(&RoutingConfig::default());
        let sysmon = plan.schema_logsource("sysmon").expect("sysmon default");
        assert_eq!(sysmon.product.as_deref(), Some("windows"));
        assert_eq!(sysmon.service.as_deref(), Some("sysmon"));
        assert_eq!(
            plan.schema_logsource("windows_eventlog")
                .and_then(|l| l.product.as_deref()),
            Some("windows")
        );
        // Cross-platform schemas imply nothing.
        assert!(plan.schema_logsource("ecs").is_none());
        assert!(plan.schema_logsource("cef").is_none());

        // A binding can attach or override a schema's implied logsource.
        let yaml = r#"
schemas:
  - name: ecs_windows
    match:
      - field_present: ecs.version
      - field_present: winlog.channel
routing:
  bindings:
    - schema: ecs_windows
      pipelines: [ecs_windows]
      logsource:
        product: windows
    - schema: sysmon
      pipelines: [sysmon]
      logsource:
        product: windows
        service: sysmon
        custom:
          tenant: acme
"#;
        let (_sigs, routing) = parse_schema_config(yaml).expect("parse");
        let plan = RoutingPlan::from_config(&routing.expect("routing"));
        assert_eq!(
            plan.schema_logsource("ecs_windows")
                .and_then(|l| l.product.as_deref()),
            Some("windows")
        );
        let sysmon = plan.schema_logsource("sysmon").expect("sysmon override");
        assert_eq!(
            sysmon.custom.get("tenant").map(String::as_str),
            Some("acme")
        );
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
