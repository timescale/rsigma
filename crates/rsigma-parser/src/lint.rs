//! Built-in linter for Sigma rules, correlations, and filters.
//!
//! Validates raw `serde_yaml::Value` documents against the Sigma specification
//! v2.1.0 constraints — catching metadata issues that the parser silently
//! ignores (invalid enums, date formats, tag patterns, etc.).
//!
//! # Usage
//!
//! ```rust
//! use rsigma_parser::lint::{lint_yaml_value, Severity};
//!
//! let yaml = "title: Test\nlogsource:\n  category: test\ndetection:\n  sel:\n    field: value\n  condition: sel\n";
//! let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
//! let warnings = lint_yaml_value(&value);
//! for w in &warnings {
//!     if w.severity == Severity::Error {
//!         eprintln!("{}", w.message);
//!     }
//! }
//! ```

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::Deserialize;
use serde_yaml::Value;

// =============================================================================
// Public types
// =============================================================================

/// Severity of a lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Spec violation — the rule is invalid.
    Error,
    /// Best-practice issue — the rule works but is not spec-ideal.
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
        }
    }
}

/// Identifies which lint rule fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LintRule {
    // ── Shared (all document types) ──────────────────────────────────────
    MissingTitle,
    TitleTooLong,
    InvalidId,
    InvalidStatus,
    InvalidLevel,
    InvalidDate,
    InvalidModified,
    ModifiedBeforeDate,
    DescriptionTooLong,
    NameTooLong,
    TaxonomyTooLong,
    NonLowercaseKey,

    // ── Detection rules ──────────────────────────────────────────────────
    MissingLogsource,
    MissingDetection,
    MissingCondition,
    EmptyDetection,
    InvalidRelatedType,
    InvalidRelatedId,
    RelatedMissingRequired,
    DeprecatedWithoutRelated,
    InvalidTag,
    UnknownTagNamespace,
    DuplicateTags,
    DuplicateReferences,
    DuplicateFields,
    FalsepositiveTooShort,
    ScopeTooShort,
    LogsourceValueNotLowercase,

    // ── Correlation rules ────────────────────────────────────────────────
    MissingCorrelation,
    MissingCorrelationType,
    InvalidCorrelationType,
    MissingCorrelationRules,
    EmptyCorrelationRules,
    MissingCorrelationTimespan,
    InvalidTimespanFormat,
    MissingGroupBy,
    MissingCorrelationCondition,
    MissingConditionField,
    InvalidConditionOperator,
    ConditionValueNotNumeric,
    GenerateNotBoolean,

    // ── Filter rules ─────────────────────────────────────────────────────
    MissingFilter,
    MissingFilterRules,
    EmptyFilterRules,
    MissingFilterSelection,
    MissingFilterCondition,
    FilterHasLevel,
    FilterHasStatus,
    MissingFilterLogsource,

    // ── Detection logic (cross-cutting) ──────────────────────────────────
    NullInValueList,
    SingleValueAllModifier,
}

impl fmt::Display for LintRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LintRule::MissingTitle => "missing_title",
            LintRule::TitleTooLong => "title_too_long",
            LintRule::InvalidId => "invalid_id",
            LintRule::InvalidStatus => "invalid_status",
            LintRule::InvalidLevel => "invalid_level",
            LintRule::InvalidDate => "invalid_date",
            LintRule::InvalidModified => "invalid_modified",
            LintRule::ModifiedBeforeDate => "modified_before_date",
            LintRule::DescriptionTooLong => "description_too_long",
            LintRule::NameTooLong => "name_too_long",
            LintRule::TaxonomyTooLong => "taxonomy_too_long",
            LintRule::NonLowercaseKey => "non_lowercase_key",
            LintRule::MissingLogsource => "missing_logsource",
            LintRule::MissingDetection => "missing_detection",
            LintRule::MissingCondition => "missing_condition",
            LintRule::EmptyDetection => "empty_detection",
            LintRule::InvalidRelatedType => "invalid_related_type",
            LintRule::InvalidRelatedId => "invalid_related_id",
            LintRule::RelatedMissingRequired => "related_missing_required",
            LintRule::DeprecatedWithoutRelated => "deprecated_without_related",
            LintRule::InvalidTag => "invalid_tag",
            LintRule::UnknownTagNamespace => "unknown_tag_namespace",
            LintRule::DuplicateTags => "duplicate_tags",
            LintRule::DuplicateReferences => "duplicate_references",
            LintRule::DuplicateFields => "duplicate_fields",
            LintRule::FalsepositiveTooShort => "falsepositive_too_short",
            LintRule::ScopeTooShort => "scope_too_short",
            LintRule::LogsourceValueNotLowercase => "logsource_value_not_lowercase",
            LintRule::MissingCorrelation => "missing_correlation",
            LintRule::MissingCorrelationType => "missing_correlation_type",
            LintRule::InvalidCorrelationType => "invalid_correlation_type",
            LintRule::MissingCorrelationRules => "missing_correlation_rules",
            LintRule::EmptyCorrelationRules => "empty_correlation_rules",
            LintRule::MissingCorrelationTimespan => "missing_correlation_timespan",
            LintRule::InvalidTimespanFormat => "invalid_timespan_format",
            LintRule::MissingGroupBy => "missing_group_by",
            LintRule::MissingCorrelationCondition => "missing_correlation_condition",
            LintRule::MissingConditionField => "missing_condition_field",
            LintRule::InvalidConditionOperator => "invalid_condition_operator",
            LintRule::ConditionValueNotNumeric => "condition_value_not_numeric",
            LintRule::GenerateNotBoolean => "generate_not_boolean",
            LintRule::MissingFilter => "missing_filter",
            LintRule::MissingFilterRules => "missing_filter_rules",
            LintRule::EmptyFilterRules => "empty_filter_rules",
            LintRule::MissingFilterSelection => "missing_filter_selection",
            LintRule::MissingFilterCondition => "missing_filter_condition",
            LintRule::FilterHasLevel => "filter_has_level",
            LintRule::FilterHasStatus => "filter_has_status",
            LintRule::MissingFilterLogsource => "missing_filter_logsource",
            LintRule::NullInValueList => "null_in_value_list",
            LintRule::SingleValueAllModifier => "single_value_all_modifier",
        };
        write!(f, "{s}")
    }
}

/// A single lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintWarning {
    /// Which lint rule fired.
    pub rule: LintRule,
    /// Error or warning.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// JSON-pointer-style location, e.g. `"/status"`, `"/tags/2"`.
    pub path: String,
}

impl fmt::Display for LintWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}]: {}\n    --> {}",
            self.severity, self.rule, self.message, self.path
        )
    }
}

/// Result of linting a single file (may contain multiple YAML documents).
#[derive(Debug, Clone)]
pub struct FileLintResult {
    pub path: std::path::PathBuf,
    pub warnings: Vec<LintWarning>,
}

impl FileLintResult {
    pub fn has_errors(&self) -> bool {
        self.warnings.iter().any(|w| w.severity == Severity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.warnings
            .iter()
            .filter(|w| w.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings
            .iter()
            .filter(|w| w.severity == Severity::Warning)
            .count()
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn key(s: &str) -> Value {
    Value::String(s.to_string())
}

fn get_str<'a>(m: &'a serde_yaml::Mapping, k: &str) -> Option<&'a str> {
    m.get(key(k)).and_then(|v| v.as_str())
}

fn get_mapping<'a>(m: &'a serde_yaml::Mapping, k: &str) -> Option<&'a serde_yaml::Mapping> {
    m.get(key(k)).and_then(|v| v.as_mapping())
}

fn get_seq<'a>(m: &'a serde_yaml::Mapping, k: &str) -> Option<&'a serde_yaml::Sequence> {
    m.get(key(k)).and_then(|v| v.as_sequence())
}

fn warn(
    rule: LintRule,
    severity: Severity,
    message: impl Into<String>,
    path: impl Into<String>,
) -> LintWarning {
    LintWarning {
        rule,
        severity,
        message: message.into(),
        path: path.into(),
    }
}

fn err(rule: LintRule, message: impl Into<String>, path: impl Into<String>) -> LintWarning {
    warn(rule, Severity::Error, message, path)
}

fn warning(rule: LintRule, message: impl Into<String>, path: impl Into<String>) -> LintWarning {
    warn(rule, Severity::Warning, message, path)
}

/// Validate a date string matches YYYY-MM-DD.
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let year_ok = bytes[0..4].iter().all(|b| b.is_ascii_digit());
    let month: u8 = s[5..7].parse().unwrap_or(0);
    let day: u8 = s[8..10].parse().unwrap_or(0);
    year_ok && (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// Validate a UUID string (any version, hyphenated form).
fn is_valid_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(part, &len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Check if a logsource value is lowercase with valid chars.
fn is_valid_logsource_value(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-'
        })
}

/// Known tag namespaces from the spec.
const KNOWN_TAG_NAMESPACES: &[&str] =
    &["attack", "car", "cve", "d3fend", "detection", "stp", "tlp"];

/// Valid status values.
const VALID_STATUSES: &[&str] = &[
    "stable",
    "test",
    "experimental",
    "deprecated",
    "unsupported",
];

/// Valid level values.
const VALID_LEVELS: &[&str] = &["informational", "low", "medium", "high", "critical"];

/// Valid related types.
const VALID_RELATED_TYPES: &[&str] = &["derived", "obsolete", "merged", "renamed", "similar"];

/// Valid correlation types.
const VALID_CORRELATION_TYPES: &[&str] = &[
    "event_count",
    "value_count",
    "temporal",
    "temporal_ordered",
    "value_sum",
    "value_avg",
    "value_percentile",
];

/// Valid condition operators.
const VALID_CONDITION_OPERATORS: &[&str] = &["gt", "gte", "lt", "lte", "eq", "neq"];

/// Correlation types that require a condition section.
const TYPES_REQUIRING_CONDITION: &[&str] = &[
    "event_count",
    "value_count",
    "value_sum",
    "value_avg",
    "value_percentile",
];

/// Correlation types that require condition.field.
const TYPES_REQUIRING_FIELD: &[&str] =
    &["value_count", "value_sum", "value_avg", "value_percentile"];

/// Tag pattern: `^[a-z0-9_-]+\.[a-z0-9._-]+$`
fn is_valid_tag(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }
    let ns_ok = !parts[0].is_empty()
        && parts[0]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    let rest_ok = !parts[1].is_empty()
        && parts[1].chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
        });
    ns_ok && rest_ok
}

// =============================================================================
// Document type detection
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocType {
    Detection,
    Correlation,
    Filter,
}

fn detect_doc_type(m: &serde_yaml::Mapping) -> DocType {
    if m.contains_key(key("correlation")) {
        DocType::Correlation
    } else if m.contains_key(key("filter")) {
        DocType::Filter
    } else {
        DocType::Detection
    }
}

/// Returns `true` if this document is a collection action fragment
/// (`action: global`, `action: reset`, `action: repeat`) that should be
/// skipped during linting.
fn is_action_fragment(m: &serde_yaml::Mapping) -> bool {
    matches!(get_str(m, "action"), Some("global" | "reset" | "repeat"))
}

// =============================================================================
// Shared lint checks
// =============================================================================

fn lint_shared(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    // ── title ────────────────────────────────────────────────────────────
    match get_str(m, "title") {
        None => warnings.push(err(
            LintRule::MissingTitle,
            "missing required field 'title'",
            "/title",
        )),
        Some(t) if t.len() > 256 => {
            warnings.push(warning(
                LintRule::TitleTooLong,
                format!("title is {} characters, maximum is 256", t.len()),
                "/title",
            ));
        }
        _ => {}
    }

    // ── id ───────────────────────────────────────────────────────────────
    if let Some(id) = get_str(m, "id")
        && !is_valid_uuid(id)
    {
        warnings.push(warning(
            LintRule::InvalidId,
            format!("id \"{id}\" is not a valid UUID"),
            "/id",
        ));
    }

    // ── status ───────────────────────────────────────────────────────────
    if let Some(status) = get_str(m, "status")
        && !VALID_STATUSES.contains(&status)
    {
        warnings.push(err(
            LintRule::InvalidStatus,
            format!(
                "invalid status \"{status}\", expected one of: {}",
                VALID_STATUSES.join(", ")
            ),
            "/status",
        ));
    }

    // ── level ────────────────────────────────────────────────────────────
    if let Some(level) = get_str(m, "level")
        && !VALID_LEVELS.contains(&level)
    {
        warnings.push(err(
            LintRule::InvalidLevel,
            format!(
                "invalid level \"{level}\", expected one of: {}",
                VALID_LEVELS.join(", ")
            ),
            "/level",
        ));
    }

    // ── date ─────────────────────────────────────────────────────────────
    if let Some(raw) = m.get(key("date")) {
        // serde_yaml may parse dates as dates, coerce to string
        let date_str = raw.as_str().map(|s| s.to_string()).or_else(|| {
            // serde_yaml sometimes deserialises YYYY-MM-DD as a tagged string
            serde_yaml::to_string(raw)
                .ok()
                .map(|s| s.trim().to_string())
        });
        if let Some(d) = date_str
            && !is_valid_date(&d)
        {
            warnings.push(err(
                LintRule::InvalidDate,
                format!("invalid date \"{d}\", expected YYYY-MM-DD"),
                "/date",
            ));
        }
    }

    // ── modified ─────────────────────────────────────────────────────────
    if let Some(raw) = m.get(key("modified")) {
        let mod_str = raw.as_str().map(|s| s.to_string()).or_else(|| {
            serde_yaml::to_string(raw)
                .ok()
                .map(|s| s.trim().to_string())
        });
        if let Some(d) = mod_str
            && !is_valid_date(&d)
        {
            warnings.push(err(
                LintRule::InvalidModified,
                format!("invalid modified date \"{d}\", expected YYYY-MM-DD"),
                "/modified",
            ));
        }
    }

    // ── modified >= date ─────────────────────────────────────────────────
    if let (Some(date_val), Some(mod_val)) = (
        m.get(key("date")).and_then(|v| v.as_str()),
        m.get(key("modified")).and_then(|v| v.as_str()),
    ) && is_valid_date(date_val)
        && is_valid_date(mod_val)
        && mod_val < date_val
    {
        warnings.push(warning(
            LintRule::ModifiedBeforeDate,
            format!("modified date \"{mod_val}\" is before creation date \"{date_val}\""),
            "/modified",
        ));
    }

    // ── description ──────────────────────────────────────────────────────
    if let Some(desc) = get_str(m, "description")
        && desc.len() > 65535
    {
        warnings.push(warning(
            LintRule::DescriptionTooLong,
            format!("description is {} characters, maximum is 65535", desc.len()),
            "/description",
        ));
    }

    // ── name ─────────────────────────────────────────────────────────────
    if let Some(name) = get_str(m, "name")
        && name.len() > 256
    {
        warnings.push(warning(
            LintRule::NameTooLong,
            format!("name is {} characters, maximum is 256", name.len()),
            "/name",
        ));
    }

    // ── taxonomy ─────────────────────────────────────────────────────────
    if let Some(tax) = get_str(m, "taxonomy")
        && tax.len() > 256
    {
        warnings.push(warning(
            LintRule::TaxonomyTooLong,
            format!("taxonomy is {} characters, maximum is 256", tax.len()),
            "/taxonomy",
        ));
    }

    // ── lowercase keys ───────────────────────────────────────────────────
    for k in m.keys() {
        if let Some(ks) = k.as_str()
            && ks != ks.to_ascii_lowercase()
        {
            warnings.push(warning(
                LintRule::NonLowercaseKey,
                format!("key \"{ks}\" should be lowercase"),
                format!("/{ks}"),
            ));
        }
    }
}

// =============================================================================
// Detection rule lint checks
// =============================================================================

fn lint_detection_rule(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    // ── logsource ────────────────────────────────────────────────────────
    if !m.contains_key(key("logsource")) {
        warnings.push(err(
            LintRule::MissingLogsource,
            "missing required field 'logsource'",
            "/logsource",
        ));
    } else {
        lint_logsource(m, warnings);
    }

    // ── detection ────────────────────────────────────────────────────────
    if let Some(det_val) = m.get(key("detection")) {
        if let Some(det) = det_val.as_mapping() {
            if !det.contains_key(key("condition")) {
                warnings.push(err(
                    LintRule::MissingCondition,
                    "detection section is missing required 'condition'",
                    "/detection/condition",
                ));
            }

            // Check for at least one named identifier besides condition/timeframe
            let named_count = det
                .keys()
                .filter(|k| {
                    let ks = k.as_str().unwrap_or("");
                    ks != "condition" && ks != "timeframe"
                })
                .count();
            if named_count == 0 {
                warnings.push(warning(
                    LintRule::EmptyDetection,
                    "detection section has no named search identifiers",
                    "/detection",
                ));
            }

            // Detection logic checks
            lint_detection_logic(det, warnings);
        }
    } else {
        warnings.push(err(
            LintRule::MissingDetection,
            "missing required field 'detection'",
            "/detection",
        ));
    }

    // ── related ──────────────────────────────────────────────────────────
    if let Some(related) = get_seq(m, "related") {
        for (i, item) in related.iter().enumerate() {
            let path_prefix = format!("/related/{i}");
            if let Some(item_map) = item.as_mapping() {
                let has_id = item_map.contains_key(key("id"));
                let has_type = item_map.contains_key(key("type"));

                if !has_id || !has_type {
                    warnings.push(err(
                        LintRule::RelatedMissingRequired,
                        "related entry must have both 'id' and 'type'",
                        &path_prefix,
                    ));
                }

                if let Some(id) = get_str(item_map, "id")
                    && !is_valid_uuid(id)
                {
                    warnings.push(warning(
                        LintRule::InvalidRelatedId,
                        format!("related id \"{id}\" is not a valid UUID"),
                        format!("{path_prefix}/id"),
                    ));
                }

                if let Some(type_val) = get_str(item_map, "type")
                    && !VALID_RELATED_TYPES.contains(&type_val)
                {
                    warnings.push(err(
                        LintRule::InvalidRelatedType,
                        format!(
                            "invalid related type \"{type_val}\", expected one of: {}",
                            VALID_RELATED_TYPES.join(", ")
                        ),
                        format!("{path_prefix}/type"),
                    ));
                }
            }
        }
    }

    // ── deprecated + related consistency ─────────────────────────────────
    if get_str(m, "status") == Some("deprecated") {
        let has_related = get_seq(m, "related")
            .map(|seq| !seq.is_empty())
            .unwrap_or(false);
        if !has_related {
            warnings.push(warning(
                LintRule::DeprecatedWithoutRelated,
                "deprecated rule should have a 'related' entry linking to its replacement",
                "/status",
            ));
        }
    }

    // ── tags ─────────────────────────────────────────────────────────────
    if let Some(tags) = get_seq(m, "tags") {
        let mut seen_tags: HashSet<String> = HashSet::new();
        for (i, tag_val) in tags.iter().enumerate() {
            if let Some(tag) = tag_val.as_str() {
                if !is_valid_tag(tag) {
                    warnings.push(warning(
                        LintRule::InvalidTag,
                        format!(
                            "tag \"{tag}\" does not match required pattern (lowercase, dotted namespace)"
                        ),
                        format!("/tags/{i}"),
                    ));
                } else {
                    // Check known namespace
                    if let Some(ns) = tag.split('.').next()
                        && !KNOWN_TAG_NAMESPACES.contains(&ns)
                    {
                        warnings.push(warning(
                            LintRule::UnknownTagNamespace,
                            format!(
                                "unknown tag namespace \"{ns}\", known namespaces: {}",
                                KNOWN_TAG_NAMESPACES.join(", ")
                            ),
                            format!("/tags/{i}"),
                        ));
                    }
                }

                if !seen_tags.insert(tag.to_string()) {
                    warnings.push(warning(
                        LintRule::DuplicateTags,
                        format!("duplicate tag \"{tag}\""),
                        format!("/tags/{i}"),
                    ));
                }
            }
        }
    }

    // ── references (unique) ──────────────────────────────────────────────
    if let Some(refs) = get_seq(m, "references") {
        let mut seen: HashSet<String> = HashSet::new();
        for (i, r) in refs.iter().enumerate() {
            if let Some(s) = r.as_str()
                && !seen.insert(s.to_string())
            {
                warnings.push(warning(
                    LintRule::DuplicateReferences,
                    format!("duplicate reference \"{s}\""),
                    format!("/references/{i}"),
                ));
            }
        }
    }

    // ── fields (unique) ──────────────────────────────────────────────────
    if let Some(fields) = get_seq(m, "fields") {
        let mut seen: HashSet<String> = HashSet::new();
        for (i, f) in fields.iter().enumerate() {
            if let Some(s) = f.as_str()
                && !seen.insert(s.to_string())
            {
                warnings.push(warning(
                    LintRule::DuplicateFields,
                    format!("duplicate field \"{s}\""),
                    format!("/fields/{i}"),
                ));
            }
        }
    }

    // ── falsepositives (minLength 2) ─────────────────────────────────────
    if let Some(fps) = get_seq(m, "falsepositives") {
        for (i, fp) in fps.iter().enumerate() {
            if let Some(s) = fp.as_str()
                && s.len() < 2
            {
                warnings.push(warning(
                    LintRule::FalsepositiveTooShort,
                    format!("falsepositive entry \"{s}\" must be at least 2 characters"),
                    format!("/falsepositives/{i}"),
                ));
            }
        }
    }

    // ── scope (minLength 2) ──────────────────────────────────────────────
    if let Some(scope) = get_seq(m, "scope") {
        for (i, s_val) in scope.iter().enumerate() {
            if let Some(s) = s_val.as_str()
                && s.len() < 2
            {
                warnings.push(warning(
                    LintRule::ScopeTooShort,
                    format!("scope entry \"{s}\" must be at least 2 characters"),
                    format!("/scope/{i}"),
                ));
            }
        }
    }
}

fn lint_logsource(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    if let Some(ls) = get_mapping(m, "logsource") {
        for field in &["category", "product", "service"] {
            if let Some(val) = get_str(ls, field)
                && !is_valid_logsource_value(val)
            {
                warnings.push(warning(
                    LintRule::LogsourceValueNotLowercase,
                    format!("logsource {field} \"{val}\" should be lowercase (a-z, 0-9, _, ., -)"),
                    format!("/logsource/{field}"),
                ));
            }
        }
    }
}

/// Checks detection logic: null in value lists, single-value |all.
fn lint_detection_logic(det: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    for (det_key, det_val) in det {
        let det_key_str = det_key.as_str().unwrap_or("");
        if det_key_str == "condition" || det_key_str == "timeframe" {
            continue;
        }

        lint_detection_value(det_val, det_key_str, warnings);
    }
}

fn lint_detection_value(value: &Value, det_name: &str, warnings: &mut Vec<LintWarning>) {
    match value {
        Value::Mapping(m) => {
            for (field_key, field_val) in m {
                let field_key_str = field_key.as_str().unwrap_or("");

                // Check |all with single value
                if field_key_str.contains("|all") {
                    if let Value::Sequence(seq) = field_val {
                        if seq.len() <= 1 {
                            warnings.push(warning(
                                LintRule::SingleValueAllModifier,
                                format!(
                                    "'{field_key_str}' in '{det_name}' uses |all modifier with {} value(s); |all requires multiple values",
                                    seq.len()
                                ),
                                format!("/detection/{det_name}/{field_key_str}"),
                            ));
                        }
                    } else {
                        // single value with |all
                        warnings.push(warning(
                            LintRule::SingleValueAllModifier,
                            format!(
                                "'{field_key_str}' in '{det_name}' uses |all modifier with a single value; |all requires multiple values"
                            ),
                            format!("/detection/{det_name}/{field_key_str}"),
                        ));
                    }
                }

                // Check null in value list
                if let Value::Sequence(seq) = field_val {
                    let has_null = seq.iter().any(|v| v.is_null());
                    let has_non_null = seq.iter().any(|v| !v.is_null());
                    if has_null && has_non_null {
                        warnings.push(warning(
                            LintRule::NullInValueList,
                            format!(
                                "'{field_key_str}' in '{det_name}' mixes null with other values; null should be in its own selection"
                            ),
                            format!("/detection/{det_name}/{field_key_str}"),
                        ));
                    }
                }
            }
        }
        Value::Sequence(seq) => {
            // List of maps (OR-linked) or keyword list
            for item in seq {
                if item.is_mapping() {
                    lint_detection_value(item, det_name, warnings);
                }
            }
        }
        _ => {}
    }
}

// =============================================================================
// Correlation rule lint checks
// =============================================================================

fn lint_correlation_rule(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    let Some(corr_val) = m.get(key("correlation")) else {
        warnings.push(err(
            LintRule::MissingCorrelation,
            "missing required field 'correlation'",
            "/correlation",
        ));
        return;
    };

    let Some(corr) = corr_val.as_mapping() else {
        warnings.push(err(
            LintRule::MissingCorrelation,
            "'correlation' must be a mapping",
            "/correlation",
        ));
        return;
    };

    // ── type ─────────────────────────────────────────────────────────────
    let corr_type = get_str(corr, "type");
    match corr_type {
        None => {
            warnings.push(err(
                LintRule::MissingCorrelationType,
                "missing required field 'correlation.type'",
                "/correlation/type",
            ));
        }
        Some(t) if !VALID_CORRELATION_TYPES.contains(&t) => {
            warnings.push(err(
                LintRule::InvalidCorrelationType,
                format!(
                    "invalid correlation type \"{t}\", expected one of: {}",
                    VALID_CORRELATION_TYPES.join(", ")
                ),
                "/correlation/type",
            ));
        }
        _ => {}
    }

    // ── rules ────────────────────────────────────────────────────────────
    if let Some(rules) = corr.get(key("rules")) {
        if let Some(seq) = rules.as_sequence()
            && seq.is_empty()
        {
            warnings.push(warning(
                LintRule::EmptyCorrelationRules,
                "correlation.rules should not be empty",
                "/correlation/rules",
            ));
        }
    } else {
        warnings.push(err(
            LintRule::MissingCorrelationRules,
            "missing required field 'correlation.rules'",
            "/correlation/rules",
        ));
    }

    // ── timespan ─────────────────────────────────────────────────────────
    if let Some(ts) = get_str(corr, "timespan").or_else(|| get_str(corr, "timeframe")) {
        if !is_valid_timespan(ts) {
            warnings.push(err(
                LintRule::InvalidTimespanFormat,
                format!("invalid timespan \"{ts}\", expected format like 5m, 1h, 30s, 7d"),
                "/correlation/timespan",
            ));
        }
    } else {
        warnings.push(err(
            LintRule::MissingCorrelationTimespan,
            "missing required field 'correlation.timespan'",
            "/correlation/timespan",
        ));
    }

    // ── Conditional requirements per correlation type ─────────────────────
    if let Some(ct) = corr_type {
        // group-by is required for all correlation types
        if !corr.contains_key(key("group-by")) {
            warnings.push(err(
                LintRule::MissingGroupBy,
                format!("{ct} correlation requires 'group-by'"),
                "/correlation/group-by",
            ));
        }

        // condition required for non-temporal types
        if TYPES_REQUIRING_CONDITION.contains(&ct) {
            if let Some(cond_val) = corr.get(key("condition")) {
                if let Some(cond_map) = cond_val.as_mapping() {
                    lint_correlation_condition(cond_map, ct, warnings);
                }
            } else {
                warnings.push(err(
                    LintRule::MissingCorrelationCondition,
                    format!("{ct} correlation requires a 'condition'"),
                    "/correlation/condition",
                ));
            }
        }
    }

    // ── generate ─────────────────────────────────────────────────────────
    if let Some(gen_val) = corr.get(key("generate"))
        && !gen_val.is_bool()
    {
        warnings.push(err(
            LintRule::GenerateNotBoolean,
            "'generate' must be a boolean (true/false)",
            "/correlation/generate",
        ));
    }
}

fn lint_correlation_condition(
    cond: &serde_yaml::Mapping,
    corr_type: &str,
    warnings: &mut Vec<LintWarning>,
) {
    // Check condition.field requirement
    if TYPES_REQUIRING_FIELD.contains(&corr_type) && !cond.contains_key(key("field")) {
        warnings.push(err(
            LintRule::MissingConditionField,
            format!("{corr_type} correlation condition requires 'field'"),
            "/correlation/condition/field",
        ));
    }

    // Validate operator keys and numeric values
    for (k, v) in cond {
        let ks = k.as_str().unwrap_or("");
        if ks == "field" {
            continue;
        }
        if !VALID_CONDITION_OPERATORS.contains(&ks) {
            warnings.push(err(
                LintRule::InvalidConditionOperator,
                format!(
                    "invalid condition operator \"{ks}\", expected one of: {}",
                    VALID_CONDITION_OPERATORS.join(", ")
                ),
                format!("/correlation/condition/{ks}"),
            ));
        } else if !v.is_i64() && !v.is_u64() && !v.is_f64() {
            warnings.push(err(
                LintRule::ConditionValueNotNumeric,
                format!("condition operator '{ks}' requires a numeric value"),
                format!("/correlation/condition/{ks}"),
            ));
        }
    }
}

fn is_valid_timespan(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let last = s.as_bytes()[s.len() - 1];
    if !matches!(last, b's' | b'm' | b'h' | b'd') {
        return false;
    }
    let num_part = &s[..s.len() - 1];
    !num_part.is_empty() && num_part.chars().all(|c| c.is_ascii_digit())
}

// =============================================================================
// Filter rule lint checks
// =============================================================================

fn lint_filter_rule(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    // ── filter section ───────────────────────────────────────────────────
    let Some(filter_val) = m.get(key("filter")) else {
        warnings.push(err(
            LintRule::MissingFilter,
            "missing required field 'filter'",
            "/filter",
        ));
        return;
    };

    let Some(filter) = filter_val.as_mapping() else {
        warnings.push(err(
            LintRule::MissingFilter,
            "'filter' must be a mapping",
            "/filter",
        ));
        return;
    };

    // ── filter.rules ─────────────────────────────────────────────────────
    if let Some(rules_val) = filter.get(key("rules")) {
        if let Some(seq) = rules_val.as_sequence()
            && seq.is_empty()
        {
            warnings.push(warning(
                LintRule::EmptyFilterRules,
                "filter.rules should have at least one entry",
                "/filter/rules",
            ));
        }
    } else {
        warnings.push(err(
            LintRule::MissingFilterRules,
            "missing required field 'filter.rules'",
            "/filter/rules",
        ));
    }

    // ── filter.selection ─────────────────────────────────────────────────
    if !filter.contains_key(key("selection")) {
        warnings.push(err(
            LintRule::MissingFilterSelection,
            "missing required field 'filter.selection'",
            "/filter/selection",
        ));
    }

    // ── filter.condition ─────────────────────────────────────────────────
    if !filter.contains_key(key("condition")) {
        warnings.push(err(
            LintRule::MissingFilterCondition,
            "missing required field 'filter.condition'",
            "/filter/condition",
        ));
    }

    // ── logsource required for filters ───────────────────────────────────
    if !m.contains_key(key("logsource")) {
        warnings.push(err(
            LintRule::MissingFilterLogsource,
            "missing required field 'logsource' for filter rule",
            "/logsource",
        ));
    } else {
        lint_logsource(m, warnings);
    }

    // ── Filters should NOT have level or status ──────────────────────────
    if m.contains_key(key("level")) {
        warnings.push(warning(
            LintRule::FilterHasLevel,
            "filter rules should not have a 'level' field",
            "/level",
        ));
    }

    if m.contains_key(key("status")) {
        warnings.push(warning(
            LintRule::FilterHasStatus,
            "filter rules should not have a 'status' field",
            "/status",
        ));
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Lint a single YAML document value.
///
/// Auto-detects document type (detection / correlation / filter) and runs
/// the appropriate checks. Returns all findings.
pub fn lint_yaml_value(value: &Value) -> Vec<LintWarning> {
    let Some(m) = value.as_mapping() else {
        return vec![err(
            LintRule::MissingTitle,
            "document is not a YAML mapping",
            "/",
        )];
    };

    // Skip collection action fragments
    if is_action_fragment(m) {
        return Vec::new();
    }

    let mut warnings = Vec::new();

    // Run shared checks
    lint_shared(m, &mut warnings);

    // Run type-specific checks
    match detect_doc_type(m) {
        DocType::Detection => lint_detection_rule(m, &mut warnings),
        DocType::Correlation => lint_correlation_rule(m, &mut warnings),
        DocType::Filter => lint_filter_rule(m, &mut warnings),
    }

    warnings
}

/// Lint all YAML documents in a file.
///
/// Handles multi-document YAML (separated by `---`). Collection action
/// fragments (`action: global/reset/repeat`) are skipped.
pub fn lint_yaml_file(path: &Path) -> crate::error::Result<Vec<FileLintResult>> {
    let content = std::fs::read_to_string(path)?;
    let mut all_warnings = Vec::new();

    for doc in serde_yaml::Deserializer::from_str(&content) {
        let value: Value = match Value::deserialize(doc) {
            Ok(v) => v,
            Err(e) => {
                all_warnings.push(err(
                    LintRule::MissingTitle,
                    format!("YAML parse error: {e}"),
                    "/",
                ));
                continue;
            }
        };

        all_warnings.extend(lint_yaml_value(&value));
    }

    Ok(vec![FileLintResult {
        path: path.to_path_buf(),
        warnings: all_warnings,
    }])
}

/// Lint all `.yml`/`.yaml` files in a directory recursively.
pub fn lint_yaml_directory(dir: &Path) -> crate::error::Result<Vec<FileLintResult>> {
    let mut results = Vec::new();

    fn walk(dir: &Path, results: &mut Vec<FileLintResult>) -> crate::error::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, results)?;
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                match crate::lint::lint_yaml_file(&path) {
                    Ok(file_results) => results.extend(file_results),
                    Err(e) => {
                        results.push(FileLintResult {
                            path: path.clone(),
                            warnings: vec![err(
                                LintRule::MissingTitle,
                                format!("error reading file: {e}"),
                                "/",
                            )],
                        });
                    }
                }
            }
        }
        Ok(())
    }

    walk(dir, &mut results)?;
    Ok(results)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_value(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn lint(yaml: &str) -> Vec<LintWarning> {
        lint_yaml_value(&yaml_value(yaml))
    }

    fn has_rule(warnings: &[LintWarning], rule: LintRule) -> bool {
        warnings.iter().any(|w| w.rule == rule)
    }

    fn has_no_rule(warnings: &[LintWarning], rule: LintRule) -> bool {
        !has_rule(warnings, rule)
    }

    // ── Valid rule produces no errors ────────────────────────────────────

    #[test]
    fn valid_detection_rule_no_errors() {
        let w = lint(
            r#"
title: Test Rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059
"#,
        );
        let errors: Vec<_> = w.iter().filter(|w| w.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    // ── Shared checks ───────────────────────────────────────────────────

    #[test]
    fn missing_title() {
        let w = lint(
            r#"
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingTitle));
    }

    #[test]
    fn title_too_long() {
        let long_title = "a".repeat(257);
        let yaml = format!(
            r#"
title: '{long_title}'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#
        );
        let w = lint(&yaml);
        assert!(has_rule(&w, LintRule::TitleTooLong));
    }

    #[test]
    fn invalid_id() {
        let w = lint(
            r#"
title: Test
id: not-a-uuid
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidId));
    }

    #[test]
    fn valid_id_no_warning() {
        let w = lint(
            r#"
title: Test
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_no_rule(&w, LintRule::InvalidId));
    }

    #[test]
    fn invalid_status() {
        let w = lint(
            r#"
title: Test
status: invalid
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidStatus));
    }

    #[test]
    fn invalid_level() {
        let w = lint(
            r#"
title: Test
level: important
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidLevel));
    }

    #[test]
    fn invalid_date_format() {
        let w = lint(
            r#"
title: Test
date: 'Jan 2025'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidDate));
    }

    #[test]
    fn modified_before_date() {
        let w = lint(
            r#"
title: Test
date: '2025-06-15'
modified: '2025-06-10'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::ModifiedBeforeDate));
    }

    #[test]
    fn non_lowercase_key() {
        let w = lint(
            r#"
title: Test
Status: test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::NonLowercaseKey));
    }

    // ── Detection rule checks ───────────────────────────────────────────

    #[test]
    fn missing_logsource() {
        let w = lint(
            r#"
title: Test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingLogsource));
    }

    #[test]
    fn missing_detection() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
"#,
        );
        assert!(has_rule(&w, LintRule::MissingDetection));
    }

    #[test]
    fn missing_condition() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
"#,
        );
        assert!(has_rule(&w, LintRule::MissingCondition));
    }

    #[test]
    fn empty_detection() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::EmptyDetection));
    }

    #[test]
    fn invalid_related_type() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
related:
    - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
      type: invalid_type
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidRelatedType));
    }

    #[test]
    fn related_missing_required_fields() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
related:
    - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
"#,
        );
        assert!(has_rule(&w, LintRule::RelatedMissingRequired));
    }

    #[test]
    fn deprecated_without_related() {
        let w = lint(
            r#"
title: Test
status: deprecated
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::DeprecatedWithoutRelated));
    }

    #[test]
    fn invalid_tag_pattern() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - 'Invalid Tag'
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidTag));
    }

    #[test]
    fn unknown_tag_namespace() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - custom.something
"#,
        );
        assert!(has_rule(&w, LintRule::UnknownTagNamespace));
    }

    #[test]
    fn duplicate_tags() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - attack.execution
    - attack.execution
"#,
        );
        assert!(has_rule(&w, LintRule::DuplicateTags));
    }

    #[test]
    fn logsource_not_lowercase() {
        let w = lint(
            r#"
title: Test
logsource:
    category: Process_Creation
    product: Windows
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::LogsourceValueNotLowercase));
    }

    #[test]
    fn single_value_all_modifier() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|all: 'single'
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::SingleValueAllModifier));
    }

    #[test]
    fn null_in_value_list() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA:
            - 'value1'
            - null
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::NullInValueList));
    }

    // ── Correlation rule checks ─────────────────────────────────────────

    #[test]
    fn valid_correlation_no_errors() {
        let w = lint(
            r#"
title: Brute Force
correlation:
    type: event_count
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 100
level: high
"#,
        );
        let errors: Vec<_> = w.iter().filter(|w| w.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn invalid_correlation_type() {
        let w = lint(
            r#"
title: Test
correlation:
    type: invalid_type
    rules:
        - some-rule
    timespan: 1h
    group-by:
        - User
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidCorrelationType));
    }

    #[test]
    fn missing_correlation_timespan() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::MissingCorrelationTimespan));
    }

    #[test]
    fn invalid_timespan_format() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1hour
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidTimespanFormat));
    }

    #[test]
    fn missing_group_by() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    timespan: 1h
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::MissingGroupBy));
    }

    #[test]
    fn missing_condition_field_for_value_count() {
        let w = lint(
            r#"
title: Test
correlation:
    type: value_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::MissingConditionField));
    }

    #[test]
    fn invalid_condition_operator() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    condition:
        bigger: 10
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidConditionOperator));
    }

    #[test]
    fn generate_not_boolean() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 10
    generate: 'yes'
"#,
        );
        assert!(has_rule(&w, LintRule::GenerateNotBoolean));
    }

    // ── Filter rule checks ──────────────────────────────────────────────

    #[test]
    fn valid_filter_no_errors() {
        let w = lint(
            r#"
title: Filter Admin
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User|startswith: 'adm_'
    condition: selection
"#,
        );
        let errors: Vec<_> = w.iter().filter(|w| w.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn missing_filter_rules() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterRules));
    }

    #[test]
    fn missing_filter_selection() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules:
        - some-rule
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterSelection));
    }

    #[test]
    fn missing_filter_condition() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules:
        - some-rule
    selection:
        User: admin
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterCondition));
    }

    #[test]
    fn filter_has_level_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
level: high
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::FilterHasLevel));
    }

    #[test]
    fn filter_has_status_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
status: test
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::FilterHasStatus));
    }

    #[test]
    fn missing_filter_logsource() {
        let w = lint(
            r#"
title: Test
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterLogsource));
    }

    // ── Action fragments are skipped ────────────────────────────────────

    #[test]
    fn action_global_skipped() {
        let w = lint(
            r#"
action: global
title: Global Template
logsource:
    product: windows
"#,
        );
        assert!(w.is_empty());
    }

    #[test]
    fn action_reset_skipped() {
        let w = lint(
            r#"
action: reset
"#,
        );
        assert!(w.is_empty());
    }
}
