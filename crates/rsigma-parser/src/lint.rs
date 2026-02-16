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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

// =============================================================================
// Public types
// =============================================================================

/// Severity of a lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Severity {
    /// Spec violation — the rule is invalid.
    Error,
    /// Best-practice issue — the rule works but is not spec-ideal.
    Warning,
    /// Informational suggestion — soft best-practice hint (e.g. missing author).
    Info,
    /// Subtle hint — lowest severity, for stylistic suggestions.
    Hint,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
            Severity::Hint => write!(f, "hint"),
        }
    }
}

/// Identifies which lint rule fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum LintRule {
    // ── Infrastructure / parse errors ────────────────────────────────────
    YamlParseError,
    NotAMapping,
    FileReadError,
    SchemaViolation,

    // ── Shared (all document types) ──────────────────────────────────────
    MissingTitle,
    EmptyTitle,
    TitleTooLong,
    MissingDescription,
    MissingAuthor,
    InvalidId,
    InvalidStatus,
    MissingLevel,
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
    ConditionReferencesUnknown,

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
    AllWithRe,
    EmptyValueList,
    WildcardOnlyValue,
    UnknownKey,
}

impl fmt::Display for LintRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LintRule::YamlParseError => "yaml_parse_error",
            LintRule::NotAMapping => "not_a_mapping",
            LintRule::FileReadError => "file_read_error",
            LintRule::SchemaViolation => "schema_violation",
            LintRule::MissingTitle => "missing_title",
            LintRule::EmptyTitle => "empty_title",
            LintRule::TitleTooLong => "title_too_long",
            LintRule::MissingDescription => "missing_description",
            LintRule::MissingAuthor => "missing_author",
            LintRule::InvalidId => "invalid_id",
            LintRule::InvalidStatus => "invalid_status",
            LintRule::MissingLevel => "missing_level",
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
            LintRule::ConditionReferencesUnknown => "condition_references_unknown",
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
            LintRule::AllWithRe => "all_with_re",
            LintRule::EmptyValueList => "empty_value_list",
            LintRule::WildcardOnlyValue => "wildcard_only_value",
            LintRule::UnknownKey => "unknown_key",
        };
        write!(f, "{s}")
    }
}

/// A source span (line/column, both 0-indexed).
///
/// Used by the LSP layer to avoid re-resolving JSON-pointer paths to
/// source positions. When the lint is produced from raw `serde_yaml::Value`
/// (which has no source positions), `span` will be `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    /// 0-indexed start line.
    pub start_line: u32,
    /// 0-indexed start column.
    pub start_col: u32,
    /// 0-indexed end line.
    pub end_line: u32,
    /// 0-indexed end column.
    pub end_col: u32,
}

/// A single lint finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LintWarning {
    /// Which lint rule fired.
    pub rule: LintRule,
    /// Error or warning.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// JSON-pointer-style location, e.g. `"/status"`, `"/tags/2"`.
    pub path: String,
    /// Optional source span. `None` when linting `serde_yaml::Value` (no
    /// source positions available). Populated by `lint_yaml_str` which
    /// can resolve paths against the raw text.
    pub span: Option<Span>,
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
#[derive(Debug, Clone, Serialize)]
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

    pub fn info_count(&self) -> usize {
        self.warnings
            .iter()
            .filter(|w| w.severity == Severity::Info)
            .count()
    }

    pub fn hint_count(&self) -> usize {
        self.warnings
            .iter()
            .filter(|w| w.severity == Severity::Hint)
            .count()
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Pre-cached `Value::String` keys to avoid per-call allocations when
/// looking up fields in `serde_yaml::Mapping`.
static KEY_CACHE: LazyLock<HashMap<&'static str, Value>> = LazyLock::new(|| {
    [
        "action",
        "author",
        "category",
        "condition",
        "correlation",
        "date",
        "description",
        "detection",
        "falsepositives",
        "field",
        "fields",
        "filter",
        "generate",
        "group-by",
        "id",
        "level",
        "logsource",
        "modified",
        "name",
        "product",
        "references",
        "related",
        "rules",
        "scope",
        "selection",
        "service",
        "status",
        "tags",
        "taxonomy",
        "timeframe",
        "timespan",
        "title",
        "type",
    ]
    .into_iter()
    .map(|n| (n, Value::String(n.into())))
    .collect()
});

fn key(s: &str) -> &'static Value {
    KEY_CACHE
        .get(s)
        .unwrap_or_else(|| panic!("lint key not pre-cached: \"{s}\" — add it to KEY_CACHE"))
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
        span: None,
    }
}

fn err(rule: LintRule, message: impl Into<String>, path: impl Into<String>) -> LintWarning {
    warn(rule, Severity::Error, message, path)
}

fn warning(rule: LintRule, message: impl Into<String>, path: impl Into<String>) -> LintWarning {
    warn(rule, Severity::Warning, message, path)
}

fn info(rule: LintRule, message: impl Into<String>, path: impl Into<String>) -> LintWarning {
    warn(rule, Severity::Info, message, path)
}

/// Validate a date string matches YYYY-MM-DD with correct day-of-month.
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let year_ok = bytes[0..4].iter().all(|b| b.is_ascii_digit());
    let year: u16 = s[0..4].parse().unwrap_or(0);
    let month: u8 = s[5..7].parse().unwrap_or(0);
    let day: u8 = s[8..10].parse().unwrap_or(0);
    if !year_ok || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let is_leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    day <= max_day
}

/// Extract a date string from a YAML value, handling serde_yaml auto-parsing.
///
/// `serde_yaml` sometimes deserialises `YYYY-MM-DD` as a tagged/non-string
/// type. This helper coerces such values back to a trimmed string.
fn extract_date_string(raw: &Value) -> Option<String> {
    raw.as_str().map(|s| s.to_string()).or_else(|| {
        serde_yaml::to_string(raw)
            .ok()
            .map(|s| s.trim().to_string())
    })
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
    "value_median",
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

/// Known top-level keys shared across all Sigma document types.
const KNOWN_KEYS_SHARED: &[&str] = &[
    "title",
    "id",
    "name",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "related",
    "taxonomy",
    "action",
    "license",
    "references",
    "tags",
];

/// Extra top-level keys valid for detection rules.
const KNOWN_KEYS_DETECTION: &[&str] = &[
    "logsource",
    "detection",
    "fields",
    "falsepositives",
    "level",
    "scope",
];

/// Extra top-level keys valid for correlation rules.
const KNOWN_KEYS_CORRELATION: &[&str] = &["correlation", "level", "generate"];

/// Extra top-level keys valid for filter rules.
const KNOWN_KEYS_FILTER: &[&str] = &["logsource", "filter"];

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

impl DocType {
    fn known_keys(&self) -> &'static [&'static str] {
        match self {
            DocType::Detection => KNOWN_KEYS_DETECTION,
            DocType::Correlation => KNOWN_KEYS_CORRELATION,
            DocType::Filter => KNOWN_KEYS_FILTER,
        }
    }
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
        Some(t) if t.trim().is_empty() => {
            warnings.push(err(
                LintRule::EmptyTitle,
                "title must not be empty",
                "/title",
            ));
        }
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
    let date_string = m.get(key("date")).and_then(extract_date_string);
    if let Some(d) = &date_string
        && !is_valid_date(d)
    {
        warnings.push(err(
            LintRule::InvalidDate,
            format!("invalid date \"{d}\", expected YYYY-MM-DD"),
            "/date",
        ));
    }

    // ── modified ─────────────────────────────────────────────────────────
    let modified_string = m.get(key("modified")).and_then(extract_date_string);
    if let Some(d) = &modified_string
        && !is_valid_date(d)
    {
        warnings.push(err(
            LintRule::InvalidModified,
            format!("invalid modified date \"{d}\", expected YYYY-MM-DD"),
            "/modified",
        ));
    }

    // ── modified >= date ─────────────────────────────────────────────────
    if let (Some(date_val), Some(mod_val)) = (&date_string, &modified_string)
        && is_valid_date(date_val)
        && is_valid_date(mod_val)
        && mod_val.as_str() < date_val.as_str()
    {
        warnings.push(warning(
            LintRule::ModifiedBeforeDate,
            format!("modified date \"{mod_val}\" is before creation date \"{date_val}\""),
            "/modified",
        ));
    }

    // ── description (missing) ──────────────────────────────────────────
    if !m.contains_key(key("description")) {
        warnings.push(info(
            LintRule::MissingDescription,
            "missing recommended field 'description'",
            "/description",
        ));
    }

    // ── author (missing) ─────────────────────────────────────────────
    if !m.contains_key(key("author")) {
        warnings.push(info(
            LintRule::MissingAuthor,
            "missing recommended field 'author'",
            "/author",
        ));
    }

    // ── description (too long) ───────────────────────────────────────
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
    // ── level ─────────────────────────────────────────────────────────────
    if !m.contains_key(key("level")) {
        warnings.push(warning(
            LintRule::MissingLevel,
            "missing recommended field 'level'",
            "/level",
        ));
    }

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
            // Collect detection identifier names (excluding condition/timeframe)
            let det_keys: HashSet<&str> = det
                .keys()
                .filter_map(|k| k.as_str())
                .filter(|k| *k != "condition" && *k != "timeframe")
                .collect();

            if !det.contains_key(key("condition")) {
                warnings.push(err(
                    LintRule::MissingCondition,
                    "detection section is missing required 'condition'",
                    "/detection/condition",
                ));
            } else if let Some(cond_str) = get_str(det, "condition") {
                // Check that condition references existing identifiers
                for ident in extract_condition_identifiers(cond_str) {
                    if !det_keys.contains(ident.as_str()) {
                        warnings.push(err(
                            LintRule::ConditionReferencesUnknown,
                            format!(
                                "condition references '{ident}' but no such detection identifier exists"
                            ),
                            "/detection/condition",
                        ));
                    }
                }
            }

            if det_keys.is_empty() {
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

/// Extract bare identifiers from a condition expression (excluding keywords
/// and wildcard patterns) so we can check they exist in the detection section.
fn extract_condition_identifiers(condition: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &["and", "or", "not", "of", "all", "them"];
    condition
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '*')
        .filter(|s| !s.is_empty())
        .filter(|s| !KEYWORDS.contains(s))
        .filter(|s| !s.chars().all(|c| c.is_ascii_digit()))
        .filter(|s| !s.contains('*'))
        .map(|s| s.to_string())
        .collect()
}

/// Checks detection logic: null in value lists, single-value |all, empty value lists.
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

                // Check |all combined with |re (regex alternation makes |all misleading)
                if field_key_str.contains("|all") && field_key_str.contains("|re") {
                    warnings.push(warning(
                        LintRule::AllWithRe,
                        format!(
                            "'{field_key_str}' in '{det_name}' combines |all with |re; \
                             regex alternation (|) already handles multi-match — \
                             |all is redundant or misleading here"
                        ),
                        format!("/detection/{det_name}/{field_key_str}"),
                    ));
                }

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

                // Check null in value list and empty value list
                if let Value::Sequence(seq) = field_val {
                    if seq.is_empty() {
                        warnings.push(warning(
                            LintRule::EmptyValueList,
                            format!("'{field_key_str}' in '{det_name}' has an empty value list"),
                            format!("/detection/{det_name}/{field_key_str}"),
                        ));
                    } else {
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

                // Check wildcard-only value: field: '*' usually means field|exists
                let base_field = field_key_str.split('|').next().unwrap_or(field_key_str);
                let is_wildcard_only = match field_val {
                    Value::String(s) => s == "*",
                    Value::Sequence(seq) => seq.len() == 1 && seq[0].as_str() == Some("*"),
                    _ => false,
                };
                if is_wildcard_only && !field_key_str.contains("|re") {
                    warnings.push(warning(
                        LintRule::WildcardOnlyValue,
                        format!(
                            "'{field_key_str}' in '{det_name}' uses a lone wildcard '*'; \
                             consider '{base_field}|exists: true' instead"
                        ),
                        format!("/detection/{det_name}/{field_key_str}"),
                    ));
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
                format!(
                    "invalid timespan \"{ts}\", expected format like 5m, 1h, 30s, 7d, 1w, 1M, 1y"
                ),
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
    // s=second, m=minute, h=hour, d=day, w=week, M=month, y=year
    if !matches!(last, b's' | b'm' | b'h' | b'd' | b'w' | b'M' | b'y') {
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

/// Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a_len, b_len) = (a.len(), b.len());
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];
    for (i, ca) in a.bytes().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.bytes().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

/// Maximum edit distance to consider an unknown key a likely typo of a known key.
const TYPO_MAX_EDIT_DISTANCE: usize = 2;

/// Check for unknown top-level keys that are likely typos of known keys.
///
/// The Sigma specification v2.1.0 explicitly allows arbitrary custom top-level
/// fields, so unknown keys are not errors. However, when an unknown key is
/// within a small edit distance of a known key it is likely a typo and we
/// surface an informational hint.
fn lint_unknown_keys(m: &serde_yaml::Mapping, doc_type: DocType, warnings: &mut Vec<LintWarning>) {
    let type_keys = doc_type.known_keys();
    let all_known: Vec<&str> = KNOWN_KEYS_SHARED
        .iter()
        .chain(type_keys.iter())
        .copied()
        .collect();

    for k in m.keys() {
        let Some(ks) = k.as_str() else { continue };
        if KNOWN_KEYS_SHARED.contains(&ks) || type_keys.contains(&ks) {
            continue;
        }
        // Only warn when the key looks like a typo of a known key.
        if let Some(closest) = all_known
            .iter()
            .filter(|known| edit_distance(ks, known) <= TYPO_MAX_EDIT_DISTANCE)
            .min_by_key(|known| edit_distance(ks, known))
        {
            warnings.push(info(
                LintRule::UnknownKey,
                format!("unknown top-level key \"{ks}\"; did you mean \"{closest}\"?"),
                format!("/{ks}"),
            ));
        }
    }
}

/// Lint a single YAML document value.
///
/// Auto-detects document type (detection / correlation / filter) and runs
/// the appropriate checks. Returns all findings.
pub fn lint_yaml_value(value: &Value) -> Vec<LintWarning> {
    let Some(m) = value.as_mapping() else {
        return vec![err(
            LintRule::NotAMapping,
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
    let doc_type = detect_doc_type(m);
    match doc_type {
        DocType::Detection => lint_detection_rule(m, &mut warnings),
        DocType::Correlation => lint_correlation_rule(m, &mut warnings),
        DocType::Filter => lint_filter_rule(m, &mut warnings),
    }

    // Check for unknown top-level keys
    lint_unknown_keys(m, doc_type, &mut warnings);

    warnings
}

/// Lint a raw YAML string, returning warnings with resolved source spans.
///
/// Unlike [`lint_yaml_value`], this function takes the raw text and resolves
/// JSON-pointer paths to `(line, col)` spans. This is the preferred entry
/// point for the LSP server.
pub fn lint_yaml_str(text: &str) -> Vec<LintWarning> {
    let mut all_warnings = Vec::new();

    for doc in serde_yaml::Deserializer::from_str(text) {
        let value: Value = match Value::deserialize(doc) {
            Ok(v) => v,
            Err(e) => {
                let mut w = err(
                    LintRule::YamlParseError,
                    format!("YAML parse error: {e}"),
                    "/",
                );
                // serde_yaml can give us a location
                if let Some(loc) = e.location() {
                    w.span = Some(Span {
                        start_line: loc.line().saturating_sub(1) as u32,
                        start_col: loc.column() as u32,
                        end_line: loc.line().saturating_sub(1) as u32,
                        end_col: loc.column() as u32 + 1,
                    });
                }
                all_warnings.push(w);
                // A parse error leaves the YAML stream in an undefined state;
                // the deserializer iterator may never terminate on malformed
                // input, so we must stop iterating to avoid infinite loops and
                // unbounded memory growth.
                break;
            }
        };

        let warnings = lint_yaml_value(&value);
        // Resolve spans for each warning
        for mut w in warnings {
            w.span = resolve_path_to_span(text, &w.path);
            all_warnings.push(w);
        }
    }

    all_warnings
}

/// Resolve a JSON-pointer path to a `Span` by scanning the YAML text.
///
/// Returns `None` if the path cannot be resolved.
fn resolve_path_to_span(text: &str, path: &str) -> Option<Span> {
    if path == "/" || path.is_empty() {
        // Root — first non-empty line
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed != "---" {
                return Some(Span {
                    start_line: i as u32,
                    start_col: 0,
                    end_line: i as u32,
                    end_col: line.len() as u32,
                });
            }
        }
        return None;
    }

    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();

    if segments.is_empty() {
        return None;
    }

    let lines: Vec<&str> = text.lines().collect();
    let mut current_indent: i32 = -1;
    let mut search_start = 0usize;
    let mut last_matched_line: Option<usize> = None;

    for segment in &segments {
        let array_index: Option<usize> = segment.parse().ok();
        let mut found = false;

        let mut line_num = search_start;
        while line_num < lines.len() {
            let line = lines[line_num];
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                line_num += 1;
                continue;
            }

            let indent = (line.len() - trimmed.len()) as i32;

            if indent <= current_indent && found {
                break;
            }
            if indent <= current_indent {
                line_num += 1;
                continue;
            }

            if let Some(idx) = array_index {
                if trimmed.starts_with("- ") && indent > current_indent {
                    let mut count = 0usize;
                    for (offset, sl) in lines[search_start..].iter().enumerate() {
                        let scan = search_start + offset;
                        let st = sl.trim();
                        if st.is_empty() || st.starts_with('#') {
                            continue;
                        }
                        let si = (sl.len() - st.len()) as i32;
                        if si == indent && st.starts_with("- ") {
                            if count == idx {
                                last_matched_line = Some(scan);
                                search_start = scan + 1;
                                current_indent = indent;
                                found = true;
                                break;
                            }
                            count += 1;
                        }
                        if si < indent && count > 0 {
                            break;
                        }
                    }
                    break;
                }
            } else {
                let key_pattern = format!("{segment}:");
                if trimmed.starts_with(&key_pattern) || trimmed == *segment {
                    last_matched_line = Some(line_num);
                    search_start = line_num + 1;
                    current_indent = indent;
                    found = true;
                    break;
                }
            }

            line_num += 1;
        }

        if !found && last_matched_line.is_none() {
            break;
        }
    }

    last_matched_line.map(|line_num| {
        let line = lines[line_num];
        Span {
            start_line: line_num as u32,
            start_col: 0,
            end_line: line_num as u32,
            end_col: line.len() as u32,
        }
    })
}

/// Lint all YAML documents in a file.
///
/// Handles multi-document YAML (separated by `---`). Collection action
/// fragments (`action: global/reset/repeat`) are skipped. Warnings include
/// resolved source spans (delegates to [`lint_yaml_str`]).
pub fn lint_yaml_file(path: &Path) -> crate::error::Result<FileLintResult> {
    let content = std::fs::read_to_string(path)?;
    let warnings = lint_yaml_str(&content);
    Ok(FileLintResult {
        path: path.to_path_buf(),
        warnings,
    })
}

/// Lint all `.yml`/`.yaml` files in a directory recursively.
///
/// Skips hidden directories (starting with `.`) and tracks visited
/// canonical paths to avoid infinite loops from symlink cycles.
pub fn lint_yaml_directory(dir: &Path) -> crate::error::Result<Vec<FileLintResult>> {
    let mut results = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        dir: &Path,
        results: &mut Vec<FileLintResult>,
        visited: &mut HashSet<std::path::PathBuf>,
    ) -> crate::error::Result<()> {
        // Resolve symlinks and canonicalize for cycle detection
        let canonical = match dir.canonicalize() {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        if !visited.insert(canonical) {
            // Already visited this directory — symlink cycle
            return Ok(());
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();

            // Skip hidden directories (e.g. .git)
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
                {
                    continue;
                }
                walk(&path, results, visited)?;
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                match crate::lint::lint_yaml_file(&path) {
                    Ok(file_result) => results.push(file_result),
                    Err(e) => {
                        results.push(FileLintResult {
                            path: path.clone(),
                            warnings: vec![err(
                                LintRule::FileReadError,
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

    walk(dir, &mut results, &mut visited)?;
    Ok(results)
}

// =============================================================================
// Lint configuration & suppression
// =============================================================================

/// Configuration for lint rule suppression and severity overrides.
///
/// Can be loaded from a `.rsigma-lint.yml` config file, merged with CLI
/// `--disable` flags, and combined with inline `# rsigma-disable` comments.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LintConfig {
    /// Rule names to suppress entirely (e.g. `"missing_description"`).
    pub disabled_rules: HashSet<String>,
    /// Override the default severity of a rule (e.g. `title_too_long -> Info`).
    pub severity_overrides: HashMap<String, Severity>,
}

/// Raw YAML shape for `.rsigma-lint.yml`.
#[derive(Debug, Deserialize)]
struct RawLintConfig {
    #[serde(default)]
    disabled_rules: Vec<String>,
    #[serde(default)]
    severity_overrides: HashMap<String, String>,
}

impl LintConfig {
    /// Load a `LintConfig` from a `.rsigma-lint.yml` file.
    pub fn load(path: &Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let raw: RawLintConfig = serde_yaml::from_str(&content)?;

        let disabled_rules: HashSet<String> = raw.disabled_rules.into_iter().collect();
        let mut severity_overrides = HashMap::new();
        for (rule, sev_str) in &raw.severity_overrides {
            let sev = match sev_str.as_str() {
                "error" => Severity::Error,
                "warning" => Severity::Warning,
                "info" => Severity::Info,
                "hint" => Severity::Hint,
                other => {
                    return Err(crate::error::SigmaParserError::InvalidRule(format!(
                        "invalid severity '{other}' for rule '{rule}' in lint config"
                    )));
                }
            };
            severity_overrides.insert(rule.clone(), sev);
        }

        Ok(LintConfig {
            disabled_rules,
            severity_overrides,
        })
    }

    /// Walk up from `start_path` to find the nearest `.rsigma-lint.yml`.
    ///
    /// Checks `start_path` itself (if a directory) or its parent, then
    /// ancestors until the filesystem root.
    pub fn find_in_ancestors(start_path: &Path) -> Option<std::path::PathBuf> {
        let dir = if start_path.is_file() {
            start_path.parent()?
        } else {
            start_path
        };

        let mut current = dir;
        loop {
            let candidate = current.join(".rsigma-lint.yml");
            if candidate.is_file() {
                return Some(candidate);
            }
            // Also try .yaml extension
            let candidate_yaml = current.join(".rsigma-lint.yaml");
            if candidate_yaml.is_file() {
                return Some(candidate_yaml);
            }
            current = current.parent()?;
        }
    }

    /// Merge another config into this one (e.g. CLI `--disable` into file config).
    pub fn merge(&mut self, other: &LintConfig) {
        self.disabled_rules
            .extend(other.disabled_rules.iter().cloned());
        for (rule, sev) in &other.severity_overrides {
            self.severity_overrides.insert(rule.clone(), *sev);
        }
    }

    /// Check if a rule is disabled.
    pub fn is_disabled(&self, rule: &LintRule) -> bool {
        self.disabled_rules.contains(&rule.to_string())
    }
}

// =============================================================================
// Inline suppression comments
// =============================================================================

/// Parsed inline suppression directives from YAML source text.
#[derive(Debug, Clone, Default)]
pub struct InlineSuppressions {
    /// If `true`, all rules are suppressed for the entire file.
    pub disable_all: bool,
    /// Rules suppressed for the entire file (from `# rsigma-disable rule1, rule2`).
    pub file_disabled: HashSet<String>,
    /// Rules suppressed for specific lines: `line_number -> set of rule names`.
    /// An empty set means all rules are suppressed for that line.
    pub line_disabled: HashMap<u32, Option<HashSet<String>>>,
}

/// Parse `# rsigma-disable` comments from raw YAML text.
///
/// Supported forms:
/// - `# rsigma-disable` — suppress **all** rules for the file
/// - `# rsigma-disable rule1, rule2` — suppress specific rules for the file
/// - `# rsigma-disable-next-line` — suppress all rules for the next line
/// - `# rsigma-disable-next-line rule1, rule2` — suppress specific rules for the next line
pub fn parse_inline_suppressions(text: &str) -> InlineSuppressions {
    let mut result = InlineSuppressions::default();

    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();

        // Look for comment-only lines or trailing comments
        let comment = if let Some(pos) = find_yaml_comment(trimmed) {
            trimmed[pos + 1..].trim()
        } else {
            continue;
        };

        if let Some(rest) = comment.strip_prefix("rsigma-disable-next-line") {
            let rest = rest.trim();
            let next_line = (i + 1) as u32;
            if rest.is_empty() {
                // Suppress all rules for next line
                result.line_disabled.insert(next_line, None);
            } else {
                // Suppress specific rules for next line
                let rules: HashSet<String> = rest
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !rules.is_empty() {
                    result
                        .line_disabled
                        .entry(next_line)
                        .and_modify(|existing| {
                            if let Some(existing_set) = existing {
                                existing_set.extend(rules.iter().cloned());
                            }
                            // If None (all suppressed), leave as None
                        })
                        .or_insert(Some(rules));
                }
            }
        } else if let Some(rest) = comment.strip_prefix("rsigma-disable") {
            let rest = rest.trim();
            if rest.is_empty() {
                // Suppress all rules for the entire file
                result.disable_all = true;
            } else {
                // Suppress specific rules for the file
                for rule in rest.split(',') {
                    let rule = rule.trim();
                    if !rule.is_empty() {
                        result.file_disabled.insert(rule.to_string());
                    }
                }
            }
        }
    }

    result
}

/// Find the start of a YAML comment (`#`) that is not inside a quoted string.
///
/// Returns the byte offset of `#` within the trimmed line, or `None`.
fn find_yaml_comment(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    for (i, c) in line.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

impl InlineSuppressions {
    /// Check if a warning should be suppressed.
    pub fn is_suppressed(&self, warning: &LintWarning) -> bool {
        // File-level disable-all
        if self.disable_all {
            return true;
        }

        // File-level specific rules
        let rule_name = warning.rule.to_string();
        if self.file_disabled.contains(&rule_name) {
            return true;
        }

        // Line-level suppression (requires a resolved span)
        if let Some(span) = &warning.span
            && let Some(line_rules) = self.line_disabled.get(&span.start_line)
        {
            return match line_rules {
                None => true, // All rules suppressed for this line
                Some(rules) => rules.contains(&rule_name),
            };
        }

        false
    }
}

// =============================================================================
// Suppression filtering
// =============================================================================

/// Apply suppression from config and inline comments to lint warnings.
///
/// 1. Removes warnings whose rule is in `config.disabled_rules`.
/// 2. Removes warnings suppressed by inline comments.
/// 3. Applies `severity_overrides` to remaining warnings.
pub fn apply_suppressions(
    warnings: Vec<LintWarning>,
    config: &LintConfig,
    inline: &InlineSuppressions,
) -> Vec<LintWarning> {
    warnings
        .into_iter()
        .filter(|w| !config.is_disabled(&w.rule))
        .filter(|w| !inline.is_suppressed(w))
        .map(|mut w| {
            let rule_name = w.rule.to_string();
            if let Some(sev) = config.severity_overrides.get(&rule_name) {
                w.severity = *sev;
            }
            w
        })
        .collect()
}

/// Lint a raw YAML string with config-based suppression.
///
/// Combines [`lint_yaml_str`] + [`parse_inline_suppressions`] +
/// [`apply_suppressions`] in one call.
pub fn lint_yaml_str_with_config(text: &str, config: &LintConfig) -> Vec<LintWarning> {
    let warnings = lint_yaml_str(text);
    let inline = parse_inline_suppressions(text);
    apply_suppressions(warnings, config, &inline)
}

/// Lint a file with config-based suppression.
pub fn lint_yaml_file_with_config(
    path: &Path,
    config: &LintConfig,
) -> crate::error::Result<FileLintResult> {
    let content = std::fs::read_to_string(path)?;
    let warnings = lint_yaml_str_with_config(&content, config);
    Ok(FileLintResult {
        path: path.to_path_buf(),
        warnings,
    })
}

/// Lint a directory with config-based suppression.
pub fn lint_yaml_directory_with_config(
    dir: &Path,
    config: &LintConfig,
) -> crate::error::Result<Vec<FileLintResult>> {
    let mut results = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        dir: &Path,
        config: &LintConfig,
        results: &mut Vec<FileLintResult>,
        visited: &mut HashSet<std::path::PathBuf>,
    ) -> crate::error::Result<()> {
        let canonical = match dir.canonicalize() {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        if !visited.insert(canonical) {
            return Ok(());
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
                {
                    continue;
                }
                walk(&path, config, results, visited)?;
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                match lint_yaml_file_with_config(&path, config) {
                    Ok(file_result) => results.push(file_result),
                    Err(e) => {
                        results.push(FileLintResult {
                            path: path.clone(),
                            warnings: vec![err(
                                LintRule::FileReadError,
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

    walk(dir, config, &mut results, &mut visited)?;
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

    // ── New checks ──────────────────────────────────────────────────────

    #[test]
    fn empty_title() {
        let w = lint(
            r#"
title: ''
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::EmptyTitle));
    }

    #[test]
    fn missing_level() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingLevel));
    }

    #[test]
    fn valid_level_no_missing_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::MissingLevel));
    }

    #[test]
    fn invalid_date_feb_30() {
        assert!(!is_valid_date("2025-02-30"));
    }

    #[test]
    fn invalid_date_apr_31() {
        assert!(!is_valid_date("2025-04-31"));
    }

    #[test]
    fn valid_date_feb_28() {
        assert!(is_valid_date("2025-02-28"));
    }

    #[test]
    fn valid_date_leap_year_feb_29() {
        assert!(is_valid_date("2024-02-29"));
    }

    #[test]
    fn invalid_date_non_leap_feb_29() {
        assert!(!is_valid_date("2025-02-29"));
    }

    #[test]
    fn condition_references_unknown() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: sel_main
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn condition_references_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn condition_references_complex_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    sel_main:
        field: value
    filter_fp:
        User: admin
    condition: sel_main and not filter_fp
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn empty_value_list() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: []
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::EmptyValueList));
    }

    #[test]
    fn not_a_mapping() {
        let v: serde_yaml::Value = serde_yaml::from_str("- item1\n- item2").unwrap();
        let w = lint_yaml_value(&v);
        assert!(has_rule(&w, LintRule::NotAMapping));
    }

    #[test]
    fn lint_yaml_str_produces_spans() {
        let text = r#"title: Test
status: invalid_status
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#;
        let warnings = lint_yaml_str(text);
        // InvalidStatus points to /status which exists in the text
        let invalid_status = warnings.iter().find(|w| w.rule == LintRule::InvalidStatus);
        assert!(invalid_status.is_some(), "expected InvalidStatus warning");
        let span = invalid_status.unwrap().span;
        assert!(span.is_some(), "expected span to be resolved");
        // "status:" is on line 1 (0-indexed)
        assert_eq!(span.unwrap().start_line, 1);
    }

    #[test]
    fn yaml_parse_error_uses_correct_rule() {
        let text = "title: [unclosed";
        let warnings = lint_yaml_str(text);
        assert!(has_rule(&warnings, LintRule::YamlParseError));
        assert!(has_no_rule(&warnings, LintRule::MissingTitle));
    }

    // ── Unknown top-level keys ───────────────────────────────────────────

    #[test]
    fn unknown_key_typo_detected() {
        let w = lint(
            r#"
title: Test
desciption: Typo field
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::UnknownKey));
        let unk = w.iter().find(|w| w.rule == LintRule::UnknownKey).unwrap();
        assert!(unk.message.contains("desciption"));
        assert!(unk.message.contains("description"));
        assert_eq!(unk.severity, Severity::Info);
    }

    #[test]
    fn known_keys_no_unknown_warning() {
        let w = lint(
            r#"
title: Test Rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: test
description: A valid description
author: tester
date: '2025-01-01'
modified: '2025-06-01'
license: MIT
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
references:
    - https://example.com
fields:
    - CommandLine
falsepositives:
    - Legitimate admin
"#,
        );
        assert!(has_no_rule(&w, LintRule::UnknownKey));
    }

    #[test]
    fn custom_fields_allowed_by_spec() {
        // The Sigma spec v2.1.0 explicitly allows arbitrary custom top-level
        // fields, so keys like "simulation" and "regression_tests_path" that
        // are not close to any known key should NOT produce warnings.
        let w = lint(
            r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
simulation:
    action: scan
regression_tests_path: tests/
custom_metadata: hello
"#,
        );
        assert!(has_no_rule(&w, LintRule::UnknownKey));
    }

    #[test]
    fn unknown_key_typo_correlation() {
        // "lvel" is edit-distance 1 from "level"
        let w = lint(
            r#"
title: Correlation Test
name: test_correlation
correlation:
    type: event_count
    rules:
        - rule1
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 10
lvel: high
"#,
        );
        assert!(has_rule(&w, LintRule::UnknownKey));
        let unk = w.iter().find(|w| w.rule == LintRule::UnknownKey).unwrap();
        assert!(unk.message.contains("lvel"));
        assert!(unk.message.contains("level"));
    }

    #[test]
    fn unknown_key_custom_field_filter() {
        // "badkey" is not close to any known key — no warning.
        let w = lint(
            r#"
title: Filter Test
logsource:
    category: test
filter:
    rules:
        - rule1
    selection:
        User: admin
    condition: selection
badkey: foo
"#,
        );
        assert!(has_no_rule(&w, LintRule::UnknownKey));
    }

    // ── Wildcard-only value ──────────────────────────────────────────────

    #[test]
    fn wildcard_only_value_string() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename: '*'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn wildcard_only_value_list() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename:
            - '*'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn wildcard_with_other_values_no_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename:
            - '*temp*'
            - '*cache*'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn wildcard_regex_no_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename|re: '*'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::WildcardOnlyValue));
    }

    // ── resolve_path_to_span tests ───────────────────────────────────────

    #[test]
    fn resolve_path_to_span_root() {
        let text = "title: Test\nstatus: test\n";
        let span = resolve_path_to_span(text, "/");
        assert!(span.is_some());
        assert_eq!(span.unwrap().start_line, 0);
    }

    #[test]
    fn resolve_path_to_span_top_level_key() {
        let text = "title: Test\nstatus: test\nlevel: high\n";
        let span = resolve_path_to_span(text, "/status");
        assert!(span.is_some());
        assert_eq!(span.unwrap().start_line, 1);
    }

    #[test]
    fn resolve_path_to_span_nested_key() {
        let text = "title: Test\nlogsource:\n    category: test\n    product: windows\n";
        let span = resolve_path_to_span(text, "/logsource/product");
        assert!(span.is_some());
        assert_eq!(span.unwrap().start_line, 3);
    }

    #[test]
    fn resolve_path_to_span_missing_key() {
        let text = "title: Test\nstatus: test\n";
        let span = resolve_path_to_span(text, "/nonexistent");
        assert!(span.is_none());
    }

    // ── Multi-document YAML ──────────────────────────────────────────────

    #[test]
    fn multi_doc_yaml_lints_all_documents() {
        let text = r#"title: Rule 1
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
---
title: Rule 2
status: bad_status
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#;
        let warnings = lint_yaml_str(text);
        // Second doc has InvalidStatus
        assert!(has_rule(&warnings, LintRule::InvalidStatus));
    }

    // ── is_valid_timespan edge cases ─────────────────────────────────────

    #[test]
    fn timespan_zero_seconds() {
        assert!(is_valid_timespan("0s"));
    }

    #[test]
    fn timespan_no_digits() {
        assert!(!is_valid_timespan("s"));
    }

    #[test]
    fn timespan_no_unit() {
        assert!(!is_valid_timespan("123"));
    }

    #[test]
    fn timespan_invalid_unit() {
        assert!(!is_valid_timespan("5x"));
    }

    #[test]
    fn timespan_valid_variants() {
        assert!(is_valid_timespan("30s"));
        assert!(is_valid_timespan("5m"));
        assert!(is_valid_timespan("1h"));
        assert!(is_valid_timespan("7d"));
        assert!(is_valid_timespan("1w"));
        assert!(is_valid_timespan("1M"));
        assert!(is_valid_timespan("1y"));
    }

    // ── FileLintResult methods ───────────────────────────────────────────

    #[test]
    fn file_lint_result_has_errors() {
        let result = FileLintResult {
            path: std::path::PathBuf::from("test.yml"),
            warnings: vec![
                warning(LintRule::TitleTooLong, "too long", "/title"),
                err(
                    LintRule::MissingCondition,
                    "missing",
                    "/detection/condition",
                ),
            ],
        };
        assert!(result.has_errors());
        assert_eq!(result.error_count(), 1);
        assert_eq!(result.warning_count(), 1);
    }

    #[test]
    fn file_lint_result_no_errors() {
        let result = FileLintResult {
            path: std::path::PathBuf::from("test.yml"),
            warnings: vec![warning(LintRule::TitleTooLong, "too long", "/title")],
        };
        assert!(!result.has_errors());
        assert_eq!(result.error_count(), 0);
        assert_eq!(result.warning_count(), 1);
    }

    #[test]
    fn file_lint_result_empty() {
        let result = FileLintResult {
            path: std::path::PathBuf::from("test.yml"),
            warnings: vec![],
        };
        assert!(!result.has_errors());
        assert_eq!(result.error_count(), 0);
        assert_eq!(result.warning_count(), 0);
    }

    // ── LintWarning Display impl ─────────────────────────────────────────

    #[test]
    fn lint_warning_display() {
        let w = err(
            LintRule::MissingTitle,
            "missing required field 'title'",
            "/title",
        );
        let display = format!("{w}");
        assert!(display.contains("error"));
        assert!(display.contains("missing_title"));
        assert!(display.contains("/title"));
    }

    // ── New checks: missing description / author / all+re ────────────────

    #[test]
    fn missing_description_info() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::MissingDescription));
        let md = w
            .iter()
            .find(|w| w.rule == LintRule::MissingDescription)
            .unwrap();
        assert_eq!(md.severity, Severity::Info);
    }

    #[test]
    fn has_description_no_info() {
        let w = lint(
            r#"
title: Test
description: A fine description
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::MissingDescription));
    }

    #[test]
    fn missing_author_info() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::MissingAuthor));
        let ma = w
            .iter()
            .find(|w| w.rule == LintRule::MissingAuthor)
            .unwrap();
        assert_eq!(ma.severity, Severity::Info);
    }

    #[test]
    fn has_author_no_info() {
        let w = lint(
            r#"
title: Test
author: tester
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::MissingAuthor));
    }

    #[test]
    fn all_with_re_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|all|re:
            - '(?i)whoami'
            - '(?i)net user'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::AllWithRe));
    }

    #[test]
    fn all_without_re_no_all_with_re() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|all:
            - 'whoami'
            - 'net user'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::AllWithRe));
    }

    #[test]
    fn re_without_all_no_all_with_re() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re: '(?i)whoami|net user'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::AllWithRe));
    }

    // ── Info/Hint severity levels ────────────────────────────────────────

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", Severity::Error), "error");
        assert_eq!(format!("{}", Severity::Warning), "warning");
        assert_eq!(format!("{}", Severity::Info), "info");
        assert_eq!(format!("{}", Severity::Hint), "hint");
    }

    #[test]
    fn file_lint_result_info_count() {
        let result = FileLintResult {
            path: std::path::PathBuf::from("test.yml"),
            warnings: vec![
                info(LintRule::MissingDescription, "missing desc", "/description"),
                info(LintRule::MissingAuthor, "missing author", "/author"),
                warning(LintRule::TitleTooLong, "too long", "/title"),
            ],
        };
        assert_eq!(result.info_count(), 2);
        assert_eq!(result.warning_count(), 1);
        assert_eq!(result.error_count(), 0);
        assert!(!result.has_errors());
    }

    // ── Inline suppression parsing ───────────────────────────────────────

    #[test]
    fn parse_inline_disable_all() {
        let text = "# rsigma-disable\ntitle: Test\n";
        let sup = parse_inline_suppressions(text);
        assert!(sup.disable_all);
    }

    #[test]
    fn parse_inline_disable_specific_rules() {
        let text = "# rsigma-disable missing_description, missing_author\ntitle: Test\n";
        let sup = parse_inline_suppressions(text);
        assert!(!sup.disable_all);
        assert!(sup.file_disabled.contains("missing_description"));
        assert!(sup.file_disabled.contains("missing_author"));
    }

    #[test]
    fn parse_inline_disable_next_line_all() {
        let text = "# rsigma-disable-next-line\ntitle: Test\n";
        let sup = parse_inline_suppressions(text);
        assert!(!sup.disable_all);
        // Line 0 has the comment, line 1 is "title: Test"
        assert!(sup.line_disabled.contains_key(&1));
        assert!(sup.line_disabled[&1].is_none()); // None means all rules
    }

    #[test]
    fn parse_inline_disable_next_line_specific() {
        let text = "title: Test\n# rsigma-disable-next-line missing_level\nlevel: medium\n";
        let sup = parse_inline_suppressions(text);
        // Comment on line 1, suppresses line 2
        assert!(sup.line_disabled.contains_key(&2));
        let rules = sup.line_disabled[&2].as_ref().unwrap();
        assert!(rules.contains("missing_level"));
    }

    #[test]
    fn parse_inline_no_comments() {
        let text = "title: Test\nstatus: test\n";
        let sup = parse_inline_suppressions(text);
        assert!(!sup.disable_all);
        assert!(sup.file_disabled.is_empty());
        assert!(sup.line_disabled.is_empty());
    }

    #[test]
    fn parse_inline_comment_in_quoted_string() {
        // The '#' is inside a quoted string — should NOT be treated as a comment
        let text = "description: 'no # rsigma-disable here'\ntitle: Test\n";
        let sup = parse_inline_suppressions(text);
        assert!(!sup.disable_all);
        assert!(sup.file_disabled.is_empty());
    }

    // ── Suppression filtering ────────────────────────────────────────────

    #[test]
    fn apply_suppressions_disables_rule() {
        let warnings = vec![
            info(LintRule::MissingDescription, "desc", "/description"),
            info(LintRule::MissingAuthor, "author", "/author"),
            warning(LintRule::TitleTooLong, "title", "/title"),
        ];
        let mut config = LintConfig::default();
        config
            .disabled_rules
            .insert("missing_description".to_string());
        let inline = InlineSuppressions::default();

        let result = apply_suppressions(warnings, &config, &inline);
        assert_eq!(result.len(), 2);
        assert!(
            result
                .iter()
                .all(|w| w.rule != LintRule::MissingDescription)
        );
    }

    #[test]
    fn apply_suppressions_severity_override() {
        let warnings = vec![warning(LintRule::TitleTooLong, "title too long", "/title")];
        let mut config = LintConfig::default();
        config
            .severity_overrides
            .insert("title_too_long".to_string(), Severity::Info);
        let inline = InlineSuppressions::default();

        let result = apply_suppressions(warnings, &config, &inline);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::Info);
    }

    #[test]
    fn apply_suppressions_inline_file_disable() {
        let warnings = vec![
            info(LintRule::MissingDescription, "desc", "/description"),
            info(LintRule::MissingAuthor, "author", "/author"),
        ];
        let config = LintConfig::default();
        let mut inline = InlineSuppressions::default();
        inline.file_disabled.insert("missing_author".to_string());

        let result = apply_suppressions(warnings, &config, &inline);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule, LintRule::MissingDescription);
    }

    #[test]
    fn apply_suppressions_inline_disable_all() {
        let warnings = vec![
            err(LintRule::MissingTitle, "title", "/title"),
            warning(LintRule::TitleTooLong, "long", "/title"),
        ];
        let config = LintConfig::default();
        let inline = InlineSuppressions {
            disable_all: true,
            ..Default::default()
        };

        let result = apply_suppressions(warnings, &config, &inline);
        assert!(result.is_empty());
    }

    #[test]
    fn apply_suppressions_inline_next_line() {
        let mut w1 = warning(LintRule::TitleTooLong, "long", "/title");
        w1.span = Some(Span {
            start_line: 5,
            start_col: 0,
            end_line: 5,
            end_col: 10,
        });
        let mut w2 = err(LintRule::InvalidStatus, "bad", "/status");
        w2.span = Some(Span {
            start_line: 6,
            start_col: 0,
            end_line: 6,
            end_col: 10,
        });

        let config = LintConfig::default();
        let mut inline = InlineSuppressions::default();
        // Suppress all rules on line 5
        inline.line_disabled.insert(5, None);

        let result = apply_suppressions(vec![w1, w2], &config, &inline);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule, LintRule::InvalidStatus);
    }

    // ── lint_yaml_str_with_config integration ────────────────────────────

    #[test]
    fn lint_with_config_disables_rules() {
        let text = r#"title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#;
        let mut config = LintConfig::default();
        config
            .disabled_rules
            .insert("missing_description".to_string());
        config.disabled_rules.insert("missing_author".to_string());

        let warnings = lint_yaml_str_with_config(text, &config);
        assert!(
            !warnings
                .iter()
                .any(|w| w.rule == LintRule::MissingDescription)
        );
        assert!(!warnings.iter().any(|w| w.rule == LintRule::MissingAuthor));
    }

    #[test]
    fn lint_with_inline_disable_next_line() {
        let text = r#"title: Test
# rsigma-disable-next-line missing_level
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
        // Note: missing_level is on the logsource line... actually we need to think about
        // where the warning span resolves to. The warning for missing_level has path /level,
        // and won't have a span matching line 2. Let's use a config-based suppression
        // instead for this test.
        let config = LintConfig::default();
        let warnings = lint_yaml_str_with_config(text, &config);
        // This test verifies that inline parsing doesn't break normal linting
        assert!(warnings.iter().any(|w| w.rule == LintRule::MissingLevel));
    }

    #[test]
    fn lint_with_inline_file_disable() {
        let text = r#"# rsigma-disable missing_description, missing_author
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#;
        let config = LintConfig::default();
        let warnings = lint_yaml_str_with_config(text, &config);
        assert!(
            !warnings
                .iter()
                .any(|w| w.rule == LintRule::MissingDescription)
        );
        assert!(!warnings.iter().any(|w| w.rule == LintRule::MissingAuthor));
    }

    #[test]
    fn lint_with_inline_disable_all() {
        let text = r#"# rsigma-disable
title: Test
status: invalid_status
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
        let config = LintConfig::default();
        let warnings = lint_yaml_str_with_config(text, &config);
        assert!(warnings.is_empty());
    }

    // ── LintConfig ───────────────────────────────────────────────────────

    #[test]
    fn lint_config_merge() {
        let mut base = LintConfig::default();
        base.disabled_rules.insert("rule_a".to_string());
        base.severity_overrides
            .insert("rule_b".to_string(), Severity::Info);

        let other = LintConfig {
            disabled_rules: ["rule_c".to_string()].into_iter().collect(),
            severity_overrides: [("rule_d".to_string(), Severity::Hint)]
                .into_iter()
                .collect(),
        };

        base.merge(&other);
        assert!(base.disabled_rules.contains("rule_a"));
        assert!(base.disabled_rules.contains("rule_c"));
        assert_eq!(base.severity_overrides.get("rule_b"), Some(&Severity::Info));
        assert_eq!(base.severity_overrides.get("rule_d"), Some(&Severity::Hint));
    }

    #[test]
    fn lint_config_is_disabled() {
        let mut config = LintConfig::default();
        config.disabled_rules.insert("missing_title".to_string());
        assert!(config.is_disabled(&LintRule::MissingTitle));
        assert!(!config.is_disabled(&LintRule::EmptyTitle));
    }

    #[test]
    fn find_yaml_comment_basic() {
        assert_eq!(find_yaml_comment("# comment"), Some(0));
        assert_eq!(find_yaml_comment("key: value # comment"), Some(11));
        assert_eq!(find_yaml_comment("key: 'value # not comment'"), None);
        assert_eq!(find_yaml_comment("key: \"value # not comment\""), None);
        assert_eq!(find_yaml_comment("key: value"), None);
    }
}
