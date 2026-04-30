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

mod rules;

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
    DeprecatedAggregationSyntax,

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
    IncompatibleModifiers,
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
            LintRule::DeprecatedAggregationSyntax => "deprecated_aggregation_syntax",
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
            LintRule::IncompatibleModifiers => "incompatible_modifiers",
            LintRule::EmptyValueList => "empty_value_list",
            LintRule::WildcardOnlyValue => "wildcard_only_value",
            LintRule::UnknownKey => "unknown_key",
        };
        write!(f, "{s}")
    }
}

/// A source span (line/column, both 0-indexed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

// =============================================================================
// Auto-fix types
// =============================================================================

/// Whether a fix is safe to apply automatically or needs manual review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FixDisposition {
    Safe,
    Unsafe,
}

/// A single patch operation within a [`Fix`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FixPatch {
    ReplaceValue { path: String, new_value: String },
    ReplaceKey { path: String, new_key: String },
    Remove { path: String },
}

/// A suggested fix for a lint finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    pub title: String,
    pub disposition: FixDisposition,
    pub patches: Vec<FixPatch>,
}

/// A single lint finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LintWarning {
    pub rule: LintRule,
    pub severity: Severity,
    pub message: String,
    pub path: String,
    pub span: Option<Span>,
    pub fix: Option<Fix>,
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
// Helpers (shared with rule submodules)
// =============================================================================

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

pub(crate) fn key(s: &str) -> &'static Value {
    KEY_CACHE
        .get(s)
        .unwrap_or_else(|| panic!("lint key not pre-cached: \"{s}\" — add it to KEY_CACHE"))
}

pub(crate) fn get_str<'a>(m: &'a serde_yaml::Mapping, k: &str) -> Option<&'a str> {
    m.get(key(k)).and_then(|v| v.as_str())
}

pub(crate) fn get_mapping<'a>(
    m: &'a serde_yaml::Mapping,
    k: &str,
) -> Option<&'a serde_yaml::Mapping> {
    m.get(key(k)).and_then(|v| v.as_mapping())
}

pub(crate) fn get_seq<'a>(m: &'a serde_yaml::Mapping, k: &str) -> Option<&'a serde_yaml::Sequence> {
    m.get(key(k)).and_then(|v| v.as_sequence())
}

pub(crate) fn warn(
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
        fix: None,
    }
}

pub(crate) fn err(
    rule: LintRule,
    message: impl Into<String>,
    path: impl Into<String>,
) -> LintWarning {
    warn(rule, Severity::Error, message, path)
}

pub(crate) fn warning(
    rule: LintRule,
    message: impl Into<String>,
    path: impl Into<String>,
) -> LintWarning {
    warn(rule, Severity::Warning, message, path)
}

pub(crate) fn info(
    rule: LintRule,
    message: impl Into<String>,
    path: impl Into<String>,
) -> LintWarning {
    warn(rule, Severity::Info, message, path)
}

pub(crate) fn safe_fix(title: impl Into<String>, patches: Vec<FixPatch>) -> Option<Fix> {
    Some(Fix {
        title: title.into(),
        disposition: FixDisposition::Safe,
        patches,
    })
}

/// Find the closest match for `input` among `candidates` using edit distance.
pub(crate) fn closest_match<'a>(
    input: &str,
    candidates: &[&'a str],
    max_distance: usize,
) -> Option<&'a str> {
    candidates
        .iter()
        .filter(|c| edit_distance(input, c) <= max_distance)
        .min_by_key(|c| edit_distance(input, c))
        .copied()
}

/// Levenshtein edit distance between two strings.
pub(crate) fn edit_distance(a: &str, b: &str) -> usize {
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

pub(crate) const TYPO_MAX_EDIT_DISTANCE: usize = 2;

// =============================================================================
// Document type detection
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocType {
    Detection,
    Correlation,
    Filter,
}

impl DocType {
    pub(crate) fn known_keys(&self) -> &'static [&'static str] {
        match self {
            DocType::Detection => rules::shared::KNOWN_KEYS_DETECTION,
            DocType::Correlation => rules::shared::KNOWN_KEYS_CORRELATION,
            DocType::Filter => rules::shared::KNOWN_KEYS_FILTER,
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

fn is_action_fragment(m: &serde_yaml::Mapping) -> bool {
    matches!(get_str(m, "action"), Some("global" | "reset" | "repeat"))
}

// =============================================================================
// Public API
// =============================================================================

/// Lint a single YAML document value.
pub fn lint_yaml_value(value: &Value) -> Vec<LintWarning> {
    let Some(m) = value.as_mapping() else {
        return vec![err(
            LintRule::NotAMapping,
            "document is not a YAML mapping",
            "/",
        )];
    };

    if is_action_fragment(m) {
        return Vec::new();
    }

    let mut warnings = Vec::new();

    rules::metadata::lint_shared(m, &mut warnings);

    let doc_type = detect_doc_type(m);
    match doc_type {
        DocType::Detection => rules::detection::lint_detection_rule(m, &mut warnings),
        DocType::Correlation => rules::correlation::lint_correlation_rule(m, &mut warnings),
        DocType::Filter => rules::filter::lint_filter_rule(m, &mut warnings),
    }

    rules::shared::lint_unknown_keys(m, doc_type, &mut warnings);

    warnings
}

/// Lint a raw YAML string, returning warnings with resolved source spans.
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
                if let Some(loc) = e.location() {
                    w.span = Some(Span {
                        start_line: loc.line().saturating_sub(1) as u32,
                        start_col: loc.column() as u32,
                        end_line: loc.line().saturating_sub(1) as u32,
                        end_col: loc.column() as u32 + 1,
                    });
                }
                all_warnings.push(w);
                break;
            }
        };

        let warnings = lint_yaml_value(&value);
        for mut w in warnings {
            w.span = resolve_path_to_span(text, &w.path);
            all_warnings.push(w);
        }
    }

    all_warnings
}

fn resolve_path_to_span(text: &str, path: &str) -> Option<Span> {
    if path == "/" || path.is_empty() {
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
pub fn lint_yaml_file(path: &Path) -> crate::error::Result<FileLintResult> {
    let content = std::fs::read_to_string(path)?;
    let warnings = lint_yaml_str(&content);
    Ok(FileLintResult {
        path: path.to_path_buf(),
        warnings,
    })
}

/// Lint all `.yml`/`.yaml` files in a directory recursively.
pub fn lint_yaml_directory(dir: &Path) -> crate::error::Result<Vec<FileLintResult>> {
    let mut results = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        dir: &Path,
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
#[derive(Debug, Clone, Default, Serialize)]
pub struct LintConfig {
    pub disabled_rules: HashSet<String>,
    pub severity_overrides: HashMap<String, Severity>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawLintConfig {
    #[serde(default)]
    disabled_rules: Vec<String>,
    #[serde(default)]
    severity_overrides: HashMap<String, String>,
    #[serde(default)]
    exclude: Vec<String>,
}

impl LintConfig {
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
            exclude_patterns: raw.exclude,
        })
    }

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
            let candidate_yaml = current.join(".rsigma-lint.yaml");
            if candidate_yaml.is_file() {
                return Some(candidate_yaml);
            }
            current = current.parent()?;
        }
    }

    pub fn merge(&mut self, other: &LintConfig) {
        self.disabled_rules
            .extend(other.disabled_rules.iter().cloned());
        for (rule, sev) in &other.severity_overrides {
            self.severity_overrides.insert(rule.clone(), *sev);
        }
        self.exclude_patterns
            .extend(other.exclude_patterns.iter().cloned());
    }

    pub fn is_disabled(&self, rule: &LintRule) -> bool {
        self.disabled_rules.contains(&rule.to_string())
    }

    pub fn build_exclude_set(&self) -> Option<globset::GlobSet> {
        if self.exclude_patterns.is_empty() {
            return None;
        }
        let mut builder = globset::GlobSetBuilder::new();
        for pat in &self.exclude_patterns {
            if let Ok(glob) = globset::GlobBuilder::new(pat)
                .literal_separator(false)
                .build()
            {
                builder.add(glob);
            }
        }
        builder.build().ok()
    }
}

// =============================================================================
// Inline suppression comments
// =============================================================================

#[derive(Debug, Clone, Default)]
pub struct InlineSuppressions {
    pub disable_all: bool,
    pub file_disabled: HashSet<String>,
    pub line_disabled: HashMap<u32, Option<HashSet<String>>>,
}

pub fn parse_inline_suppressions(text: &str) -> InlineSuppressions {
    let mut result = InlineSuppressions::default();

    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();

        let comment = if let Some(pos) = find_yaml_comment(trimmed) {
            trimmed[pos + 1..].trim()
        } else {
            continue;
        };

        if let Some(rest) = comment.strip_prefix("rsigma-disable-next-line") {
            let rest = rest.trim();
            let next_line = (i + 1) as u32;
            if rest.is_empty() {
                result.line_disabled.insert(next_line, None);
            } else {
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
                        })
                        .or_insert(Some(rules));
                }
            }
        } else if let Some(rest) = comment.strip_prefix("rsigma-disable") {
            let rest = rest.trim();
            if rest.is_empty() {
                result.disable_all = true;
            } else {
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
    pub fn is_suppressed(&self, warning: &LintWarning) -> bool {
        if self.disable_all {
            return true;
        }

        let rule_name = warning.rule.to_string();
        if self.file_disabled.contains(&rule_name) {
            return true;
        }

        if let Some(span) = &warning.span
            && let Some(line_rules) = self.line_disabled.get(&span.start_line)
        {
            return match line_rules {
                None => true,
                Some(rules) => rules.contains(&rule_name),
            };
        }

        false
    }
}

// =============================================================================
// Suppression filtering
// =============================================================================

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

pub fn lint_yaml_str_with_config(text: &str, config: &LintConfig) -> Vec<LintWarning> {
    let warnings = lint_yaml_str(text);
    let inline = parse_inline_suppressions(text);
    apply_suppressions(warnings, config, &inline)
}

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

pub fn lint_yaml_directory_with_config(
    dir: &Path,
    config: &LintConfig,
) -> crate::error::Result<Vec<FileLintResult>> {
    let mut results = Vec::new();
    let mut visited = HashSet::new();
    let exclude_set = config.build_exclude_set();

    fn walk(
        dir: &Path,
        base: &Path,
        config: &LintConfig,
        exclude_set: &Option<globset::GlobSet>,
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

            if let Some(gs) = exclude_set
                && let Ok(rel) = path.strip_prefix(base)
                && gs.is_match(rel)
            {
                continue;
            }

            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
                {
                    continue;
                }
                walk(&path, base, config, exclude_set, results, visited)?;
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

    walk(dir, dir, config, &exclude_set, &mut results, &mut visited)?;
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
        let invalid_status = warnings.iter().find(|w| w.rule == LintRule::InvalidStatus);
        assert!(invalid_status.is_some(), "expected InvalidStatus warning");
        let span = invalid_status.unwrap().span;
        assert!(span.is_some(), "expected span to be resolved");
        assert_eq!(span.unwrap().start_line, 1);
    }

    #[test]
    fn yaml_parse_error_uses_correct_rule() {
        let text = "title: [unclosed";
        let warnings = lint_yaml_str(text);
        assert!(has_rule(&warnings, LintRule::YamlParseError));
        assert!(has_no_rule(&warnings, LintRule::MissingTitle));
    }

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
        assert!(has_rule(&warnings, LintRule::InvalidStatus));
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", Severity::Error), "error");
        assert_eq!(format!("{}", Severity::Warning), "warning");
        assert_eq!(format!("{}", Severity::Info), "info");
        assert_eq!(format!("{}", Severity::Hint), "hint");
    }

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
        assert!(sup.line_disabled.contains_key(&1));
        assert!(sup.line_disabled[&1].is_none());
    }

    #[test]
    fn parse_inline_disable_next_line_specific() {
        let text = "title: Test\n# rsigma-disable-next-line missing_level\nlevel: medium\n";
        let sup = parse_inline_suppressions(text);
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
        let text = "description: 'no # rsigma-disable here'\ntitle: Test\n";
        let sup = parse_inline_suppressions(text);
        assert!(!sup.disable_all);
        assert!(sup.file_disabled.is_empty());
    }

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
        inline.line_disabled.insert(5, None);

        let result = apply_suppressions(vec![w1, w2], &config, &inline);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule, LintRule::InvalidStatus);
    }

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
        let config = LintConfig::default();
        let warnings = lint_yaml_str_with_config(text, &config);
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
            exclude_patterns: vec!["test/**".to_string()],
        };

        base.merge(&other);
        assert!(base.disabled_rules.contains("rule_a"));
        assert!(base.disabled_rules.contains("rule_c"));
        assert_eq!(base.severity_overrides.get("rule_b"), Some(&Severity::Info));
        assert_eq!(base.severity_overrides.get("rule_d"), Some(&Severity::Hint));
        assert_eq!(base.exclude_patterns, vec!["test/**".to_string()]);
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

    #[test]
    fn no_fix_for_unfixable_rule() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
"#,
        );
        assert!(has_rule(&w, LintRule::MissingDetection));
        let fix = w
            .iter()
            .find(|w| w.rule == LintRule::MissingDetection)
            .and_then(|w| w.fix.as_ref());
        assert!(fix.is_none());
    }

    #[test]
    fn lint_config_exclude_from_yaml() {
        let yaml = r#"
disabled_rules:
  - missing_description
exclude:
  - "config/**"
  - "**/unsupported/**"
"#;
        let tmp = std::env::temp_dir().join("rsigma_test_exclude.yml");
        std::fs::write(&tmp, yaml).unwrap();
        let config = LintConfig::load(&tmp).unwrap();
        std::fs::remove_file(&tmp).ok();

        assert!(config.disabled_rules.contains("missing_description"));
        assert_eq!(config.exclude_patterns.len(), 2);
        assert_eq!(config.exclude_patterns[0], "config/**");
        assert_eq!(config.exclude_patterns[1], "**/unsupported/**");
    }

    #[test]
    fn lint_config_build_exclude_set_empty() {
        let config = LintConfig::default();
        assert!(config.build_exclude_set().is_none());
    }

    #[test]
    fn lint_config_build_exclude_set_matches() {
        let config = LintConfig {
            exclude_patterns: vec!["config/**".to_string()],
            ..Default::default()
        };
        let gs = config.build_exclude_set().expect("should build");
        assert!(gs.is_match("config/data_mapping/foo.yaml"));
        assert!(gs.is_match("config/nested/deep/bar.yml"));
        assert!(!gs.is_match("rules/windows/test.yml"));
    }

    #[test]
    fn lint_directory_with_excludes() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        let config_dir = tmp.path().join("config");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();

        std::fs::write(
            rules_dir.join("good.yml"),
            r#"
title: Good Rule
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
level: medium
"#,
        )
        .unwrap();

        std::fs::write(
            config_dir.join("mapping.yaml"),
            r#"
Title: Logon
Channel: Security
EventID: 4624
"#,
        )
        .unwrap();

        let no_exclude = LintConfig::default();
        let results = lint_yaml_directory_with_config(tmp.path(), &no_exclude).unwrap();
        let config_warnings: Vec<_> = results
            .iter()
            .filter(|r| r.path.to_string_lossy().contains("config"))
            .flat_map(|r| &r.warnings)
            .collect();
        assert!(
            !config_warnings.is_empty(),
            "config file should produce warnings without excludes"
        );

        let with_exclude = LintConfig {
            exclude_patterns: vec!["config/**".to_string()],
            ..Default::default()
        };
        let results = lint_yaml_directory_with_config(tmp.path(), &with_exclude).unwrap();
        let config_results: Vec<_> = results
            .iter()
            .filter(|r| r.path.to_string_lossy().contains("config"))
            .collect();
        assert!(config_results.is_empty(), "config file should be excluded");

        let rule_results: Vec<_> = results
            .iter()
            .filter(|r| r.path.to_string_lossy().contains("good.yml"))
            .collect();
        assert_eq!(rule_results.len(), 1);
    }
}
