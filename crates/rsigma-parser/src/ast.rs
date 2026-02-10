//! AST types for all Sigma constructs: rules, detections, conditions,
//! correlations, and filters.
//!
//! Reference: Sigma specification V2.0.0 (2024-08-08)
//! Reference: pySigma types, conditions, correlations, rule modules

use std::collections::HashMap;
use std::fmt;

use serde::Serialize;

use crate::value::{SigmaValue, Timespan};

// =============================================================================
// Enumerations
// =============================================================================

/// Rule maturity status.
///
/// Reference: pySigma rule.py SigmaStatus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

impl Status {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "stable" => Some(Status::Stable),
            "test" => Some(Status::Test),
            "experimental" => Some(Status::Experimental),
            "deprecated" => Some(Status::Deprecated),
            "unsupported" => Some(Status::Unsupported),
            _ => None,
        }
    }
}

/// Severity level of a triggered rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "informational" => Some(Level::Informational),
            "low" => Some(Level::Low),
            "medium" => Some(Level::Medium),
            "high" => Some(Level::High),
            "critical" => Some(Level::Critical),
            _ => None,
        }
    }
}

/// Relationship type for the `related` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelationType {
    Derived,
    Obsolete,
    Merged,
    Renamed,
    Similar,
}

impl RelationType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "derived" => Some(RelationType::Derived),
            "obsolete" => Some(RelationType::Obsolete),
            "merged" => Some(RelationType::Merged),
            "renamed" => Some(RelationType::Renamed),
            "similar" => Some(RelationType::Similar),
            _ => None,
        }
    }
}

// =============================================================================
// Field Modifiers
// =============================================================================

/// All supported Sigma field modifiers.
///
/// Reference: pySigma modifiers.py modifier_mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Modifier {
    // String matching modifiers
    Contains,
    StartsWith,
    EndsWith,

    // Value linking
    All,

    // Encoding modifiers
    Base64,
    Base64Offset,
    Wide,
    WindAsh,

    // Pattern matching
    Re,
    Cidr,

    // Case sensitivity
    Cased,

    // Field existence
    Exists,

    // Placeholder expansion
    Expand,

    // Field reference
    FieldRef,

    // Numeric comparison
    Gt,
    Gte,
    Lt,
    Lte,

    // Regex flags
    #[serde(rename = "i")]
    IgnoreCase,
    #[serde(rename = "m")]
    Multiline,
    #[serde(rename = "s")]
    DotAll,

    // Timestamp parts
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl Modifier {
    /// Parse a modifier identifier string.
    ///
    /// Reference: pySigma modifiers.py modifier_mapping
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "contains" => Some(Modifier::Contains),
            "startswith" => Some(Modifier::StartsWith),
            "endswith" => Some(Modifier::EndsWith),
            "all" => Some(Modifier::All),
            "base64" => Some(Modifier::Base64),
            "base64offset" => Some(Modifier::Base64Offset),
            "wide" => Some(Modifier::Wide),
            "windash" => Some(Modifier::WindAsh),
            "re" => Some(Modifier::Re),
            "cidr" => Some(Modifier::Cidr),
            "cased" => Some(Modifier::Cased),
            "exists" => Some(Modifier::Exists),
            "expand" => Some(Modifier::Expand),
            "fieldref" => Some(Modifier::FieldRef),
            "gt" => Some(Modifier::Gt),
            "gte" => Some(Modifier::Gte),
            "lt" => Some(Modifier::Lt),
            "lte" => Some(Modifier::Lte),
            "i" | "ignorecase" => Some(Modifier::IgnoreCase),
            "m" | "multiline" => Some(Modifier::Multiline),
            "s" | "dotall" => Some(Modifier::DotAll),
            "minute" => Some(Modifier::Minute),
            "hour" => Some(Modifier::Hour),
            "day" => Some(Modifier::Day),
            "week" => Some(Modifier::Week),
            "month" => Some(Modifier::Month),
            "year" => Some(Modifier::Year),
            _ => None,
        }
    }
}

// =============================================================================
// Field Specification
// =============================================================================

/// A field name with optional modifiers, parsed from detection keys like
/// `TargetObject|endswith` or `Destination|contains|all`.
///
/// Reference: pySigma rule/detection.py SigmaDetectionItem.from_mapping
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldSpec {
    /// Field name (`None` for keyword detections without a field).
    pub name: Option<String>,
    /// Ordered list of modifiers applied to this field.
    pub modifiers: Vec<Modifier>,
}

impl FieldSpec {
    pub fn new(name: Option<String>, modifiers: Vec<Modifier>) -> Self {
        FieldSpec { name, modifiers }
    }

    pub fn has_modifier(&self, m: Modifier) -> bool {
        self.modifiers.contains(&m)
    }

    pub fn is_keyword(&self) -> bool {
        self.name.is_none()
    }
}

// =============================================================================
// Condition Expression AST
// =============================================================================

/// Parsed condition expression AST.
///
/// Produced by the PEG parser + Pratt parser from condition strings like
/// `selection and not filter` or `1 of selection_* and not 1 of filter_*`.
///
/// Reference: pySigma conditions.py ConditionItem hierarchy
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ConditionExpr {
    /// Logical AND of sub-expressions.
    And(Vec<ConditionExpr>),
    /// Logical OR of sub-expressions.
    Or(Vec<ConditionExpr>),
    /// Logical NOT of a sub-expression.
    Not(Box<ConditionExpr>),
    /// Reference to a named detection identifier.
    Identifier(String),
    /// Quantified selector: `1 of selection_*`, `all of them`, etc.
    Selector {
        quantifier: Quantifier,
        pattern: SelectorPattern,
    },
}

impl fmt::Display for ConditionExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConditionExpr::And(args) => {
                let parts: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                write!(f, "({})", parts.join(" and "))
            }
            ConditionExpr::Or(args) => {
                let parts: Vec<String> = args.iter().map(|a| format!("{a}")).collect();
                write!(f, "({})", parts.join(" or "))
            }
            ConditionExpr::Not(arg) => write!(f, "not {arg}"),
            ConditionExpr::Identifier(id) => write!(f, "{id}"),
            ConditionExpr::Selector {
                quantifier,
                pattern,
            } => write!(f, "{quantifier} of {pattern}"),
        }
    }
}

/// Quantifier in a selector expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Quantifier {
    /// Match any (at least one): `1 of ...` or `any of ...`
    Any,
    /// Match all: `all of ...`
    All,
    /// Match a specific count: `N of ...`
    Count(u64),
}

impl fmt::Display for Quantifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Quantifier::Any => write!(f, "1"),
            Quantifier::All => write!(f, "all"),
            Quantifier::Count(n) => write!(f, "{n}"),
        }
    }
}

/// Target pattern in a selector expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SelectorPattern {
    /// All detection identifiers: `... of them`
    Them,
    /// A wildcard pattern matching detection names: `... of selection_*`
    Pattern(String),
}

impl fmt::Display for SelectorPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectorPattern::Them => write!(f, "them"),
            SelectorPattern::Pattern(p) => write!(f, "{p}"),
        }
    }
}

// =============================================================================
// Detection Section
// =============================================================================

/// A single detection item: a field (with modifiers) mapped to one or more values.
///
/// Examples:
/// - `EventType: "user.mfa.factor.deactivate"` → field="EventType", values=["user.mfa..."]
/// - `Destination|contains|all: ['new-object', 'net.webclient']` → field="Destination",
///   modifiers=[Contains, All], values=[...]
///
/// Reference: pySigma rule/detection.py SigmaDetectionItem
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetectionItem {
    /// The field specification (name + modifiers).
    pub field: FieldSpec,
    /// One or more values to match against.
    pub values: Vec<SigmaValue>,
}

/// A detection definition: a group of detection items or nested detections.
///
/// When constructed from a YAML mapping, items are AND-linked.
/// When constructed from a YAML list of mappings, sub-detections are OR-linked.
///
/// Reference: pySigma rule/detection.py SigmaDetection
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Detection {
    /// AND-linked detection items (from a YAML mapping).
    AllOf(Vec<DetectionItem>),
    /// OR-linked sub-detections (from a YAML list of mappings).
    AnyOf(Vec<Detection>),
    /// Keyword detection: plain value(s) without a field.
    Keywords(Vec<SigmaValue>),
}

/// The complete detection section of a Sigma rule.
///
/// Contains named detection identifiers, condition expressions, and optional timeframe.
///
/// Reference: pySigma rule/detection.py SigmaDetections
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Detections {
    /// Named detections (e.g. `selection`, `filter_main`, etc.)
    pub named: HashMap<String, Detection>,
    /// One or more condition expressions (parsed from condition string or list).
    pub conditions: Vec<ConditionExpr>,
    /// Raw condition strings (before parsing).
    pub condition_strings: Vec<String>,
    /// Optional timeframe for aggregation rules (deprecated in favor of correlations).
    pub timeframe: Option<String>,
}

// =============================================================================
// Log Source
// =============================================================================

/// Log source specification.
///
/// Reference: Sigma schema `logsource` object
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    pub definition: Option<String>,
    /// Any additional custom logsource fields.
    #[serde(flatten)]
    pub custom: HashMap<String, String>,
}

// =============================================================================
// Related Rule Reference
// =============================================================================

/// A reference to a related Sigma rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Related {
    pub id: String,
    pub relation_type: RelationType,
}

// =============================================================================
// Sigma Detection Rule
// =============================================================================

/// A complete Sigma detection rule.
///
/// Reference: Sigma schema V2.0.0, pySigma rule.py SigmaRule
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SigmaRule {
    // Required fields
    pub title: String,
    pub logsource: LogSource,
    pub detection: Detections,

    // Optional metadata
    pub id: Option<String>,
    pub name: Option<String>,
    pub related: Vec<Related>,
    pub taxonomy: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub fields: Vec<String>,
    pub falsepositives: Vec<String>,
    pub level: Option<Level>,
    pub tags: Vec<String>,
    pub scope: Vec<String>,
}

// =============================================================================
// Correlation Rule
// =============================================================================

/// Correlation rule type.
///
/// Reference: pySigma correlations.py SigmaCorrelationType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
    ValueSum,
    ValueAvg,
    ValuePercentile,
    ValueMedian,
}

impl CorrelationType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "event_count" => Some(CorrelationType::EventCount),
            "value_count" => Some(CorrelationType::ValueCount),
            "temporal" => Some(CorrelationType::Temporal),
            "temporal_ordered" => Some(CorrelationType::TemporalOrdered),
            "value_sum" => Some(CorrelationType::ValueSum),
            "value_avg" => Some(CorrelationType::ValueAvg),
            "value_percentile" => Some(CorrelationType::ValuePercentile),
            "value_median" => Some(CorrelationType::ValueMedian),
            _ => None,
        }
    }
}

/// Comparison operator in a correlation condition.
///
/// Reference: pySigma correlations.py SigmaCorrelationConditionOperator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConditionOperator {
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
    Neq,
}

impl ConditionOperator {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "lt" => Some(ConditionOperator::Lt),
            "lte" => Some(ConditionOperator::Lte),
            "gt" => Some(ConditionOperator::Gt),
            "gte" => Some(ConditionOperator::Gte),
            "eq" => Some(ConditionOperator::Eq),
            "neq" => Some(ConditionOperator::Neq),
            _ => None,
        }
    }
}

/// Condition for a correlation rule.
///
/// Reference: pySigma correlations.py SigmaCorrelationCondition
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum CorrelationCondition {
    /// Simple threshold condition: `gte: 100`, `lt: 5`, etc.
    Threshold {
        op: ConditionOperator,
        count: u64,
        /// Optional field reference (required for `value_count` type).
        field: Option<String>,
    },
    /// Extended boolean condition for temporal types: `"rule_a and rule_b"`
    Extended(ConditionExpr),
}

/// Field alias mapping in a correlation rule.
///
/// Maps a canonical alias name to per-rule field name mappings.
///
/// Reference: pySigma correlations.py SigmaCorrelationFieldAlias
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldAlias {
    pub alias: String,
    /// Maps rule reference (ID or name) → field name in that rule's events.
    pub mapping: HashMap<String, String>,
}

/// A Sigma correlation rule.
///
/// Reference: pySigma correlations.py SigmaCorrelationRule
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CorrelationRule {
    // Metadata (shared with detection rules)
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub level: Option<Level>,

    // Correlation-specific fields
    pub correlation_type: CorrelationType,
    pub rules: Vec<String>,
    pub group_by: Vec<String>,
    pub timespan: Timespan,
    pub condition: CorrelationCondition,
    pub aliases: Vec<FieldAlias>,
    pub generate: bool,
}

// =============================================================================
// Filter Rule
// =============================================================================

/// A Sigma filter rule that modifies the detection logic of referenced rules.
///
/// Filters add additional conditions (typically exclusions) to existing rules
/// without modifying the original rule files.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FilterRule {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub logsource: Option<LogSource>,

    /// Rules this filter applies to (by ID or name).
    pub rules: Vec<String>,
    /// The filter detection section.
    pub detection: Detections,
}

// =============================================================================
// Collection / Document
// =============================================================================

/// A single parsed document from a Sigma YAML file.
///
/// A YAML file may contain multiple documents separated by `---`.
/// Each document is either a detection rule, correlation rule, filter, or action.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum SigmaDocument {
    Rule(SigmaRule),
    Correlation(CorrelationRule),
    Filter(FilterRule),
}

/// A collection of parsed Sigma documents from one or more YAML files.
#[derive(Debug, Clone, Serialize)]
pub struct SigmaCollection {
    pub rules: Vec<SigmaRule>,
    pub correlations: Vec<CorrelationRule>,
    pub filters: Vec<FilterRule>,
    /// Parsing errors that were collected (when `collect_errors` is true).
    #[serde(skip)]
    pub errors: Vec<String>,
}

impl SigmaCollection {
    pub fn new() -> Self {
        SigmaCollection {
            rules: Vec::new(),
            correlations: Vec::new(),
            filters: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Total number of parsed documents.
    pub fn len(&self) -> usize {
        self.rules.len() + self.correlations.len() + self.filters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SigmaCollection {
    fn default() -> Self {
        Self::new()
    }
}
