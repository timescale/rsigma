//! AST types for all Sigma constructs: rules, detections, conditions,
//! correlations, and filters.
//!
//! Reference: Sigma specification V2.0.0 (2024-08-08)
//! Reference: pySigma types, conditions, correlations, rule modules

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::value::{SigmaValue, Timespan};

// =============================================================================
// Enumerations
// =============================================================================

/// Rule maturity status.
///
/// Reference: pySigma rule.py SigmaStatus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

impl FromStr for Status {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "stable" => Ok(Status::Stable),
            "test" => Ok(Status::Test),
            "experimental" => Ok(Status::Experimental),
            "deprecated" => Ok(Status::Deprecated),
            "unsupported" => Ok(Status::Unsupported),
            _ => Err(()),
        }
    }
}

/// Severity level of a triggered rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Informational => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }
}

impl FromStr for Level {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "informational" => Ok(Level::Informational),
            "low" => Ok(Level::Low),
            "medium" => Ok(Level::Medium),
            "high" => Ok(Level::High),
            "critical" => Ok(Level::Critical),
            _ => Err(()),
        }
    }
}

/// Relationship type for the `related` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelationType {
    Correlation,
    Derived,
    Obsolete,
    Merged,
    Renamed,
    Similar,
}

impl FromStr for RelationType {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "correlation" => Ok(RelationType::Correlation),
            "derived" => Ok(RelationType::Derived),
            "obsolete" => Ok(RelationType::Obsolete),
            "merged" => Ok(RelationType::Merged),
            "renamed" => Ok(RelationType::Renamed),
            "similar" => Ok(RelationType::Similar),
            _ => Err(()),
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
    Utf16be,
    Utf16,
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

    // Numeric/value comparison
    Gt,
    Gte,
    Lt,
    Lte,
    /// Not equal: field value must differ from the specified value.
    Neq,

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

/// Parse a modifier identifier string.
///
/// Reference: pySigma modifiers.py modifier_mapping
impl FromStr for Modifier {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "contains" => Ok(Modifier::Contains),
            "startswith" => Ok(Modifier::StartsWith),
            "endswith" => Ok(Modifier::EndsWith),
            "all" => Ok(Modifier::All),
            "base64" => Ok(Modifier::Base64),
            "base64offset" => Ok(Modifier::Base64Offset),
            "wide" | "utf16le" => Ok(Modifier::Wide),
            "utf16be" => Ok(Modifier::Utf16be),
            "utf16" => Ok(Modifier::Utf16),
            "windash" => Ok(Modifier::WindAsh),
            "re" => Ok(Modifier::Re),
            "cidr" => Ok(Modifier::Cidr),
            "cased" => Ok(Modifier::Cased),
            "exists" => Ok(Modifier::Exists),
            "expand" => Ok(Modifier::Expand),
            "fieldref" => Ok(Modifier::FieldRef),
            "gt" => Ok(Modifier::Gt),
            "gte" => Ok(Modifier::Gte),
            "lt" => Ok(Modifier::Lt),
            "lte" => Ok(Modifier::Lte),
            "neq" => Ok(Modifier::Neq),
            "i" | "ignorecase" => Ok(Modifier::IgnoreCase),
            "m" | "multiline" => Ok(Modifier::Multiline),
            "s" | "dotall" => Ok(Modifier::DotAll),
            "minute" => Ok(Modifier::Minute),
            "hour" => Ok(Modifier::Hour),
            "day" => Ok(Modifier::Day),
            "week" => Ok(Modifier::Week),
            "month" => Ok(Modifier::Month),
            "year" => Ok(Modifier::Year),
            _ => Err(()),
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Quantifier for matching the members of an array-valued field.
///
/// Used by array object-scope blocks (`field[any]:` / `field[all]:`). This is
/// deliberately distinct from the `all` value-list modifier ([`Modifier::All`]),
/// which links several *values* of one field with AND. An array quantifier
/// instead ranges over the *members* of an array-valued field.
///
/// Reference: proposed Sigma array-matching extension (sigma-specification
/// Discussion #106).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArrayQuantifier {
    /// At least one array member must satisfy the nested detection.
    Any,
    /// Every array member must satisfy the nested detection, and the array
    /// must be non-empty.
    All,
    /// Every array member must satisfy the nested detection, but an empty or
    /// missing array also matches (the vacuously-true reading of [`All`]).
    ///
    /// [`All`]: ArrayQuantifier::All
    AllOrEmpty,
    /// No array member satisfies the nested detection (the dual of [`Any`]).
    /// Matches an empty or missing array (vacuously, no member matches).
    ///
    /// [`Any`]: ArrayQuantifier::Any
    None,
}

impl fmt::Display for ArrayQuantifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArrayQuantifier::Any => write!(f, "any"),
            ArrayQuantifier::All => write!(f, "all"),
            ArrayQuantifier::AllOrEmpty => write!(f, "all_or_empty"),
            ArrayQuantifier::None => write!(f, "none"),
        }
    }
}

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
    /// Array object-scope quantifier block: `field[any]:` / `field[all]:`
    /// opening a nested detection that is evaluated against a single array
    /// member.
    ///
    /// - `field` is the dot-path to the array (quantifier markers stripped).
    /// - `quantifier` decides whether one (`any`) or every (`all`) member must
    ///   satisfy `body`.
    /// - `body` is the nested detection applied per member. A `body` item with
    ///   no field name (`FieldSpec::name == None`) matches the array member
    ///   value itself (the scalar-array case `field[all]: value`).
    ///
    /// This is the only construct that expresses same-member correlation across
    /// multiple predicates, and the only one that lowers cleanly to backend
    /// array primitives (Elasticsearch `nested`, KQL `mv-apply`, SQL
    /// `jsonb_array_elements`, Splunk `mvexpand`).
    ArrayMatch {
        /// Dot-path to the array field (quantifier markers stripped).
        field: String,
        /// Whether one or all members must satisfy `body`.
        quantifier: ArrayQuantifier,
        /// Nested detection evaluated against a single array member.
        body: Box<Detection>,
    },
    /// AND of heterogeneous sub-detections. Produced when a YAML mapping mixes
    /// plain detection items with one or more array object-scope blocks, which
    /// [`Detection::AllOf`] (a list of simple items) cannot represent.
    And(Vec<Detection>),
    /// Extended object-scope block body: named element-scoped sub-selections
    /// combined by a `condition` expression (the recursive "mini-event" form),
    /// enabling per-element `and`/`or`/`not`. Produced only as an
    /// [`ArrayMatch`](Detection::ArrayMatch) body when the block map carries a
    /// `condition:` key. The basic conjunction-map body is the degenerate case
    /// (an implicit AND of items); this is the explicit-condition form.
    Conditional {
        /// Element-scoped named sub-selections (each a nested detection).
        named: HashMap<String, Detection>,
        /// Boolean combination of the named sub-selections, evaluated per
        /// array member.
        condition: ConditionExpr,
    },
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// The Sigma specification MAJOR version this rule targets (the
    /// `sigma-version` attribute, e.g. `3`). `None` means absent, which resolves
    /// to the fixed floor [`crate::version::SPEC_VERSION_FLOOR`]. Only the major
    /// is stored, since breaking spec changes occur only at major bumps; it
    /// gates version-sensitive interpretation such as array-matching brackets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_version: Option<u32>,

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

    /// Custom attributes attached to the rule.
    ///
    /// Populated from (a) any top-level YAML key that is not part of the
    /// standard Sigma rule schema, (b) the entries of the dedicated top-level
    /// `custom_attributes:` mapping (explicit entries win over arbitrary keys
    /// of the same name), and (c) pipeline transformations such as
    /// `SetCustomAttribute`, which are applied last and override both.
    ///
    /// Mirrors pySigma's `SigmaRule.custom_attributes` dict. Engines and
    /// backends can read these to modify per-rule behavior.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: HashMap<String, yaml_serde::Value>,
}

// =============================================================================
// Correlation Rule
// =============================================================================

/// Correlation rule type.
///
/// Reference: pySigma correlations.py SigmaCorrelationType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn as_str(&self) -> &'static str {
        match self {
            CorrelationType::EventCount => "event_count",
            CorrelationType::ValueCount => "value_count",
            CorrelationType::Temporal => "temporal",
            CorrelationType::TemporalOrdered => "temporal_ordered",
            CorrelationType::ValueSum => "value_sum",
            CorrelationType::ValueAvg => "value_avg",
            CorrelationType::ValuePercentile => "value_percentile",
            CorrelationType::ValueMedian => "value_median",
        }
    }
}

impl FromStr for CorrelationType {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "event_count" => Ok(CorrelationType::EventCount),
            "value_count" => Ok(CorrelationType::ValueCount),
            "temporal" => Ok(CorrelationType::Temporal),
            "temporal_ordered" => Ok(CorrelationType::TemporalOrdered),
            "value_sum" => Ok(CorrelationType::ValueSum),
            "value_avg" => Ok(CorrelationType::ValueAvg),
            "value_percentile" => Ok(CorrelationType::ValuePercentile),
            "value_median" => Ok(CorrelationType::ValueMedian),
            _ => Err(()),
        }
    }
}

/// Window semantics for a correlation rule's `timespan`.
///
/// Controls how `timespan` is anchored to the event stream. `Sliding` is the
/// default and matches the behavior the Sigma correlation specification already
/// prefers (a trailing per-event window), so omitting `window` never changes the
/// meaning of an existing rule.
///
/// - `Sliding`: trailing window `(t - timespan, t]` evaluated per event.
/// - `Tumbling`: fixed, boundary-aligned, non-overlapping buckets of size
///   `timespan`.
/// - `Session`: dynamic window that extends while consecutive in-group events
///   stay within `gap`, capped by `timespan` as the maximum total span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowMode {
    #[default]
    Sliding,
    Tumbling,
    Session,
}

impl WindowMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            WindowMode::Sliding => "sliding",
            WindowMode::Tumbling => "tumbling",
            WindowMode::Session => "session",
        }
    }
}

impl FromStr for WindowMode {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "sliding" => Ok(WindowMode::Sliding),
            "tumbling" => Ok(WindowMode::Tumbling),
            "session" => Ok(WindowMode::Session),
            _ => Err(()),
        }
    }
}

/// Comparison operator in a correlation condition.
///
/// Reference: pySigma correlations.py SigmaCorrelationConditionOperator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionOperator {
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
    Neq,
}

impl FromStr for ConditionOperator {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "lt" => Ok(ConditionOperator::Lt),
            "lte" => Ok(ConditionOperator::Lte),
            "gt" => Ok(ConditionOperator::Gt),
            "gte" => Ok(ConditionOperator::Gte),
            "eq" => Ok(ConditionOperator::Eq),
            "neq" => Ok(ConditionOperator::Neq),
            _ => Err(()),
        }
    }
}

/// Condition for a correlation rule.
///
/// Reference: pySigma correlations.py SigmaCorrelationCondition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CorrelationCondition {
    /// Threshold condition with one or more predicates (supports ranges).
    ///
    /// Single: `gte: 100`
    /// Range: `gt: 100` + `lte: 200`
    Threshold {
        /// One or more (operator, value) predicates. All must be satisfied.
        predicates: Vec<(ConditionOperator, u64)>,
        /// Optional field reference(s) (required for `value_count` type).
        /// A single string is normalized to a one-element vec.
        field: Option<Vec<String>>,
        /// Percentile rank (0-100) for `value_percentile` type.
        /// Defaults to 50 if not specified.
        percentile: Option<u64>,
    },
    /// Extended boolean condition for temporal types: `"rule_a and rule_b"`
    Extended(ConditionExpr),
}

/// Field alias mapping in a correlation rule.
///
/// Maps a canonical alias name to per-rule field name mappings.
///
/// Reference: pySigma correlations.py SigmaCorrelationFieldAlias
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The Sigma specification MAJOR version this document targets (the
    /// `sigma-version` attribute). See [`SigmaRule::sigma_version`]. A
    /// correlation rule and the rules it aggregates should share a major.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_version: Option<u32>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub related: Vec<Related>,
    pub references: Vec<String>,
    pub taxonomy: Option<String>,
    pub license: Option<String>,
    pub tags: Vec<String>,
    pub fields: Vec<String>,
    pub falsepositives: Vec<String>,
    pub level: Option<Level>,
    pub scope: Vec<String>,

    // Correlation-specific fields
    pub correlation_type: CorrelationType,
    pub rules: Vec<String>,
    pub group_by: Vec<String>,
    pub timespan: Timespan,
    /// Window semantics for `timespan`: `sliding` (default), `tumbling`, or
    /// `session`. Absent in the source defaults to [`WindowMode::Sliding`].
    pub window: WindowMode,
    /// Maximum inactivity between consecutive in-group events for a `session`
    /// window. Required when `window` is `session`, and unset otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap: Option<Timespan>,
    pub condition: CorrelationCondition,
    pub aliases: Vec<FieldAlias>,
    pub generate: bool,

    /// Custom attributes attached to the correlation rule.
    ///
    /// Populated the same way as `SigmaRule.custom_attributes`: arbitrary
    /// top-level YAML keys, the dedicated `custom_attributes:` block, and
    /// pipeline `SetCustomAttribute` transformations (last-write-wins).
    /// Engine-level `rsigma.*` extensions (e.g. `rsigma.correlation_event_mode`,
    /// `rsigma.suppress`, `rsigma.action`) are read from here.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: HashMap<String, yaml_serde::Value>,
}

// =============================================================================
// Filter Rule
// =============================================================================

/// Which rules a filter applies to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FilterRuleTarget {
    /// The filter applies to every loaded rule.
    Any,
    /// The filter applies only to rules matching these IDs or titles.
    Specific(Vec<String>),
}

/// A Sigma filter rule that modifies the detection logic of referenced rules.
///
/// Filters add additional conditions (typically exclusions) to existing rules
/// without modifying the original rule files.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FilterRule {
    pub title: String,
    /// The Sigma specification MAJOR version this document targets (the
    /// `sigma-version` attribute). See [`SigmaRule::sigma_version`]. A filter and
    /// the rules it targets should share a major.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_version: Option<u32>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub taxonomy: Option<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub related: Vec<Related>,
    pub license: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub fields: Vec<String>,
    pub falsepositives: Vec<String>,
    pub level: Option<Level>,
    pub scope: Vec<String>,
    pub logsource: Option<LogSource>,

    /// Rules this filter applies to (by ID or name), or all rules.
    pub rules: FilterRuleTarget,
    /// The filter detection section.
    pub detection: Detections,

    /// Custom attributes attached to the filter rule.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: HashMap<String, yaml_serde::Value>,
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
    Rule(Box<SigmaRule>),
    Correlation(CorrelationRule),
    Filter(FilterRule),
}

/// A collection of parsed Sigma documents from one or more YAML files.
#[derive(Debug, Clone, Serialize)]
pub struct SigmaCollection {
    pub rules: Vec<SigmaRule>,
    pub correlations: Vec<CorrelationRule>,
    pub filters: Vec<FilterRule>,
    /// Per-document parse errors accumulated while building the
    /// collection. Populated by [`parse_sigma_yaml`](crate::parse_sigma_yaml)
    /// and friends; one entry per document the parser could not
    /// produce a [`SigmaRule`], [`CorrelationRule`], or [`FilterRule`]
    /// from. The collection is still returned on `Ok(_)` so callers
    /// can decide whether a partial parse is acceptable; the
    /// [`SigmaCollection::has_errors`] / [`SigmaCollection::error_count`]
    /// / [`SigmaCollection::into_result`] helpers cover the common
    /// "treat any error as a failure" path.
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

    /// True when the parser recorded one or more per-document parse
    /// errors while building this collection.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Number of per-document parse errors recorded while building
    /// this collection. Equivalent to `self.errors.len()`.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Promote the accumulated errors to a hard failure. Returns the
    /// collection when [`SigmaCollection::has_errors`] is false;
    /// otherwise returns the collection's [`errors`](Self::errors) so
    /// callers can format them. The original collection is consumed
    /// either way so the success path can move out of `self` without
    /// re-cloning the documents.
    pub fn into_result(self) -> Result<Self, Vec<String>> {
        if self.has_errors() {
            Err(self.errors)
        } else {
            Ok(self)
        }
    }
}

impl Default for SigmaCollection {
    fn default() -> Self {
        Self::new()
    }
}
