//! Intermediate representation types for Sigma rules.
//!
//! The HIR captures the full semantic meaning of a Sigma rule after static
//! pipeline transforms. It is:
//!
//! - **modifier-resolved**: `FieldSpec + modifiers + SigmaValue` lowers into
//!   explicit [`IrMatcher`] variants.
//! - **Selector-preserving**: [`IrCondition::Selector`] keeps the quantifier
//!   and name pattern so counting and reported matched-selections stay
//!   identical to native evaluation (no boolean expansion).
//! - **Array-scope complete**: [`IrDetection`] mirrors
//!   `CompiledDetection::{ArrayMatch, And, Conditional}`.
//! - **Faithful and lossless**: string matches keep a wildcard-aware,
//!   original-case [`IrPattern`]; encoding modifiers stay explicit as
//!   [`IrEncoding`]. Lowering never lowercases, compiles regexes, or expands
//!   encodings, so both eval (at compile time) and convert (at emit time)
//!   render it exactly.
//! - **`RuleHeader`-projecting**: [`IrRuleMetadata`] is a superset; compile
//!   projects the subset used by `rsigma_eval::result::RuleHeader`.

use std::collections::HashMap;

use rsigma_parser::{
    ArrayQuantifier, CorrelationCondition, CorrelationType, FieldAlias, FilterRuleTarget, Level,
    LogSource, Quantifier, Related, SelectorPattern, Status, Timespan, WindowMode,
};
use serde_json::Value;

// =============================================================================
// IrRule
// =============================================================================

/// Top-level detection rule in the intermediate representation.
#[derive(Debug, Clone, PartialEq)]
pub struct IrRule {
    pub metadata: IrRuleMetadata,
    pub logsource: LogSource,
    /// Sigma major from `sigma-version` (gates array-matching, etc.).
    pub sigma_version: Option<u32>,
    pub detections: HashMap<String, IrDetection>,
    pub conditions: Vec<IrCondition>,
}

// =============================================================================
// IrRuleMetadata
// =============================================================================

/// Metadata carried by an [`IrRule`] / [`IrCorrelation`] / [`IrFilter`].
///
/// Superset of `rsigma_eval::result::RuleHeader` plus the rest of the Sigma
/// rule metadata convert and offline tools need.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrRuleMetadata {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub level: Option<Level>,
    pub tags: Vec<String>,
    pub status: Option<Status>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub references: Vec<String>,
    pub falsepositives: Vec<String>,
    pub fields: Vec<String>,
    pub related: Vec<Related>,
    pub license: Option<String>,
    pub taxonomy: Option<String>,
    pub scope: Vec<String>,
    /// Arbitrary / `custom_attributes:` / pipeline-set keys. Behavior-driving
    /// `rsigma.*` keys must survive here.
    pub custom_attributes: HashMap<String, Value>,
    /// Optional affinity hint for pack consumers; schema routing stays outside IR.
    pub schema_affinity: Option<Vec<String>>,
}

// =============================================================================
// IrDetection
// =============================================================================

/// Detection definition — semantic shape, independent of compiled matchers.
#[derive(Debug, Clone, PartialEq)]
pub enum IrDetection {
    AllOf(Vec<IrDetectionItem>),
    AnyOf(Vec<IrDetection>),
    Keywords(IrMatcher),
    ArrayMatch {
        field: String,
        quantifier: ArrayQuantifier,
        body: Box<IrDetection>,
    },
    /// Heterogeneous AND of plain items and nested `ArrayMatch` blocks.
    And(Vec<IrDetection>),
    Conditional {
        named: HashMap<String, IrDetection>,
        condition: IrCondition,
    },
}

// =============================================================================
// IrDetectionItem
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct IrDetectionItem {
    pub field: Option<String>,
    pub matcher: IrMatcher,
    pub exists: Option<bool>,
}

// =============================================================================
// IrMatcher
// =============================================================================

/// String match operator.
///
/// The comparison is decided here rather than re-derived from modifiers by
/// each consumer. `Exact` is full-value equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrStrOp {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
}

/// A backend-neutral string pattern: decoded literal segments interleaved with
/// wildcards, **original case preserved**.
///
/// This is the lossless heart of the faithful HIR. Eval lowercases (for
/// case-insensitive matching) and compiles wildcards into a regex at compile
/// time; convert renders the wildcards into backend-native tokens. Neither
/// transform happens during lowering, so the pattern round-trips exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrPatternPart {
    Literal(String),
    /// `*` — matches any run of characters.
    WildcardMulti,
    /// `?` — matches any single character.
    WildcardSingle,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IrPattern {
    pub parts: Vec<IrPatternPart>,
}

impl IrPattern {
    /// A pattern with no wildcards.
    pub fn is_plain(&self) -> bool {
        self.parts
            .iter()
            .all(|p| matches!(p, IrPatternPart::Literal(_)))
    }

    /// Whether the pattern contains any wildcard.
    pub fn has_wildcards(&self) -> bool {
        !self.is_plain()
    }

    /// The concatenated literal text if the pattern is plain.
    pub fn as_plain(&self) -> Option<String> {
        if !self.is_plain() {
            return None;
        }
        let mut s = String::new();
        for p in &self.parts {
            if let IrPatternPart::Literal(t) = p {
                s.push_str(t);
            }
        }
        Some(s)
    }
}

/// A value transformation applied before matching (an encoding modifier).
///
/// Kept explicit rather than pre-expanded so consumers can either replay the
/// transform (eval) or reject it as inexpressible (convert backends).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrEncoding {
    Wide,
    Utf16,
    Utf16Be,
    Base64,
    Base64Offset,
    Windash,
}

/// Resolved match operation. Grow by appending variants and bumping the pack
/// IR schema major. No `Unknown` catch-all.
#[derive(Debug, Clone, PartialEq)]
pub enum IrMatcher {
    /// Structured string match (equality/substring/prefix/suffix) over a
    /// wildcard-aware, original-case [`IrPattern`].
    Str {
        op: IrStrOp,
        pattern: IrPattern,
        case_insensitive: bool,
    },
    /// Encoding-transformed string match (`base64`, `base64offset`, `wide`,
    /// `utf16`, `utf16be`, `windash`). `value` is the untransformed plain
    /// string. Eval replays `encodings` (in order) to build the concrete
    /// matcher; convert backends that cannot express the transform reject it.
    Encoded {
        encodings: Vec<IrEncoding>,
        op: IrStrOp,
        value: String,
        case_insensitive: bool,
    },
    /// Explicit regex (`|re`) with raw pattern and flags kept separate so eval
    /// compiles them and convert renders them (case-sensitive vs insensitive).
    Regex {
        pattern: String,
        case_insensitive: bool,
        multiline: bool,
        dotall: bool,
    },
    Cidr {
        network: String,
    },
    NumericEq(IrNumber),
    NumericGt(IrNumber),
    NumericGte(IrNumber),
    NumericLt(IrNumber),
    NumericLte(IrNumber),
    Exists(bool),
    FieldRef {
        field: String,
        case_insensitive: bool,
    },
    Null,
    BoolEq(bool),
    Expand {
        template: Vec<IrExpandPart>,
        case_insensitive: bool,
    },
    TimestampPart {
        part: IrTimePart,
        inner: Box<IrMatcher>,
    },
    Not(Box<IrMatcher>),
    AnyOf(Vec<IrMatcher>),
    AllOf(Vec<IrMatcher>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrExpandPart {
    Literal(String),
    /// Deferred `${source.*}` token awaiting specialization.
    Placeholder(String),
}

/// Mirrors `rsigma_eval::matcher::TimePart`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrTimePart {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

// =============================================================================
// IrNumber
// =============================================================================

/// Numeric literal or deferred source reference.
#[derive(Debug, Clone, PartialEq)]
pub enum IrNumber {
    Literal(f64),
    DynamicSourceRef {
        source_id: String,
        extract: Option<IrExtractExpr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrExtractExpr {
    Jq(String),
    JsonPath(String),
    Cel(String),
}

// =============================================================================
// IrCondition
// =============================================================================

/// Selector-free condition expression.
///
/// A quantified selector keeps its [`Quantifier`] and [`SelectorPattern`]
/// rather than being expanded into a boolean tree. This preserves eval's
/// count-based semantics (evaluate every matching detection, report all that
/// match) and avoids the combinatorial blow-up of expanding `N of` into an
/// `Or` of `And`s.
#[derive(Debug, Clone, PartialEq)]
pub enum IrCondition {
    Detection(String),
    And(Vec<IrCondition>),
    Or(Vec<IrCondition>),
    Not(Box<IrCondition>),
    Selector {
        quantifier: Quantifier,
        pattern: SelectorPattern,
    },
}

// =============================================================================
// IrCorrelation
// =============================================================================

/// Correlation rule shape. Field set mirrors [`rsigma_parser::CorrelationRule`]
/// (no logsource on correlations).
#[derive(Debug, Clone, PartialEq)]
pub struct IrCorrelation {
    pub metadata: IrRuleMetadata,
    pub sigma_version: Option<u32>,
    pub correlation_type: CorrelationType,
    pub rules: Vec<String>,
    pub group_by: Vec<String>,
    pub timespan: Timespan,
    pub window: WindowMode,
    pub gap: Option<Timespan>,
    pub condition: CorrelationCondition,
    pub aliases: Vec<FieldAlias>,
    pub generate: bool,
}

// =============================================================================
// IrFilter
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct IrFilter {
    pub metadata: IrRuleMetadata,
    pub sigma_version: Option<u32>,
    pub rules: FilterRuleTarget,
    pub logsource: Option<LogSource>,
    pub detections: HashMap<String, IrDetection>,
    pub conditions: Vec<IrCondition>,
}
