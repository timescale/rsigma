//! Intermediate representation types for Sigma rules.
//!
//! The HIR captures the full semantic meaning of a Sigma rule after static
//! pipeline transforms. It is:
//!
//! - **modifier-resolved**: `FieldSpec + modifiers + SigmaValue` lowers into
//!   explicit [`IrMatcher`] variants.
//! - **Selector-resolved**: [`IrCondition`] has no `Selector` variant.
//! - **Array-scope complete**: [`IrDetection`] mirrors
//!   `CompiledDetection::{ArrayMatch, And, Conditional}`.
//! - **Serializable**: no compiled `Regex`, no `IpNet`.
//! - **Placeholder-aware** when lowering preserves `${source.*}` as
//!   [`IrValue::DynamicSourceRef`].
//! - **`RuleHeader`-projecting**: [`IrRuleMetadata`] is a superset; compile
//!   projects the subset used by `rsigma_eval::result::RuleHeader`.
//! - **Convert-friendly**: each [`IrDetectionItem`] may carry an optional
//!   [`SurfaceSpec`] that eval ignores but convert / reverse-convert uses.

use std::collections::HashMap;

use rsigma_parser::{
    ArrayQuantifier, CorrelationCondition, CorrelationType, FieldAlias, FilterRuleTarget, Level,
    LogSource, Related, Status, Timespan, WindowMode,
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
    /// Original surface for convert / reverse-convert. Eval ignores this.
    pub surface: Option<SurfaceSpec>,
}

/// Original field declaration before modifier resolution.
#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceSpec {
    pub field: Option<String>,
    pub modifiers: Vec<rsigma_parser::Modifier>,
    pub values: Vec<rsigma_parser::SigmaValue>,
}

// =============================================================================
// IrMatcher
// =============================================================================

/// Resolved match operation. Grow by appending variants and bumping the pack
/// IR schema major. No `Unknown` catch-all.
#[derive(Debug, Clone, PartialEq)]
pub enum IrMatcher {
    Exact {
        value: IrValue,
        case_insensitive: bool,
    },
    Contains {
        value: IrValue,
        case_insensitive: bool,
    },
    StartsWith {
        value: IrValue,
        case_insensitive: bool,
    },
    EndsWith {
        value: IrValue,
        case_insensitive: bool,
    },
    Regex {
        pattern: IrValue,
    },
    Cidr {
        network: IrValue,
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
// IrValue / IrNumber
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum IrValue {
    Literal(String),
    DynamicSourceRef {
        source_id: String,
        extract: Option<IrExtractExpr>,
    },
}

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
/// Parser `ConditionExpr::Selector` is collapsed at lower time.
#[derive(Debug, Clone, PartialEq)]
pub enum IrCondition {
    Detection(String),
    And(Vec<IrCondition>),
    Or(Vec<IrCondition>),
    Not(Box<IrCondition>),
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
