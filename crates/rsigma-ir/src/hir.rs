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
use serde::{Deserialize, Serialize};
use serde_json::Value;

// =============================================================================
// IrRule
// =============================================================================

/// Top-level detection rule in the intermediate representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrPatternPart {
    Literal(String),
    /// `*` — matches any run of characters.
    WildcardMulti,
    /// `?` — matches any single character.
    WildcardSingle,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrMatcher {
    /// Structured string match (equality/substring/prefix/suffix) over a
    /// wildcard-aware, original-case [`IrPattern`].
    Str {
        op: IrStrOp,
        pattern: IrPattern,
        case_insensitive: bool,
    },
    /// Encoding-transformed string match (`base64`, `base64offset`, `wide`,
    /// `utf16`, `utf16be`, `windash`). `pattern` is the untransformed value;
    /// it has wildcards only when no base64 encoding applies. Eval replays
    /// `encodings` to build the concrete matcher; convert backends that cannot
    /// express the transform reject it.
    Encoded {
        encodings: Vec<IrEncoding>,
        op: IrStrOp,
        pattern: IrPattern,
        case_insensitive: bool,
    },
    /// Explicit regex (`|re`) with raw pattern and flags kept separate so eval
    /// compiles them and convert renders them (case-sensitive vs insensitive).
    ///
    /// `case_insensitive` is the `|i` flag (eval's regex case sensitivity).
    /// `cased` records the `|cased` modifier, which eval ignores for regex but
    /// some backends use to choose a case-sensitive regex operator.
    Regex {
        pattern: String,
        case_insensitive: bool,
        multiline: bool,
        dotall: bool,
        cased: bool,
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
    /// Field-to-field comparison. `op` is equality, or a substring,
    /// prefix, or suffix check against the referenced field's value
    /// (`fieldref` followed by `contains`, `startswith`, or `endswith`).
    FieldRef {
        field: String,
        op: IrStrOp,
        case_insensitive: bool,
    },
    Null,
    BoolEq(bool),
    /// `expand` value whose `%name%` placeholders no pipeline resolved; they
    /// are filled from the event field of the same name at match time and
    /// the result is compared with `op`.
    Expand {
        template: Vec<IrExpandPart>,
        op: IrStrOp,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrExpandPart {
    Literal(String),
    /// `%name%` placeholder.
    Placeholder(String),
}

/// Mirrors `rsigma_eval::matcher::TimePart`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IrNumber {
    Literal(NumericLiteral),
    DynamicSourceRef {
        source_id: String,
        extract: Option<IrExtractExpr>,
    },
}

/// A numeric literal that keeps integers exact.
///
/// A rule integer stays an `i64` so values above 2^53, which an `f64` cannot
/// represent, match, compare, and render exactly.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NumericLiteral {
    Integer(i64),
    Float(f64),
}

impl NumericLiteral {
    /// Parse decimal text, preferring an exact integer.
    pub fn parse(s: &str) -> Option<Self> {
        s.parse::<i64>()
            .map(Self::Integer)
            .ok()
            .or_else(|| s.parse::<f64>().ok().map(Self::Float))
    }

    /// The value as an `f64`, rounding integers above 2^53.
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Integer(n) => n as f64,
            Self::Float(f) => f,
        }
    }
}

/// Decimal text without a fractional part for whole numbers.
impl std::fmt::Display for NumericLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Integer(n) => write!(f, "{n}"),
            Self::Float(v)
                if v.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&v) =>
            {
                write!(f, "{}", v as i64)
            }
            Self::Float(v) => write!(f, "{v}"),
        }
    }
}

impl From<i64> for NumericLiteral {
    fn from(n: i64) -> Self {
        Self::Integer(n)
    }
}

impl From<f64> for NumericLiteral {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
///
/// Deserializing rejects a tree deeper than
/// [`MAX_CONDITION_TREE_DEPTH`](rsigma_parser::condition::MAX_CONDITION_TREE_DEPTH).
#[derive(Debug, Clone, PartialEq, Serialize)]
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

impl<'de> Deserialize<'de> for IrCondition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename = "IrCondition")]
        enum Repr {
            Detection(String),
            And(Vec<IrCondition>),
            Or(Vec<IrCondition>),
            Not(Box<IrCondition>),
            Selector {
                quantifier: Quantifier,
                pattern: SelectorPattern,
            },
        }

        thread_local! {
            static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        }
        let _guard = rsigma_parser::condition::TreeDepthGuard::enter(&DEPTH)?;
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Detection(name) => IrCondition::Detection(name),
            Repr::And(children) => IrCondition::And(children),
            Repr::Or(children) => IrCondition::Or(children),
            Repr::Not(inner) => IrCondition::Not(inner),
            Repr::Selector {
                quantifier,
                pattern,
            } => IrCondition::Selector {
                quantifier,
                pattern,
            },
        })
    }
}

// =============================================================================
// IrCorrelation
// =============================================================================

/// Correlation rule shape. Field set mirrors [`rsigma_parser::CorrelationRule`]
/// (no logsource on correlations).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrFilter {
    pub metadata: IrRuleMetadata,
    pub sigma_version: Option<u32>,
    pub rules: FilterRuleTarget,
    pub logsource: Option<LogSource>,
    pub detections: HashMap<String, IrDetection>,
    pub conditions: Vec<IrCondition>,
}

#[cfg(test)]
mod tests {
    use super::{IrCondition, NumericLiteral};
    use rsigma_parser::condition::MAX_CONDITION_TREE_DEPTH;

    fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap()
    }

    fn nested_not_json(depth: usize) -> String {
        format!(
            "{}{{\"Detection\":\"a\"}}{}",
            "{\"Not\":".repeat(depth - 1),
            "}".repeat(depth - 1)
        )
    }

    fn from_json_unbounded(json: &str) -> serde_json::Result<IrCondition> {
        let mut de = serde_json::Deserializer::from_str(json);
        de.disable_recursion_limit();
        serde::Deserialize::deserialize(&mut de)
    }

    /// CBOR for `{"Not": {"Not": ... {"Detection": "a"}}}`, written by hand so
    /// building the input does not recurse.
    fn nested_not_cbor(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 1..depth {
            bytes.extend_from_slice(&[0xa1, 0x63]);
            bytes.extend_from_slice(b"Not");
        }
        bytes.extend_from_slice(&[0xa1, 0x69]);
        bytes.extend_from_slice(b"Detection");
        bytes.extend_from_slice(&[0x61, b'a']);
        bytes
    }

    #[test]
    fn deep_condition_is_rejected_from_json() {
        on_small_stack(|| {
            for depth in [10_000, MAX_CONDITION_TREE_DEPTH + 1] {
                let err = from_json_unbounded(&nested_not_json(depth)).unwrap_err();
                assert!(err.to_string().contains("maximum depth"), "{err}");
            }
            assert!(from_json_unbounded(&nested_not_json(MAX_CONDITION_TREE_DEPTH)).is_ok());
        });
    }

    #[test]
    fn deep_condition_is_rejected_from_cbor() {
        on_small_stack(|| {
            let decode = |depth| {
                ciborium::de::from_reader_with_recursion_limit::<IrCondition, _>(
                    nested_not_cbor(depth).as_slice(),
                    usize::MAX,
                )
            };
            let err = decode(10_000).unwrap_err();
            assert!(err.to_string().contains("maximum depth"), "{err}");
            assert!(decode(MAX_CONDITION_TREE_DEPTH).is_ok());
        });
    }

    #[test]
    fn numeric_literal_keeps_integers_exact() {
        assert_eq!(
            NumericLiteral::parse("9007199254740993"),
            Some(NumericLiteral::Integer(9007199254740993))
        );
        assert_eq!(
            NumericLiteral::parse("1.5"),
            Some(NumericLiteral::Float(1.5))
        );
        assert_eq!(NumericLiteral::parse("x"), None);
        assert_eq!(
            NumericLiteral::Integer(9007199254740993).to_string(),
            "9007199254740993"
        );
        assert_eq!(NumericLiteral::Float(4688.0).to_string(), "4688");
        assert_eq!(NumericLiteral::Float(1.5).to_string(), "1.5");
    }
}
