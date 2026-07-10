//! STIX pattern abstract syntax tree (STIX Specification §9).

use crate::core::{ScoKind, StixTimestamp};

/// SCO type at the root of an object path (built-in or custom per STIX §9.7).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PatternScoType {
    /// One of the 18 STIX 2.1 cyber-observable types.
    Known(ScoKind),
    /// Custom or vendor SCO type (STIX §9.8 allows arbitrary `type` values in observations).
    Custom(String),
}

impl PatternScoType {
    /// Parse a pattern object-type token.
    pub fn parse(type_name: &str) -> Self {
        ScoKind::from_type_str(type_name)
            .map(Self::Known)
            .unwrap_or_else(|| Self::Custom(type_name.to_owned()))
    }

    /// STIX `type` string for this path root.
    pub fn type_name(&self) -> &str {
        match self {
            Self::Known(kind) => kind.as_str(),
            Self::Custom(name) => name.as_str(),
        }
    }

    /// Built-in SCO kind when the type is one of the 18 predefined types.
    pub fn known(&self) -> Option<ScoKind> {
        match self {
            Self::Known(kind) => Some(*kind),
            Self::Custom(_) => None,
        }
    }
}

/// Source span (byte offsets into the original pattern string).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start byte index.
    pub start: usize,
    /// Exclusive end byte index.
    pub end: usize,
}

/// Top-level pattern AST node (Levels 1–3 grammar).
#[derive(Clone, Debug, PartialEq)]
pub enum PatternAst {
    /// Single observation expression `[ … ]`.
    Observation(ObservationExpr),
    /// Different-observation AND (Level 2).
    And {
        /// Left operand.
        left: Box<PatternAst>,
        /// Right operand.
        right: Box<PatternAst>,
        /// Source span of this node.
        span: Span,
    },
    /// Different-observation OR (Level 2).
    Or {
        /// Left operand.
        left: Box<PatternAst>,
        /// Right operand.
        right: Box<PatternAst>,
        /// Source span of this node.
        span: Span,
    },
    /// FOLLOWEDBY (Level 2).
    FollowedBy {
        /// Left operand (must match before the right).
        left: Box<PatternAst>,
        /// Right operand.
        right: Box<PatternAst>,
        /// Source span of this node.
        span: Span,
    },
    /// WITHIN qualifier (Level 3).
    Within {
        /// Inner pattern constrained by the duration.
        inner: Box<PatternAst>,
        /// Maximum elapsed time between qualifying observations.
        duration: Duration,
        /// Source span of this node.
        span: Span,
    },
    /// REPEATS qualifier (Level 3).
    Repeats {
        /// Inner pattern that must match repeatedly.
        inner: Box<PatternAst>,
        /// Required match count.
        count: u32,
        /// Source span of this node.
        span: Span,
    },
    /// START/STOP qualifier (Level 3).
    StartStop {
        /// Inner pattern constrained to the time window.
        inner: Box<PatternAst>,
        /// Inclusive window start (STIX timestamp literal).
        start: StixTimestamp,
        /// Inclusive window stop (STIX timestamp literal).
        stop: StixTimestamp,
        /// Source span of this node.
        span: Span,
    },
}

/// One bracketed observation expression.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservationExpr {
    /// Primary SCO type for path resolution (first `object-type` in comparisons).
    pub object_type: PatternScoType,
    /// Boolean combination of comparisons inside this observation.
    pub root: ComparisonTree,
    /// Source span of the full `[ … ]` expression.
    pub span: Span,
}

/// Boolean combination inside one observation (same SCO context).
#[derive(Clone, Debug, PartialEq)]
pub enum ComparisonTree {
    /// Leaf comparison against an object path.
    Cmp(Comparison),
    /// Conjunction of two subtrees.
    And {
        /// Left subtree.
        left: Box<ComparisonTree>,
        /// Right subtree.
        right: Box<ComparisonTree>,
        /// Source span of this node.
        span: Span,
    },
    /// Disjunction of two subtrees.
    Or {
        /// Left subtree.
        left: Box<ComparisonTree>,
        /// Right subtree.
        right: Box<ComparisonTree>,
        /// Source span of this node.
        span: Span,
    },
    /// Negated subtree.
    Not {
        /// Inner subtree.
        inner: Box<ComparisonTree>,
        /// Source span of this node.
        span: Span,
    },
}

/// One comparison against an object path.
#[derive(Clone, Debug, PartialEq)]
pub struct Comparison {
    /// Resolved object path for property lookup.
    pub path: ObjectPath,
    /// Comparison operator.
    pub op: ComparisonOp,
    /// `true` when `NOT` precedes the operator (`value NOT LIKE 'x'`).
    pub negated: bool,
    /// Right-hand constant; absent for unary `EXISTS`.
    pub value: Option<PatternConstant>,
    /// Source span of this comparison.
    pub span: Span,
}

/// Comparison operators (STIX Specification §9.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComparisonOp {
    /// `=`
    Eq,
    /// `!=`
    NotEq,
    /// `>`
    Gt,
    /// `<`
    Lt,
    /// `>=`
    Gte,
    /// `<=`
    Lte,
    /// `IN`
    In,
    /// `LIKE`
    Like,
    /// `MATCHES`
    Matches,
    /// `ISSUBSET`
    IsSubset,
    /// `ISSUPERSET`
    IsSuperset,
    /// `EXISTS`
    Exists,
}

/// Resolved object path for property lookup.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectPath {
    /// SCO type at the path root.
    pub object_type: PatternScoType,
    /// Property, index, dict-key, and `_ref` steps after the root segment.
    pub steps: Vec<PathStep>,
    /// Source span of the full path expression.
    pub span: Span,
}

/// Steps after the initial `object-type:property` segment.
#[derive(Clone, Debug, PartialEq)]
pub enum PathStep {
    /// Dot-separated property name.
    Property(String),
    /// Bracketed dictionary key (`hashes.'SHA-256'`).
    DictKey(String),
    /// Numeric list index (`body_multipart[0]`).
    Index(usize),
    /// Wildcard index (`body_multipart[*]`).
    AnyIndex,
    /// `_ref` / `_refs` dereference before the next property step.
    Reference,
}

/// Pattern literal constant (STIX Specification §9.2).
#[derive(Clone, Debug, PartialEq)]
pub enum PatternConstant {
    /// Single-quoted string literal.
    String(String),
    /// Integer literal.
    Int(i64),
    /// Floating-point literal.
    Float(f64),
    /// Boolean literal (`true` / `false`).
    Bool(bool),
    /// Timestamp literal (`t'…'`).
    Timestamp(StixTimestamp),
    /// Hex byte string (`h'…'`).
    Hex(Vec<u8>),
    /// Base64 byte string (`b'…'`).
    Binary(Vec<u8>),
    /// List literal for `IN` and set operators.
    List(Vec<PatternConstant>),
}

/// Temporal duration for `WITHIN` (Level 3).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Duration {
    /// Numeric magnitude.
    pub value: f64,
    /// Unit keyword following the number.
    pub unit: TimeUnit,
}

/// Time units for `WITHIN` qualifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeUnit {
    /// `SECONDS`
    Seconds,
    /// `MINUTES`
    Minutes,
    /// `HOURS`
    Hours,
    /// `DAYS`
    Days,
    /// `MONTHS`
    Months,
    /// `YEARS`
    Years,
}

impl PatternAst {
    /// Count bracketed observation expressions in this pattern tree.
    pub fn observation_count(&self) -> usize {
        match self {
            Self::Observation(_) => 1,
            Self::And { left, right, .. }
            | Self::Or { left, right, .. }
            | Self::FollowedBy { left, right, .. } => {
                left.observation_count() + right.observation_count()
            }
            Self::Within { inner, .. }
            | Self::Repeats { inner, .. }
            | Self::StartStop { inner, .. } => inner.observation_count(),
        }
    }

    /// Collect built-in SCO types referenced by this pattern tree.
    pub fn observed_types(&self) -> Vec<ScoKind> {
        self.observed_type_names()
            .into_iter()
            .filter_map(|name| ScoKind::from_type_str(&name))
            .collect()
    }

    /// Collect all SCO type names (built-in and custom) referenced by this pattern tree.
    pub fn observed_type_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        Self::collect_observed_type_names(self, &mut names);
        names.sort();
        names.dedup();
        names
    }

    fn collect_observed_type_names(node: &PatternAst, out: &mut Vec<String>) {
        match node {
            PatternAst::Observation(obs) => out.push(obs.object_type.type_name().to_owned()),
            PatternAst::And { left, right, .. }
            | PatternAst::Or { left, right, .. }
            | PatternAst::FollowedBy { left, right, .. } => {
                Self::collect_observed_type_names(left, out);
                Self::collect_observed_type_names(right, out);
            }
            PatternAst::Within { inner, .. }
            | PatternAst::Repeats { inner, .. }
            | PatternAst::StartStop { inner, .. } => Self::collect_observed_type_names(inner, out),
        }
    }
}

impl ComparisonTree {
    /// Count comparison nodes in this subtree.
    pub fn comparison_count(&self) -> usize {
        match self {
            Self::Cmp(_) => 1,
            Self::And { left, right, .. } | Self::Or { left, right, .. } => {
                left.comparison_count() + right.comparison_count()
            }
            Self::Not { inner, .. } => inner.comparison_count(),
        }
    }

    /// Compare AST shape and values, ignoring source spans.
    pub fn semantic_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Cmp(a), Self::Cmp(b)) => a.semantic_eq(b),
            (
                Self::And {
                    left: l1,
                    right: r1,
                    ..
                },
                Self::And {
                    left: l2,
                    right: r2,
                    ..
                },
            ) => l1.semantic_eq(l2) && r1.semantic_eq(r2),
            (
                Self::Or {
                    left: l1,
                    right: r1,
                    ..
                },
                Self::Or {
                    left: l2,
                    right: r2,
                    ..
                },
            ) => l1.semantic_eq(l2) && r1.semantic_eq(r2),
            (Self::Not { inner: i1, .. }, Self::Not { inner: i2, .. }) => i1.semantic_eq(i2),
            _ => false,
        }
    }
}

impl PatternAst {
    /// Compare AST shape and values, ignoring source spans.
    pub fn semantic_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Observation(a), Self::Observation(b)) => a.semantic_eq(b),
            (
                Self::And {
                    left: l1,
                    right: r1,
                    ..
                },
                Self::And {
                    left: l2,
                    right: r2,
                    ..
                },
            ) => l1.semantic_eq(l2) && r1.semantic_eq(r2),
            (
                Self::Or {
                    left: l1,
                    right: r1,
                    ..
                },
                Self::Or {
                    left: l2,
                    right: r2,
                    ..
                },
            ) => l1.semantic_eq(l2) && r1.semantic_eq(r2),
            (
                Self::FollowedBy {
                    left: l1,
                    right: r1,
                    ..
                },
                Self::FollowedBy {
                    left: l2,
                    right: r2,
                    ..
                },
            ) => l1.semantic_eq(l2) && r1.semantic_eq(r2),
            (
                Self::Within {
                    inner: i1,
                    duration: d1,
                    ..
                },
                Self::Within {
                    inner: i2,
                    duration: d2,
                    ..
                },
            ) => i1.semantic_eq(i2) && d1 == d2,
            (
                Self::Repeats {
                    inner: i1,
                    count: c1,
                    ..
                },
                Self::Repeats {
                    inner: i2,
                    count: c2,
                    ..
                },
            ) => i1.semantic_eq(i2) && c1 == c2,
            (
                Self::StartStop {
                    inner: i1,
                    start: s1,
                    stop: e1,
                    ..
                },
                Self::StartStop {
                    inner: i2,
                    start: s2,
                    stop: e2,
                    ..
                },
            ) => i1.semantic_eq(i2) && s1 == s2 && e1 == e2,
            _ => false,
        }
    }
}

impl ObservationExpr {
    /// Compare AST shape and values, ignoring source spans.
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.object_type == other.object_type && self.root.semantic_eq(&other.root)
    }
}

impl Comparison {
    fn semantic_eq(&self, other: &Self) -> bool {
        self.path.semantic_eq(&other.path)
            && self.op == other.op
            && self.negated == other.negated
            && option_constant_semantic_eq(&self.value, &other.value)
    }
}

fn option_constant_semantic_eq(a: &Option<PatternConstant>, b: &Option<PatternConstant>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(left), Some(right)) => left.semantic_eq_value(right),
        _ => false,
    }
}

impl ObjectPath {
    fn semantic_eq(&self, other: &Self) -> bool {
        self.object_type == other.object_type && self.steps == other.steps
    }
}

impl PatternConstant {
    fn semantic_eq_value(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Float(a), Self::Int(b)) => (a - *b as f64).abs() < f64::EPSILON,
            (Self::Int(a), Self::Float(b)) => (*a as f64 - b).abs() < f64::EPSILON,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Timestamp(a), Self::Timestamp(b)) => a == b,
            (Self::Hex(a), Self::Hex(b)) => a == b,
            (Self::Binary(a), Self::Binary(b)) => a == b,
            (Self::List(a), Self::List(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.semantic_eq_value(y))
            }
            _ => false,
        }
    }
}
