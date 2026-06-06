//! Compiled matchers for zero-allocation hot-path evaluation.
//!
//! Each `CompiledMatcher` variant is pre-compiled at rule load time.
//! At evaluation time, `matches()` performs the comparison against an
//! [`EventValue`](crate::event::EventValue) from the event with no
//! dynamic dispatch or allocation.

mod helpers;
mod matching;

pub use helpers::{ascii_lowercase_cow, parse_expand_template, sigma_string_to_regex};

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

use crate::event::Event;
use crate::result::MatcherKind;
use ipnet::IpNet;

/// Upper bound on the length of a `pattern` string recorded in match
/// detail. Long Aho-Corasick / regex-set joins are truncated with an
/// ellipsis so a single match cannot bloat the output line.
const MAX_PATTERN_LEN: usize = 256;

/// A structural description of a compiled matcher, used to populate the
/// match-detail fields on a [`FieldMatch`](crate::result::FieldMatch).
///
/// Purely descriptive: it reports the matcher's shape and pattern, not
/// which value matched. Composite matchers collapse to
/// [`MatcherKind::OneOf`] with their child patterns joined.
#[derive(Debug, Clone)]
pub struct MatchDescriptor {
    /// The matcher kind that fired.
    pub kind: MatcherKind,
    /// The pattern the matcher tested against, truncated to `MAX_PATTERN_LEN`.
    pub pattern: Option<String>,
    /// Whether matching was case-sensitive, when meaningful.
    pub case_sensitive: Option<bool>,
    /// Whether the matcher is negated.
    pub negated: bool,
}

fn truncate_pattern(s: String) -> String {
    if s.len() <= MAX_PATTERN_LEN {
        return s;
    }
    let mut end = MAX_PATTERN_LEN.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str("...");
    out
}

fn numeric_descriptor(op: &str, n: f64) -> MatchDescriptor {
    MatchDescriptor {
        kind: MatcherKind::Numeric,
        pattern: Some(format!("{op} {n}")),
        case_sensitive: None,
        negated: false,
    }
}

fn join_child_patterns(children: &[CompiledMatcher]) -> String {
    children
        .iter()
        .filter_map(|c| c.describe().pattern)
        .collect::<Vec<_>>()
        .join(", ")
}

fn expand_template_to_string(parts: &[ExpandPart]) -> String {
    let mut s = String::new();
    for part in parts {
        match part {
            ExpandPart::Literal(t) => s.push_str(t),
            ExpandPart::Placeholder(name) => {
                s.push('%');
                s.push_str(name);
                s.push('%');
            }
        }
    }
    s
}

/// A pre-compiled matcher for a single value comparison.
///
/// All string matchers store their values in the form needed for comparison
/// (Unicode-lowercased for case-insensitive). The `case_insensitive` flag
/// controls whether the input is lowercased before comparison.
#[derive(Debug, Clone)]
pub enum CompiledMatcher {
    // -- String matchers --
    /// Exact string equality.
    Exact {
        value: String,
        case_insensitive: bool,
    },
    /// Substring containment.
    Contains {
        value: String,
        case_insensitive: bool,
    },
    /// String starts with prefix.
    StartsWith {
        value: String,
        case_insensitive: bool,
    },
    /// String ends with suffix.
    EndsWith {
        value: String,
        case_insensitive: bool,
    },
    /// Compiled regex pattern (flags baked in at compile time).
    Regex(Regex),

    /// Multi-pattern substring match via Aho-Corasick automaton.
    ///
    /// Built by the optimizer when an `AnyOf` group contains
    /// `AHO_CORASICK_THRESHOLD` or more plain `Contains` matchers with the
    /// same case sensitivity. Replaces the sequential O(N * haystack_len)
    /// scan of `AnyOf([Contains, ...])` with a single linear pass.
    ///
    /// **Invariant**: this variant only encodes `AnyOf` (OR) semantics.
    /// `AllOf(Contains)` (`|all` modifier) MUST NOT be collapsed into this
    /// variant - the optimizer enforces this.
    ///
    /// **Case insensitivity**: when `case_insensitive` is true, needles are
    /// stored pre-lowered (matching the `Contains` invariant) and the hot
    /// path lowers the haystack via [`ascii_lowercase_cow`] before searching.
    /// The `AhoCorasick` automaton itself is built case-sensitively.
    AhoCorasickSet {
        automaton: AhoCorasick,
        case_insensitive: bool,
        /// Pre-lowered needles in the same order they were fed to
        /// [`AhoCorasick::new`]. Retained so downstream consumers (e.g. the
        /// engine's per-field bloom builder) can recover the pattern set
        /// without parsing the automaton's internal state.
        needles: Vec<String>,
    },

    /// Multi-pattern regex match via [`regex::RegexSet`].
    ///
    /// Built by the optimizer when an `AnyOf` group contains
    /// `REGEX_SET_THRESHOLD` or more individual `Regex` matchers. Compiles
    /// every pattern into a single combined DFA so one traversal of the
    /// haystack tests all patterns at once.
    ///
    /// **Pattern reconstruction**: the optimizer rebuilds the set from each
    /// matcher's [`Regex::as_str`], which preserves any inline flags the
    /// compiler inlined (e.g. `(?i)`, `(?ims)`). This relies on the eval
    /// crate's regex builder always inlining flags into the pattern string
    /// rather than configuring them via `RegexBuilder`. A unit test guards
    /// against future drift in that contract.
    RegexSetMatch { set: RegexSet, mode: GroupMode },

    // -- Network --
    /// CIDR network match for IP addresses.
    Cidr(IpNet),

    // -- Numeric --
    /// Numeric equality.
    NumericEq(f64),
    /// Numeric greater-than.
    NumericGt(f64),
    /// Numeric greater-than-or-equal.
    NumericGte(f64),
    /// Numeric less-than.
    NumericLt(f64),
    /// Numeric less-than-or-equal.
    NumericLte(f64),

    // -- Special --
    /// Field existence check. `true` = field must exist, `false` = must not exist.
    Exists(bool),
    /// Compare against another field's value.
    FieldRef {
        field: String,
        case_insensitive: bool,
    },
    /// Match null / missing values.
    Null,
    /// Boolean equality.
    BoolEq(bool),

    // -- Expand --
    /// Placeholder expansion: `%fieldname%` is resolved from the event at match time.
    Expand {
        template: Vec<ExpandPart>,
        case_insensitive: bool,
    },

    // -- Timestamp --
    /// Extract a time component from a timestamp field value and match it.
    TimestampPart {
        part: TimePart,
        inner: Box<CompiledMatcher>,
    },

    // -- Negation --
    /// Negated matcher: matches if the inner matcher does NOT match.
    Not(Box<CompiledMatcher>),

    // -- Composite --
    /// Match if ANY child matches (OR).
    AnyOf(Vec<CompiledMatcher>),
    /// Match if ALL children match (AND).
    AllOf(Vec<CompiledMatcher>),

    /// A composite of case-insensitive string matchers that lowers the haystack
    /// once before dispatching to children.
    ///
    /// Built by the optimizer when an `AnyOf` or `AllOf` group is composed
    /// entirely of case-insensitive string matchers (`Contains`, `StartsWith`,
    /// `EndsWith`, `Exact`, `AhoCorasickSet`, plus regexes that carry the
    /// `(?i)` flag, plus `Not` / nested `AnyOf` / `AllOf` whose every leaf
    /// satisfies these rules).
    ///
    /// **Invariant**: every child must be pre-lowerable. The optimizer's
    /// `is_pre_lowerable` validator enforces this; `matches_pre_lowered`
    /// `debug_assert!`s on violation.
    ///
    /// **Why this exists**: a mixed `AnyOf([Contains, StartsWith, EndsWith])`
    /// previously called `s.to_lowercase()` once per child. Pre-lowering the
    /// haystack a single time and dispatching to a CI-aware match path
    /// eliminates the redundant allocations.
    CaseInsensitiveGroup {
        children: Vec<CompiledMatcher>,
        mode: GroupMode,
    },
}

/// Reduction mode for composite matchers.
///
/// `Any` corresponds to OR semantics; `All` to AND. Used by
/// `CaseInsensitiveGroup` to encode whether a single match suffices or every
/// child must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMode {
    /// At least one child must match (`AnyOf` semantics).
    Any,
    /// Every child must match (`AllOf` semantics).
    All,
}

/// A part of an expand template.
#[derive(Debug, Clone)]
pub enum ExpandPart {
    /// Literal text.
    Literal(String),
    /// A placeholder field name (between `%` delimiters).
    Placeholder(String),
}

/// Which time component to extract from a timestamp.
#[derive(Debug, Clone, Copy)]
pub enum TimePart {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl CompiledMatcher {
    /// Check if this matcher matches any string value in the event.
    /// Used for keyword detection (field-less matching).
    ///
    /// Avoids allocating a `Vec` of all strings and a `String` per value by
    /// using `matches_str` with a short-circuiting traversal.
    #[inline]
    pub fn matches_keyword(&self, event: &impl Event) -> bool {
        event.any_string_value(&|s| self.matches_str(s))
    }

    /// Describe this matcher's shape for match-detail reporting.
    ///
    /// Runs only when assembling a detection result above
    /// [`MatchDetailLevel::Off`](crate::result::MatchDetailLevel), never on
    /// the matching hot path.
    pub fn describe(&self) -> MatchDescriptor {
        match self {
            CompiledMatcher::Exact {
                value,
                case_insensitive,
            } => MatchDescriptor {
                kind: MatcherKind::Exact,
                pattern: Some(truncate_pattern(value.clone())),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::Contains {
                value,
                case_insensitive,
            } => MatchDescriptor {
                kind: MatcherKind::Contains,
                pattern: Some(truncate_pattern(value.clone())),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::StartsWith {
                value,
                case_insensitive,
            } => MatchDescriptor {
                kind: MatcherKind::StartsWith,
                pattern: Some(truncate_pattern(value.clone())),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::EndsWith {
                value,
                case_insensitive,
            } => MatchDescriptor {
                kind: MatcherKind::EndsWith,
                pattern: Some(truncate_pattern(value.clone())),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::Regex(re) => MatchDescriptor {
                kind: MatcherKind::Regex,
                pattern: Some(truncate_pattern(re.as_str().to_string())),
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::AhoCorasickSet {
                needles,
                case_insensitive,
                ..
            } => MatchDescriptor {
                kind: MatcherKind::OneOf,
                pattern: Some(truncate_pattern(needles.join(", "))),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::RegexSetMatch { set, .. } => MatchDescriptor {
                kind: MatcherKind::OneOf,
                pattern: Some(truncate_pattern(set.patterns().join(", "))),
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::Cidr(net) => MatchDescriptor {
                kind: MatcherKind::Cidr,
                pattern: Some(net.to_string()),
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::NumericEq(n) => numeric_descriptor("=", *n),
            CompiledMatcher::NumericGt(n) => numeric_descriptor(">", *n),
            CompiledMatcher::NumericGte(n) => numeric_descriptor(">=", *n),
            CompiledMatcher::NumericLt(n) => numeric_descriptor("<", *n),
            CompiledMatcher::NumericLte(n) => numeric_descriptor("<=", *n),
            CompiledMatcher::Exists(expect) => MatchDescriptor {
                kind: MatcherKind::Exists,
                pattern: Some(expect.to_string()),
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::FieldRef {
                field,
                case_insensitive,
            } => MatchDescriptor {
                kind: MatcherKind::FieldRef,
                pattern: Some(field.clone()),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::Null => MatchDescriptor {
                kind: MatcherKind::Null,
                pattern: None,
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::BoolEq(b) => MatchDescriptor {
                kind: MatcherKind::Bool,
                pattern: Some(b.to_string()),
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::Expand {
                template,
                case_insensitive,
            } => MatchDescriptor {
                kind: MatcherKind::Expand,
                pattern: Some(truncate_pattern(expand_template_to_string(template))),
                case_sensitive: Some(!case_insensitive),
                negated: false,
            },
            CompiledMatcher::TimestampPart { inner, .. } => {
                let inner_d = inner.describe();
                MatchDescriptor {
                    kind: MatcherKind::Timestamp,
                    pattern: inner_d.pattern,
                    case_sensitive: inner_d.case_sensitive,
                    negated: inner_d.negated,
                }
            }
            CompiledMatcher::Not(inner) => {
                let mut d = inner.describe();
                d.negated = !d.negated;
                d
            }
            CompiledMatcher::AnyOf(ms) | CompiledMatcher::AllOf(ms) => MatchDescriptor {
                kind: MatcherKind::OneOf,
                pattern: Some(truncate_pattern(join_child_patterns(ms))),
                case_sensitive: None,
                negated: false,
            },
            CompiledMatcher::CaseInsensitiveGroup { children, .. } => MatchDescriptor {
                kind: MatcherKind::OneOf,
                pattern: Some(truncate_pattern(join_child_patterns(children))),
                case_sensitive: Some(false),
                negated: false,
            },
        }
    }
}

#[cfg(test)]
mod describe_tests {
    use super::*;

    #[test]
    fn string_matchers_report_kind_pattern_and_case() {
        let d = CompiledMatcher::Contains {
            value: "abc".to_string(),
            case_insensitive: true,
        }
        .describe();
        assert_eq!(d.kind, MatcherKind::Contains);
        assert_eq!(d.pattern.as_deref(), Some("abc"));
        assert_eq!(d.case_sensitive, Some(false));
        assert!(!d.negated);

        let cased = CompiledMatcher::EndsWith {
            value: "\\powershell.exe".to_string(),
            case_insensitive: false,
        }
        .describe();
        assert_eq!(cased.kind, MatcherKind::EndsWith);
        assert_eq!(cased.case_sensitive, Some(true));
    }

    #[test]
    fn numeric_exists_and_null_descriptors() {
        let gt = CompiledMatcher::NumericGt(5.0).describe();
        assert_eq!(gt.kind, MatcherKind::Numeric);
        assert_eq!(gt.pattern.as_deref(), Some("> 5"));

        let exists = CompiledMatcher::Exists(false).describe();
        assert_eq!(exists.kind, MatcherKind::Exists);
        assert_eq!(exists.pattern.as_deref(), Some("false"));

        let null = CompiledMatcher::Null.describe();
        assert_eq!(null.kind, MatcherKind::Null);
        assert!(null.pattern.is_none());
    }

    #[test]
    fn not_inverts_negated_flag_and_keeps_inner_kind() {
        let inner = CompiledMatcher::Contains {
            value: "evil".to_string(),
            case_insensitive: true,
        };
        let d = CompiledMatcher::Not(Box::new(inner)).describe();
        assert_eq!(d.kind, MatcherKind::Contains);
        assert!(d.negated);
        assert_eq!(d.pattern.as_deref(), Some("evil"));
    }

    #[test]
    fn composite_collapses_to_one_of_with_joined_patterns() {
        let d = CompiledMatcher::AnyOf(vec![
            CompiledMatcher::Contains {
                value: "foo".to_string(),
                case_insensitive: true,
            },
            CompiledMatcher::Contains {
                value: "bar".to_string(),
                case_insensitive: true,
            },
        ])
        .describe();
        assert_eq!(d.kind, MatcherKind::OneOf);
        assert_eq!(d.pattern.as_deref(), Some("foo, bar"));
    }

    #[test]
    fn long_patterns_are_truncated() {
        let long = "x".repeat(MAX_PATTERN_LEN * 2);
        let d = CompiledMatcher::Contains {
            value: long,
            case_insensitive: true,
        }
        .describe();
        let pattern = d.pattern.unwrap();
        assert!(pattern.len() <= MAX_PATTERN_LEN);
        assert!(pattern.ends_with("..."));
    }
}
