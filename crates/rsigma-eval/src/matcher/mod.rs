//! Compiled matchers for zero-allocation hot-path evaluation.
//!
//! Each `CompiledMatcher` variant is pre-compiled at rule load time.
//! At evaluation time, `matches()` performs the comparison against an
//! [`EventValue`] from the event with no dynamic dispatch or allocation.

mod helpers;
mod matching;

pub use helpers::{ascii_lowercase_cow, parse_expand_template, sigma_string_to_regex};

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

use crate::event::Event;
use ipnet::IpNet;

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
}
