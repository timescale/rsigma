//! STIX 2.1 patterning engine (STIX Specification §9).

mod ast;
mod context;
mod error;
mod eval;
mod lexer;
mod normalize;
mod observables;
mod parser;
mod path;
mod print;
mod security;
mod typeck;

pub use ast::{PatternAst, PatternScoType, Span};
pub use context::{ObservationContext, TimestampedObservation};
pub use error::{PatternError, PatternMatchError};
pub use lexer::{MAX_OBSERVATIONS, MAX_PATTERN_BYTES};
pub use observables::{ObservableExtraction, ObservableKind, SimpleObservable, UnsupportedReason};

use crate::core::ScoKind;
use crate::model::Bundle;
use crate::model::sco::ScoObject;
use crate::model::sdo::ObservedData;

/// A parsed and type-checked STIX pattern syntax tree.
#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    ast: PatternAst,
    source: String,
}

impl Pattern {
    /// Parse and type-check a STIX pattern string (Levels 1–3 grammar).
    ///
    /// Returns an error with a byte offset on lex/parse failure, or a path string on
    /// type-check failure.
    pub fn parse(source: &str) -> Result<Self, PatternError> {
        let ast = parser::parse(source)?;
        typeck::type_check(&ast)?;
        Ok(Self {
            ast,
            source: source.to_owned(),
        })
    }

    /// Parse and type-check a Level-1 STIX pattern (single observation expression).
    pub fn parse_level1(source: &str) -> Result<Self, PatternError> {
        let ast = parser::parse_level1(source)?;
        typeck::type_check(&ast)?;
        Ok(Self {
            ast,
            source: source.to_owned(),
        })
    }

    /// Parsed syntax tree.
    pub fn ast(&self) -> &PatternAst {
        &self.ast
    }

    /// Original pattern source text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// SCO types referenced by this pattern (built-in types only).
    pub fn observed_types(&self) -> Vec<ScoKind> {
        self.ast.observed_types()
    }

    /// All SCO type names referenced by this pattern (built-in and custom).
    pub fn observed_type_names(&self) -> Vec<String> {
        self.ast.observed_type_names()
    }

    /// Full evaluation (Levels 1–3) against timestamped observations.
    pub fn evaluate(&self, ctx: &ObservationContext<'_>) -> Result<bool, PatternMatchError> {
        eval::evaluate(&self.ast, ctx)
    }

    /// Level 1 shortcut: single top-level observation without temporal qualifiers.
    pub fn matches_single(&self, sco: &ScoObject) -> Result<bool, PatternMatchError> {
        eval::matches_single(&self.ast, sco)
    }

    /// Level 1 shortcut with optional bundle for `_ref` path dereference.
    ///
    /// Returns [`PatternMatchError::NotSingleObservation`] when the pattern contains
    /// temporal or multi-observation operators. Returns [`PatternMatchError::RefResolution`]
    /// when a present `_ref` cannot be resolved in the bundle (missing target, non-SCO).
    /// Absent optional `_ref` properties yield no match for comparisons and `false` for `EXISTS`.
    pub fn matches_single_with_bundle(
        &self,
        sco: &ScoObject,
        bundle: Option<&Bundle>,
    ) -> Result<bool, PatternMatchError> {
        eval::matches_single_with_bundle(&self.ast, sco, bundle)
    }

    /// Build context from observed-data + bundle, then evaluate.
    ///
    /// Resolves `object_refs` against the bundle, stamps observations with
    /// `first_observed`, then runs full evaluation.
    pub fn evaluate_observed_data(
        &self,
        observed_data: &ObservedData,
        bundle: &Bundle,
    ) -> Result<bool, PatternMatchError> {
        eval::evaluate_observed_data(&self.ast, observed_data, bundle)
    }

    /// Render this pattern as a canonical STIX pattern string.
    pub fn canonical(&self) -> String {
        print::print(&self.ast)
    }

    /// Extract equality and `IN` observables that a watchlist can match exactly.
    ///
    /// A pattern is simple when it is one observation, or observations combined only
    /// with `OR`, and every comparison is a non-negated `=` or `IN` of a string or
    /// integer constant. Qualifiers, `AND`, `FOLLOWEDBY`, and `NOT` are unsupported.
    /// `AND` inside one observation is unsupported as well: those comparisons share
    /// one object and cannot be flattened into independent values.
    ///
    /// ```
    /// use rstix::{ObservableExtraction, Pattern};
    ///
    /// let pattern = Pattern::parse(
    ///     "[ipv4-addr:value = '198.51.100.7'] OR [domain-name:value = 'bad.example.com']",
    /// )
    /// .unwrap();
    /// let ObservableExtraction::Simple(items) = pattern.simple_observables() else {
    ///     panic!("two equality observations are simple");
    /// };
    /// assert_eq!(items.len(), 2);
    /// assert_eq!(items[0].value, "198.51.100.7");
    /// assert_eq!(items[1].value, "bad.example.com");
    /// ```
    pub fn simple_observables(&self) -> ObservableExtraction {
        observables::extract(&self.ast)
    }
}

/// Parse a STIX pattern AST without running the type-checker.
pub fn parse_ast(source: &str) -> Result<PatternAst, PatternError> {
    parser::parse(source)
}

/// Type-check a parsed STIX pattern AST.
pub fn type_check_ast(ast: &PatternAst) -> Result<(), PatternError> {
    typeck::type_check(ast)
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&print::print(&self.ast))
    }
}

/// Compile a `MATCHES` regex with the same limits as evaluation.
pub fn compile_matches_regex(pattern: &str) -> Result<regex::Regex, PatternMatchError> {
    security::compile_regex(pattern)
}

/// Maximum compiled regex size enforced during `MATCHES` evaluation.
pub const MATCHES_REGEX_SIZE_LIMIT: usize = security::REGEX_SIZE_LIMIT;

#[doc(hidden)]
pub fn test_pattern_match_error_unsupported_operator_like() -> PatternMatchError {
    PatternMatchError::UnsupportedOperator(ast::ComparisonOp::Like)
}

#[doc(hidden)]
pub fn test_pattern_match_error_non_stix_pattern(kind: impl Into<String>) -> PatternMatchError {
    PatternMatchError::NonStixPattern(kind.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ScoKind;

    #[test]
    fn parse_spec_file_hash_example() {
        let pattern = Pattern::parse(
            "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
        )
        .expect("parse");
        assert_eq!(pattern.observed_types(), vec![ScoKind::File]);
    }

    #[test]
    fn parse_spec_ipv4_cidr_example() {
        let pattern = Pattern::parse("[ipv4-addr:value = '198.51.100.1/32']").expect("parse");
        assert_eq!(pattern.observed_types(), vec![ScoKind::Ipv4Addr]);
    }
}
