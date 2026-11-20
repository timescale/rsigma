//! Fibratus conversion backend.
//!
//! Converts Sigma rules into [Fibratus](https://github.com/rabbitstack/fibratus)
//! YAML rule files and bare filter expressions. Fibratus is an Apache-2.0
//! Windows kernel-event detection and EDR engine; this backend targets its
//! native rule format so a Sigma rule converted with `-t fibratus` lands as
//! an idiomatic file the upstream loader accepts.
//!
//! Three Fibratus-specific behaviors drive the implementation:
//!
//! - **Case-insensitive matching needs an operator switch, not a wrapper.**
//!   Fibratus's plain operators (`=`, `contains`, `startswith`,
//!   `endswith`, `matches`, `in`, `intersects`) are case-sensitive; the
//!   `i`-prefixed cousins (`icontains`, `istartswith`, ...) and the `~=`
//!   case-insensitive string-equality operator are not. The Sigma
//!   default is case-insensitive, so this config populates the default
//!   `TextQueryConfig` operator slots with the case-insensitive forms
//!   and the `case_sensitive_*_expression` slots with the bare forms
//!   (exactly inverse to how other backends use those slots) plus
//!   collapses multi-value string lists into a single list-operator
//!   clause that picks `iin` vs `in` from the matcher's case
//!   sensitivity. Plain string equality without a glob
//!   uses the dedicated string-equality operators (`~=` default, `=`
//!   when `|cased`), which evaluate more efficiently than a wildcard
//!   match; `imatches`/`matches` are reserved for values that actually
//!   carry `*`/`?` wildcards. The `evt.name` event discriminator always
//!   uses the exact `=` operator to match the upstream rules-library and
//!   macro-library style.
//! - **Regex is a function call, not an operator.** Sigma `|re` lowers
//!   to the [`regex(field, 'pat1', 'pat2', ...) = true`](https://fibratus.io/docs/rules/functions)
//!   filter function. Multi-value `|re` lists collapse into a single
//!   call; the negated form uses a leading `not`. RE2 differs from PCRE
//!   on a few constructs (lookarounds, backreferences), so patterns that
//!   use those return `ConvertError::UnsupportedModifier` rather than
//!   emit something Fibratus would reject at load time.
//! - **YAML envelope, not query string.** `finalize_query` builds a
//!   per-rule YAML document and `finalize_output` joins documents with
//!   `---`. The `expr` output format strips the envelope and emits the
//!   bare condition for piping into other tooling.

pub mod config;
pub mod correlation;
pub mod envelope;
pub mod macros;
pub mod shared;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::{IrDetectionItem, IrMatcher, IrPattern, IrPatternPart, IrStrOp, NumericLiteral};
use rsigma_parser::*;

use crate::backend::*;
use crate::condition_ir::convert_rule_via_ir;
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

pub use config::FibratusConfig;

// =============================================================================
// TextQueryConfig — Fibratus dialect
// =============================================================================

/// `TextQueryConfig` populated with Fibratus's filter-engine surface.
///
/// The default operator slots carry the `i`-prefixed (case-insensitive)
/// forms because Sigma defaults to case-insensitive matching. The
/// `case_sensitive_*_expression` slots carry the bare forms and are used
/// when the Sigma `|cased` modifier flips the value to case-sensitive
/// matching. This inversion is the opposite of how PostgreSQL/LynxDB
/// populate the slots and is the core reason Fibratus needs its own
/// dialect.
pub static FIBRATUS_CONFIG: TextQueryConfig = TextQueryConfig {
    // NOT binds tightest, then AND, then OR — standard Sigma precedence.
    precedence: (TokenType::NOT, TokenType::AND, TokenType::OR),
    group_expression: "({expr})",
    token_separator: " ",

    and_token: "and",
    or_token: "or",
    not_token: "not",
    eq_token: " = ",

    not_eq_token: Some(" != "),
    eq_expression: None,
    not_eq_expression: None,
    convert_not_as_not_eq: false,

    // Fibratus globs are `*` (multi-char) and `?` (single-char), matching
    // Sigma's two wildcard tokens 1:1.
    wildcard_multi: "*",
    wildcard_single: "?",

    // Fibratus string literals are single-quoted. Quoting and escaping are
    // handled in `shared::quote_sigma_string`; the generic `add_escaped`
    // path is bypassed by the leaf overrides below.
    str_quote: "'",
    str_quote_pattern: None,
    str_quote_pattern_negation: false,
    escape_char: "\\",
    add_escaped: &[],
    filter_chars: &[],

    // Fibratus identifiers are bare lowercase dotted paths; no quoting.
    field_quote: None,
    field_quote_pattern: None,
    field_quote_pattern_negation: false,
    field_escape: None,
    field_escape_pattern: None,

    // Case-insensitive defaults (Sigma default). Bare forms live in the
    // `case_sensitive_*` slots below and engage when `|cased` is set.
    startswith_expression: Some("{field} istartswith {value}"),
    not_startswith_expression: None,
    startswith_expression_allow_special: false,
    endswith_expression: Some("{field} iendswith {value}"),
    not_endswith_expression: None,
    endswith_expression_allow_special: false,
    contains_expression: Some("{field} icontains {value}"),
    not_contains_expression: None,
    contains_expression_allow_special: false,
    wildcard_match_expression: Some("{field} imatches {value}"),

    // Case-sensitive (`|cased`) leaves.
    case_sensitive_match_expression: Some("{field} matches {value}"),
    case_sensitive_startswith_expression: Some("{field} startswith {value}"),
    case_sensitive_endswith_expression: Some("{field} endswith {value}"),
    case_sensitive_contains_expression: Some("{field} contains {value}"),

    // Regex is rendered by a backend-specific override
    // (`regex(field, 'pat') = true`); the template slots stay None so the
    // generic dispatch never fires for `|re`.
    re_expression: None,
    not_re_expression: None,
    re_escape_char: Some("\\"),
    re_escape: &[],
    re_escape_escape_char: None,

    // CIDR is also rendered by the backend override using the
    // `cidr_contains(field, 'cidr')` filter function.
    cidr_expression: None,
    not_cidr_expression: None,

    // Fibratus has no `null` token, and the rule engine resolves a field
    // the event lacks to its type's zero value, so absence is only
    // observable as an empty string. A Sigma `field: null` and
    // `|exists: false` both compare with `''`; the negated form tests
    // presence. Absence on a numeric, boolean, or IP field is not
    // expressible.
    field_null_expression: "{field} = ''",
    field_exists_expression: Some("{field} != ''"),
    field_not_exists_expression: Some("{field} = ''"),

    compare_op_expression: Some("{field} {op} {value}"),
    compare_ops: &[("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")],

    // IN-list collapsing: a multi-value OR string list lowers to
    // `field iin ('a', 'b')` by default and to bare `in` when the list is
    // case-sensitive, via the IR-native `convert_ir_detection_item` override.
    convert_or_as_in: true,
    convert_and_as_in: false,
    in_expressions_allow_wildcards: false,
    field_in_list_expression: Some("{field} {op} ({list})"),
    or_in_operator: Some("iin"),
    and_in_operator: None,
    list_separator: ", ",

    // Fibratus has no unbound/keyword search; the keyword override
    // returns UnsupportedKeyword with an explanatory hint.
    unbound_value_str_expression: None,
    unbound_value_num_expression: None,
    unbound_value_re_expression: None,

    // Field-to-field comparison is native: `ps.pid = ps.parent.pid`.
    field_eq_field_expression: Some("{field1} = {field2}"),
    field_eq_field_escaping_quoting: false,

    // No deferred-tail section: the YAML envelope is built in
    // `finalize_query`, not via the generic `text_finish_query` deferred
    // append path.
    deferred_start: None,
    deferred_separator: None,
    deferred_only_query: "",

    bool_true: "true",
    bool_false: "false",

    // The condition string is the bare filter expression; envelope
    // wrapping happens in `finalize_query` so the `expr` output format
    // can short-circuit it.
    query_expression: "{query}",
    state_defaults: &[],
};

/// Whether a literal part of the pattern contains `*` or `?`.
fn has_literal_glob_char(pattern: &IrPattern) -> bool {
    pattern
        .parts
        .iter()
        .any(|p| matches!(p, IrPatternPart::Literal(s) if s.contains(['*', '?'])))
}

/// The RE2 regex a Sigma pattern matches, anchored for `op`. Wildcards match
/// a line break, as in a Fibratus glob.
fn glob_regex(pattern: &IrPattern, op: IrStrOp, case_insensitive: bool) -> String {
    let mut re = String::from(if case_insensitive { "(?is)" } else { "(?s)" });
    if matches!(op, IrStrOp::Exact | IrStrOp::StartsWith) {
        re.push('^');
    }
    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(s) => re.push_str(&regex::escape(s)),
            IrPatternPart::WildcardMulti => re.push_str(".*"),
            IrPatternPart::WildcardSingle => re.push('.'),
        }
    }
    if matches!(op, IrStrOp::Exact | IrStrOp::EndsWith) {
        re.push('$');
    }
    re
}

// =============================================================================
// FibratusBackend
// =============================================================================

/// Sigma-to-Fibratus conversion backend.
pub struct FibratusBackend {
    pub config: &'static TextQueryConfig,
    pub fibratus: FibratusConfig,
}

impl FibratusBackend {
    /// Construct a backend with default `FibratusConfig`.
    pub fn new() -> Self {
        Self {
            config: &FIBRATUS_CONFIG,
            fibratus: FibratusConfig::default(),
        }
    }

    /// Construct a backend from CLI-style `-O key=value` options.
    pub fn from_options(options: &HashMap<String, String>) -> Self {
        Self {
            config: &FIBRATUS_CONFIG,
            fibratus: FibratusConfig::from_options(options),
        }
    }

    /// Collapse a uniform `AnyOf` of string matchers into a single Fibratus
    /// list-operator clause (`field iin ('a', 'b')`,
    /// `field imatches ('a*', 'b?')`, `field icontains ('a', 'b')`, ...).
    ///
    /// Fibratus operators accept a parenthesized list on the right-hand side
    /// with "any of" (OR) semantics, which is exactly what a multi-value Sigma
    /// list means, so a single clause replaces the OR-of-equalities the generic
    /// dispatch would otherwise emit. Returns `None` (fall back to per-value
    /// dispatch) unless every matcher is an `IrMatcher::Str` with the same
    /// operator and case sensitivity.
    fn try_string_value_list_ir(&self, field: &str, ms: &[IrMatcher]) -> Option<String> {
        let mut op: Option<IrStrOp> = None;
        let mut ci: Option<bool> = None;
        let mut patterns = Vec::with_capacity(ms.len());
        for m in ms {
            match m {
                IrMatcher::Str {
                    op: o,
                    pattern,
                    case_insensitive,
                } => {
                    if *op.get_or_insert(*o) != *o {
                        return None;
                    }
                    if *ci.get_or_insert(*case_insensitive) != *case_insensitive {
                        return None;
                    }
                    if reject_nul_pattern("Fibratus", pattern).is_err() {
                        return None;
                    }
                    patterns.push(pattern);
                }
                _ => return None,
            }
        }
        let op = op?;
        let cased = self.fibratus.case_sensitive || !ci?;
        let any_wild = patterns.iter().any(|p| p.has_wildcards());
        // Substring operators take no wildcards, and a glob cannot carry a
        // literal `*` or `?`; those values convert one at a time.
        if any_wild && (op != IrStrOp::Exact || patterns.iter().any(|p| has_literal_glob_char(p))) {
            return None;
        }
        let f = shared::field_ident(field).ok()?;

        let list_op = match op {
            IrStrOp::Contains => {
                if cased {
                    "contains"
                } else {
                    "icontains"
                }
            }
            IrStrOp::StartsWith => {
                if cased {
                    "startswith"
                } else {
                    "istartswith"
                }
            }
            IrStrOp::EndsWith => {
                if cased {
                    "endswith"
                } else {
                    "iendswith"
                }
            }
            IrStrOp::Exact => {
                if any_wild {
                    if cased { "matches" } else { "imatches" }
                } else if cased || field == "evt.name" {
                    "in"
                } else {
                    "iin"
                }
            }
        };

        let list = patterns
            .iter()
            .map(|p| shared::quote_sigma_string(&crate::backend::ir_pattern_to_sigma(p)))
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!("{f} {list_op} ({list})"))
    }
}

impl Default for FibratusBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for FibratusBackend {
    fn name(&self) -> &str {
        "fibratus"
    }

    fn formats(&self) -> &[(&str, &str)] {
        &[
            (
                "default",
                "one YAML rule document per Sigma rule, --- separated",
            ),
            ("expr", "filter expression only, no YAML envelope"),
            ("yaml", "alias of `default`"),
            ("rule", "alias of `default`"),
        ]
    }

    fn requires_pipeline(&self) -> bool {
        false
    }

    // --- Detection rule conversion ---

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        convert_rule_via_ir(self, rule, output_format, pipeline_state)
    }

    // --- Condition combinators ---

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        let non_empty: Vec<String> = exprs.iter().filter(|s| !s.is_empty()).cloned().collect();
        if non_empty.is_empty() {
            return Ok(String::new());
        }
        Ok(text_convert_condition_and(self.config, &non_empty))
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        let non_empty: Vec<String> = exprs.iter().filter(|s| !s.is_empty()).cloned().collect();
        if non_empty.is_empty() {
            return Ok(String::new());
        }
        let joined = text_convert_condition_or(self.config, &non_empty);
        // OR groups are always parenthesized so they nest safely under AND
        // (see `convert_condition_group`).
        if non_empty.len() > 1 {
            Ok(format!("({joined})"))
        } else {
            Ok(joined)
        }
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        // Fibratus has a native `not` operator; no De Morgan push-down
        // is required. Wrap in parens so precedence is unambiguous.
        if expr.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("not ({expr})"))
    }

    /// Fibratus groups in its own combinators: unary `not` only accepts a
    /// parenthesized expression, OR groups are always parenthesized, and a
    /// value list collapses into a single list clause, so walker grouping
    /// would only add redundant parentheses.
    fn convert_condition_group(
        &self,
        expr: &str,
        _outer: TokenType,
        _inner: TokenType,
    ) -> Result<String> {
        Ok(expr.to_string())
    }

    fn convert_ir_detection_item(
        &self,
        item: &IrDetectionItem,
        state: &mut ConversionState,
    ) -> Result<String> {
        // `|neq` over a list negates the collapsed list clause.
        if let IrMatcher::Not(inner) = &item.matcher
            && matches!(inner.as_ref(), IrMatcher::AnyOf(_) | IrMatcher::AllOf(_))
        {
            let positive = IrDetectionItem {
                matcher: inner.as_ref().clone(),
                ..item.clone()
            };
            let expr = self.convert_ir_detection_item(&positive, state)?;
            return self.convert_condition_not(&expr);
        }

        // Multi-value OR lists (`AnyOf`) collapse into a single Fibratus
        // list-operator / variadic-function clause. `|all` lowers to `AllOf`
        // and falls through to the generic AND-join.
        if let IrMatcher::AnyOf(ms) = &item.matcher
            && let Some(field) = item.field.as_deref()
            && ms.len() >= 2
        {
            // Multi-value `|re` → one variadic `regex(field, 'a', 'b') = true`.
            if ms.iter().all(|m| matches!(m, IrMatcher::Regex { .. })) {
                let mut quoted = Vec::with_capacity(ms.len());
                for m in ms {
                    if let IrMatcher::Regex {
                        pattern,
                        case_insensitive,
                        multiline,
                        dotall,
                        cased,
                    } = m
                    {
                        if !shared::is_re2_compatible(pattern) {
                            return Err(ConvertError::UnsupportedModifier(format!(
                                "regex pattern uses PCRE-only construct (lookaround/backreference) Fibratus's RE2 engine does not support: {pattern}"
                            )));
                        }
                        reject_nul("Fibratus", pattern)?;
                        let flags = RegexFlags {
                            case_insensitive: *case_insensitive,
                            multiline: *multiline,
                            dotall: *dotall,
                            cased: *cased,
                        };
                        quoted.push(shared::quote_plain_str(&format!(
                            "{}{pattern}",
                            flags.inline_prefix()
                        )));
                    }
                }
                let f = shared::field_ident(field)?;
                return Ok(format!("regex({f}, {}) = true", quoted.join(", ")));
            }

            // Multi-value `|cidr` → one variadic `cidr_contains(field, ...)`.
            if ms.iter().all(|m| matches!(m, IrMatcher::Cidr { .. })) {
                let masks: Vec<String> = ms
                    .iter()
                    .filter_map(|m| match m {
                        IrMatcher::Cidr { network } => Some(shared::quote_plain_str(network)),
                        _ => None,
                    })
                    .collect();
                let f = shared::field_ident(field)?;
                return Ok(format!("cidr_contains({f}, {})", masks.join(", ")));
            }

            // Uniform string list → a single list-operator clause.
            if let Some(list_expr) = self.try_string_value_list_ir(field, ms) {
                return Ok(list_expr);
            }
        }

        crate::ir_convert::default_convert_ir_detection_item(self, item, state)
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        field.to_string()
    }

    // --- Value-type-specific leaves (IR-native) ---

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        reject_nul_pattern("Fibratus", pattern)?;
        let f = shared::field_ident(field)?;
        let is_cased = self.fibratus.case_sensitive || !case_insensitive;

        // A glob has no escape for a literal `*` or `?`, so such a pattern
        // matches through an anchored regex instead.
        if pattern.has_wildcards() && has_literal_glob_char(pattern) {
            let re = shared::quote_plain_str(&glob_regex(pattern, op, !is_cased));
            return Ok(ConvertResult::Query(format!("regex({f}, {re}) = true")));
        }

        // The substring operators treat `*` and `?` as literal characters,
        // so a wildcard pattern matches as a glob with the operator's own
        // leading or trailing `*`.
        let globbed;
        let (op, pattern) = if pattern.has_wildcards() && op != IrStrOp::Exact {
            let mut parts = Vec::with_capacity(pattern.parts.len() + 2);
            if matches!(op, IrStrOp::Contains | IrStrOp::EndsWith) {
                parts.push(IrPatternPart::WildcardMulti);
            }
            parts.extend(pattern.parts.iter().cloned());
            if matches!(op, IrStrOp::Contains | IrStrOp::StartsWith) {
                parts.push(IrPatternPart::WildcardMulti);
            }
            globbed = IrPattern { parts };
            (IrStrOp::Exact, &globbed)
        } else {
            (op, pattern)
        };

        let val = shared::quote_sigma_string(&crate::backend::ir_pattern_to_sigma(pattern));
        let is_contains = matches!(op, IrStrOp::Contains);
        let is_startswith = matches!(op, IrStrOp::StartsWith);
        let is_endswith = matches!(op, IrStrOp::EndsWith);

        // Substring operators (`contains`/`startswith`/`endswith`) always
        // use the dedicated Fibratus operators, case-insensitive by
        // default (`icontains`, ...) and bare with `|cased` (`contains`,
        // ...), matching the Sigma default.
        if is_contains || is_startswith || is_endswith {
            let template = match (is_cased, is_contains, is_startswith, is_endswith) {
                (true, true, _, _) => self.config.case_sensitive_contains_expression,
                (true, _, true, _) => self.config.case_sensitive_startswith_expression,
                (true, _, _, true) => self.config.case_sensitive_endswith_expression,
                (false, true, _, _) => self.config.contains_expression,
                (false, _, true, _) => self.config.startswith_expression,
                (false, _, _, true) => self.config.endswith_expression,
                _ => unreachable!("substring branch guarded above"),
            };
            let expr = template.ok_or_else(|| {
                ConvertError::UnsupportedModifier(format!("string operator for {field}"))
            })?;
            return Ok(ConvertResult::Query(
                expr.replace("{field}", f).replace("{value}", &val),
            ));
        }

        // Plain equality. Sigma string comparisons are case-insensitive by
        // default; Fibratus's bare `=` is case-sensitive. The operator
        // therefore depends on whether the value carries glob wildcards
        // and on the `|cased` modifier:
        //
        // - With wildcards: `imatches` (default) / `matches` (`|cased`),
        //   the glob-matching operators.
        // - Without wildcards: `~=` (default, case-insensitive string
        //   equality) / `=` (`|cased`, exact). These are cheaper than a
        //   wildcard match and read the way the upstream rules library
        //   writes literal equality.
        //
        // `evt.name` is the canonical event discriminator and always uses
        // the exact `=` operator (the event-name vocabulary is a fixed,
        // canonically-cased enum and every upstream macro/rule writes
        // `evt.name = '...'`).
        let expr = if pattern.has_wildcards() {
            let template = if is_cased {
                self.config.case_sensitive_match_expression
            } else {
                self.config.wildcard_match_expression
            };
            let template = template.ok_or_else(|| {
                ConvertError::UnsupportedModifier(format!("string operator for {field}"))
            })?;
            template.replace("{field}", f).replace("{value}", &val)
        } else {
            let op = if is_cased || field == "evt.name" {
                "="
            } else {
                "~="
            };
            format!("{f} {op} {val}")
        };
        Ok(ConvertResult::Query(expr))
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = shared::field_ident(field)?;
        Ok(format!("{f} = {value}"))
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = shared::field_ident(field)?;
        let v = if value {
            self.config.bool_true
        } else {
            self.config.bool_false
        };
        Ok(format!("{f} = {v}"))
    }

    fn convert_field_eq_null(&self, field: &str, _state: &mut ConversionState) -> Result<String> {
        let f = shared::field_ident(field)?;
        Ok(self.config.field_null_expression.replace("{field}", f))
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if !shared::is_re2_compatible(pattern) {
            return Err(ConvertError::UnsupportedModifier(format!(
                "regex pattern uses PCRE-only construct (lookaround/backreference) Fibratus's RE2 engine does not support: {pattern}"
            )));
        }
        reject_nul("Fibratus", pattern)?;
        let f = shared::field_ident(field)?;
        let quoted = shared::quote_plain_str(&format!("{}{pattern}", flags.inline_prefix()));
        Ok(ConvertResult::Query(format!("regex({f}, {quoted}) = true")))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = shared::field_ident(field)?;
        let quoted = shared::quote_plain_str(cidr);
        Ok(ConvertResult::Query(format!(
            "cidr_contains({f}, {quoted})"
        )))
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = shared::field_ident(field)?;
        let op_name = match op {
            CompareOp::Lt => "lt",
            CompareOp::Lte => "lte",
            CompareOp::Gt => "gt",
            CompareOp::Gte => "gte",
        };
        let op_token = self
            .config
            .compare_ops
            .iter()
            .find(|(n, _)| *n == op_name)
            .map(|(_, t)| *t)
            .ok_or_else(|| ConvertError::UnsupportedModifier(op_name.into()))?;
        let val_str = value.to_string();
        Ok(format!("{f} {op_token} {val_str}"))
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = shared::field_ident(field)?;
        let template = if exists {
            self.config.field_exists_expression
        } else {
            self.config.field_not_exists_expression
        };
        let expr = template.ok_or_else(|| {
            ConvertError::UnsupportedModifier(if exists { "exists" } else { "not exists" }.into())
        })?;
        Ok(expr.replace("{field}", f))
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        _id: &str,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = shared::field_ident(field)?;
        Ok(format!("{f} = {expr}"))
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        op: IrStrOp,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f1 = shared::field_ident(field1)?;
        let f2 = shared::field_ident(field2)?;
        let cased = self.fibratus.case_sensitive || !case_insensitive;
        let token = match (op, cased) {
            (IrStrOp::Exact, false) => "~=",
            (IrStrOp::Exact, true) => "=",
            (IrStrOp::Contains, false) => "icontains",
            (IrStrOp::Contains, true) => "contains",
            (IrStrOp::StartsWith, false) => "istartswith",
            (IrStrOp::StartsWith, true) => "startswith",
            (IrStrOp::EndsWith, false) => "iendswith",
            (IrStrOp::EndsWith, true) => "endswith",
        };
        Ok(ConvertResult::Query(format!("{f1} {token} {f2}")))
    }

    fn convert_keyword_str(
        &self,
        _pattern: &IrPattern,
        _state: &mut ConversionState,
    ) -> Result<String> {
        // Fibratus has no unbound full-text search; keyword detections
        // cannot be expressed. Return the structured error so the rule
        // shows up in the conversion-errors list rather than emitting
        // silently-wrong YAML.
        Err(ConvertError::UnsupportedKeyword)
    }

    fn convert_keyword_num(
        &self,
        _value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        Err(ConvertError::UnsupportedKeyword)
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        _rule: &SigmaRule,
        query: String,
        _state: &ConversionState,
    ) -> Result<String> {
        // No deferred parts to splice; the YAML envelope is built in
        // `finalize_query` so the `expr` format can opt out of it.
        Ok(query)
    }

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        _index: usize,
        _state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        // Apply macro recognition before envelope wrapping so the
        // YAML `condition:` block carries idiomatic macro calls
        // (`spawn_process`, `open_file`, ...) instead of the raw
        // `evt.name imatches '...'` clauses. The recognizer is a
        // no-op on inputs that match no macros, so callers that
        // disable `use_macros` get byte-equivalent output.
        let condition = if self.fibratus.use_macros {
            macros::recognize(&query)
        } else {
            query
        };
        match output_format {
            "expr" => Ok(condition),
            "default" | "yaml" | "rule" => {
                Ok(envelope::render_rule_yaml(rule, &condition, &self.fibratus))
            }
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    fn output_file_extension(&self, output_format: &str) -> &str {
        // The YAML envelope formats drop into a Fibratus `Rules/` directory
        // as `.yml` files the loader picks up directly; the bare-expression
        // `expr` format is plain text with no envelope.
        match output_format {
            "expr" => "txt",
            _ => "yml",
        }
    }

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String> {
        match output_format {
            "expr" => Ok(queries.join("\n")),
            "default" | "yaml" | "rule" => {
                // Join YAML documents with the document-separator. The
                // trailing newline on each document keeps the separator
                // on its own line.
                let mut out = String::new();
                for (i, q) in queries.iter().enumerate() {
                    if i > 0 {
                        out.push_str("---\n");
                    }
                    out.push_str(q);
                }
                Ok(out)
            }
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    // --- Correlation rule conversion ---

    fn supports_correlation(&self) -> bool {
        true
    }

    fn correlation_methods(&self) -> &[(&str, &str)] {
        &[
            (
                "sliding",
                "Native sliding sequence with `maxspan` (default; the Fibratus sequence DSL's only \
                 time-window primitive is a total-span cap, which is a sliding constraint per stage)",
            ),
            (
                "session",
                "Degraded: emits a sliding sequence and a warning that the requested per-step gap \
                 is not enforced (Fibratus has no `maxpause`-style inactivity timeout)",
            ),
        ]
    }

    fn default_correlation_method(&self) -> &str {
        "sliding"
    }

    fn convert_correlation_rule_with_warnings(
        &self,
        rule: &CorrelationRule,
        output_format: &str,
        pipeline_state: &PipelineState,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        correlation::convert(self, rule, output_format, pipeline_state, warnings)
    }
}
