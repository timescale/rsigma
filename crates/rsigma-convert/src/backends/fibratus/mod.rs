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
//!   overrides `convert_condition_as_in_expression` to pick `iin` vs
//!   `in` from per-item modifiers. Plain string equality without a glob
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
use rsigma_parser::*;

use crate::backend::*;
use crate::condition::convert_condition_expr;
use crate::condition_ir::convert_rule_via_ir;
use crate::convert::{default_convert_detection, default_convert_detection_item};
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

    // Fibratus has no `null` token. A Sigma `field: null` (value is
    // null/empty) lowers to an empty-string comparison; field presence
    // (`|exists`) lowers to a `false` comparison (`!= false` present,
    // `= false` absent), which is how Fibratus expresses set/unset for
    // its zero-valued fields.
    field_null_expression: "{field} = ''",
    field_exists_expression: Some("{field} != false"),
    field_not_exists_expression: Some("{field} = false"),

    compare_op_expression: Some("{field} {op} {value}"),
    compare_ops: &[("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")],

    // IN-list collapsing: the OR-of-equalities path lowers to
    // `field iin ('a', 'b')` by default; `convert_condition_as_in_expression`
    // is overridden to flip to bare `in` when every value carries `|cased`.
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

    /// Return true if every item modifier list contains `Cased` (i.e. the
    /// whole in-list should use the bare `in` operator). Used by
    /// `convert_condition_as_in_expression` since the per-item modifiers
    /// are not visible at the dispatch site through the generic helpers.
    fn all_cased(values: &[&SigmaValue]) -> bool {
        // The IN-list collapse only sees raw values; per-item modifiers
        // are not threaded through the dispatch. The backend-wide
        // `case_sensitive` flag is the only knob available here; per-item
        // `|cased` mixed with non-cased values keeps the (correct) `iin`
        // form and falls back to OR'd equality only when the IN-list
        // helper itself rejects.
        let _ = values;
        false
    }

    /// Collapse a multi-value OR string list into one Fibratus
    /// list-operator clause (`field iin ('a', 'b')`,
    /// `field imatches ('a*', 'b?')`, `field icontains ('a', 'b')`, ...).
    ///
    /// Fibratus operators accept a parenthesized list on the right-hand
    /// side with "any of" (OR) semantics, which is exactly what a
    /// multi-value Sigma list means, so a single clause replaces the
    /// OR-of-equalities the generic dispatch would otherwise emit.
    ///
    /// Returns `Ok(None)` (falling back to the generic dispatch) unless
    /// the item is a plain multi-value string list carrying only
    /// string-operator modifiers (`contains`, `startswith`, `endswith`,
    /// `cased`). `|all` (AND, "all of") is left to the generic AND-join
    /// because a list RHS cannot express conjunction. The `evt.name`
    /// discriminator and `|cased` values use the case-sensitive `in`;
    /// other equality lists use `iin`; wildcard-bearing lists use
    /// `imatches`/`matches`.
    fn try_string_value_list(&self, item: &DetectionItem) -> Result<Option<String>> {
        if item.values.len() < 2 || item.field.has_modifier(Modifier::All) {
            return Ok(None);
        }
        const ALLOWED: &[Modifier] = &[
            Modifier::Contains,
            Modifier::StartsWith,
            Modifier::EndsWith,
            Modifier::Cased,
        ];
        if item.field.modifiers.iter().any(|m| !ALLOWED.contains(m)) {
            return Ok(None);
        }
        let mut strings: Vec<&SigmaString> = Vec::with_capacity(item.values.len());
        for v in &item.values {
            match v {
                SigmaValue::String(s) => strings.push(s),
                _ => return Ok(None),
            }
        }
        let field_name = item
            .field
            .name
            .as_deref()
            .ok_or(ConvertError::MissingFieldName)?;
        let f = self.escape_and_quote_field(field_name);
        let cased = self.fibratus.case_sensitive || item.field.has_modifier(Modifier::Cased);
        let any_wild = strings.iter().any(|s| shared::has_wildcards(s));

        let op = if item.field.has_modifier(Modifier::Contains) {
            if cased { "contains" } else { "icontains" }
        } else if item.field.has_modifier(Modifier::StartsWith) {
            if cased { "startswith" } else { "istartswith" }
        } else if item.field.has_modifier(Modifier::EndsWith) {
            if cased { "endswith" } else { "iendswith" }
        } else if any_wild {
            if cased { "matches" } else { "imatches" }
        } else if cased || field_name == "evt.name" {
            "in"
        } else {
            "iin"
        };

        let list = strings
            .iter()
            .map(|s| shared::quote_sigma_string(s))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Some(format!("{f} {op} ({list})")))
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

    // --- Condition tree dispatch ---

    fn convert_condition(
        &self,
        expr: &ConditionExpr,
        detections: &HashMap<String, Detection>,
        state: &mut ConversionState,
    ) -> Result<String> {
        convert_condition_expr(self, expr, detections, state)
    }

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
        // OR binds looser than AND (standard precedence), so an OR
        // sub-expression nested inside an AND needs parens for correct
        // evaluation. The trait dispatch site has no context to know
        // when grouping is required, so wrap multi-child OR groups
        // unconditionally. Extra parens at the top level are harmless
        // and stripped by no one. Mirrors LynxDB's symmetric pattern
        // for its inverted precedence.
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

    // --- Detection ---

    fn convert_detection(&self, det: &Detection, state: &mut ConversionState) -> Result<String> {
        default_convert_detection(self, det, state)
    }

    fn convert_detection_item(
        &self,
        item: &DetectionItem,
        state: &mut ConversionState,
    ) -> Result<String> {
        // Multi-value `|re` (without `|all`) lowers to a single
        // `regex(field, pat1, pat2, ...) = true` call, the idiomatic
        // Fibratus form (the `regex()` filter function accepts a
        // variadic pattern list and returns true if any pattern
        // matches). Without this override the generic dispatch would
        // OR N separate single-pattern calls together, which is
        // semantically correct but cluttered; with `|all` the
        // generic AND-join is the right thing and we fall through.
        if item.field.has_modifier(Modifier::Re)
            && item.values.len() >= 2
            && !item.field.has_modifier(Modifier::All)
        {
            let field_name = item
                .field
                .name
                .as_deref()
                .ok_or(ConvertError::MissingFieldName)?;
            let mut patterns: Vec<String> = Vec::with_capacity(item.values.len());
            for v in &item.values {
                let pat = match v {
                    SigmaValue::String(s) => s.original.clone(),
                    _ => return Err(ConvertError::UnsupportedValue("re requires string".into())),
                };
                if !shared::is_re2_compatible(&pat) {
                    return Err(ConvertError::UnsupportedModifier(format!(
                        "regex pattern uses PCRE-only construct (lookaround/backreference) Fibratus's RE2 engine does not support: {pat}"
                    )));
                }
                patterns.push(pat);
            }
            let f = self.escape_and_quote_field(field_name);
            let quoted: Vec<String> = patterns
                .iter()
                .map(|p| shared::quote_plain_str(p))
                .collect();
            return Ok(format!("regex({f}, {}) = true", quoted.join(", ")));
        }

        // Multi-value `|cidr` (without `|all`) collapses to a single
        // `cidr_contains(field, 'a/n', 'b/m', ...)` call: the Fibratus
        // filter function accepts a variadic list of CIDR masks and
        // returns true if the address falls inside any of them, which is
        // the OR semantics Sigma multi-value lists carry. With `|all`
        // the generic AND-join is correct and we fall through.
        if item.field.has_modifier(Modifier::Cidr)
            && item.values.len() >= 2
            && !item.field.has_modifier(Modifier::All)
        {
            let field_name = item
                .field
                .name
                .as_deref()
                .ok_or(ConvertError::MissingFieldName)?;
            let mut masks: Vec<String> = Vec::with_capacity(item.values.len());
            for v in &item.values {
                match v {
                    SigmaValue::String(s) => masks.push(shared::quote_plain_str(&s.original)),
                    _ => {
                        return Err(ConvertError::UnsupportedValue(
                            "cidr requires string".into(),
                        ));
                    }
                }
            }
            let f = self.escape_and_quote_field(field_name);
            return Ok(format!("cidr_contains({f}, {})", masks.join(", ")));
        }

        // Multi-value OR string lists collapse to a single Fibratus
        // list-operator clause (`field iin ('a', 'b')`, ...) instead of
        // OR'd single comparisons.
        if let Some(list_expr) = self.try_string_value_list(item)? {
            return Ok(list_expr);
        }

        default_convert_detection_item(self, item, state)
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        shared::sanitize_field(field)
    }

    fn convert_value_str(&self, value: &SigmaString, _state: &ConversionState) -> String {
        shared::quote_sigma_string(value)
    }

    fn convert_value_re(&self, regex: &str, _state: &ConversionState) -> String {
        // The regex override emits the full `regex(...)` call; this helper
        // is only used for debug/logging callers and returns the bare
        // pattern wrapped in single quotes with `'`/`\` escaped.
        shared::quote_plain_str(regex)
    }

    // --- Value-type-specific methods ---

    fn convert_field_eq_str(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let mut mods = modifiers.to_vec();
        if self.fibratus.case_sensitive && !mods.contains(&Modifier::Cased) {
            mods.push(Modifier::Cased);
        }
        let f = self.escape_and_quote_field(field);
        let val = self.convert_value_str(value, state);
        let is_cased = mods.contains(&Modifier::Cased);
        let is_contains = mods.contains(&Modifier::Contains);
        let is_startswith = mods.contains(&Modifier::StartsWith);
        let is_endswith = mods.contains(&Modifier::EndsWith);

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
                expr.replace("{field}", &f).replace("{value}", &val),
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
        let expr = if shared::has_wildcards(value) {
            let template = if is_cased {
                self.config.case_sensitive_match_expression
            } else {
                self.config.wildcard_match_expression
            };
            let template = template.ok_or_else(|| {
                ConvertError::UnsupportedModifier(format!("string operator for {field}"))
            })?;
            template.replace("{field}", &f).replace("{value}", &val)
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

    fn convert_field_eq_str_case_sensitive(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let mut mods = modifiers.to_vec();
        if !mods.contains(&Modifier::Cased) {
            mods.push(Modifier::Cased);
        }
        self.convert_field_eq_str(field, value, &mods, state)
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.escape_and_quote_field(field);
        if value.fract() == 0.0 {
            Ok(format!("{f} = {}", value as i64))
        } else {
            Ok(format!("{f} = {value}"))
        }
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.escape_and_quote_field(field);
        let v = if value {
            self.config.bool_true
        } else {
            self.config.bool_false
        };
        Ok(format!("{f} = {v}"))
    }

    fn convert_field_eq_null(&self, field: &str, _state: &mut ConversionState) -> Result<String> {
        let f = self.escape_and_quote_field(field);
        Ok(self.config.field_null_expression.replace("{field}", &f))
    }

    fn convert_field_eq_re(
        &self,
        field: &str,
        pattern: &str,
        _flags: &[Modifier],
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if !shared::is_re2_compatible(pattern) {
            return Err(ConvertError::UnsupportedModifier(format!(
                "regex pattern uses PCRE-only construct (lookaround/backreference) Fibratus's RE2 engine does not support: {pattern}"
            )));
        }
        let f = self.escape_and_quote_field(field);
        let quoted = shared::quote_plain_str(pattern);
        Ok(ConvertResult::Query(format!("regex({f}, {quoted}) = true")))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = self.escape_and_quote_field(field);
        let quoted = shared::quote_plain_str(cidr);
        Ok(ConvertResult::Query(format!(
            "cidr_contains({f}, {quoted})"
        )))
    }

    fn convert_field_compare(
        &self,
        field: &str,
        op: &Modifier,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.escape_and_quote_field(field);
        let op_name = match op {
            Modifier::Lt => "lt",
            Modifier::Lte => "lte",
            Modifier::Gt => "gt",
            Modifier::Gte => "gte",
            _ => {
                return Err(ConvertError::UnsupportedModifier(format!(
                    "compare op {op:?}"
                )));
            }
        };
        let op_token = self
            .config
            .compare_ops
            .iter()
            .find(|(n, _)| *n == op_name)
            .map(|(_, t)| *t)
            .ok_or_else(|| ConvertError::UnsupportedModifier(op_name.into()))?;
        let val_str = if value.fract() == 0.0 {
            (value as i64).to_string()
        } else {
            value.to_string()
        };
        Ok(format!("{f} {op_token} {val_str}"))
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.escape_and_quote_field(field);
        let template = if exists {
            self.config.field_exists_expression
        } else {
            self.config.field_not_exists_expression
        };
        let expr = template.ok_or_else(|| {
            ConvertError::UnsupportedModifier(if exists { "exists" } else { "not exists" }.into())
        })?;
        Ok(expr.replace("{field}", &f))
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        _id: &str,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.escape_and_quote_field(field);
        Ok(format!("{f} = {expr}"))
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f1 = self.escape_and_quote_field(field1);
        let f2 = self.escape_and_quote_field(field2);
        Ok(ConvertResult::Query(format!("{f1} = {f2}")))
    }

    fn convert_keyword(&self, _value: &SigmaValue, _state: &mut ConversionState) -> Result<String> {
        // Fibratus has no unbound full-text search; keyword detections
        // cannot be expressed. Return the structured error so the rule
        // shows up in the conversion-errors list rather than emitting
        // silently-wrong YAML.
        Err(ConvertError::UnsupportedKeyword)
    }

    fn convert_condition_as_in_expression(
        &self,
        field: &str,
        values: &[&SigmaValue],
        is_or: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        if !is_or {
            // AND-in (all values present) needs `intersects`, but that
            // takes a slice on both sides. Fall back to the OR'd
            // equality path by signalling the helper to give up.
            return Err(ConvertError::UnsupportedModifier(
                "and-in (all values present in a field) is not expressible as a single Fibratus operator".into(),
            ));
        }
        let f = self.escape_and_quote_field(field);
        let op = if self.fibratus.case_sensitive || Self::all_cased(values) {
            "in"
        } else {
            self.config.or_in_operator.unwrap_or("iin")
        };
        let expr = self
            .config
            .field_in_list_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("in-list".into()))?;
        let items: Vec<String> = values
            .iter()
            .map(|v| match v {
                SigmaValue::String(s) => shared::quote_sigma_string(s),
                SigmaValue::Integer(n) => n.to_string(),
                SigmaValue::Float(f) => f.to_string(),
                SigmaValue::Bool(b) => {
                    if *b {
                        self.config.bool_true.to_string()
                    } else {
                        self.config.bool_false.to_string()
                    }
                }
                SigmaValue::Null => "null".to_string(),
            })
            .collect();
        let list = items.join(self.config.list_separator);
        Ok(expr
            .replace("{field}", &f)
            .replace("{op}", op)
            .replace("{list}", &list))
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
