use std::collections::HashMap;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::*;

use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

// =============================================================================
// Token precedence
// =============================================================================

/// Boolean operator token type, used for precedence-aware grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TokenType {
    /// Highest precedence (binds tightest).
    NOT = 0,
    AND = 1,
    OR = 2,
}

// =============================================================================
// Backend trait
// =============================================================================

/// Core conversion trait.
///
/// Backends implement this to convert parsed Sigma AST nodes into
/// backend-native query strings. The trait operates on **parsed** types
/// from `rsigma-parser` because conversion needs the original field names,
/// modifiers, and values — not compiled matchers.
pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn formats(&self) -> &[(&str, &str)];

    fn default_format(&self) -> &str {
        "default"
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
    ) -> Result<Vec<String>>;

    // --- Condition tree dispatch ---

    fn convert_condition(
        &self,
        expr: &ConditionExpr,
        detections: &HashMap<String, Detection>,
        state: &mut ConversionState,
    ) -> Result<String>;

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String>;
    fn convert_condition_or(&self, exprs: &[String]) -> Result<String>;
    fn convert_condition_not(&self, expr: &str) -> Result<String>;

    // --- Detection item conversion ---

    fn convert_detection(&self, det: &Detection, state: &mut ConversionState) -> Result<String>;

    fn convert_detection_item(
        &self,
        item: &DetectionItem,
        state: &mut ConversionState,
    ) -> Result<String>;

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String;
    fn convert_value_str(&self, value: &SigmaString, state: &ConversionState) -> String;
    fn convert_value_re(&self, regex: &str, state: &ConversionState) -> String;

    // --- Value-type-specific methods ---

    fn convert_field_eq_str(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    fn convert_field_eq_str_case_sensitive(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: f64,
        state: &mut ConversionState,
    ) -> Result<String>;

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        state: &mut ConversionState,
    ) -> Result<String>;

    fn convert_field_eq_null(&self, field: &str, state: &mut ConversionState) -> Result<String>;

    fn convert_field_eq_re(
        &self,
        field: &str,
        pattern: &str,
        flags: &[Modifier],
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    fn convert_field_compare(
        &self,
        field: &str,
        op: &Modifier,
        value: f64,
        state: &mut ConversionState,
    ) -> Result<String>;

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        state: &mut ConversionState,
    ) -> Result<String>;

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        id: &str,
        state: &mut ConversionState,
    ) -> Result<String>;

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    fn convert_keyword(&self, value: &SigmaValue, state: &mut ConversionState) -> Result<String>;

    // --- IN-list optimization (optional) ---

    fn convert_condition_as_in_expression(
        &self,
        _field: &str,
        _values: &[&SigmaValue],
        _is_or: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        Err(ConvertError::UnsupportedModifier(
            "IN expression not supported".into(),
        ))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String>;

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        index: usize,
        state: &ConversionState,
        output_format: &str,
    ) -> Result<String>;

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String>;

    // --- Correlation rule conversion (optional) ---

    fn supports_correlation(&self) -> bool {
        false
    }

    fn convert_correlation_rule(
        &self,
        _rule: &CorrelationRule,
        _output_format: &str,
        _pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        Err(ConvertError::UnsupportedCorrelation(
            "correlation rules not supported by this backend".into(),
        ))
    }
}

// =============================================================================
// TextQueryConfig
// =============================================================================

/// Configuration tokens for text-based query backends.
///
/// Mirrors pySigma's `TextQueryBackend` class variables. Backends create a
/// `const` or `static` instance of this struct and delegate to the
/// `text_convert_*` free functions for the default conversion logic.
pub struct TextQueryConfig {
    // --- Precedence and grouping ---
    pub precedence: (TokenType, TokenType, TokenType),
    pub group_expression: &'static str,
    pub token_separator: &'static str,

    // --- Boolean operators ---
    pub and_token: &'static str,
    pub or_token: &'static str,
    pub not_token: &'static str,
    pub eq_token: &'static str,

    // --- Negation expressions ---
    pub not_eq_token: Option<&'static str>,
    pub eq_expression: Option<&'static str>,
    pub not_eq_expression: Option<&'static str>,
    pub convert_not_as_not_eq: bool,

    // --- Wildcards ---
    pub wildcard_multi: &'static str,
    pub wildcard_single: &'static str,

    // --- String quoting and escaping ---
    pub str_quote: &'static str,
    pub str_quote_pattern: Option<&'static str>,
    pub str_quote_pattern_negation: bool,
    pub escape_char: &'static str,
    pub add_escaped: &'static [&'static str],
    pub filter_chars: &'static [&'static str],

    // --- Field name quoting and escaping ---
    pub field_quote: Option<&'static str>,
    pub field_quote_pattern: Option<&'static str>,
    pub field_quote_pattern_negation: bool,
    pub field_escape: Option<&'static str>,
    pub field_escape_pattern: Option<&'static str>,

    // --- String match expressions ---
    pub startswith_expression: Option<&'static str>,
    pub not_startswith_expression: Option<&'static str>,
    pub startswith_expression_allow_special: bool,
    pub endswith_expression: Option<&'static str>,
    pub not_endswith_expression: Option<&'static str>,
    pub endswith_expression_allow_special: bool,
    pub contains_expression: Option<&'static str>,
    pub not_contains_expression: Option<&'static str>,
    pub contains_expression_allow_special: bool,
    pub wildcard_match_expression: Option<&'static str>,

    // --- Case-sensitive match expressions ---
    pub case_sensitive_match_expression: Option<&'static str>,
    pub case_sensitive_startswith_expression: Option<&'static str>,
    pub case_sensitive_endswith_expression: Option<&'static str>,
    pub case_sensitive_contains_expression: Option<&'static str>,

    // --- Regex ---
    pub re_expression: Option<&'static str>,
    pub not_re_expression: Option<&'static str>,
    pub re_escape_char: Option<&'static str>,
    pub re_escape: &'static [&'static str],
    pub re_escape_escape_char: Option<&'static str>,

    // --- CIDR ---
    pub cidr_expression: Option<&'static str>,
    pub not_cidr_expression: Option<&'static str>,

    // --- Null / field existence ---
    pub field_null_expression: &'static str,
    pub field_exists_expression: Option<&'static str>,
    pub field_not_exists_expression: Option<&'static str>,

    // --- Compare operators ---
    pub compare_op_expression: Option<&'static str>,
    pub compare_ops: &'static [(&'static str, &'static str)],

    // --- IN-list optimization ---
    pub convert_or_as_in: bool,
    pub convert_and_as_in: bool,
    pub in_expressions_allow_wildcards: bool,
    pub field_in_list_expression: Option<&'static str>,
    pub or_in_operator: Option<&'static str>,
    pub and_in_operator: Option<&'static str>,
    pub list_separator: &'static str,

    // --- Unbound/keyword ---
    pub unbound_value_str_expression: Option<&'static str>,
    pub unbound_value_num_expression: Option<&'static str>,
    pub unbound_value_re_expression: Option<&'static str>,

    // --- Field-to-field comparison ---
    pub field_eq_field_expression: Option<&'static str>,
    pub field_eq_field_escaping_quoting: bool,

    // --- Deferred query parts ---
    pub deferred_start: Option<&'static str>,
    pub deferred_separator: Option<&'static str>,
    pub deferred_only_query: &'static str,

    // --- Bool values ---
    pub bool_true: &'static str,
    pub bool_false: &'static str,

    // --- Query envelope ---
    pub query_expression: &'static str,
    pub state_defaults: &'static [(&'static str, &'static str)],
}

impl TextQueryConfig {
    /// Check if `inner` needs parenthesisation when nested inside `outer`.
    pub fn needs_grouping(&self, outer: TokenType, inner: TokenType) -> bool {
        let rank = |t: TokenType| -> u8 {
            if t == self.precedence.0 {
                0
            } else if t == self.precedence.1 {
                1
            } else {
                2
            }
        };
        rank(inner) > rank(outer)
    }
}

// =============================================================================
// Text-backend free functions
// =============================================================================

/// Escape and optionally quote a field name according to the config.
pub fn text_escape_and_quote_field(cfg: &TextQueryConfig, field: &str) -> String {
    let mut escaped = field.to_string();

    if let Some(esc) = cfg.field_escape
        && let Some(pat) = cfg.field_escape_pattern
        && let Ok(re) = regex::Regex::new(pat)
    {
        escaped = re
            .replace_all(&escaped, |_: &regex::Captures| esc)
            .to_string();
    }

    if let Some(quote) = cfg.field_quote {
        let should_quote = match cfg.field_quote_pattern {
            Some(pat) => {
                let matches = regex::Regex::new(pat)
                    .map(|re| re.is_match(&escaped))
                    .unwrap_or(false);
                if cfg.field_quote_pattern_negation {
                    !matches
                } else {
                    matches
                }
            }
            None => true,
        };
        if should_quote {
            return format!("{quote}{escaped}{quote}");
        }
    }

    escaped
}

/// Convert a `SigmaString` to its text representation, applying escaping and quoting.
pub fn text_convert_value_str(cfg: &TextQueryConfig, value: &SigmaString) -> String {
    let mut result = String::new();
    let mut has_wildcards = false;

    for part in &value.parts {
        match part {
            StringPart::Plain(s) => {
                let mut escaped = String::with_capacity(s.len());
                for ch in s.chars() {
                    let ch_str = ch.to_string();
                    if cfg.filter_chars.contains(&ch_str.as_str()) {
                        continue;
                    }
                    if ch_str == cfg.escape_char
                        || ch_str == cfg.str_quote
                        || cfg.add_escaped.contains(&ch_str.as_str())
                    {
                        escaped.push_str(cfg.escape_char);
                    }
                    escaped.push(ch);
                }
                result.push_str(&escaped);
            }
            StringPart::Special(SpecialChar::WildcardMulti) => {
                result.push_str(cfg.wildcard_multi);
                has_wildcards = true;
            }
            StringPart::Special(SpecialChar::WildcardSingle) => {
                result.push_str(cfg.wildcard_single);
                has_wildcards = true;
            }
        }
    }

    if !has_wildcards {
        let should_quote = match cfg.str_quote_pattern {
            Some(pat) => {
                let matches = regex::Regex::new(pat)
                    .map(|re| re.is_match(&result))
                    .unwrap_or(false);
                if cfg.str_quote_pattern_negation {
                    !matches
                } else {
                    matches
                }
            }
            None => true,
        };
        if should_quote {
            return format!("{}{result}{}", cfg.str_quote, cfg.str_quote);
        }
    }

    result
}

/// Escape a regex pattern according to the config.
pub fn text_convert_value_re(cfg: &TextQueryConfig, regex_str: &str) -> String {
    let mut result = regex_str.to_string();

    if let Some(esc_esc) = cfg.re_escape_escape_char
        && let Some(esc) = cfg.re_escape_char
    {
        result = result.replace(esc, &format!("{esc_esc}{esc}"));
    }

    if let Some(esc) = cfg.re_escape_char {
        for pattern in cfg.re_escape {
            result = result.replace(pattern, &format!("{esc}{pattern}"));
        }
    }

    result
}

/// Precedence-aware grouping.
pub fn text_convert_condition_group(
    cfg: &TextQueryConfig,
    expr: &str,
    outer: TokenType,
    inner: TokenType,
) -> String {
    if cfg.needs_grouping(outer, inner) {
        cfg.group_expression.replace("{expr}", expr)
    } else {
        expr.to_string()
    }
}

/// Join expressions with the AND token.
pub fn text_convert_condition_and(cfg: &TextQueryConfig, exprs: &[String]) -> String {
    let sep = if cfg.and_token.is_empty() {
        cfg.token_separator.to_string()
    } else {
        format!(
            "{}{}{}",
            cfg.token_separator, cfg.and_token, cfg.token_separator
        )
    };
    exprs.join(&sep)
}

/// Join expressions with the OR token.
pub fn text_convert_condition_or(cfg: &TextQueryConfig, exprs: &[String]) -> String {
    let sep = format!(
        "{}{}{}",
        cfg.token_separator, cfg.or_token, cfg.token_separator
    );
    exprs.join(&sep)
}

/// Negate an expression with the NOT token.
pub fn text_convert_condition_not(cfg: &TextQueryConfig, expr: &str) -> String {
    format!("{}{}{expr}", cfg.not_token, cfg.token_separator)
}

/// Assemble the final query from the main condition string and any deferred parts.
pub fn text_finish_query(
    cfg: &TextQueryConfig,
    query: &str,
    state: &ConversionState,
    rule: &SigmaRule,
) -> String {
    let main_query = if state.has_deferred() && query.is_empty() {
        cfg.deferred_only_query
    } else {
        query
    };

    let mut result = cfg.query_expression.replace("{query}", main_query);

    // Substitute state defaults first, then actual state values
    for (key, default) in cfg.state_defaults {
        let placeholder = format!("{{{key}}}");
        result = result.replace(&placeholder, default);
    }
    for (key, val) in &state.processing_state {
        if let Some(s) = val.as_str() {
            let placeholder = format!("{{{key}}}");
            result = result.replace(&placeholder, s);
        }
    }

    // Substitute rule metadata
    result = result.replace("{rule.title}", &rule.title);
    if let Some(id) = &rule.id {
        result = result.replace("{rule.id}", id);
    }

    // Append deferred parts
    if state.has_deferred() {
        let deferred_start = cfg.deferred_start.unwrap_or("");
        let deferred_sep = cfg.deferred_separator.unwrap_or("");
        let parts: Vec<String> = state.deferred.iter().map(|d| d.finalize()).collect();
        result = format!("{result}{deferred_start}{}", parts.join(deferred_sep));
    }

    result
}

/// Dispatch string matching based on modifiers and wildcard positions.
///
/// Returns the query fragment for a field=value comparison, handling
/// `contains`, `startswith`, `endswith`, and wildcard patterns.
pub fn text_convert_field_eq_str(
    cfg: &TextQueryConfig,
    field: &str,
    value: &SigmaString,
    modifiers: &[Modifier],
    _state: &ConversionState,
) -> Result<ConvertResult> {
    let escaped_field = text_escape_and_quote_field(cfg, field);
    let is_cased = modifiers.contains(&Modifier::Cased);
    let is_contains = modifiers.contains(&Modifier::Contains);
    let is_startswith = modifiers.contains(&Modifier::StartsWith);
    let is_endswith = modifiers.contains(&Modifier::EndsWith);

    let value_str = text_convert_value_str(cfg, value);

    // Case-sensitive dispatch
    if is_cased {
        if is_contains && let Some(expr) = cfg.case_sensitive_contains_expression {
            return Ok(ConvertResult::Query(
                expr.replace("{field}", &escaped_field)
                    .replace("{value}", &value_str),
            ));
        }
        if is_startswith && let Some(expr) = cfg.case_sensitive_startswith_expression {
            return Ok(ConvertResult::Query(
                expr.replace("{field}", &escaped_field)
                    .replace("{value}", &value_str),
            ));
        }
        if is_endswith && let Some(expr) = cfg.case_sensitive_endswith_expression {
            return Ok(ConvertResult::Query(
                expr.replace("{field}", &escaped_field)
                    .replace("{value}", &value_str),
            ));
        }
        if let Some(expr) = cfg.case_sensitive_match_expression {
            return Ok(ConvertResult::Query(
                expr.replace("{field}", &escaped_field)
                    .replace("{value}", &value_str),
            ));
        }
    }

    // Case-insensitive dispatch (default)
    if is_contains && let Some(expr) = cfg.contains_expression {
        return Ok(ConvertResult::Query(
            expr.replace("{field}", &escaped_field)
                .replace("{value}", &value_str),
        ));
    }
    if is_startswith && let Some(expr) = cfg.startswith_expression {
        return Ok(ConvertResult::Query(
            expr.replace("{field}", &escaped_field)
                .replace("{value}", &value_str),
        ));
    }
    if is_endswith && let Some(expr) = cfg.endswith_expression {
        return Ok(ConvertResult::Query(
            expr.replace("{field}", &escaped_field)
                .replace("{value}", &value_str),
        ));
    }

    // Wildcard match fallback
    if value.contains_wildcards()
        && let Some(expr) = cfg.wildcard_match_expression
    {
        return Ok(ConvertResult::Query(
            expr.replace("{field}", &escaped_field)
                .replace("{value}", &value_str),
        ));
    }

    // Exact match (default)
    let result = if let Some(expr) = cfg.eq_expression {
        expr.replace("{field}", &escaped_field)
            .replace("{value}", &value_str)
    } else {
        format!("{escaped_field}{}{value_str}", cfg.eq_token)
    };
    Ok(ConvertResult::Query(result))
}
