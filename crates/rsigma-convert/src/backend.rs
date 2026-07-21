use std::collections::HashMap;
use std::sync::Mutex;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::{IrDetection, IrDetectionItem, IrPattern, IrPatternPart, IrStrOp};
use rsigma_parser::*;

use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

/// Process-wide cache for compiled regexes keyed by pattern string.
static REGEX_CACHE: Mutex<Option<HashMap<&'static str, regex::Regex>>> = Mutex::new(None);

fn get_cached_regex(pattern: &'static str) -> Option<regex::Regex> {
    let mut guard = REGEX_CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(re) = cache.get(pattern) {
        return Some(re.clone());
    }
    match regex::Regex::new(pattern) {
        Ok(re) => {
            cache.insert(pattern, re.clone());
            Some(re)
        }
        Err(_) => None,
    }
}

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

/// Numeric comparison operator for IR-native field comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

/// Regex match flags for [`Backend::convert_field_regex`].
///
/// `case_insensitive` is the `|i` flag; `cased` records the `|cased` modifier
/// (which some backends use to select a case-sensitive regex operator).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegexFlags {
    pub case_insensitive: bool,
    pub multiline: bool,
    pub dotall: bool,
    pub cased: bool,
}

/// Reconstruct a parser `SigmaString` from a faithful [`IrPattern`].
///
/// The canonical implementation lives in `rsigma-ir` (shared with the reverse
/// raise path); it is re-exported here so backends keep referring to
/// `crate::backend::ir_pattern_to_sigma`.
pub(crate) use rsigma_ir::ir_pattern_to_sigma;

// =============================================================================
// Backend trait
// =============================================================================

/// Core conversion trait.
///
/// Backends implement this to convert a rule's intermediate representation
/// (`rsigma-ir`) into backend-native query strings. The value leaves consume
/// the faithful HIR (`IrPattern`, `IrStrOp`, `IrNumber`, `RegexFlags`,
/// `CompareOp`) rather than parser types or compiled matchers, so a backend
/// never touches `rsigma-parser` to emit a value match.
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

    // --- Condition combinators ---

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String>;
    fn convert_condition_or(&self, exprs: &[String]) -> Result<String>;
    fn convert_condition_not(&self, expr: &str) -> Result<String>;

    /// Whether this backend can lower a positional array index (`field[N]`) in
    /// a field path. Backends that cannot must not silently emit a literal
    /// field reference (which would diverge from the evaluator's element-`N`
    /// semantics); the default item conversion rejects indexed fields with
    /// `UnsupportedArrayMatching`. PostgreSQL overrides this for JSONB mode.
    fn supports_field_index(&self) -> bool {
        false
    }

    // --- IR-native detection dispatch ---

    /// Convert a lowered [`IrDetection`] into a query fragment.
    fn convert_ir_detection(
        &self,
        det: &IrDetection,
        state: &mut ConversionState,
    ) -> Result<String> {
        crate::ir_convert::default_convert_ir_detection(self, det, state)
    }

    /// Convert a single lowered [`IrDetectionItem`] into a query fragment.
    fn convert_ir_detection_item(
        &self,
        item: &IrDetectionItem,
        state: &mut ConversionState,
    ) -> Result<String> {
        crate::ir_convert::default_convert_ir_detection_item(self, item, state)
    }

    /// Convert an array object-scope match (`field[any]:` / `field[all]:`) over
    /// a lowered body. Default reports the construct unsupported; JSONB-capable
    /// backends override it.
    fn convert_ir_array_match(
        &self,
        field: &str,
        quantifier: ArrayQuantifier,
        body: &IrDetection,
        state: &mut ConversionState,
    ) -> Result<String> {
        let _ = (field, quantifier, body, state);
        Err(ConvertError::UnsupportedArrayMatching)
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String;

    // --- Value-type-specific leaves (IR-native) ---
    //
    // These consume the faithful HIR (`IrPattern` / `IrStrOp` / flags) with no
    // parser types, so a backend (or a pack renderer) never touches
    // `rsigma-parser` to emit a value match.

    /// String match over a wildcard-aware, original-case pattern.
    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    /// Numeric equality.
    fn convert_field_eq_num(
        &self,
        field: &str,
        value: f64,
        state: &mut ConversionState,
    ) -> Result<String>;

    /// Boolean equality.
    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        state: &mut ConversionState,
    ) -> Result<String>;

    /// Null match.
    fn convert_field_eq_null(&self, field: &str, state: &mut ConversionState) -> Result<String>;

    /// Regex match with raw pattern and explicit [`RegexFlags`].
    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    /// CIDR containment match.
    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    /// Field existence / non-existence.
    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        state: &mut ConversionState,
    ) -> Result<String>;

    /// Backend-specific query-expression placeholder substitution.
    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        id: &str,
        state: &mut ConversionState,
    ) -> Result<String>;

    /// Field-to-field comparison (`|fieldref`).
    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult>;

    /// Numeric comparison (`gt`/`gte`/`lt`/`lte`).
    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: f64,
        state: &mut ConversionState,
    ) -> Result<String>;

    /// Keyword (unbound) string term over a wildcard-aware pattern.
    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        state: &mut ConversionState,
    ) -> Result<String>;

    /// Keyword (unbound) numeric term.
    fn convert_keyword_num(&self, value: f64, state: &mut ConversionState) -> Result<String>;

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

    /// File extension (no leading dot) for per-rule output files when
    /// `rsigma backend convert` writes one file per rule into a directory.
    ///
    /// The default is `txt`; backends override it so the split files land
    /// with the extension their target loader expects (`sql` for
    /// PostgreSQL, `yml` for Fibratus rule YAML). The `output_format`
    /// argument lets a backend pick a different extension per format (e.g.
    /// Fibratus emits `.txt` for the bare-expression `expr` format and
    /// `.yml` for the YAML rule envelope).
    fn output_file_extension(&self, _output_format: &str) -> &str {
        "txt"
    }

    // --- Correlation rule conversion (optional) ---

    fn supports_correlation(&self) -> bool {
        false
    }

    /// Correlation generation methods this backend offers, as
    /// `(name, description)` pairs, mirroring pySigma's `correlation_methods`.
    ///
    /// The converting user selects one with the `correlation_method` backend
    /// option, which overrides a rule's own `window` hint for that conversion.
    /// An empty slice (the default) means the backend exposes no per-conversion
    /// choice.
    fn correlation_methods(&self) -> &[(&str, &str)] {
        &[]
    }

    /// The correlation method used when the converting user selects none.
    fn default_correlation_method(&self) -> &str {
        "default"
    }

    /// Convert a correlation rule, discarding any non-fatal warnings.
    ///
    /// Convenience wrapper over [`convert_correlation_rule_with_warnings`]; the
    /// `convert_collection` entry point uses the warnings-aware form so it can
    /// surface diagnostics. Backends should override the warnings-aware method,
    /// not this one.
    ///
    /// [`convert_correlation_rule_with_warnings`]: Backend::convert_correlation_rule_with_warnings
    fn convert_correlation_rule(
        &self,
        rule: &CorrelationRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        self.convert_correlation_rule_with_warnings(
            rule,
            output_format,
            pipeline_state,
            &mut warnings,
        )
    }

    /// Convert a correlation rule, appending any non-fatal diagnostics to
    /// `warnings`.
    ///
    /// A backend pushes a warning when it can only approximate a requested
    /// feature but still emits a usable query (the Sigma "should warn" case),
    /// and returns [`ConvertError`] when a feature cannot be represented at all
    /// (the "must error" case).
    fn convert_correlation_rule_with_warnings(
        &self,
        _rule: &CorrelationRule,
        _output_format: &str,
        _pipeline_state: &PipelineState,
        _warnings: &mut Vec<String>,
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
        && let Some(re) = get_cached_regex(pat)
    {
        escaped = re
            .replace_all(&escaped, |_: &regex::Captures| esc)
            .to_string();
    }

    if let Some(quote) = cfg.field_quote {
        let should_quote = match cfg.field_quote_pattern {
            Some(pat) => {
                let matches = get_cached_regex(pat)
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

// =============================================================================
// IR-native text rendering
// =============================================================================
//
// These read the faithful `IrPattern` (wildcard-aware, original case) and an
// explicit `IrStrOp`, never a parser `SigmaString` + `&[Modifier]`. They are
// the rendering primitives the IR-native `Backend` leaves build on, so a
// backend never needs a parser type to emit a string match.

/// Convert an [`IrPattern`] to its text representation, applying escaping and
/// quoting.
pub fn text_convert_ir_pattern(cfg: &TextQueryConfig, pattern: &IrPattern) -> String {
    let mut result = String::new();
    let mut has_wildcards = false;

    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(s) => {
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
            IrPatternPart::WildcardMulti => {
                result.push_str(cfg.wildcard_multi);
                has_wildcards = true;
            }
            IrPatternPart::WildcardSingle => {
                result.push_str(cfg.wildcard_single);
                has_wildcards = true;
            }
        }
    }

    if !has_wildcards {
        let should_quote = match cfg.str_quote_pattern {
            Some(pat) => {
                let matches = get_cached_regex(pat)
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

/// Dispatch an IR string match (`op` + wildcard-aware `pattern`) to a query
/// fragment, with `op` and `case_insensitive` driving operator selection.
pub fn text_convert_field_str_ir(
    cfg: &TextQueryConfig,
    field: &str,
    op: IrStrOp,
    pattern: &IrPattern,
    case_insensitive: bool,
) -> Result<ConvertResult> {
    let escaped_field = text_escape_and_quote_field(cfg, field);
    let is_cased = !case_insensitive;
    let is_contains = op == IrStrOp::Contains;
    let is_startswith = op == IrStrOp::StartsWith;
    let is_endswith = op == IrStrOp::EndsWith;

    let value_str = text_convert_ir_pattern(cfg, pattern);

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

    if pattern.has_wildcards()
        && let Some(expr) = cfg.wildcard_match_expression
    {
        return Ok(ConvertResult::Query(
            expr.replace("{field}", &escaped_field)
                .replace("{value}", &value_str),
        ));
    }

    let result = if let Some(expr) = cfg.eq_expression {
        expr.replace("{field}", &escaped_field)
            .replace("{value}", &value_str)
    } else {
        format!("{escaped_field}{}{value_str}", cfg.eq_token)
    };
    Ok(ConvertResult::Query(result))
}
