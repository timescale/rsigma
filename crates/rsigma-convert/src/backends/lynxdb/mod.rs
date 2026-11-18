//! LynxDB conversion backend.
//!
//! Generates [LynxDB](https://github.com/lynxbase/lynxdb) SPL2-compatible
//! queries from Sigma rules. A rule renders as a `search` predicate when every
//! part of it is one LynxDB's inverted-index search matches exactly, and as a
//! `where` expression otherwise:
//!
//! - `search` binds `NOT` tightest, then `OR`, then `AND` (OR binds tighter
//!   than AND), matches case-insensitively, and has only the `*` wildcard.
//!   It matches through tokens, so values outside a small character set
//!   (`/`, `>`, quotes, brackets, and others), `?`, a literal `*`, a `*`
//!   between literals, and quoted `CASE()` values do not match exactly.
//! - `where` uses standard precedence and evaluates the actual values: strings
//!   through `match()` regexes, anchored except for `contains` and keywords, numeric comparisons through
//!   `tonumber()`, CIDR through `cidrmatch()`, and null, empty strings, and
//!   `exists` through the event's raw JSON (columns store `""` as null).
//!   Regexes, CIDR, `null`, `cased`, numeric comparisons, and any string value
//!   `search` cannot match exactly put the whole rule in `where`.

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::{IrPattern, IrPatternPart, IrStrOp, NumericLiteral};
use rsigma_parser::*;

use crate::backend::*;
use crate::condition_ir::{condition_state, convert_ir_condition, lower_rule_for_conversion};
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

// =============================================================================
// LynxDB config
// =============================================================================

const SEARCH_CONFIG: TextQueryConfig = TextQueryConfig {
    // LynxDB search binds NOT tightest, then OR, then AND loosest.
    precedence: (TokenType::NOT, TokenType::OR, TokenType::AND),
    group_expression: "({expr})",
    token_separator: " ",

    and_token: "AND",
    or_token: "OR",
    not_token: "NOT",
    eq_token: "=",

    not_eq_token: Some("!="),
    eq_expression: None,
    not_eq_expression: None,
    convert_not_as_not_eq: false,

    // Only `*` is a search wildcard; a pattern with `?` renders in `where`.
    wildcard_multi: "*",
    wildcard_single: "*",

    str_quote: "\"",
    str_quote_pattern: None,
    str_quote_pattern_negation: false,
    escape_char: "\\",
    add_escaped: &[],
    filter_chars: &[],

    // LynxDB field names are bare identifiers; no quoting needed.
    field_quote: None,
    field_quote_pattern: None,
    field_quote_pattern_negation: false,
    field_escape: None,
    field_escape_pattern: None,

    // LynxDB search predicates use glob `*` for contains/startswith/endswith.
    startswith_expression: Some("{field}={value}*"),
    not_startswith_expression: None,
    startswith_expression_allow_special: false,
    endswith_expression: Some("{field}=*{value}"),
    not_endswith_expression: None,
    endswith_expression_allow_special: false,
    contains_expression: Some("{field}=*{value}*"),
    not_contains_expression: None,
    contains_expression_allow_special: false,
    wildcard_match_expression: None,

    case_sensitive_match_expression: None,
    case_sensitive_startswith_expression: None,
    case_sensitive_endswith_expression: None,
    case_sensitive_contains_expression: None,

    re_expression: None,
    not_re_expression: None,
    re_escape_char: Some("\\"),
    re_escape: &[],
    re_escape_escape_char: None,

    cidr_expression: None,
    not_cidr_expression: None,

    field_null_expression: "isnull({field})",
    field_exists_expression: Some("{field}=*"),
    field_not_exists_expression: Some("NOT {field}=*"),

    compare_op_expression: Some("coalesce(tonumber({field}){op}{value}, false)"),
    compare_ops: &[("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")],

    convert_or_as_in: true,
    convert_and_as_in: false,
    in_expressions_allow_wildcards: false,
    field_in_list_expression: Some("{field} IN ({list})"),
    or_in_operator: Some("IN"),
    and_in_operator: None,
    list_separator: ", ",

    unbound_value_str_expression: Some("{value}"),
    unbound_value_num_expression: Some("{value}"),
    unbound_value_re_expression: None,

    field_eq_field_expression: None,
    field_eq_field_escaping_quoting: false,

    deferred_start: None,
    deferred_separator: None,
    deferred_only_query: "*",

    bool_true: "true",
    bool_false: "false",

    query_expression: "FROM {index} | search {query}",
    state_defaults: &[("index", "main")],
};

static LYNXDB_CONFIG: TextQueryConfig = SEARCH_CONFIG;

static LYNXDB_WHERE_CONFIG: TextQueryConfig = TextQueryConfig {
    // `where` expressions use standard precedence.
    precedence: (TokenType::NOT, TokenType::AND, TokenType::OR),
    query_expression: "FROM {index} | where {query}",
    ..SEARCH_CONFIG
};

/// Set in a condition's state when a part of it cannot render in `search`.
const NEEDS_WHERE: &str = "_lynxdb_needs_where";

/// Characters a `search` value matches exactly, as verified against LynxDB
/// on the SigmaHQ corpus.
fn search_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " .-_:\\".contains(c)
}

/// Whether `search` matches the pattern exactly: case-insensitive, at least
/// one literal character, only safe characters, and `*` only at the start or
/// end (a wildcard between literals misses values containing `/`).
fn search_safe(pattern: &IrPattern, case_insensitive: bool) -> bool {
    let last = pattern.parts.len().saturating_sub(1);
    case_insensitive
        && pattern
            .parts
            .iter()
            .any(|p| matches!(p, IrPatternPart::Literal(s) if !s.is_empty()))
        && pattern.parts.iter().enumerate().all(|(i, p)| match p {
            IrPatternPart::Literal(s) => s.chars().all(search_safe_char),
            IrPatternPart::WildcardMulti => i == 0 || i == last,
            IrPatternPart::WildcardSingle => false,
        })
}

/// Split the outer `*` wildcards off a `search`-safe pattern, returning the
/// operator they amount to and the literal between them. `search` splits a
/// bare value at a space and keeps a backslash escaped, so the literal must
/// render quoted, with the wildcards outside the quotes.
fn search_literal(op: IrStrOp, pattern: &IrPattern) -> (IrStrOp, IrPattern) {
    let leading = matches!(pattern.parts.first(), Some(IrPatternPart::WildcardMulti));
    let trailing = pattern.parts.len() > 1
        && matches!(pattern.parts.last(), Some(IrPatternPart::WildcardMulti));
    let parts: Vec<IrPatternPart> = pattern
        .parts
        .iter()
        .filter(|p| !matches!(p, IrPatternPart::WildcardMulti))
        .cloned()
        .collect();
    let op = match (op, leading, trailing) {
        (IrStrOp::Exact, true, true) => IrStrOp::Contains,
        (IrStrOp::Exact, true, false) => IrStrOp::EndsWith,
        (IrStrOp::Exact, false, true) => IrStrOp::StartsWith,
        (IrStrOp::StartsWith, true, _) | (IrStrOp::EndsWith, _, true) => IrStrOp::Contains,
        (op, _, _) => op,
    };
    (op, IrPattern { parts })
}

/// Quote a string as a LynxDB string literal.
fn quote_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The regex a Sigma pattern matches, anchored for `op`. Wildcards match a
/// line break, as in the rsigma engine. `raw_json` escapes literals the way
/// they appear in an event's raw JSON text.
fn pattern_regex(
    pattern: &IrPattern,
    op: IrStrOp,
    case_insensitive: bool,
    raw_json: bool,
) -> String {
    let has_wildcard = pattern
        .parts
        .iter()
        .any(|p| !matches!(p, IrPatternPart::Literal(_)));
    let flags = match (case_insensitive, has_wildcard) {
        (true, true) => "(?is)",
        (true, false) => "(?i)",
        (false, true) => "(?s)",
        (false, false) => "",
    };
    let mut re = flags.to_string();
    if matches!(op, IrStrOp::Exact | IrStrOp::StartsWith) {
        re.push('^');
    }
    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(s) if raw_json => re.push_str(&regex::escape(&json_escape(s))),
            // Inside a JSON string, so a wildcard cannot run into the next
            // value, and `?` covers a whole escape sequence.
            IrPatternPart::WildcardMulti if raw_json => re.push_str(r#"(?:[^"\\]|\\.)*"#),
            IrPatternPart::WildcardSingle if raw_json => {
                re.push_str(r#"(?:[^"\\]|\\u[0-9a-fA-F]{4}|\\.)"#)
            }
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

/// A string as serde_json writes it inside a JSON string: `"`, `\`, and
/// control characters escaped, everything else verbatim.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A field name as a bare LynxDB identifier: a letter or `_`, then letters,
/// digits, `_`, `.`, `:`, or `-`. LynxDB has no quoted identifier syntax, so a
/// name its lexer would not read as one identifier is rejected.
fn field_ident(field: &str) -> Result<&str> {
    let mut chars = field.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c));
    if valid {
        Ok(field)
    } else {
        Err(ConvertError::RuleConversion(format!(
            "invalid LynxDB field name: {field}"
        )))
    }
}

/// The field as read from the event's raw JSON. Columns store an empty string
/// as null, while the raw JSON keeps the two apart.
fn raw_field(field: &str) -> String {
    format!("json_extract(_raw, {})", quote_str(field))
}

// =============================================================================
// LynxDbBackend
// =============================================================================

pub struct LynxDbBackend {
    config: &'static TextQueryConfig,
    where_mode: bool,
}

impl LynxDbBackend {
    pub fn new() -> Self {
        Self {
            config: &LYNXDB_CONFIG,
            where_mode: false,
        }
    }

    fn where_backend() -> Self {
        Self {
            config: &LYNXDB_WHERE_CONFIG,
            where_mode: true,
        }
    }

    /// In `search` mode, record that the condition needs `where` and return a
    /// placeholder; the condition is converted again in `where` mode.
    fn needs_where(&self, state: &mut ConversionState) -> Option<String> {
        if self.where_mode {
            return None;
        }
        state
            .processing_state
            .insert(NEEDS_WHERE.to_string(), true.into());
        Some(String::new())
    }
}

impl Default for LynxDbBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for LynxDbBackend {
    fn name(&self) -> &str {
        "lynxdb"
    }

    fn formats(&self) -> &[(&str, &str)] {
        &[
            (
                "default",
                "full query: FROM <index> | search ..., or FROM <index> | where ...",
            ),
            (
                "minimal",
                "search expression only (no FROM prefix); * | where ... for a where query",
            ),
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
        let ir = lower_rule_for_conversion(rule)?;
        let where_backend = Self::where_backend();
        let mut queries = Vec::with_capacity(ir.conditions.len());
        for (idx, cond) in ir.conditions.iter().enumerate() {
            let mut backend = self;
            let mut state = condition_state(pipeline_state, output_format);
            let mut query = convert_ir_condition(self, cond, &ir.detections, &mut state)?;
            if state.processing_state.contains_key(NEEDS_WHERE) {
                backend = &where_backend;
                state = condition_state(pipeline_state, output_format);
                query = convert_ir_condition(backend, cond, &ir.detections, &mut state)?;
            }
            let finished = backend.finish_query(rule, query, &state)?;
            queries.push(backend.finalize_query(rule, finished, idx, &state, output_format)?);
        }
        Ok(queries)
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
        Ok(text_convert_condition_or(self.config, &non_empty))
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(text_convert_condition_not(self.config, expr))
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        Ok(text_convert_condition_group(
            self.config,
            expr,
            outer,
            inner,
        ))
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        text_escape_and_quote_field(self.config, field)
    }

    // --- Value-type-specific leaves (IR-native) ---

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if !self.where_mode && search_safe(pattern, case_insensitive) {
            let (op, literal) = search_literal(op, pattern);
            let field = field_ident(field)?;
            return text_convert_field_str_ir(self.config, field, op, &literal, case_insensitive);
        }
        if let Some(placeholder) = self.needs_where(state) {
            return Ok(ConvertResult::Query(placeholder));
        }
        let empty = pattern
            .parts
            .iter()
            .all(|p| matches!(p, IrPatternPart::Literal(s) if s.is_empty()));
        if op == IrStrOp::Exact && empty {
            return Ok(ConvertResult::Query(format!(
                "coalesce({}=\"\", false)",
                raw_field(field)
            )));
        }
        let f = field_ident(field)?;
        let re = pattern_regex(pattern, op, case_insensitive, false);
        Ok(ConvertResult::Query(format!(
            "match({f}, {})",
            quote_str(&re)
        )))
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = field_ident(field)?;
        let v = value.to_string();
        if self.where_mode {
            Ok(format!("coalesce(tonumber({f})={v}, false)"))
        } else {
            Ok(format!("{f}={v}"))
        }
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = field_ident(field)?;
        if self.where_mode {
            return Ok(format!("match({f}, \"(?i)^{value}$\")"));
        }
        Ok(format!("{f}={value}"))
    }

    fn convert_field_eq_null(&self, field: &str, state: &mut ConversionState) -> Result<String> {
        if let Some(placeholder) = self.needs_where(state) {
            return Ok(placeholder);
        }
        Ok(format!("isnull({})", raw_field(field)))
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if let Some(placeholder) = self.needs_where(state) {
            return Ok(ConvertResult::Query(placeholder));
        }
        let f = field_ident(field)?;
        let re = format!("{}{pattern}", flags.inline_prefix());
        Ok(ConvertResult::Query(format!(
            "match({f}, {})",
            quote_str(&re)
        )))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        if let Some(placeholder) = self.needs_where(state) {
            return Ok(ConvertResult::Query(placeholder));
        }
        let f = field_ident(field)?;
        Ok(ConvertResult::Query(format!(
            "cidrmatch({}, {f})",
            quote_str(cidr)
        )))
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        if let Some(placeholder) = self.needs_where(state) {
            return Ok(placeholder);
        }
        let f = field_ident(field)?;
        let op_token = match op {
            CompareOp::Lt => "<",
            CompareOp::Lte => "<=",
            CompareOp::Gt => ">",
            CompareOp::Gte => ">=",
        };
        let expr = self
            .config
            .compare_op_expression
            .ok_or_else(|| ConvertError::UnsupportedModifier("compare".into()))?;
        Ok(expr
            .replace("{field}", f)
            .replace("{op}", op_token)
            .replace("{value}", &value.to_string()))
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        if self.where_mode {
            // `where` cannot tell a null value from an absent field.
            let check = if exists { "isnotnull" } else { "isnull" };
            return Ok(format!("{check}({})", raw_field(field)));
        }
        let f = field_ident(field)?;
        let expr = if exists {
            self.config.field_exists_expression
        } else {
            self.config.field_not_exists_expression
        };
        let expr = expr.ok_or_else(|| ConvertError::UnsupportedModifier("exists".into()))?;
        Ok(expr.replace("{field}", f))
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        _id: &str,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = field_ident(field)?;
        Ok(format!("{f}={expr}"))
    }

    fn convert_field_ref(
        &self,
        _field1: &str,
        _field2: &str,
        _op: IrStrOp,
        _case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        Err(ConvertError::UnsupportedModifier(
            "field-to-field comparison not supported by LynxDB backend".into(),
        ))
    }

    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        state: &mut ConversionState,
    ) -> Result<String> {
        if !search_safe(pattern, true)
            && let Some(placeholder) = self.needs_where(state)
        {
            return Ok(placeholder);
        }
        if self.where_mode {
            let re = pattern_regex(pattern, IrStrOp::Contains, true, true);
            return Ok(format!("match(_raw, {})", quote_str(&re)));
        }
        // A keyword already matches as a substring, so outer wildcards add
        // nothing.
        let (_, literal) = search_literal(IrStrOp::Contains, pattern);
        let v = text_convert_ir_pattern(self.config, &literal);
        let expr = self
            .config
            .unbound_value_str_expression
            .ok_or(ConvertError::UnsupportedKeyword)?;
        Ok(expr.replace("{value}", &v))
    }

    fn convert_keyword_num(
        &self,
        value: NumericLiteral,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let s = value.to_string();
        if self.where_mode {
            return Ok(format!("match(_raw, {})", quote_str(&regex::escape(&s))));
        }
        let expr = self
            .config
            .unbound_value_num_expression
            .ok_or(ConvertError::UnsupportedKeyword)?;
        Ok(expr.replace("{value}", &s))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        // Pipeline-provided values (e.g. `index`) override the defaults
        // ("main"), unlike the generic `text_finish_query`.
        Ok(render_query_template(
            self.config.query_expression,
            |key| match key {
                "query" => Some(query.clone()),
                "rule.title" => Some(rule.title.clone()),
                "rule.id" => rule.id.clone(),
                _ => state
                    .processing_state
                    .get(key)
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        self.config
                            .state_defaults
                            .iter()
                            .find(|(k, _)| *k == key)
                            .map(|(_, v)| *v)
                    })
                    .map(str::to_string),
            },
        ))
    }

    fn finalize_query(
        &self,
        _rule: &SigmaRule,
        query: String,
        _index: usize,
        state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        match output_format {
            "default" => Ok(query),
            "minimal" => {
                let index = state
                    .processing_state
                    .get("index")
                    .and_then(|v| v.as_str())
                    .unwrap_or("main");
                let stage = if self.where_mode { "where" } else { "search" };
                let Some(expr) = query.strip_prefix(&format!("FROM {index} | {stage} ")) else {
                    return Ok(query);
                };
                Ok(if self.where_mode {
                    format!("* | where {expr}")
                } else {
                    expr.to_string()
                })
            }
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    fn finalize_output(&self, queries: Vec<String>, _output_format: &str) -> Result<String> {
        Ok(queries.join("\n"))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn convert(yaml: &str) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = LynxDbBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "default", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    #[test]
    fn positional_index_is_unsupported() {
        // SPL2 supports array indices via `mvindex`/bracket access, but the
        // LynxDB backend does not lower them yet; it must error rather than
        // emit a literal `args[0]` field reference.
        let collection = parse_sigma_yaml(
            r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[0]: 'cmd.exe'
    condition: selection
"#,
        )
        .unwrap();
        let backend = LynxDbBackend::new();
        let result =
            backend.convert_rule(&collection.rules[0], "default", &PipelineState::default());
        assert!(matches!(
            result,
            Err(ConvertError::UnsupportedArrayMatching)
        ));
    }

    #[test]
    fn array_object_scope_is_unsupported() {
        // LynxDB cannot express array object-scope matching; it must fail
        // loudly rather than emit a query with different semantics.
        let collection = parse_sigma_yaml(
            r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
    condition: selection
"#,
        )
        .unwrap();
        let backend = LynxDbBackend::new();
        let result =
            backend.convert_rule(&collection.rules[0], "default", &PipelineState::default());
        assert!(matches!(
            result,
            Err(ConvertError::UnsupportedArrayMatching)
        ));
    }

    fn convert_minimal(yaml: &str) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = LynxDbBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "minimal", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    fn convert_with_state(yaml: &str, state: PipelineState) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let backend = LynxDbBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend.convert_rule(rule, "default", &state).unwrap();
            results.extend(queries);
        }
        results
    }

    // --- Basic field equality ---

    #[test]
    fn field_eq_string() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: whoami
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search CommandLine=\"whoami\""]);
    }

    #[test]
    fn field_eq_numeric() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 4688
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search EventID=4688"]);
    }

    #[test]
    fn field_eq_boolean() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Enabled: true
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search Enabled=true"]);
    }

    #[test]
    fn field_eq_null() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: null
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where isnull(json_extract(_raw, \"FieldA\"))"]
        );
    }

    #[test]
    fn empty_string_reads_raw_json() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: ''
    condition: not selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where NOT coalesce(json_extract(_raw, \"FieldA\")=\"\", false)"]
        );
    }

    // --- Wildcards ---

    #[test]
    fn wildcard_contains() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: '*whoami*'
    condition: selection
"#,
        );
        assert_eq!(q, vec![r#"FROM main | search CommandLine=*"whoami"*"#]);
    }

    #[test]
    fn wildcard_startswith_modifier() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|startswith: cmd
    condition: selection
"#,
        );
        // startswith generates a trailing wildcard
        assert_eq!(q, vec!["FROM main | search CommandLine=\"cmd\"*"]);
    }

    #[test]
    fn wildcard_endswith_modifier() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|endswith: '.exe'
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search CommandLine=*\".exe\""]);
    }

    #[test]
    fn wildcard_contains_modifier() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search CommandLine=*\"whoami\"*"]);
    }

    // --- Boolean logic ---

    #[test]
    fn condition_and() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition: sel1 and sel2
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" AND FieldB=\"val2\""]
        );
    }

    #[test]
    fn condition_or() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition: sel1 or sel2
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" OR FieldB=\"val2\""]
        );
    }

    #[test]
    fn condition_not() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    filter:
        FieldB: val2
    condition: selection and not filter
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" AND NOT FieldB=\"val2\""]
        );
    }

    #[test]
    fn condition_grouping_and_inside_or() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    sel3:
        FieldC: val3
    condition: (sel1 and sel2) or sel3
"#,
        );
        // LynxDB's OR binds tighter than AND, so (sel1 AND sel2) needs parens
        assert_eq!(
            q,
            vec!["FROM main | search (FieldA=\"val1\" AND FieldB=\"val2\") OR FieldC=\"val3\""]
        );
    }

    #[test]
    fn condition_grouping_or_inside_and_is_bare() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    sel3:
        FieldC: val3
    condition: (sel1 or sel2) and sel3
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" OR FieldB=\"val2\" AND FieldC=\"val3\""]
        );
    }

    #[test]
    fn condition_grouping_not_over_or() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    filter_1:
        FieldB: val2
    filter_2:
        FieldC: val3
    condition: selection and not 1 of filter_*
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" AND NOT (FieldB=\"val2\" OR FieldC=\"val3\")"]
        );
    }

    #[test]
    fn condition_grouping_not_over_and() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    filter:
        FieldB: val2
        FieldC: val3
    condition: selection and not filter
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | search FieldA=\"val1\" AND NOT (FieldB=\"val2\" AND FieldC=\"val3\")"
            ]
        );
    }

    // --- Multiple values ---

    #[test]
    fn multiple_values_or() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine:
            - whoami
            - ipconfig
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search CommandLine=\"whoami\" OR CommandLine=\"ipconfig\""]
        );
    }

    #[test]
    fn multiple_values_all() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|all:
            - whoami
            - ipconfig
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search CommandLine=\"whoami\" AND CommandLine=\"ipconfig\""]
        );
    }

    #[test]
    fn multiple_fields_in_detection() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
        FieldB: val2
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | search FieldA=\"val1\" AND FieldB=\"val2\""]
        );
    }

    // --- Numeric comparisons ---

    #[test]
    fn compare_gte() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventCount|gte: 10
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where coalesce(tonumber(EventCount)>=10, false)"]
        );
    }

    #[test]
    fn compare_lt() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Duration|lt: 5
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where coalesce(tonumber(Duration)<5, false)"]
        );
    }

    // --- Regex ---

    #[test]
    fn regex_modifier() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re: '.*whoami.*'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where match(CommandLine, \".*whoami.*\")"]
        );
    }

    #[test]
    fn regex_flags_render_inline() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re|i|m: '^whoami$'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where match(CommandLine, \"(?im)^whoami$\")"]
        );
    }

    #[test]
    fn neq_negates_where_expressions() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re|neq: '.*whoami.*'
        SourceIP|cidr|neq: '10.0.0.0/8'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | where NOT match(CommandLine, \".*whoami.*\") AND NOT cidrmatch(\"10.0.0.0/8\", SourceIP)"
            ]
        );
    }

    // --- CIDR ---

    #[test]
    fn cidr_modifier() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        SourceIP|cidr: '10.0.0.0/8'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where cidrmatch(\"10.0.0.0/8\", SourceIP)"]
        );
    }

    // --- Field existence ---

    #[test]
    fn field_exists() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA|exists: true
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search FieldA=*"]);
    }

    #[test]
    fn field_not_exists() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA|exists: false
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | search NOT FieldA=*"]);
    }

    // --- Keywords (full-text search) ---

    #[test]
    fn keyword_search() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        - whoami
        - ipconfig
    condition: keywords
"#,
        );
        assert_eq!(q, vec!["FROM main | search \"whoami\" OR \"ipconfig\""]);
    }

    // --- Case-sensitive matching ---

    #[test]
    fn case_sensitive_eq() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|cased: Whoami
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec!["FROM main | where match(CommandLine, \"^Whoami$\")"]
        );
    }

    // --- Index from pipeline state ---

    #[test]
    fn custom_index_from_state() {
        let mut ps = PipelineState::default();
        ps.set_state(
            "index".to_string(),
            serde_json::Value::String("security_logs".into()),
        );
        let q = convert_with_state(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
            ps,
        );
        assert_eq!(q, vec!["FROM security_logs | search FieldA=\"val1\""]);
    }

    // --- Output formats ---

    #[test]
    fn minimal_format() {
        let q = convert_minimal(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FieldA=\"val1\""]);
    }

    // --- Multiple conditions ---

    #[test]
    fn multiple_conditions() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        FieldB: val2
    condition:
        - sel1
        - sel2
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | search FieldA=\"val1\"",
                "FROM main | search FieldB=\"val2\"",
            ]
        );
    }

    // --- Values search cannot match exactly ---

    #[test]
    fn regex_under_or_stays_inside_the_or() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: val1
    sel2:
        CommandLine|re: 'who.mi'
    condition: sel1 or sel2
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | where match(FieldA, \"(?i)^val1$\") OR match(CommandLine, \"who.mi\")"
            ]
        );
    }

    #[test]
    fn where_uses_standard_precedence() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    sel1:
        FieldA: a
    sel2:
        FieldB: b
    sel3:
        FieldC|cased: C
    condition: sel1 or sel2 and not sel3
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | where match(FieldA, \"(?i)^a$\") OR match(FieldB, \"(?i)^b$\") AND NOT match(FieldC, \"^C$\")"
            ]
        );
    }

    #[test]
    fn special_characters_render_as_anchored_regex() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: ' /q "a.b" '
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![r#"FROM main | where match(CommandLine, "(?i) /q \"a\\.b\" ")"#]
        );
    }

    #[test]
    fn single_wildcard_and_literal_star() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Image: 'c:\a?b\*x*'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![r#"FROM main | where match(Image, "(?is)^c:\\\\a.b\\*x.*$")"#]
        );
    }

    #[test]
    fn cased_contains_keeps_contains() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|cased: Whoami
    condition: selection
"#,
        );
        assert_eq!(q, vec!["FROM main | where match(CommandLine, \"Whoami\")"]);
    }

    #[test]
    fn keyword_in_where_matches_raw_json() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        - 'C:\Temp'
    selection:
        CommandLine|re: 'x'
    condition: keywords and selection
"#,
        );
        assert_eq!(
            q,
            vec![
                r#"FROM main | where match(_raw, "(?i)C:\\\\\\\\Temp") AND match(CommandLine, "x")"#
            ]
        );
    }

    #[test]
    fn keyword_with_slash_renders_in_where() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    keywords:
        - '/c whoami'
    condition: keywords
"#,
        );
        assert_eq!(q, vec!["FROM main | where match(_raw, \"(?i)/c whoami\")"]);
    }

    #[test]
    fn minimal_format_where() {
        let q = convert_minimal(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re: 'x'
    condition: selection
"#,
        );
        assert_eq!(q, vec!["* | where match(CommandLine, \"x\")"]);
    }

    // --- Mixed regex and normal fields ---

    #[test]
    fn regex_with_normal_fields() {
        let q = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        status: 500
        Path|re: '/api/.*'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![
                "FROM main | where coalesce(tonumber(status)=500, false) AND match(Path, \"/api/.*\")"
            ]
        );
    }

    #[test]
    fn search_quotes_literals_between_outer_wildcards() {
        let q = convert(
            r#"
title: T
logsource: { category: test }
detection:
    image:
        Image: '*\cmd.exe'
    cmd:
        CommandLine: '* -enc *'
    tool:
        Tool: 'net *'
    condition: image or cmd or tool
"#,
        );
        assert_eq!(
            q,
            vec![
                r#"FROM main | search Image=*"\\cmd.exe" OR CommandLine=*" -enc "* OR Tool="net "*"#
            ]
        );
    }

    #[test]
    fn search_keywords_drop_outer_wildcards() {
        let q = convert(
            r#"
title: T
logsource: { category: test }
detection:
    keywords:
        - '*foo*'
        - 'foo bar*'
    condition: keywords
"#,
        );
        assert_eq!(q, vec![r#"FROM main | search "foo" OR "foo bar""#]);
    }

    #[test]
    fn where_keywords_match_raw_json_text() {
        let q = convert(
            "title: T\nlogsource: { category: test }\ndetection:\n    keywords:\n        - \"a\\tb/\"\n        - 'foo*bar/'\n        - 'x?y/'\n    condition: keywords\n",
        );
        assert_eq!(
            q,
            vec![
                r#"FROM main | where match(_raw, "(?i)a\\\\tb/") OR match(_raw, "(?is)foo(?:[^\"\\\\]|\\\\.)*bar/") OR match(_raw, "(?is)x(?:[^\"\\\\]|\\\\u[0-9a-fA-F]{4}|\\\\.)y/")"#
            ]
        );
    }

    #[test]
    fn minimal_where_keeps_values_containing_search() {
        let q = convert_minimal(
            r#"
title: T
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: '| search x'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![r#"* | where match(CommandLine, "(?i)\\| search x")"#]
        );
    }

    #[test]
    fn large_numbers_keep_their_magnitude() {
        let num = |n: NumericLiteral| n.to_string();
        assert_eq!(num(4688.0.into()), "4688");
        assert_eq!(num(12345678901234567890.0.into()), "12345678901234567000");
        assert_eq!(num(1e300.into()), 1e300.to_string());
        assert_eq!(num(9007199254740993.into()), "9007199254740993");
    }

    // --- Field names and placeholders ---

    fn convert_err(yaml: &str) -> String {
        let collection = parse_sigma_yaml(yaml).unwrap();
        LynxDbBackend::new()
            .convert_rule(&collection.rules[0], "default", &PipelineState::default())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn rejects_field_names_outside_identifier_syntax() {
        for field in [
            "Image=* OR CommandLine",
            "{rule.title}",
            "a b",
            "x)",
            "\"x\"",
            "1abc",
            "café",
        ] {
            for value in ["whoami", "a/b"] {
                let yaml = format!(
                    "title: T\nlogsource: {{ category: test }}\ndetection:\n    selection:\n        '{field}': '{value}'\n    condition: selection\n"
                );
                assert_eq!(
                    convert_err(&yaml),
                    format!("rule conversion failed: invalid LynxDB field name: {field}"),
                    "field {field:?} with value {value:?}"
                );
            }
        }
    }

    #[test]
    fn accepts_dotted_colon_and_dash_field_names() {
        let q = convert(
            r#"
title: T
logsource: { category: test }
detection:
    selection:
        cs-uri-query: x
        winlog.event_data.Image: y
        ns:field: z
        _id: 1
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![
                r#"FROM main | search cs-uri-query="x" AND winlog.event_data.Image="y" AND ns:field="z" AND _id=1"#
            ]
        );
    }

    #[test]
    fn placeholder_in_regex_value_stays_literal() {
        let q = convert(
            r#"
title: 'x") OR true | stats count by host | where match(y, "'
id: 'x | stats count'
logsource: { category: test }
detection:
    selection:
        CommandLine|re: '{rule.title}'
        Image|re: '{rule.id}|{index}'
    condition: selection
"#,
        );
        assert_eq!(
            q,
            vec![
                r#"FROM main | where match(CommandLine, "{rule.title}") AND match(Image, "{rule.id}|{index}")"#
            ]
        );
    }
}
