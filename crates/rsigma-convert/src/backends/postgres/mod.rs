//! PostgreSQL/TimescaleDB backend for Sigma rule conversion.
//!
//! Converts Sigma detection rules into PostgreSQL SQL queries, leveraging
//! PostgreSQL-native features: `ILIKE` for case-insensitive matching,
//! `~*`/`~` for regex, `inet`/`cidr` for network address matching,
//! `tsvector`/`tsquery` for full-text keyword search, and JSONB for
//! semi-structured event data.

mod correlation;
mod jsonb;
mod select;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::{IrDetection, IrPattern, IrPatternPart, IrStrOp, NumericLiteral};
use rsigma_parser::*;

use crate::backend::*;
use crate::condition_ir::convert_rule_via_ir;
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

/// Conversion state key holding the unqualified table name of the rule, which
/// a keyword search over flat columns uses to reference the whole row.
const ROW_RELATION_STATE: &str = "_postgres_row_relation";

fn validate_sql_identifier(s: &str) -> Result<()> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_$]*$").unwrap());
    if RE.is_match(s) {
        Ok(())
    } else {
        Err(ConvertError::InvalidIdentifier(s.to_string()))
    }
}

/// One segment of a dotted field name: an identifier, optionally with a
/// leading `@` and hyphenated parts, as in `@timestamp` and `cs-method`.
fn is_field_key(s: &str) -> bool {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^@?[A-Za-z_][A-Za-z0-9_$]*(?:-[A-Za-z0-9_$]+)*$").unwrap());
    RE.is_match(s)
}

/// PostgreSQL keywords that cannot name a column, table, or schema without
/// quotes: the reserved and the type or function name categories of
/// `pg_get_keywords()` in PostgreSQL 18. Unquoted, `user` and `current_user`
/// read as the session user and `group` or `order` fail to parse. Sorted for
/// binary search.
const RESERVED_KEYWORDS: &[&str] = &[
    "all",
    "analyse",
    "analyze",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "asymmetric",
    "authorization",
    "binary",
    "both",
    "case",
    "cast",
    "check",
    "collate",
    "collation",
    "column",
    "concurrently",
    "constraint",
    "create",
    "cross",
    "current_catalog",
    "current_date",
    "current_role",
    "current_schema",
    "current_time",
    "current_timestamp",
    "current_user",
    "default",
    "deferrable",
    "desc",
    "distinct",
    "do",
    "else",
    "end",
    "except",
    "false",
    "fetch",
    "for",
    "foreign",
    "freeze",
    "from",
    "full",
    "grant",
    "group",
    "having",
    "ilike",
    "in",
    "initially",
    "inner",
    "intersect",
    "into",
    "is",
    "isnull",
    "join",
    "lateral",
    "leading",
    "left",
    "like",
    "limit",
    "localtime",
    "localtimestamp",
    "natural",
    "not",
    "notnull",
    "null",
    "offset",
    "on",
    "only",
    "or",
    "order",
    "outer",
    "overlaps",
    "placing",
    "primary",
    "references",
    "returning",
    "right",
    "select",
    "session_user",
    "similar",
    "some",
    "symmetric",
    "system_user",
    "table",
    "tablesample",
    "then",
    "to",
    "trailing",
    "true",
    "union",
    "unique",
    "user",
    "using",
    "variadic",
    "verbose",
    "when",
    "where",
    "window",
    "with",
];

fn is_reserved_keyword(name: &str) -> bool {
    RESERVED_KEYWORDS
        .binary_search(&name.to_ascii_lowercase().as_str())
        .is_ok()
}

/// A validated table or schema name. PostgreSQL folds an unquoted name to
/// lowercase, so a reserved word is quoted in its folded form to name the
/// same relation.
fn relation_ident(name: &str) -> Result<String> {
    validate_sql_identifier(name)?;
    Ok(if is_reserved_keyword(name) {
        format!("\"{}\"", name.to_ascii_lowercase())
    } else {
        name.to_string()
    })
}

/// Flatten a keyword [`IrPattern`] to its text form for full-text search,
/// rendering wildcards back to their literal `*`/`?` so `plainto_tsquery`
/// treats them as ordinary characters.
fn keyword_pattern_text(pattern: &IrPattern) -> String {
    let mut s = String::new();
    for part in &pattern.parts {
        match part {
            IrPatternPart::Literal(t) => s.push_str(t),
            IrPatternPart::WildcardMulti => s.push('*'),
            IrPatternPart::WildcardSingle => s.push('?'),
        }
    }
    s
}

/// Add PostgreSQL's `w` embedded option, which makes `^` and `$` match at
/// line breaks. PostgreSQL reads only one leading `(?...)` options group, so
/// the option joins an existing one.
fn with_newline_sensitive_option(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix("(?")
        && let Some(end) = rest.find(')')
        && end > 0
        && rest[..end].bytes().all(|b| b.is_ascii_alphabetic())
    {
        return format!("(?w{}", rest);
    }
    format!("(?w){pattern}")
}

// =============================================================================
// PostgreSQL TextQueryConfig
// =============================================================================

pub static POSTGRES_CONFIG: TextQueryConfig = TextQueryConfig {
    precedence: (TokenType::NOT, TokenType::AND, TokenType::OR),
    group_expression: "({expr})",
    token_separator: " ",

    and_token: "AND",
    or_token: "OR",
    not_token: "NOT",
    eq_token: " = ",

    not_eq_token: Some(" <> "),
    eq_expression: None,
    not_eq_expression: None,
    convert_not_as_not_eq: false,

    wildcard_multi: "%",
    wildcard_single: "_",

    str_quote: "'",
    str_quote_pattern: None,
    str_quote_pattern_negation: false,
    escape_char: "'",
    add_escaped: &[],
    filter_chars: &[],

    field_quote: Some("\""),
    field_quote_pattern: Some(r"^[a-z_][a-z0-9_]*$"),
    field_quote_pattern_negation: true,
    field_escape: Some("\"\""),
    field_escape_pattern: Some("\""),

    startswith_expression: Some("{field} ILIKE {value}"),
    not_startswith_expression: Some("{field} NOT ILIKE {value}"),
    startswith_expression_allow_special: false,
    endswith_expression: Some("{field} ILIKE {value}"),
    not_endswith_expression: Some("{field} NOT ILIKE {value}"),
    endswith_expression_allow_special: false,
    contains_expression: Some("{field} ILIKE {value}"),
    not_contains_expression: Some("{field} NOT ILIKE {value}"),
    contains_expression_allow_special: false,
    wildcard_match_expression: Some("{field} ILIKE {value}"),

    case_sensitive_match_expression: Some("{field} LIKE {value}"),
    case_sensitive_startswith_expression: Some("{field} LIKE {value}"),
    case_sensitive_endswith_expression: Some("{field} LIKE {value}"),
    case_sensitive_contains_expression: Some("{field} LIKE {value}"),

    re_expression: Some("{field} ~ {regex}"),
    not_re_expression: Some("{field} !~ {regex}"),
    re_escape_char: None,
    re_escape: &[],
    re_escape_escape_char: None,

    cidr_expression: Some("({field})::inet <<= {value}::cidr"),
    not_cidr_expression: Some("NOT (({field})::inet <<= {value}::cidr)"),

    field_null_expression: "{field} IS NULL",
    field_exists_expression: Some("{field} IS NOT NULL"),
    field_not_exists_expression: Some("{field} IS NULL"),

    compare_op_expression: Some("{field} {op} {value}"),
    compare_ops: &[("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")],

    convert_or_as_in: true,
    convert_and_as_in: false,
    in_expressions_allow_wildcards: false,
    field_in_list_expression: Some("{field} {op} ({list})"),
    or_in_operator: Some("IN"),
    and_in_operator: None,
    list_separator: ", ",

    unbound_value_str_expression: None,
    unbound_value_num_expression: None,
    unbound_value_re_expression: None,

    field_eq_field_expression: Some("{field1} = {field2}"),
    field_eq_field_startswith_expression: None,
    field_eq_field_endswith_expression: None,
    field_eq_field_contains_expression: None,
    field_eq_field_escaping_quoting: true,

    deferred_start: None,
    deferred_separator: None,
    deferred_only_query: "",

    bool_true: "true",
    bool_false: "false",
    query_expression: "SELECT * FROM {table} WHERE {query}",
    state_defaults: &[("table", "security_events")],
};

// =============================================================================
// PostgresBackend
// =============================================================================

/// PostgreSQL/TimescaleDB backend for Sigma rule conversion.
pub struct PostgresBackend {
    pub config: &'static TextQueryConfig,
    /// Default table name (overridden by pipeline state `table` key).
    pub table: String,
    /// Timestamp column name for time-windowed queries.
    pub timestamp_field: String,
    /// If set, fields are accessed via JSONB extraction (`metadata->>'fieldName'`).
    pub json_field: Option<String>,
    /// PostgreSQL schema name (e.g. `public`).
    pub schema: Option<String>,
    /// PostgreSQL database name (connection-level metadata, not used in queries).
    pub database: Option<String>,
    /// Enable TimescaleDB-specific features.
    pub timescaledb: bool,
    /// Correlation method selected via the `correlation_method` option
    /// (`sliding`/`tumbling`/`session`), mirroring pySigma's
    /// `correlation_methods`. `None` falls back to each rule's own `window`.
    pub correlation_method: Option<String>,
    /// Default session gap in seconds, from the `gap` option (e.g. `gap=5m`).
    /// Used when a session window is requested (via the rule or
    /// `correlation_method=session`) and the rule does not declare its own
    /// `gap`. A rule's own `gap` always wins.
    pub session_gap_secs: Option<u64>,
}

impl PostgresBackend {
    pub fn new() -> Self {
        Self {
            config: &POSTGRES_CONFIG,
            table: "security_events".to_string(),
            timestamp_field: "time".to_string(),
            json_field: None,
            schema: None,
            database: None,
            timescaledb: false,
            correlation_method: None,
            session_gap_secs: None,
        }
    }

    /// Create a backend from CLI-style key=value option pairs.
    ///
    /// Recognized keys: `table`, `schema`, `database`, `timestamp_field`,
    /// `json_field`, `correlation_method` (sliding/tumbling/session), `gap`
    /// (default session gap, e.g. `5m`).
    /// Unknown keys are silently ignored so forward-compatible options can be
    /// added without breaking existing invocations.
    pub fn from_options(options: &HashMap<String, String>) -> Self {
        let mut backend = Self::new();
        if let Some(v) = options.get("table") {
            backend.table = v.clone();
        }
        if let Some(v) = options.get("schema") {
            backend.schema = Some(v.clone());
        }
        if let Some(v) = options.get("database") {
            backend.database = Some(v.clone());
        }
        if let Some(v) = options.get("timestamp_field") {
            backend.timestamp_field = v.clone();
        }
        if let Some(v) = options.get("json_field") {
            backend.json_field = Some(v.clone());
        }
        if let Some(v) = options.get("correlation_method") {
            backend.correlation_method = Some(v.clone());
        }
        if let Some(v) = options.get("gap") {
            // Invalid durations are ignored here (consistent with the lenient
            // option handling above); the CLI validates the format up front.
            backend.session_gap_secs = Timespan::parse(v).ok().map(|t| t.seconds);
        }
        backend
    }

    /// Resolve the fully qualified table name `[schema.]table` using this
    /// precedence for each component:
    ///
    /// **table**: `custom_attributes["postgres.table"]` > `state["table"]` > `self.table`
    /// **schema**: `custom_attributes["postgres.schema"]` > `state["schema"]` > `self.schema`
    fn resolve_table(
        &self,
        custom_attrs: &HashMap<String, yaml_serde::Value>,
        state: &HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        let table = self.resolve_table_name(custom_attrs, state)?;

        let schema = custom_attrs
            .get("postgres.schema")
            .and_then(|v| v.as_str())
            .or(state.get("schema").and_then(|v| v.as_str()))
            .or(self.schema.as_deref())
            .filter(|s| !s.is_empty());

        if let Some(s) = schema {
            Ok(format!("{}.{table}", relation_ident(s)?))
        } else {
            Ok(table)
        }
    }

    /// The unqualified table name, with the same precedence as
    /// [`resolve_table`](Self::resolve_table), rendered for SQL.
    fn resolve_table_name(
        &self,
        custom_attrs: &HashMap<String, yaml_serde::Value>,
        state: &HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        let table = custom_attrs
            .get("postgres.table")
            .and_then(|v| v.as_str())
            .or(state.get("table").and_then(|v| v.as_str()))
            .unwrap_or(&self.table);
        relation_ident(table)
    }

    /// Text of the whole event for a keyword search: the JSONB column, or the
    /// table row referenced by its unqualified name.
    fn keyword_search_target(&self, state: &ConversionState) -> Result<String> {
        match &self.json_field {
            Some(json_col) => Ok(format!("{}::text", self.json_column(json_col)?)),
            None => {
                let row = match state.get_state_str(ROW_RELATION_STATE) {
                    Some(row) => row.to_string(),
                    None => relation_ident(&self.table)?,
                };
                Ok(format!("{row}::text"))
            }
        }
    }

    /// A column name as SQL: a plain lowercase name that is not a reserved
    /// word stays bare, and any other name is double-quoted with its case
    /// kept and `"` doubled.
    fn quote_column(&self, name: &str) -> Result<String> {
        if name.is_empty() || name.contains('\0') {
            return Err(ConvertError::InvalidIdentifier(name.to_string()));
        }
        let quoted = text_escape_and_quote_field(self.config, name);
        Ok(if quoted == name && is_reserved_keyword(name) {
            format!("\"{name}\"")
        } else {
            quoted
        })
    }

    /// The `json_field` column (or an array element alias) as SQL.
    fn json_column(&self, json_col: &str) -> Result<String> {
        validate_sql_identifier(json_col)?;
        self.quote_column(json_col)
    }

    /// The `timestamp_field` column as SQL, quoted the way field columns are.
    /// Fails with [`ConvertError::InvalidIdentifier`] when the option is not a
    /// plain SQL identifier.
    pub fn timestamp_column(&self) -> Result<String> {
        validate_sql_identifier(&self.timestamp_field)?;
        self.quote_column(&self.timestamp_field)
    }

    /// Qualify a raw table name with schema. Precedence:
    /// `per_rule_schema` > `state["schema"]` > `self.schema` > none.
    fn qualify_table_name(
        &self,
        table: &str,
        state: &HashMap<String, serde_json::Value>,
        per_rule_schema: Option<&str>,
    ) -> Result<String> {
        let table = relation_ident(table)?;

        let schema = per_rule_schema
            .or(state.get("schema").and_then(|v| v.as_str()))
            .or(self.schema.as_deref())
            .filter(|s| !s.is_empty());

        if let Some(s) = schema {
            Ok(format!("{}.{table}", relation_ident(s)?))
        } else {
            Ok(table)
        }
    }

    fn field_expr(&self, field: &str) -> Result<String> {
        match &self.json_field {
            // JSONB navigation, with text extraction (`->>`) on the final hop.
            // Supports dotted paths and positional `[N]` indices.
            Some(json_col) => jsonb::jsonb_path(&self.json_column(json_col)?, field, true),
            None => self.quote_column(field),
        }
    }

    /// A field as a JSONB value (`->` on every hop), which tells a JSON
    /// `null` from a missing key and feeds `jsonb_array_elements`.
    fn jsonb_value_expr(&self, json_col: &str, field: &str) -> Result<String> {
        jsonb::jsonb_path(&self.json_column(json_col)?, field, false)
    }

    /// Whether `field` holds text: a JSONB extraction, or the element alias of
    /// a scalar array, which `jsonb_array_elements_text` yields as text.
    fn is_text_field(&self, field: &str, state: &ConversionState) -> bool {
        self.json_field.is_some()
            || state
                .processing_state
                .get(jsonb::TEXT_ELEMENT_KEY)
                .and_then(|v| v.as_str())
                == Some(field)
    }

    /// A field as a number. Text is cast only when it reads as a number of
    /// bounded size, so a string such as `abc` or `9e999999` compares as NULL
    /// instead of failing the query, and a numeric string such as `"4"`
    /// matches as the engine does.
    fn numeric_expr(&self, field: &str, state: &ConversionState) -> Result<String> {
        self.numeric_field(field, self.is_text_field(field, state))
    }

    /// [`numeric_expr`](Self::numeric_expr) for a field known to hold text
    /// or not.
    fn numeric_field(&self, field: &str, is_text: bool) -> Result<String> {
        let f = self.field_expr(field)?;
        Ok(if is_text {
            format!(
                "(CASE WHEN {f} ~ '^[-+]?([0-9]{{1,100}}\\.?[0-9]{{0,100}}|\\.[0-9]{{1,100}})([eE][-+]?[0-9]{{1,3}})?$' \
                 THEN ({f})::numeric END)"
            )
        } else {
            f
        })
    }

    /// Escape a string value for use in a SQL single-quoted literal.
    /// PostgreSQL uses `''` to escape single quotes inside string literals.
    fn escape_sql_str(&self, s: &str) -> String {
        s.replace('\'', "''")
    }

    /// Build an [`IrPattern`] into a SQL string literal with proper escaping and
    /// wildcard translation for LIKE/ILIKE.
    fn build_like_value_ir(&self, pattern: &IrPattern) -> String {
        let mut result = String::with_capacity(pattern.parts.len() + 2);
        result.push('\'');
        for part in &pattern.parts {
            match part {
                IrPatternPart::Literal(s) => {
                    for ch in s.chars() {
                        match ch {
                            '\'' => result.push_str("''"),
                            '%' => result.push_str("\\%"),
                            '_' => result.push_str("\\_"),
                            '\\' => result.push_str("\\\\"),
                            _ => result.push(ch),
                        }
                    }
                }
                IrPatternPart::WildcardMulti => result.push('%'),
                IrPatternPart::WildcardSingle => result.push('_'),
            }
        }
        result.push('\'');
        result
    }

    /// Add `%` wildcards to a LIKE value based on modifier semantics.
    /// The value is already a quoted `'...'` string from `build_like_value`.
    fn wrap_like_wildcards(
        &self,
        quoted: &str,
        is_contains: bool,
        is_startswith: bool,
        is_endswith: bool,
    ) -> String {
        if !is_contains && !is_startswith && !is_endswith {
            return quoted.to_string();
        }
        let inner = &quoted[1..quoted.len() - 1];
        let prefix = if is_contains || is_endswith { "%" } else { "" };
        let suffix = if is_contains || is_startswith {
            "%"
        } else {
            ""
        };
        format!("'{prefix}{inner}{suffix}'")
    }

    /// Build a plain SQL string literal from an [`IrPattern`] (no wildcards).
    fn build_plain_value_ir(&self, pattern: &IrPattern) -> String {
        let plain = pattern.as_plain().unwrap_or_default();
        format!("'{}'", self.escape_sql_str(&plain))
    }
}

impl Default for PostgresBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Substring comparison of two SQL expressions. `strpos` and `right` keep
/// `%` and `_` inside the referenced value literal, unlike `LIKE`.
fn fieldref_substr_sql(lhs: &str, rhs: &str, op: IrStrOp, case_insensitive: bool) -> String {
    let (lhs, rhs) = if case_insensitive {
        (
            format!("lower(({lhs})::text)"),
            format!("lower(({rhs})::text)"),
        )
    } else {
        (format!("({lhs})::text"), format!("({rhs})::text"))
    };
    match op {
        IrStrOp::Contains => format!("strpos({lhs}, {rhs}) > 0"),
        IrStrOp::StartsWith => format!("strpos({lhs}, {rhs}) = 1"),
        IrStrOp::EndsWith => format!("right({lhs}, char_length({rhs})) = {rhs}"),
        IrStrOp::Exact => unreachable!("equality is rendered with ="),
    }
}

impl Backend for PostgresBackend {
    fn name(&self) -> &str {
        "postgres"
    }

    fn formats(&self) -> &[(&str, &str)] {
        &[
            ("default", "Plain PostgreSQL SQL"),
            ("view", "CREATE OR REPLACE VIEW for each rule"),
            (
                "timescaledb",
                "TimescaleDB-optimized queries with time_bucket()",
            ),
            (
                "continuous_aggregate",
                "CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)",
            ),
            (
                "sliding_window",
                "Correlation queries using window functions for per-row sliding detection",
            ),
        ]
    }

    fn requires_pipeline(&self) -> bool {
        false
    }

    fn output_file_extension(&self, _output_format: &str) -> &str {
        "sql"
    }

    // --- Detection rule conversion ---

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        let table = self.resolve_table_name(&rule.custom_attributes, &pipeline_state.state)?;
        let mut state = pipeline_state.clone();
        state.set_state(ROW_RELATION_STATE.to_string(), table.into());
        convert_rule_via_ir(self, rule, output_format, &state)
    }

    // --- Condition combinators ---

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_and(self.config, exprs))
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_or(self.config, exprs))
    }

    /// `NOT` over a missing field is NULL, which drops the row, while Sigma
    /// treats the negated detection as true. `IS NOT TRUE` maps NULL to true.
    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(format!("({expr}) IS NOT TRUE"))
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        if outer == TokenType::NOT {
            return Ok(expr.to_string());
        }
        Ok(text_convert_condition_group(
            self.config,
            expr,
            outer,
            inner,
        ))
    }

    fn convert_negated_field_ref(&self, _field: &str, expr: &str) -> Result<String> {
        Ok(format!("({expr}) IS NOT TRUE"))
    }

    fn convert_ir_array_match(
        &self,
        field: &str,
        quantifier: ArrayQuantifier,
        body: &IrDetection,
        state: &mut ConversionState,
    ) -> Result<String> {
        let json_col = self
            .json_field
            .as_deref()
            .ok_or(ConvertError::UnsupportedArrayMatching)?;
        let array_expr = self.jsonb_value_expr(json_col, field)?;
        self.array_exists_from_expr_ir(&array_expr, quantifier, body, state)
    }

    fn supports_field_index(&self) -> bool {
        // Positional `field[N]` lowers to JSONB `->n` / `->>n`, but only when
        // events are stored in a JSONB column; flat columns have no array.
        self.json_field.is_some()
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        self.field_expr(field)
            .unwrap_or_else(|_| text_escape_and_quote_field(self.config, field))
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
        reject_nul_pattern("PostgreSQL", pattern)?;
        let f = self.field_expr(field)?;
        let is_cased = !case_insensitive;
        let is_contains = matches!(op, IrStrOp::Contains);
        let is_startswith = matches!(op, IrStrOp::StartsWith);
        let is_endswith = matches!(op, IrStrOp::EndsWith);
        let has_wildcards = pattern.has_wildcards();

        let like_op = if is_cased { "LIKE" } else { "ILIKE" };

        // Without wildcards or cased characters ILIKE matches exactly what `=`
        // matches, and `=` also accepts a quoted literal on a non-text column.
        let caseless = !pattern.parts.iter().any(|p| match p {
            IrPatternPart::Literal(s) => s.chars().any(|c| c.to_lowercase().ne(c.to_uppercase())),
            _ => false,
        });
        if is_contains || is_startswith || is_endswith || has_wildcards || !(is_cased || caseless) {
            let inner = self.build_like_value_ir(pattern);
            let val = self.wrap_like_wildcards(&inner, is_contains, is_startswith, is_endswith);
            return Ok(ConvertResult::Query(format!("{f} {like_op} {val}")));
        }

        let val = self.build_plain_value_ir(pattern);
        Ok(ConvertResult::Query(format!("{f} = {val}")))
    }

    fn convert_field_eq_num(
        &self,
        field: &str,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.numeric_expr(field, state)?;
        Ok(format!("{f} = {value}"))
    }

    fn convert_field_eq_bool(
        &self,
        field: &str,
        value: bool,
        state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.field_expr(field)?;
        let v = if value {
            self.config.bool_true
        } else {
            self.config.bool_false
        };
        if self.is_text_field(field, state) {
            return Ok(format!("{f} ILIKE '{v}'"));
        }
        Ok(format!("{f} = {v}"))
    }

    fn convert_field_eq_null(&self, field: &str, _state: &mut ConversionState) -> Result<String> {
        let f = self.field_expr(field)?;
        Ok(format!("{f} IS NULL"))
    }

    fn convert_field_regex(
        &self,
        field: &str,
        pattern: &str,
        flags: RegexFlags,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        reject_nul("PostgreSQL", pattern)?;
        let f = self.field_expr(field)?;
        // PostgreSQL's default regex mode lets `.` match a newline even
        // without `|s`, so a regex can over-match a multi-line value but never
        // misses one. The `w` embedded option makes `^` and `$` match at line
        // breaks for `|m` without changing what `.` matches.
        let pattern = if flags.multiline {
            with_newline_sensitive_option(pattern)
        } else {
            pattern.to_string()
        };
        let escaped_pattern = self.escape_sql_str(&pattern);
        let op = if flags.case_insensitive { "~*" } else { "~" };
        Ok(ConvertResult::Query(format!(
            "{f} {op} '{escaped_pattern}'"
        )))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = self.field_expr(field)?;
        // The value is cast only when its text is an address of the network's
        // family, so a value such as `-` compares as NULL instead of failing
        // the query. A column may be of type `inet`, whose text carries a
        // mask, so a mask is allowed there.
        let v6 = cidr.contains(':');
        let address = if v6 {
            ipv6_address_pattern()
        } else {
            IPV4_ADDRESS_PATTERN.to_string()
        };
        let pattern = match (self.is_text_field(field, state), v6) {
            (true, _) => address,
            (false, true) => format!("{address}(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))?"),
            (false, false) => format!("{address}(/(3[0-2]|[12]?[0-9]))?"),
        };
        Ok(ConvertResult::Query(format!(
            "(CASE WHEN ({f})::text ~ '^{pattern}$' THEN ({f})::inet END) <<= '{cidr}'::cidr"
        )))
    }

    fn convert_field_compare_op(
        &self,
        field: &str,
        op: CompareOp,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.numeric_expr(field, state)?;
        let op_token = match op {
            CompareOp::Lt => "<",
            CompareOp::Lte => "<=",
            CompareOp::Gt => ">",
            CompareOp::Gte => ">=",
        };
        let val_str = value.to_string();
        Ok(format!("{f} {op_token} {val_str}"))
    }

    fn convert_field_exists(
        &self,
        field: &str,
        exists: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        // `->` yields a jsonb `null` for a null value and SQL NULL only when
        // the key is absent, so it tells a null field from a missing one.
        let f = match &self.json_field {
            Some(json_col) => self.jsonb_value_expr(json_col, field)?,
            None => self.field_expr(field)?,
        };
        if exists {
            Ok(format!("{f} IS NOT NULL"))
        } else {
            Ok(format!("{f} IS NULL"))
        }
    }

    fn convert_field_eq_query_expr(
        &self,
        field: &str,
        expr: &str,
        _id: &str,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.field_expr(field)?;
        let resolved = expr.replace("{field}", &f);
        Ok(resolved)
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        op: IrStrOp,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f1 = self.field_expr(field1)?;
        let f2 = self.field_expr(field2)?;
        let expr = match op {
            IrStrOp::Exact if case_insensitive => {
                format!("lower(({f1})::text) = lower(({f2})::text)")
            }
            IrStrOp::Exact => format!("{f1} = {f2}"),
            IrStrOp::Contains | IrStrOp::StartsWith | IrStrOp::EndsWith => {
                fieldref_substr_sql(&f1, &f2, op, case_insensitive)
            }
        };
        Ok(ConvertResult::Query(expr))
    }

    fn convert_keyword_str(
        &self,
        pattern: &IrPattern,
        state: &mut ConversionState,
    ) -> Result<String> {
        reject_nul_pattern("PostgreSQL", pattern)?;
        let search_target = self.keyword_search_target(state)?;
        let plain = keyword_pattern_text(pattern);
        if plain.is_empty() {
            return Err(ConvertError::UnsupportedKeyword);
        }
        let escaped = self.escape_sql_str(&plain);
        Ok(format!(
            "to_tsvector('simple', {search_target}) @@ plainto_tsquery('simple', '{escaped}')"
        ))
    }

    /// Full-text search matches whole words, so a term inside a word is a
    /// `LIKE` substring match over the event text.
    fn convert_keyword_substr(
        &self,
        pattern: &IrPattern,
        case_insensitive: bool,
        state: &mut ConversionState,
    ) -> Result<String> {
        reject_nul_pattern("PostgreSQL", pattern)?;
        let search_target = self.keyword_search_target(state)?;
        let like_op = if case_insensitive { "ILIKE" } else { "LIKE" };
        let inner = self.build_like_value_ir(pattern);
        let val = self.wrap_like_wildcards(&inner, true, false, false);
        Ok(format!("{search_target} {like_op} {val}"))
    }

    fn convert_keyword_num(
        &self,
        value: NumericLiteral,
        state: &mut ConversionState,
    ) -> Result<String> {
        let search_target = self.keyword_search_target(state)?;
        let v = value.to_string();
        Ok(format!(
            "to_tsvector('simple', {search_target}) @@ plainto_tsquery('simple', '{v}')"
        ))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        let qualified = self.resolve_table(&rule.custom_attributes, &state.processing_state)?;

        let effective_tmpl = match state.get_state_str("query_expression_template") {
            Some(t) => t.to_string(),
            None => {
                let (select, group_by) =
                    self.select_list(&rule.fields, state.get_state_str("_output_format"), state)?;
                format!("SELECT {select} FROM {{table}} WHERE {{query}}{group_by}")
            }
        };

        // Rule metadata is free text, so it renders as string literal content.
        Ok(render_query_template(&effective_tmpl, |key| match key {
            "query" => Some(query.clone()),
            "table" => Some(qualified.clone()),
            "rule.title" => Some(rule.title.replace('\'', "''")),
            "rule.id" => rule.id.as_ref().map(|id| id.replace('\'', "''")),
            _ => None,
        }))
    }

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        _index: usize,
        _state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        let view_name = || {
            let raw = match &rule.id {
                Some(id) => id.replace('-', "_"),
                None => rule.title.to_lowercase().replace([' ', '-'], "_"),
            };
            let sanitized: String = raw
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if sanitized.is_empty() {
                "sigma_rule".to_string()
            } else {
                format!("sigma_{sanitized}")
            }
        };

        match output_format {
            "default" | "timescaledb" => Ok(query),
            "view" => Ok(format!("CREATE OR REPLACE VIEW {} AS {query}", view_name())),
            "continuous_aggregate" => Ok(format!(
                "CREATE MATERIALIZED VIEW {} \
                 WITH (timescaledb.continuous) AS {query} \
                 WITH NO DATA",
                view_name()
            )),
            other => Err(ConvertError::RuleConversion(format!(
                "unknown output format: {other}"
            ))),
        }
    }

    fn finalize_output(&self, queries: Vec<String>, output_format: &str) -> Result<String> {
        let sep = match output_format {
            "view" | "continuous_aggregate" => ";\n\n",
            _ => "\n",
        };
        Ok(queries.join(sep))
    }

    // --- Correlation ---

    fn supports_correlation(&self) -> bool {
        true
    }

    fn correlation_methods(&self) -> &[(&str, &str)] {
        &[
            (
                "sliding",
                "Trailing per-event window (default; preserves existing SQL)",
            ),
            (
                "tumbling",
                "Fixed boundary-aligned buckets (time_bucket/date_bin)",
            ),
            (
                "session",
                "Gaps-and-islands sessionization (requires a gap)",
            ),
        ]
    }

    fn default_correlation_method(&self) -> &str {
        "sliding"
    }

    /// The rule's `default` query with every column, whatever the output
    /// format and the rule's `fields`.
    fn correlation_source_query(
        &self,
        rule: &SigmaRule,
        _output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Option<String>> {
        let mut rule = rule.clone();
        rule.fields.clear();
        Ok(self
            .convert_rule(&rule, "default", pipeline_state)?
            .into_iter()
            .next())
    }

    fn convert_correlation_rule_with_warnings(
        &self,
        rule: &CorrelationRule,
        output_format: &str,
        pipeline_state: &PipelineState,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        self.convert_correlation(rule, output_format, pipeline_state, warnings)
    }
}

/// A dotted-quad IPv4 address with octets from 0 to 255 and no leading zeros.
const IPV4_ADDRESS_PATTERN: &str = "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";

/// An IPv6 address in any RFC 4291 text form, following the RFC 3986
/// `IPv6address` grammar.
fn ipv6_address_pattern() -> String {
    let h16 = "[0-9A-Fa-f]{1,4}";
    let ls32 = format!("({h16}:{h16}|{IPV4_ADDRESS_PATTERN})");
    let head = |n: usize| format!("(({h16}:){{0,{n}}}{h16})?");
    let forms = [
        format!("({h16}:){{6}}{ls32}"),
        format!("::({h16}:){{5}}{ls32}"),
        format!("({h16})?::({h16}:){{4}}{ls32}"),
        format!("{}::({h16}:){{3}}{ls32}", head(1)),
        format!("{}::({h16}:){{2}}{ls32}", head(2)),
        format!("{}::{h16}:{ls32}", head(3)),
        format!("{}::{ls32}", head(4)),
        format!("{}::{h16}", head(5)),
        format!("{}::", head(6)),
    ];
    format!("({})", forms.join("|"))
}
