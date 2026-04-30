//! PostgreSQL/TimescaleDB backend for Sigma rule conversion.
//!
//! Converts Sigma detection rules into PostgreSQL SQL queries, leveraging
//! PostgreSQL-native features: `ILIKE` for case-insensitive matching,
//! `~*`/`~` for regex, `inet`/`cidr` for network address matching,
//! `tsvector`/`tsquery` for full-text keyword search, and JSONB for
//! semi-structured event data.

mod correlation;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::*;

use crate::backend::*;
use crate::condition::convert_condition_expr;
use crate::convert::{default_convert_detection, default_convert_detection_item};
use crate::error::{ConvertError, Result};
use crate::state::{ConversionState, ConvertResult};

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
    field_escape: None,
    field_escape_pattern: None,

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

    re_expression: Some("{field} ~* {regex}"),
    not_re_expression: Some("{field} !~* {regex}"),
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
    /// Use case-sensitive regex (`~`) instead of case-insensitive (`~*`).
    pub case_sensitive_re: bool,
    /// PostgreSQL schema name (e.g. `public`).
    pub schema: Option<String>,
    /// PostgreSQL database name (connection-level metadata, not used in queries).
    pub database: Option<String>,
    /// Enable TimescaleDB-specific features.
    pub timescaledb: bool,
}

impl PostgresBackend {
    pub fn new() -> Self {
        Self {
            config: &POSTGRES_CONFIG,
            table: "security_events".to_string(),
            timestamp_field: "time".to_string(),
            json_field: None,
            case_sensitive_re: false,
            schema: None,
            database: None,
            timescaledb: false,
        }
    }

    /// Create a backend from CLI-style key=value option pairs.
    ///
    /// Recognized keys: `table`, `schema`, `database`, `timestamp_field`,
    /// `json_field`, `case_sensitive_re` (true/false).
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
        if let Some(v) = options.get("case_sensitive_re") {
            backend.case_sensitive_re = v == "true";
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
        custom_attrs: &HashMap<String, serde_yaml::Value>,
        state: &HashMap<String, serde_json::Value>,
    ) -> String {
        let table = custom_attrs
            .get("postgres.table")
            .and_then(|v| v.as_str())
            .or(state.get("table").and_then(|v| v.as_str()))
            .unwrap_or(&self.table);

        let schema = custom_attrs
            .get("postgres.schema")
            .and_then(|v| v.as_str())
            .or(state.get("schema").and_then(|v| v.as_str()))
            .or(self.schema.as_deref())
            .filter(|s| !s.is_empty());

        match schema {
            Some(s) => format!("{s}.{table}"),
            None => table.to_string(),
        }
    }

    /// Qualify a raw table name with schema. Precedence:
    /// `per_rule_schema` > `state["schema"]` > `self.schema` > none.
    fn qualify_table_name(
        &self,
        table: &str,
        state: &HashMap<String, serde_json::Value>,
        per_rule_schema: Option<&str>,
    ) -> String {
        let schema = per_rule_schema
            .or(state.get("schema").and_then(|v| v.as_str()))
            .or(self.schema.as_deref())
            .filter(|s| !s.is_empty());

        match schema {
            Some(s) => format!("{s}.{table}"),
            None => table.to_string(),
        }
    }

    fn field_expr(&self, field: &str) -> String {
        match &self.json_field {
            Some(json_col) if field.contains('.') => {
                let parts: Vec<&str> = field.split('.').collect();
                let last = parts.len() - 1;
                let mut expr = json_col.clone();
                for (i, part) in parts.iter().enumerate() {
                    if i == last {
                        expr.push_str(&format!("->>'{part}'"));
                    } else {
                        expr.push_str(&format!("->'{part}'"));
                    }
                }
                expr
            }
            Some(json_col) => format!("{json_col}->>'{field}'"),
            None => text_escape_and_quote_field(self.config, field),
        }
    }

    /// Escape a string value for use in a SQL single-quoted literal.
    /// PostgreSQL uses `''` to escape single quotes inside string literals.
    fn escape_sql_str(&self, s: &str) -> String {
        s.replace('\'', "''")
    }

    /// Build a SigmaString value into a SQL string literal with proper escaping
    /// and wildcard translation for LIKE/ILIKE.
    fn build_like_value(&self, value: &SigmaString) -> String {
        let mut result = String::with_capacity(value.original.len() + 2);
        result.push('\'');
        for part in &value.parts {
            match part {
                StringPart::Plain(s) => {
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
                StringPart::Special(SpecialChar::WildcardMulti) => result.push('%'),
                StringPart::Special(SpecialChar::WildcardSingle) => result.push('_'),
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

    /// Build a plain SQL string literal from a SigmaString (no wildcards).
    fn build_plain_value(&self, value: &SigmaString) -> String {
        let plain = value.as_plain().unwrap_or_else(|| value.original.clone());
        format!("'{}'", self.escape_sql_str(&plain))
    }
}

impl Default for PostgresBackend {
    fn default() -> Self {
        Self::new()
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

    // --- Detection rule conversion ---

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        let mut queries = Vec::new();
        for (idx, cond_expr) in rule.detection.conditions.iter().enumerate() {
            let mut state = ConversionState::new(pipeline_state.state.clone());
            state
                .processing_state
                .insert("_output_format".to_string(), output_format.into());
            let query = self.convert_condition(cond_expr, &rule.detection.named, &mut state)?;
            let finished = self.finish_query(rule, query, &state)?;
            let finalized = self.finalize_query(rule, finished, idx, &state, output_format)?;
            queries.push(finalized);
        }
        Ok(queries)
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
        Ok(text_convert_condition_and(self.config, exprs))
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_or(self.config, exprs))
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(text_convert_condition_not(self.config, expr))
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
        default_convert_detection_item(self, item, state)
    }

    // --- Field/value escaping ---

    fn escape_and_quote_field(&self, field: &str) -> String {
        self.field_expr(field)
    }

    fn convert_value_str(&self, value: &SigmaString, _state: &ConversionState) -> String {
        self.build_like_value(value)
    }

    fn convert_value_re(&self, regex: &str, _state: &ConversionState) -> String {
        format!("'{}'", self.escape_sql_str(regex))
    }

    // --- Value-type-specific methods ---

    fn convert_field_eq_str(
        &self,
        field: &str,
        value: &SigmaString,
        modifiers: &[Modifier],
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = self.field_expr(field);
        let is_cased = modifiers.contains(&Modifier::Cased);
        let is_contains = modifiers.contains(&Modifier::Contains);
        let is_startswith = modifiers.contains(&Modifier::StartsWith);
        let is_endswith = modifiers.contains(&Modifier::EndsWith);
        let has_wildcards = value.contains_wildcards();

        let like_op = if is_cased { "LIKE" } else { "ILIKE" };

        if is_contains || is_startswith || is_endswith || has_wildcards {
            let inner = self.build_like_value(value);
            let val = self.wrap_like_wildcards(&inner, is_contains, is_startswith, is_endswith);
            return Ok(ConvertResult::Query(format!("{f} {like_op} {val}")));
        }

        let val = self.build_plain_value(value);
        Ok(ConvertResult::Query(format!("{f} = {val}")))
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
        let f = self.field_expr(field);
        if value.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&value) {
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
        let f = self.field_expr(field);
        let v = if value {
            self.config.bool_true
        } else {
            self.config.bool_false
        };
        Ok(format!("{f} = {v}"))
    }

    fn convert_field_eq_null(&self, field: &str, _state: &mut ConversionState) -> Result<String> {
        let f = self.field_expr(field);
        Ok(format!("{f} IS NULL"))
    }

    fn convert_field_eq_re(
        &self,
        field: &str,
        pattern: &str,
        flags: &[Modifier],
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = self.field_expr(field);
        let escaped_pattern = self.escape_sql_str(pattern);
        let is_cased = flags.contains(&Modifier::Cased) || self.case_sensitive_re;
        let op = if is_cased { "~" } else { "~*" };
        Ok(ConvertResult::Query(format!(
            "{f} {op} '{escaped_pattern}'"
        )))
    }

    fn convert_field_eq_cidr(
        &self,
        field: &str,
        cidr: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f = self.field_expr(field);
        Ok(ConvertResult::Query(format!(
            "({f})::inet <<= '{cidr}'::cidr"
        )))
    }

    fn convert_field_compare(
        &self,
        field: &str,
        op: &Modifier,
        value: f64,
        _state: &mut ConversionState,
    ) -> Result<String> {
        let f = self.field_expr(field);
        let op_token = match op {
            Modifier::Lt => "<",
            Modifier::Lte => "<=",
            Modifier::Gt => ">",
            Modifier::Gte => ">=",
            _ => {
                return Err(ConvertError::UnsupportedModifier(format!(
                    "compare op {op:?}"
                )));
            }
        };
        let val_str =
            if value.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&value) {
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
        let f = self.field_expr(field);
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
        let f = self.field_expr(field);
        let resolved = expr.replace("{field}", &f);
        Ok(resolved)
    }

    fn convert_field_ref(
        &self,
        field1: &str,
        field2: &str,
        _state: &mut ConversionState,
    ) -> Result<ConvertResult> {
        let f1 = self.field_expr(field1);
        let f2 = self.field_expr(field2);
        Ok(ConvertResult::Query(format!("{f1} = {f2}")))
    }

    fn convert_keyword(&self, value: &SigmaValue, _state: &mut ConversionState) -> Result<String> {
        let search_target = match &self.json_field {
            Some(json_col) => format!("{json_col}::text"),
            None => "ROW(*)::text".to_string(),
        };
        match value {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                if plain.is_empty() {
                    return Err(ConvertError::UnsupportedKeyword);
                }
                let escaped = self.escape_sql_str(&plain);
                Ok(format!(
                    "to_tsvector('simple', {search_target}) @@ plainto_tsquery('simple', '{escaped}')"
                ))
            }
            SigmaValue::Integer(n) => Ok(format!(
                "to_tsvector('simple', {search_target}) @@ plainto_tsquery('simple', '{n}')"
            )),
            SigmaValue::Float(f) => Ok(format!(
                "to_tsvector('simple', {search_target}) @@ plainto_tsquery('simple', '{f}')"
            )),
            _ => Err(ConvertError::UnsupportedKeyword),
        }
    }

    fn convert_condition_as_in_expression(
        &self,
        field: &str,
        values: &[&SigmaValue],
        is_or: bool,
        _state: &mut ConversionState,
    ) -> Result<String> {
        if !is_or {
            return Err(ConvertError::UnsupportedModifier(
                "AND IN-list not supported for PostgreSQL".into(),
            ));
        }
        let f = self.field_expr(field);
        let items: Vec<String> = values
            .iter()
            .map(|v| match v {
                SigmaValue::String(s) => self.build_plain_value(s),
                SigmaValue::Integer(n) => n.to_string(),
                SigmaValue::Float(f) => f.to_string(),
                _ => String::new(),
            })
            .collect();
        let list = items.join(", ");
        Ok(format!("{f} IN ({list})"))
    }

    // --- Query finalization ---

    fn finish_query(
        &self,
        rule: &SigmaRule,
        query: String,
        state: &ConversionState,
    ) -> Result<String> {
        let qualified = self.resolve_table(&rule.custom_attributes, &state.processing_state);

        let is_timescaledb = state
            .get_state_str("_output_format")
            .is_some_and(|f| f == "timescaledb" || f == "continuous_aggregate");

        let base_cols = if rule.fields.is_empty() {
            "*".to_string()
        } else {
            rule.fields
                .iter()
                .map(|f| self.format_select_field(f))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let select_cols = if is_timescaledb {
            format!(
                "time_bucket('1 hour', {}) AS bucket, {}",
                self.timestamp_field, base_cols
            )
        } else {
            base_cols
        };

        let custom_tmpl = state.get_state_str("query_expression_template");

        let effective_tmpl = match custom_tmpl {
            Some(t) => t.to_string(),
            None => format!("SELECT {select_cols} FROM {{table}} WHERE {{query}}"),
        };

        let mut result = effective_tmpl.replace("{query}", &query);
        result = result.replace("{table}", &qualified);
        result = result.replace("{rule.title}", &rule.title);
        if let Some(id) = &rule.id {
            result = result.replace("{rule.id}", id);
        }

        Ok(result)
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

    fn convert_correlation_rule(
        &self,
        rule: &CorrelationRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        let table = self.resolve_table(&rule.custom_attributes, &pipeline_state.state);
        let ts = &self.timestamp_field;
        let use_time_bucket =
            output_format == "timescaledb" || output_format == "continuous_aggregate";

        let mut group_by_cols: Vec<String> =
            rule.group_by.iter().map(|g| self.field_expr(g)).collect();
        if use_time_bucket {
            group_by_cols.insert(0, format!("time_bucket('1 hour', {ts})"));
        }
        let group_by_clause = if group_by_cols.is_empty() {
            String::new()
        } else {
            format!(" GROUP BY {}", group_by_cols.join(", "))
        };
        let group_by_select = if group_by_cols.is_empty() {
            String::new()
        } else {
            format!("{}, ", group_by_cols.join(", "))
        };

        let window_secs = rule.timespan.seconds;
        let having_clause = self.build_having_clause(&rule.condition)?;

        let field_from_condition = match &rule.condition {
            CorrelationCondition::Threshold { field, .. } => {
                field.as_ref().and_then(|f| f.first().cloned())
            }
            _ => None,
        };
        let value_field = field_from_condition.as_deref().or_else(|| {
            rule.aliases
                .first()
                .and_then(|a| a.mapping.values().next().map(|s| s.as_str()))
        });

        // Build per-rule table mapping from _rule_tables injected by convert_collection
        let rule_tables: HashMap<String, String> = pipeline_state
            .state
            .get("_rule_tables")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Per-rule converted queries for CTE-based pre-filtering
        let rule_queries: HashMap<String, String> = pipeline_state
            .state
            .get("_rule_queries")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let (cte_prefix, source_table, time_filter) =
            self.build_correlation_source(&rule.rules, &rule_queries, &table, ts, window_secs);

        let query = match rule.correlation_type {
            CorrelationType::EventCount if output_format == "sliding_window" => self
                .build_sliding_window_query(
                    &cte_prefix,
                    &source_table,
                    &time_filter,
                    &rule.group_by,
                    ts,
                    window_secs,
                    &rule.condition,
                )?,
            CorrelationType::EventCount => {
                format!(
                    "{cte_prefix}SELECT {group_by_select}COUNT(*) AS event_count \
                     FROM {source_table}\
                     {time_filter}\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", "COUNT(*)")
                )
            }
            CorrelationType::ValueCount => {
                let field = value_field
                    .map(|f| self.field_expr(f))
                    .unwrap_or_else(|| "'unknown_field'".to_string());
                let agg = format!("COUNT(DISTINCT {field})");
                format!(
                    "{cte_prefix}SELECT {group_by_select}{agg} AS value_count \
                     FROM {source_table}\
                     {time_filter}\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", &agg)
                )
            }
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => self
                .build_temporal_query(
                    rule,
                    &table,
                    ts,
                    window_secs,
                    &group_by_select,
                    &group_by_clause,
                    &having_clause,
                    &rule_tables,
                    pipeline_state,
                )?,
            CorrelationType::ValueSum => {
                let field = value_field
                    .map(|f| self.field_expr(f))
                    .unwrap_or_else(|| "'unknown_field'".to_string());
                let agg = format!("SUM({field})");
                format!(
                    "{cte_prefix}SELECT {group_by_select}{agg} AS value_sum \
                     FROM {source_table}\
                     {time_filter}\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", &agg)
                )
            }
            CorrelationType::ValueAvg => {
                let field = value_field
                    .map(|f| self.field_expr(f))
                    .unwrap_or_else(|| "'unknown_field'".to_string());
                let agg = format!("AVG({field})");
                format!(
                    "{cte_prefix}SELECT {group_by_select}{agg} AS value_avg \
                     FROM {source_table}\
                     {time_filter}\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", &agg)
                )
            }
            CorrelationType::ValuePercentile | CorrelationType::ValueMedian => {
                let field = value_field
                    .map(|f| self.field_expr(f))
                    .unwrap_or_else(|| "'unknown_field'".to_string());
                let percentile = if rule.correlation_type == CorrelationType::ValueMedian {
                    0.5
                } else {
                    match &rule.condition {
                        CorrelationCondition::Threshold { percentile, .. } => {
                            percentile.map(|p| p as f64 / 100.0).unwrap_or(0.95)
                        }
                        _ => 0.95,
                    }
                };
                let agg = format!("PERCENTILE_CONT({percentile}) WITHIN GROUP (ORDER BY {field})");
                format!(
                    "{cte_prefix}SELECT {group_by_select}\
                     {agg} AS pct_value \
                     FROM {source_table}\
                     {time_filter}\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", &agg)
                )
            }
        };

        Ok(vec![query])
    }
}
