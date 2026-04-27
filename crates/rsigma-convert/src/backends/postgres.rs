//! PostgreSQL/TimescaleDB backend for Sigma rule conversion.
//!
//! Converts Sigma detection rules into PostgreSQL SQL queries, leveraging
//! PostgreSQL-native features: `ILIKE` for case-insensitive matching,
//! `~*`/`~` for regex, `inet`/`cidr` for network address matching,
//! `tsvector`/`tsquery` for full-text keyword search, and JSONB for
//! semi-structured event data.

use std::collections::{BTreeMap, HashMap};

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

        let select_cols = if is_timescaledb {
            format!(
                "time_bucket('1 hour', {}) AS bucket, *",
                self.timestamp_field
            )
        } else {
            "*".to_string()
        };

        let custom_tmpl = state.get_state_str("query_expression_template");

        let effective_tmpl = match custom_tmpl {
            Some(t) => t.to_string(),
            None if is_timescaledb => {
                format!("SELECT {select_cols} FROM {{table}} WHERE {{query}}")
            }
            None => self.config.query_expression.to_string(),
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

        let query = match rule.correlation_type {
            CorrelationType::EventCount => {
                format!(
                    "SELECT {group_by_select}COUNT(*) AS event_count \
                     FROM {table} \
                     WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
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
                    "SELECT {group_by_select}{agg} AS value_count \
                     FROM {table} \
                     WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
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
                    "SELECT {group_by_select}{agg} AS value_sum \
                     FROM {table} \
                     WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
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
                    "SELECT {group_by_select}{agg} AS value_avg \
                     FROM {table} \
                     WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
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
                    "SELECT {group_by_select}\
                     {agg} AS pct_value \
                     FROM {table} \
                     WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", &agg)
                )
            }
        };

        Ok(vec![query])
    }
}

impl PostgresBackend {
    /// Build HAVING clause from correlation condition predicates.
    /// Uses `{agg}` as placeholder for the aggregate expression.
    fn build_having_clause(&self, cond: &CorrelationCondition) -> Result<String> {
        match cond {
            CorrelationCondition::Threshold { predicates, .. } => {
                let parts: Vec<String> = predicates
                    .iter()
                    .map(|(op, val)| {
                        let op_str = match op {
                            ConditionOperator::Lt => "<",
                            ConditionOperator::Lte => "<=",
                            ConditionOperator::Gt => ">",
                            ConditionOperator::Gte => ">=",
                            ConditionOperator::Eq => "=",
                            ConditionOperator::Neq => "<>",
                        };
                        format!("{{agg}} {op_str} {val}")
                    })
                    .collect();
                Ok(parts.join(" AND "))
            }
            CorrelationCondition::Extended(_) => Err(ConvertError::UnsupportedCorrelation(
                "extended boolean conditions not yet supported for PostgreSQL".into(),
            )),
        }
    }

    /// Build a temporal or temporal_ordered correlation query.
    ///
    /// When all referenced rules target the same table, produces a single-table
    /// CTE filtering on `rule_name IN (...)`. When rules target different tables
    /// (from `_rule_tables` pipeline state), produces a `UNION ALL` CTE with one
    /// leg per rule.
    ///
    /// **Schema compatibility requirement:** The multi-table path uses
    /// `SELECT * ... UNION ALL SELECT * ...`. PostgreSQL requires all legs of a
    /// `UNION ALL` to produce the same number of columns with compatible types.
    /// This works when all referenced tables share an identical schema (e.g. a
    /// normalized event schema). If the tables have different column layouts the
    /// query will fail at execution time. Callers should ensure that pipeline
    /// field-mappings normalize the schemas, or use a single-table approach with
    /// a discriminator column instead.
    #[allow(clippy::too_many_arguments)]
    fn build_temporal_query(
        &self,
        rule: &CorrelationRule,
        default_table: &str,
        ts: &str,
        window_secs: u64,
        group_by_select: &str,
        group_by_clause: &str,
        having_clause: &str,
        rule_tables: &HashMap<String, String>,
        pipeline_state: &PipelineState,
    ) -> Result<String> {
        let agg = "COUNT(DISTINCT rule_name)";
        let having = having_clause.replace("{agg}", agg);

        let rule_schemas: HashMap<String, String> = pipeline_state
            .state
            .get("_rule_schemas")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Collect per-rule tables, qualifying each with its own schema
        let mut table_to_rules: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for rule_ref in &rule.rules {
            let raw_table = rule_tables.get(rule_ref).map(|s| s.as_str());
            let per_rule_schema = rule_schemas.get(rule_ref).map(|s| s.as_str());
            let qualified = match raw_table {
                Some(t) => self.qualify_table_name(t, &pipeline_state.state, per_rule_schema),
                None => default_table.to_string(),
            };
            table_to_rules
                .entry(qualified)
                .or_default()
                .push(rule_ref.clone());
        }

        if table_to_rules.len() <= 1 {
            // Single table: filter by rule_name column
            let rule_names = rule.rules.join("', '");
            Ok(format!(
                "WITH matched AS (\
                 SELECT *, rule_name FROM {default_table} \
                 WHERE rule_name IN ('{rule_names}') \
                 AND {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
                 ) \
                 SELECT {group_by_select}\
                 {agg} AS distinct_rules, \
                 MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
                 FROM matched\
                 {group_by_clause} \
                 HAVING {having}"
            ))
        } else {
            // Multi-table: UNION ALL CTE with one leg per rule
            let union_parts: Vec<String> = table_to_rules
                .iter()
                .flat_map(|(tbl, rules)| {
                    rules.iter().map(move |rule_ref| {
                        format!(
                            "SELECT *, '{rule_ref}' AS rule_name FROM {tbl} \
                             WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'"
                        )
                    })
                })
                .collect();

            let union_cte = union_parts.join(" UNION ALL ");

            Ok(format!(
                "WITH matched AS (\
                 {union_cte}\
                 ) \
                 SELECT {group_by_select}\
                 {agg} AS distinct_rules, \
                 MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
                 FROM matched\
                 {group_by_clause} \
                 HAVING {having}"
            ))
        }
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
        let backend = PostgresBackend::new();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "default", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    fn convert_with(yaml: &str, backend: &PostgresBackend) -> Vec<String> {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut results = Vec::new();
        for rule in &collection.rules {
            let queries = backend
                .convert_rule(rule, "default", &PipelineState::default())
                .unwrap();
            results.extend(queries);
        }
        results
    }

    // --- Basic detection ---
    // Note: PostgreSQL quoted identifiers use double quotes for mixed-case field names.
    // Fields matching ^[a-z_][a-z0-9_]*$ are unquoted; others get "quoted".

    #[test]
    fn test_simple_eq() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" = 'whoami'"#]
        );
    }

    #[test]
    fn test_lowercase_field_unquoted() {
        let queries = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec!["SELECT * FROM security_events WHERE action = 'login'"]
        );
    }

    #[test]
    fn test_and_condition() {
        let queries = convert(
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
            queries,
            vec![r#"SELECT * FROM security_events WHERE "FieldA" = 'val1' AND "FieldB" = 'val2'"#]
        );
    }

    #[test]
    fn test_or_condition() {
        let queries = convert(
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
            queries,
            vec![r#"SELECT * FROM security_events WHERE "FieldA" = 'val1' OR "FieldB" = 'val2'"#]
        );
    }

    #[test]
    fn test_not_condition() {
        let queries = convert(
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
            queries,
            vec![
                r#"SELECT * FROM security_events WHERE "FieldA" = 'val1' AND NOT "FieldB" = 'val2'"#
            ]
        );
    }

    // --- ILIKE modifiers ---

    #[test]
    fn test_contains() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#]
        );
    }

    #[test]
    fn test_startswith() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE 'cmd%'"#]
        );
    }

    #[test]
    fn test_endswith() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '%.exe'"#]
        );
    }

    #[test]
    fn test_cased_contains() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" LIKE '%Whoami%'"#]
        );
    }

    #[test]
    fn test_wildcard_value() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#]
        );
    }

    // --- Regex ---

    #[test]
    fn test_regex() {
        let queries = convert(
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
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ~* '.*whoami.*'"#]
        );
    }

    #[test]
    fn test_regex_case_sensitive() {
        let queries = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re|cased: '^Whoami$'
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ~ '^Whoami$'"#]
        );
    }

    // --- CIDR ---

    #[test]
    fn test_cidr() {
        let queries = convert(
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
            queries,
            vec![
                r#"SELECT * FROM security_events WHERE ("SourceIP")::inet <<= '10.0.0.0/8'::cidr"#
            ]
        );
    }

    // --- Numeric, Boolean, Null ---

    #[test]
    fn test_numeric() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "EventID" = 4688"#]
        );
    }

    #[test]
    fn test_boolean() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "Enabled" = true"#]
        );
    }

    #[test]
    fn test_null() {
        let queries = convert(
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
            queries,
            vec![r#"SELECT * FROM security_events WHERE "FieldA" IS NULL"#]
        );
    }

    // --- Exists ---

    #[test]
    fn test_exists() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "FieldA" IS NOT NULL"#]
        );
    }

    #[test]
    fn test_not_exists() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "FieldA" IS NULL"#]
        );
    }

    // --- Compare operators ---

    #[test]
    fn test_gte() {
        let queries = convert(
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
            queries,
            vec![r#"SELECT * FROM security_events WHERE "EventCount" >= 10"#]
        );
    }

    #[test]
    fn test_lt() {
        let queries = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Score|lt: 5
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "Score" < 5"#]
        );
    }

    // --- Multiple values ---

    #[test]
    fn test_multiple_values_or() {
        let queries = convert(
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
            queries,
            vec![
                r#"SELECT * FROM security_events WHERE "CommandLine" = 'whoami' OR "CommandLine" = 'ipconfig'"#
            ]
        );
    }

    #[test]
    fn test_multiple_values_all() {
        let queries = convert(
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
            queries,
            vec![
                r#"SELECT * FROM security_events WHERE "CommandLine" = 'whoami' AND "CommandLine" = 'ipconfig'"#
            ]
        );
    }

    // --- Keywords (full-text search) ---

    #[test]
    fn test_keywords() {
        let queries = convert(
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
        assert_eq!(
            queries,
            vec![
                "SELECT * FROM security_events WHERE \
                 to_tsvector('simple', ROW(*)::text) @@ plainto_tsquery('simple', 'whoami') OR \
                 to_tsvector('simple', ROW(*)::text) @@ plainto_tsquery('simple', 'ipconfig')"
            ]
        );
    }

    // --- SQL injection prevention (single-quote escaping) ---

    #[test]
    fn test_single_quote_escaping() {
        let queries = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: "it's a test"
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" = 'it''s a test'"#]
        );
    }

    // --- JSONB field access ---

    #[test]
    fn test_jsonb_field_access() {
        let mut backend = PostgresBackend::new();
        backend.json_field = Some("metadata".to_string());
        let queries = convert_with(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: whoami
    condition: selection
"#,
            &backend,
        );
        assert_eq!(
            queries,
            vec!["SELECT * FROM security_events WHERE metadata->>'CommandLine' = 'whoami'"]
        );
    }

    #[test]
    fn test_jsonb_cidr() {
        let mut backend = PostgresBackend::new();
        backend.json_field = Some("metadata".to_string());
        let queries = convert_with(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        SourceIP|cidr: '10.0.0.0/8'
    condition: selection
"#,
            &backend,
        );
        assert_eq!(
            queries,
            vec![
                "SELECT * FROM security_events WHERE (metadata->>'SourceIP')::inet <<= '10.0.0.0/8'::cidr"
            ]
        );
    }

    // --- Output formats ---

    #[test]
    fn test_view_format() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
id: 12345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_rule(&collection.rules[0], "view", &PipelineState::default())
            .unwrap();
        assert_eq!(
            queries,
            vec![
                r#"CREATE OR REPLACE VIEW sigma_12345678_1234_1234_1234_123456789abc AS SELECT * FROM security_events WHERE "FieldA" = 'val1'"#
            ]
        );
    }

    #[test]
    fn test_view_format_title_sanitization() {
        let collection = parse_sigma_yaml(
            r#"
title: "Suspicious Process: cmd.exe /c (T1059.003)"
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_rule(&collection.rules[0], "view", &PipelineState::default())
            .unwrap();
        assert!(
            queries[0].starts_with(
                "CREATE OR REPLACE VIEW sigma_suspicious_process_cmdexe_c_t1059003 AS"
            )
        );
    }

    // --- Schema prefix ---

    #[test]
    fn test_schema_prefix() {
        let mut backend = PostgresBackend::new();
        backend.schema = Some("audit".to_string());
        let queries = convert_with(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
            &backend,
        );
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM audit.security_events WHERE "FieldA" = 'val1'"#]
        );
    }

    // --- Multiple detection items (AND) ---

    #[test]
    fn test_multiple_detection_items_and() {
        let queries = convert(
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
            queries,
            vec![r#"SELECT * FROM security_events WHERE "FieldA" = 'val1' AND "FieldB" = 'val2'"#]
        );
    }

    // --- LIKE wildcard escaping ---

    #[test]
    fn test_like_wildcard_escaping() {
        let queries = convert(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Path|contains: '100%'
    condition: selection
"#,
        );
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM security_events WHERE "Path" ILIKE '%100\%%'"#]
        );
    }

    // --- TimescaleDB output formats ---

    #[test]
    fn test_timescaledb_format() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_rule(
                &collection.rules[0],
                "timescaledb",
                &PipelineState::default(),
            )
            .unwrap();
        assert_eq!(
            queries,
            vec![
                r#"SELECT time_bucket('1 hour', time) AS bucket, * FROM security_events WHERE "FieldA" = 'val1'"#
            ]
        );
    }

    #[test]
    fn test_continuous_aggregate_format() {
        let collection = parse_sigma_yaml(
            r#"
title: Test Rule
id: abcdef01-2345-6789-abcd-ef0123456789
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_rule(
                &collection.rules[0],
                "continuous_aggregate",
                &PipelineState::default(),
            )
            .unwrap();
        assert_eq!(
            queries,
            vec![
                "CREATE MATERIALIZED VIEW sigma_abcdef01_2345_6789_abcd_ef0123456789 \
                 WITH (timescaledb.continuous) AS \
                 SELECT time_bucket('1 hour', time) AS bucket, * \
                 FROM security_events WHERE \"FieldA\" = 'val1' WITH NO DATA"
            ]
        );
    }

    // --- resolve_table precedence ---

    #[test]
    fn test_resolve_table_defaults() {
        let backend = PostgresBackend::new();
        let attrs = HashMap::new();
        let state = HashMap::new();
        assert_eq!(backend.resolve_table(&attrs, &state), "security_events");
    }

    #[test]
    fn test_resolve_table_backend_schema() {
        let mut backend = PostgresBackend::new();
        backend.schema = Some("audit".to_string());
        let attrs = HashMap::new();
        let state = HashMap::new();
        assert_eq!(
            backend.resolve_table(&attrs, &state),
            "audit.security_events"
        );
    }

    #[test]
    fn test_resolve_table_state_overrides_default() {
        let backend = PostgresBackend::new();
        let attrs = HashMap::new();
        let mut state = HashMap::new();
        state.insert("table".to_string(), serde_json::json!("process_events"));
        assert_eq!(backend.resolve_table(&attrs, &state), "process_events");
    }

    #[test]
    fn test_resolve_table_state_with_backend_schema() {
        let mut backend = PostgresBackend::new();
        backend.schema = Some("audit".to_string());
        let attrs = HashMap::new();
        let mut state = HashMap::new();
        state.insert("table".to_string(), serde_json::json!("process_events"));
        assert_eq!(
            backend.resolve_table(&attrs, &state),
            "audit.process_events"
        );
    }

    #[test]
    fn test_resolve_table_state_schema_overrides_backend() {
        let mut backend = PostgresBackend::new();
        backend.schema = Some("audit".to_string());
        let attrs = HashMap::new();
        let mut state = HashMap::new();
        state.insert("table".to_string(), serde_json::json!("process_events"));
        state.insert("schema".to_string(), serde_json::json!("siem"));
        assert_eq!(backend.resolve_table(&attrs, &state), "siem.process_events");
    }

    #[test]
    fn test_resolve_table_custom_attrs_override_all() {
        let mut backend = PostgresBackend::new();
        backend.schema = Some("audit".to_string());
        let mut attrs = HashMap::new();
        attrs.insert(
            "postgres.table".to_string(),
            serde_yaml::Value::String("my_events".to_string()),
        );
        attrs.insert(
            "postgres.schema".to_string(),
            serde_yaml::Value::String("custom".to_string()),
        );
        let mut state = HashMap::new();
        state.insert("table".to_string(), serde_json::json!("pipeline_events"));
        state.insert("schema".to_string(), serde_json::json!("siem"));
        assert_eq!(backend.resolve_table(&attrs, &state), "custom.my_events");
    }

    #[test]
    fn test_resolve_table_custom_table_only() {
        let backend = PostgresBackend::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "postgres.table".to_string(),
            serde_yaml::Value::String("my_events".to_string()),
        );
        let state = HashMap::new();
        assert_eq!(backend.resolve_table(&attrs, &state), "my_events");
    }

    #[test]
    fn test_resolve_table_empty_schema_treated_as_none() {
        let mut backend = PostgresBackend::new();
        backend.schema = Some("audit".to_string());
        let mut attrs = HashMap::new();
        attrs.insert(
            "postgres.schema".to_string(),
            serde_yaml::Value::String(String::new()),
        );
        let state = HashMap::new();
        // Empty schema in custom_attrs removes the schema prefix
        assert_eq!(backend.resolve_table(&attrs, &state), "security_events");
    }

    // --- Custom attributes in detection rules ---

    #[test]
    fn test_custom_table_via_custom_attributes() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
custom_attributes:
    postgres.table: custom_events
    postgres.schema: siem
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_rule(&collection.rules[0], "default", &PipelineState::default())
            .unwrap();
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM siem.custom_events WHERE "FieldA" = 'val1'"#]
        );
    }

    // --- Pipeline state table override ---

    #[test]
    fn test_pipeline_state_table_override() {
        let collection = parse_sigma_yaml(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA: val1
    condition: selection
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let mut pipeline_state = PipelineState::default();
        pipeline_state.set_state("table".to_string(), serde_json::json!("process_events"));
        let queries = backend
            .convert_rule(&collection.rules[0], "default", &pipeline_state)
            .unwrap();
        assert_eq!(
            queries,
            vec![r#"SELECT * FROM process_events WHERE "FieldA" = 'val1'"#]
        );
    }

    // --- Correlation with pipeline state ---

    #[test]
    fn test_correlation_uses_pipeline_state_table() {
        let collection = parse_sigma_yaml(
            r#"
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 10
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let mut pipeline_state = PipelineState::default();
        pipeline_state.set_state("table".to_string(), serde_json::json!("auth_events"));
        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        assert_eq!(queries.len(), 1);
        assert!(queries[0].contains("FROM auth_events"));
    }

    #[test]
    fn test_correlation_custom_attributes_table() {
        let collection = parse_sigma_yaml(
            r#"
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 10
custom_attributes:
    postgres.table: login_events
    postgres.schema: auth
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_correlation_rule(
                &collection.correlations[0],
                "default",
                &PipelineState::default(),
            )
            .unwrap();
        assert_eq!(queries.len(), 1);
        assert!(
            queries[0].contains("FROM auth.login_events"),
            "expected table auth.login_events in: {}",
            queries[0]
        );
    }

    // --- Multi-table UNION ALL for temporal correlations ---

    #[test]
    fn test_temporal_single_table_unchanged() {
        let collection = parse_sigma_yaml(
            r#"
title: Multi-Stage Attack
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let queries = backend
            .convert_correlation_rule(
                &collection.correlations[0],
                "default",
                &PipelineState::default(),
            )
            .unwrap();
        assert_eq!(queries.len(), 1);
        // No UNION ALL, uses single table approach
        assert!(
            queries[0].contains("rule_name IN ('rule_a', 'rule_b')"),
            "expected single-table approach in: {}",
            queries[0]
        );
        assert!(
            !queries[0].contains("UNION ALL"),
            "should not contain UNION ALL in single-table mode"
        );
    }

    #[test]
    fn test_temporal_multi_table_union_all() {
        let collection = parse_sigma_yaml(
            r#"
title: Multi-Stage Attack
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let mut pipeline_state = PipelineState::default();

        // Inject _rule_tables mapping different rules to different tables
        let rule_tables = serde_json::json!({
            "rule_a": "process_events",
            "rule_b": "network_events"
        });
        pipeline_state.set_state("_rule_tables".to_string(), rule_tables);

        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        assert_eq!(queries.len(), 1);
        let q = &queries[0];
        assert!(q.contains("UNION ALL"), "expected UNION ALL in: {q}");
        assert!(
            q.contains("FROM network_events"),
            "expected network_events in: {q}"
        );
        assert!(
            q.contains("FROM process_events"),
            "expected process_events in: {q}"
        );
        assert!(
            q.contains("'rule_a' AS rule_name"),
            "expected rule_a label in: {q}"
        );
        assert!(
            q.contains("'rule_b' AS rule_name"),
            "expected rule_b label in: {q}"
        );
    }

    #[test]
    fn test_temporal_multi_table_with_backend_schema() {
        let collection = parse_sigma_yaml(
            r#"
title: Multi-Stage Attack
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let mut backend = PostgresBackend::new();
        backend.schema = Some("siem".to_string());
        let mut pipeline_state = PipelineState::default();

        let rule_tables = serde_json::json!({
            "rule_a": "process_events",
            "rule_b": "network_events"
        });
        pipeline_state.set_state("_rule_tables".to_string(), rule_tables);

        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        let q = &queries[0];
        assert!(
            q.contains("FROM siem.network_events"),
            "expected siem.network_events in: {q}"
        );
        assert!(
            q.contains("FROM siem.process_events"),
            "expected siem.process_events in: {q}"
        );
    }

    #[test]
    fn test_temporal_multi_table_per_rule_schemas() {
        let collection = parse_sigma_yaml(
            r#"
title: Cross-Schema Correlation
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
        - rule_c
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let mut pipeline_state = PipelineState::default();

        pipeline_state.set_state(
            "_rule_tables".to_string(),
            serde_json::json!({
                "rule_a": "process_events",
                "rule_b": "network_events",
                "rule_c": "auth_events"
            }),
        );
        pipeline_state.set_state(
            "_rule_schemas".to_string(),
            serde_json::json!({
                "rule_a": "siem",
                "rule_b": "network",
                "rule_c": "iam"
            }),
        );

        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        let q = &queries[0];
        assert!(q.contains("UNION ALL"), "expected UNION ALL in: {q}");
        assert!(
            q.contains("FROM iam.auth_events"),
            "expected iam.auth_events in: {q}"
        );
        assert!(
            q.contains("FROM network.network_events"),
            "expected network.network_events in: {q}"
        );
        assert!(
            q.contains("FROM siem.process_events"),
            "expected siem.process_events in: {q}"
        );
    }

    #[test]
    fn test_temporal_mixed_per_rule_and_default_schema() {
        let collection = parse_sigma_yaml(
            r#"
title: Mixed Schema Correlation
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let mut backend = PostgresBackend::new();
        backend.schema = Some("default_schema".to_string());
        let mut pipeline_state = PipelineState::default();

        pipeline_state.set_state(
            "_rule_tables".to_string(),
            serde_json::json!({
                "rule_a": "process_events",
                "rule_b": "network_events"
            }),
        );
        // Only rule_a has an explicit schema; rule_b falls back to backend default
        pipeline_state.set_state(
            "_rule_schemas".to_string(),
            serde_json::json!({
                "rule_a": "custom"
            }),
        );

        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        let q = &queries[0];
        assert!(
            q.contains("FROM custom.process_events"),
            "rule_a should use per-rule schema 'custom' in: {q}"
        );
        assert!(
            q.contains("FROM default_schema.network_events"),
            "rule_b should fall back to backend schema 'default_schema' in: {q}"
        );
    }

    #[test]
    fn test_temporal_same_table_in_rule_tables() {
        let collection = parse_sigma_yaml(
            r#"
title: Multi-Stage Attack
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let mut pipeline_state = PipelineState::default();

        // Both rules point to the same table so the single-table path is used
        let rule_tables = serde_json::json!({
            "rule_a": "security_events",
            "rule_b": "security_events"
        });
        pipeline_state.set_state("_rule_tables".to_string(), rule_tables);

        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        let q = &queries[0];
        assert!(
            !q.contains("UNION ALL"),
            "same table should use single-table path, got: {q}"
        );
        assert!(
            q.contains("rule_name IN ('rule_a', 'rule_b')"),
            "expected single-table approach in: {q}"
        );
    }

    #[test]
    fn test_non_temporal_ignores_multi_table() {
        let collection = parse_sigma_yaml(
            r#"
title: High Event Count
correlation:
    type: event_count
    rules:
        - rule_a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 100
"#,
        )
        .unwrap();
        let backend = PostgresBackend::new();
        let mut pipeline_state = PipelineState::default();

        // Even though _rule_tables has multiple tables, event_count uses the default table
        let rule_tables = serde_json::json!({
            "rule_a": "process_events",
            "rule_b": "network_events"
        });
        pipeline_state.set_state("_rule_tables".to_string(), rule_tables);

        let queries = backend
            .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
            .unwrap();
        let q = &queries[0];
        assert!(
            !q.contains("UNION ALL"),
            "event_count should not use UNION ALL: {q}"
        );
        assert!(
            q.contains("FROM security_events"),
            "event_count uses default table: {q}"
        );
    }
}
