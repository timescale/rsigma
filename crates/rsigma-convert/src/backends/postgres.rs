//! PostgreSQL/TimescaleDB backend for Sigma rule conversion.
//!
//! Converts Sigma detection rules into PostgreSQL SQL queries, leveraging
//! PostgreSQL-native features: `ILIKE` for case-insensitive matching,
//! `~*`/`~` for regex, `inet`/`cidr` for network address matching,
//! `tsvector`/`tsquery` for full-text keyword search, and JSONB for
//! semi-structured event data.

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

    cidr_expression: Some("{field}::inet <<= {value}::cidr"),
    not_cidr_expression: Some("NOT ({field}::inet <<= {value}::cidr)"),

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
            timescaledb: false,
        }
    }

    fn qualified_table(&self) -> String {
        match &self.schema {
            Some(s) => format!("{s}.{}", self.table),
            None => self.table.clone(),
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
        let not_like_op = if is_cased { "NOT LIKE" } else { "NOT ILIKE" };
        let _ = not_like_op;

        if is_contains || is_startswith || is_endswith || has_wildcards {
            let val = self.build_like_value(value);
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
            "{f}::inet <<= '{cidr}'::cidr"
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
        match value {
            SigmaValue::String(s) => {
                let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                let escaped = self.escape_sql_str(&plain);
                let search_target = match &self.json_field {
                    Some(json_col) => format!("{json_col}::text"),
                    None => "ROW(*)::text".to_string(),
                };
                Ok(format!(
                    "to_tsvector('simple', {search_target}) @@ to_tsquery('simple', '{escaped}')"
                ))
            }
            SigmaValue::Integer(n) => {
                let search_target = match &self.json_field {
                    Some(json_col) => format!("{json_col}::text"),
                    None => "ROW(*)::text".to_string(),
                };
                Ok(format!(
                    "to_tsvector('simple', {search_target}) @@ to_tsquery('simple', '{n}')"
                ))
            }
            SigmaValue::Float(f) => {
                let search_target = match &self.json_field {
                    Some(json_col) => format!("{json_col}::text"),
                    None => "ROW(*)::text".to_string(),
                };
                Ok(format!(
                    "to_tsvector('simple', {search_target}) @@ to_tsquery('simple', '{f}')"
                ))
            }
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
        let table = state.get_state_str("table").unwrap_or(&self.table);
        let qualified = match &self.schema {
            Some(s) if state.get_state_str("table").is_none() => format!("{s}.{table}"),
            _ => table.to_string(),
        };

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
        let view_name = || match &rule.id {
            Some(id) => format!("sigma_{}", id.replace('-', "_")),
            None => format!(
                "sigma_{}",
                rule.title.to_lowercase().replace([' ', '-'], "_")
            ),
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
        _pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        let table = self.qualified_table();
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
            CorrelationCondition::Threshold { field, .. } => field.clone(),
            _ => None,
        };
        let value_field = field_from_condition.as_deref().or_else(|| {
            rule.aliases
                .first()
                .and_then(|a| a.mapping.values().next().map(|s| s.as_str()))
        });

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
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                let rule_names = rule.rules.join("', '");
                let agg = "COUNT(DISTINCT rule_name)";
                format!(
                    "WITH matched AS (\
                     SELECT *, rule_name FROM {table} \
                     WHERE rule_name IN ('{rule_names}') \
                     AND {ts} >= NOW() - INTERVAL '{window_secs} seconds'\
                     ) \
                     SELECT {group_by_select}\
                     {agg} AS distinct_rules, \
                     MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
                     FROM matched\
                     {group_by_clause} \
                     HAVING {having_clause}",
                    having_clause = having_clause.replace("{agg}", agg)
                )
            }
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
                    0.95
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
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE 'whoami'"#]
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
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE 'cmd'"#]
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
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '.exe'"#]
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
            vec![r#"SELECT * FROM security_events WHERE "CommandLine" LIKE 'Whoami'"#]
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
            vec![r#"SELECT * FROM security_events WHERE "SourceIP"::inet <<= '10.0.0.0/8'::cidr"#]
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
                 to_tsvector('simple', ROW(*)::text) @@ to_tsquery('simple', 'whoami') OR \
                 to_tsvector('simple', ROW(*)::text) @@ to_tsquery('simple', 'ipconfig')"
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
            vec![r#"SELECT * FROM security_events WHERE "Path" ILIKE '100\%'"#]
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
}
