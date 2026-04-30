use std::collections::{BTreeMap, HashMap};

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::*;

use crate::error::{ConvertError, Result};

impl super::PostgresBackend {
    /// Format a field name for use in a SELECT column list.
    ///
    /// Inspired by the pySigma Athena backend's `_format_select_field`:
    /// - Expressions containing parentheses (function calls) pass through unchanged
    /// - `field as alias` is split and both sides are quoted independently
    /// - Plain field names are quoted via `field_expr`
    pub(super) fn format_select_field(&self, field: &str) -> String {
        if field == "*" {
            return "*".to_string();
        }
        if field.contains('(') && field.contains(')') {
            return field.to_string();
        }
        if let Some((expr, alias)) = field.split_once(" as ") {
            let quoted_expr = self.field_expr(expr.trim());
            let quoted_alias = self.field_expr(alias.trim());
            return format!("{quoted_expr} AS {quoted_alias}");
        }
        if let Some((expr, alias)) = field.split_once(" AS ") {
            let quoted_expr = self.field_expr(expr.trim());
            let quoted_alias = self.field_expr(alias.trim());
            return format!("{quoted_expr} AS {quoted_alias}");
        }
        self.field_expr(field)
    }

    /// Build the CTE prefix and source for non-temporal correlations.
    ///
    /// When per-rule converted queries are available (from `_rule_queries`
    /// injected by `convert_collection`), wraps them in a
    /// `WITH combined_events AS (q1 UNION ALL q2 ...)` CTE. The aggregate
    /// query then reads from `combined_events` instead of the raw table.
    ///
    /// When no per-rule queries are available, falls back to the original
    /// behavior: scan the full table with a time-window filter.
    ///
    /// Returns `(cte_prefix, source_table, time_filter)`.
    pub(super) fn build_correlation_source(
        &self,
        rule_refs: &[String],
        rule_queries: &HashMap<String, String>,
        default_table: &str,
        ts: &str,
        window_secs: u64,
    ) -> (String, String, String) {
        let matched: Vec<&str> = rule_refs
            .iter()
            .filter_map(|r| rule_queries.get(r).map(|q| q.as_str()))
            .collect();

        if matched.is_empty() {
            let time_filter = format!(" WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'");
            (String::new(), default_table.to_string(), time_filter)
        } else {
            let union = matched.join(" UNION ALL ");
            let cte = format!("WITH combined_events AS ({union}) ");
            (cte, "combined_events".to_string(), String::new())
        }
    }

    /// Build a sliding window query for `event_count` correlations.
    ///
    /// Generates a two-CTE query inspired by the pySigma Athena backend:
    /// ```sql
    /// WITH combined_events AS (...),
    /// event_counts AS (
    ///     SELECT *, COUNT(*) OVER (
    ///         PARTITION BY {group_by}
    ///         ORDER BY {time_field}
    ///         RANGE BETWEEN INTERVAL '{N}' SECOND PRECEDING AND CURRENT ROW
    ///     ) AS correlation_event_count
    ///     FROM combined_events
    /// )
    /// SELECT * FROM event_counts WHERE correlation_event_count >= {threshold}
    /// ```
    ///
    /// This produces a per-row sliding window that emits every event crossing
    /// the threshold within its trailing window.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_sliding_window_query(
        &self,
        cte_prefix: &str,
        source_table: &str,
        time_filter: &str,
        group_by: &[String],
        ts: &str,
        window_secs: u64,
        condition: &CorrelationCondition,
    ) -> Result<String> {
        let partition_clause = if group_by.is_empty() {
            String::new()
        } else {
            let cols: Vec<String> = group_by.iter().map(|g| self.field_expr(g)).collect();
            format!("PARTITION BY {} ", cols.join(", "))
        };

        let where_clause = self.build_threshold_where("correlation_event_count", condition)?;

        // When there is a CTE prefix (combined_events), chain the window CTE
        // onto it. Otherwise, build a standalone source CTE from the table.
        let full_cte = if cte_prefix.is_empty() {
            format!(
                "WITH source AS (\
                 SELECT * FROM {source_table}{time_filter}\
                 ), \
                 event_counts AS (\
                 SELECT *, COUNT(*) OVER (\
                 {partition_clause}\
                 ORDER BY {ts} \
                 RANGE BETWEEN INTERVAL '{window_secs} seconds' PRECEDING AND CURRENT ROW\
                 ) AS correlation_event_count \
                 FROM source\
                 ) "
            )
        } else {
            // cte_prefix already has "WITH combined_events AS (...) "
            // Strip the trailing space and append the window CTE
            let base = cte_prefix.trim_end();
            format!(
                "{base}, \
                 event_counts AS (\
                 SELECT *, COUNT(*) OVER (\
                 {partition_clause}\
                 ORDER BY {ts} \
                 RANGE BETWEEN INTERVAL '{window_secs} seconds' PRECEDING AND CURRENT ROW\
                 ) AS correlation_event_count \
                 FROM {source_table}\
                 ) "
            )
        };

        Ok(format!(
            "{full_cte}SELECT * FROM event_counts WHERE {where_clause}"
        ))
    }

    /// Build a WHERE clause from a correlation condition for sliding window queries.
    fn build_threshold_where(&self, column: &str, cond: &CorrelationCondition) -> Result<String> {
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
                        format!("{column} {op_str} {val}")
                    })
                    .collect();
                Ok(parts.join(" AND "))
            }
            CorrelationCondition::Extended(_) => Err(ConvertError::UnsupportedCorrelation(
                "extended boolean conditions not yet supported for PostgreSQL".into(),
            )),
        }
    }

    /// Build HAVING clause from correlation condition predicates.
    /// Uses `{agg}` as placeholder for the aggregate expression.
    pub(super) fn build_having_clause(&self, cond: &CorrelationCondition) -> Result<String> {
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
    pub(super) fn build_temporal_query(
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
