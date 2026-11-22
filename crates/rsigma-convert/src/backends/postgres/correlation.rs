use std::collections::{BTreeMap, HashMap};

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::*;

use crate::backend::Backend;
use crate::error::{ConvertError, Result};

impl super::PostgresBackend {
    /// Convert a correlation rule into its aggregate query, choosing the
    /// sliding, tumbling, or session strategy from [`Self::resolve_window_mode`].
    pub(super) fn convert_correlation(
        &self,
        rule: &CorrelationRule,
        output_format: &str,
        pipeline_state: &PipelineState,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        if rule.condition.has_negated_refs() {
            return Err(ConvertError::UnsupportedCorrelation(
                "absence/missing-event correlations are engine-only; the Postgres backend cannot honor a wall-clock deadline"
                    .to_string(),
            ));
        }
        let table = self.resolve_table(&rule.custom_attributes, &pipeline_state.state)?;
        let ts = &self.timestamp_field;
        let use_time_bucket =
            output_format == "timescaledb" || output_format == "continuous_aggregate";

        let mut group_by_cols: Vec<String> = rule
            .group_by
            .iter()
            .map(|g| self.field_expr(g))
            .collect::<Result<_>>()?;
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

        let temporal = matches!(
            rule.correlation_type,
            CorrelationType::Temporal | CorrelationType::TemporalOrdered
        );

        // Per-rule converted queries for CTE-based pre-filtering, present when
        // converting a collection. Temporal types filter on `rule_name` instead.
        let rule_queries: Option<HashMap<String, String>> = pipeline_state
            .state
            .get("_rule_queries")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let (cte_prefix, source_table, time_filter) = if temporal {
            Default::default()
        } else {
            self.build_correlation_source(
                &rule.rules,
                rule_queries.as_ref(),
                &table,
                ts,
                window_secs,
            )?
        };

        // The windowing strategy (sliding/tumbling/session). The
        // `correlation_method` option is the converting user's explicit choice
        // (pySigma-style) and overrides the rule's own `window` hint; otherwise
        // the rule's `window` is used. `sliding` (the default, also what an
        // absent `window` resolves to) preserves the existing per-output_format
        // behavior, so existing rules are unaffected. `tumbling` and `session`
        // are opt-in.
        let window = self.resolve_window_mode(rule)?;
        if matches!(window, WindowMode::Tumbling) {
            let query = if temporal {
                self.build_temporal_tumbling(
                    rule,
                    &table,
                    ts,
                    window_secs,
                    use_time_bucket,
                    &having_clause,
                    &rule_tables,
                    pipeline_state,
                )?
            } else {
                self.build_tumbling_correlation(
                    rule,
                    &cte_prefix,
                    &source_table,
                    ts,
                    window_secs,
                    value_field,
                    use_time_bucket,
                )?
            };
            return Ok(vec![query]);
        }
        if matches!(window, WindowMode::Session) {
            // The rule's own `gap` wins; the `gap` backend option provides the
            // default so `correlation_method=session` works for rules that do
            // not declare one.
            let gap_secs = rule
                .gap
                .as_ref()
                .map(|g| g.seconds)
                .or(self.session_gap_secs)
                .ok_or_else(|| {
                    ConvertError::UnsupportedCorrelation(
                        "session window requires a 'gap' (set it on the rule or pass \
                         -O gap=5m as a conversion default)"
                            .into(),
                    )
                })?;
            let query = if temporal {
                self.build_temporal_session(
                    rule,
                    &table,
                    ts,
                    window_secs,
                    gap_secs,
                    &having_clause,
                    &rule_tables,
                    pipeline_state,
                    warnings,
                )?
            } else {
                self.build_session_correlation(
                    rule,
                    &cte_prefix,
                    &source_table,
                    ts,
                    window_secs,
                    gap_secs,
                    value_field,
                    warnings,
                )?
            };
            return Ok(vec![query]);
        }

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
                let field = match value_field {
                    Some(f) => self.field_expr(f)?,
                    None => "'unknown_field'".to_string(),
                };
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
                    &group_by_cols,
                    &group_by_select,
                    &group_by_clause,
                    &having_clause,
                    &rule_tables,
                    pipeline_state,
                )?,
            CorrelationType::ValueSum => {
                let field = match value_field {
                    Some(f) => self.field_expr(f)?,
                    None => "'unknown_field'".to_string(),
                };
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
                let field = match value_field {
                    Some(f) => self.field_expr(f)?,
                    None => "'unknown_field'".to_string(),
                };
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
                let field = match value_field {
                    Some(f) => self.field_expr(f)?,
                    None => "'unknown_field'".to_string(),
                };
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

    /// Resolve the effective window mode for a correlation conversion.
    ///
    /// The `correlation_method` backend option, when set, is the converting
    /// user's explicit choice and overrides the rule's own `window` hint;
    /// otherwise the rule's `window` (default `sliding`) is used. An option that
    /// is not one of [`Self::correlation_methods`] is rejected.
    fn resolve_window_mode(&self, rule: &CorrelationRule) -> Result<WindowMode> {
        match self.correlation_method.as_deref() {
            None => Ok(rule.window),
            Some(method) => {
                if !self.correlation_methods().iter().any(|(n, _)| *n == method) {
                    let available = self
                        .correlation_methods()
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(ConvertError::UnsupportedCorrelation(format!(
                        "unknown correlation_method '{method}'; available: {available}"
                    )));
                }
                method.parse::<WindowMode>().map_err(|_| {
                    ConvertError::UnsupportedCorrelation(format!(
                        "correlation_method '{method}' has no window mapping"
                    ))
                })
            }
        }
    }

    /// Format a field name for use in a SELECT column list.
    ///
    /// Inspired by the pySigma Athena backend's `_format_select_field`:
    /// - Expressions containing parentheses (function calls) pass through unchanged
    /// - `field as alias` is split and both sides are quoted independently
    /// - Plain field names are quoted via `field_expr`
    pub(super) fn format_select_field(&self, field: &str) -> Result<String> {
        if field == "*" {
            return Ok("*".to_string());
        }
        if field.contains('(') && field.contains(')') {
            return Ok(field.to_string());
        }
        if let Some((expr, alias)) = field.split_once(" as ") {
            let quoted_expr = self.field_expr(expr.trim())?;
            let quoted_alias = self.field_expr(alias.trim())?;
            return Ok(format!("{quoted_expr} AS {quoted_alias}"));
        }
        if let Some((expr, alias)) = field.split_once(" AS ") {
            let quoted_expr = self.field_expr(expr.trim())?;
            let quoted_alias = self.field_expr(alias.trim())?;
            return Ok(format!("{quoted_expr} AS {quoted_alias}"));
        }
        self.field_expr(field)
    }

    /// Build the CTE prefix and source for non-temporal correlations.
    ///
    /// When converting a collection, `convert_collection` injects the
    /// converted detection queries as `_rule_queries`, and they are wrapped in
    /// a `WITH combined_events AS (q1 UNION ALL q2 ...)` CTE. The aggregate
    /// query then reads from `combined_events` instead of the raw table. A
    /// reference without a converted query (another correlation, or a
    /// detection rule that failed to convert) is an error, since scanning the
    /// table instead would count unrelated events.
    ///
    /// Without `_rule_queries`, as when a single correlation is converted on
    /// its own, the query scans the full table with a time-window filter.
    ///
    /// Returns `(cte_prefix, source_table, time_filter)`.
    fn build_correlation_source(
        &self,
        rule_refs: &[String],
        rule_queries: Option<&HashMap<String, String>>,
        default_table: &str,
        ts: &str,
        window_secs: u64,
    ) -> Result<(String, String, String)> {
        let Some(rule_queries) = rule_queries else {
            let time_filter = format!(" WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'");
            return Ok((String::new(), default_table.to_string(), time_filter));
        };
        let mut matched = Vec::with_capacity(rule_refs.len());
        for rule_ref in rule_refs {
            let query = rule_queries.get(rule_ref).ok_or_else(|| {
                ConvertError::UnsupportedCorrelation(format!(
                    "rule reference '{rule_ref}' has no converted detection query; \
                     PostgreSQL aggregate correlations can only reference detection rules \
                     that convert successfully, not other correlations"
                ))
            })?;
            matched.push(query.as_str());
        }
        let union = matched.join(" UNION ALL ");
        let cte = format!("WITH combined_events AS ({union}) ");
        Ok((cte, "combined_events".to_string(), String::new()))
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
    fn build_sliding_window_query(
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
            let cols: Vec<String> = group_by
                .iter()
                .map(|g| self.field_expr(g))
                .collect::<Result<_>>()?;
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

    /// Aggregate SELECT expression and its column alias for a correlation type.
    ///
    /// Shared by the tumbling and session builders. Temporal types are handled
    /// by [`build_temporal_query`](Self::build_temporal_query) and are rejected
    /// here.
    fn correlation_aggregate(
        &self,
        rule: &CorrelationRule,
        value_field: Option<&str>,
    ) -> Result<(String, &'static str)> {
        let field = match value_field {
            Some(f) => self.field_expr(f)?,
            None => "'unknown_field'".to_string(),
        };
        Ok(match rule.correlation_type {
            CorrelationType::EventCount => ("COUNT(*)".to_string(), "event_count"),
            CorrelationType::ValueCount => (format!("COUNT(DISTINCT {field})"), "value_count"),
            CorrelationType::ValueSum => (format!("SUM({field})"), "value_sum"),
            CorrelationType::ValueAvg => (format!("AVG({field})"), "value_avg"),
            CorrelationType::ValuePercentile | CorrelationType::ValueMedian => {
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
                (
                    format!("PERCENTILE_CONT({percentile}) WITHIN GROUP (ORDER BY {field})"),
                    "pct_value",
                )
            }
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                return Err(ConvertError::UnsupportedCorrelation(
                    "temporal correlations are handled by a dedicated builder".into(),
                ));
            }
        })
    }

    /// Build a tumbling-window correlation query for the non-temporal aggregate
    /// types: events are grouped into fixed, boundary-aligned buckets of size
    /// `window_secs` (via `time_bucket` on TimescaleDB, or `date_bin` aligned to
    /// the epoch on plain PostgreSQL) plus the rule's group-by columns.
    #[allow(clippy::too_many_arguments)]
    fn build_tumbling_correlation(
        &self,
        rule: &CorrelationRule,
        cte_prefix: &str,
        source_table: &str,
        ts: &str,
        window_secs: u64,
        value_field: Option<&str>,
        use_time_bucket: bool,
    ) -> Result<String> {
        let (agg, alias) = self.correlation_aggregate(rule, value_field)?;
        let bucket_expr = if use_time_bucket {
            format!("time_bucket('{window_secs} seconds', {ts})")
        } else {
            format!("date_bin('{window_secs} seconds', {ts}, TIMESTAMPTZ 'epoch')")
        };
        let group_exprs: Vec<String> = rule
            .group_by
            .iter()
            .map(|g| self.field_expr(g))
            .collect::<Result<_>>()?;
        let group_by_select = if group_exprs.is_empty() {
            String::new()
        } else {
            format!("{}, ", group_exprs.join(", "))
        };
        let mut gb = vec![bucket_expr.clone()];
        gb.extend(group_exprs);
        let group_by_clause = format!(" GROUP BY {}", gb.join(", "));
        let having = self
            .build_having_clause(&rule.condition)?
            .replace("{agg}", &agg);

        Ok(format!(
            "{cte_prefix}SELECT {bucket_expr} AS correlation_bucket, \
             {group_by_select}{agg} AS {alias} \
             FROM {source_table}\
             {group_by_clause} \
             HAVING {having}"
        ))
    }

    /// Build a session-window correlation query for the non-temporal aggregate
    /// types using the gaps-and-islands pattern: `LAG` flags the first event of
    /// each session (a gap larger than `gap_secs`), a running `SUM` assigns a
    /// per-group session id, and the aggregate is computed per session.
    ///
    /// The `gap` is honored exactly. The `timespan` cap can only be enforced as
    /// a post-aggregation filter (sessions longer than the cap are dropped, not
    /// split mid-session as the runtime does), which is recorded in `warnings`.
    #[allow(clippy::too_many_arguments)]
    fn build_session_correlation(
        &self,
        rule: &CorrelationRule,
        cte_prefix: &str,
        source_table: &str,
        ts: &str,
        window_secs: u64,
        gap_secs: u64,
        value_field: Option<&str>,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        let (agg, alias) = self.correlation_aggregate(rule, value_field)?;
        let group_exprs: Vec<String> = rule
            .group_by
            .iter()
            .map(|g| self.field_expr(g))
            .collect::<Result<_>>()?;

        let partition = if group_exprs.is_empty() {
            String::new()
        } else {
            format!("PARTITION BY {} ", group_exprs.join(", "))
        };
        let group_by_select = if group_exprs.is_empty() {
            String::new()
        } else {
            format!("{}, ", group_exprs.join(", "))
        };
        let mut final_group = group_exprs;
        final_group.push("session_id".to_string());
        let final_group_clause = final_group.join(", ");

        let having = self
            .build_having_clause(&rule.condition)?
            .replace("{agg}", &agg);

        warnings.push(format!(
            "PostgreSQL session window: the {gap_secs}s gap is exact, but the {window_secs}s \
             'timespan' cap is enforced as a post-aggregation filter (sessions exceeding it are \
             dropped, not split)"
        ));
        let cap_clause =
            format!(" AND (MAX({ts}) - MIN({ts})) <= INTERVAL '{window_secs} seconds'");

        // Chain onto an existing combined_events CTE when present, otherwise
        // open the WITH chain with a plain source CTE.
        let (head, src) = if cte_prefix.is_empty() {
            (
                format!("WITH source AS (SELECT * FROM {source_table}), "),
                "source".to_string(),
            )
        } else {
            (
                format!("{}, ", cte_prefix.trim_end()),
                source_table.to_string(),
            )
        };

        Ok(format!(
            "{head}\
             marked AS (\
             SELECT *, \
             CASE WHEN LAG({ts}) OVER ({partition}ORDER BY {ts}) IS NULL \
             OR {ts} - LAG({ts}) OVER ({partition}ORDER BY {ts}) > INTERVAL '{gap_secs} seconds' \
             THEN 1 ELSE 0 END AS is_new_session \
             FROM {src}\
             ), \
             sessions AS (\
             SELECT *, SUM(is_new_session) OVER (\
             {partition}ORDER BY {ts} ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW\
             ) AS session_id \
             FROM marked\
             ) \
             SELECT {group_by_select}session_id, {agg} AS {alias}, \
             MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
             FROM sessions \
             GROUP BY {final_group_clause} \
             HAVING {having}{cap_clause}"
        ))
    }

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

    /// Build the inner SELECT for the temporal `matched` CTE (the SQL between
    /// `matched AS (` and `)`), tagging each row with a `rule_name`.
    ///
    /// Single-table references filter a `rule_name` column with `IN (...)`;
    /// multi-table references (from `_rule_tables`) become a `UNION ALL` with a
    /// literal `rule_name` discriminator per leg. `include_time_filter` adds the
    /// relative `NOW() - INTERVAL` window used by the default (sliding) temporal
    /// query; tumbling and session windows omit it because they derive their
    /// own bounds from the data.
    #[allow(clippy::too_many_arguments)]
    fn build_temporal_matched_inner(
        &self,
        rule: &CorrelationRule,
        default_table: &str,
        ts: &str,
        window_secs: u64,
        rule_tables: &HashMap<String, String>,
        pipeline_state: &PipelineState,
        include_time_filter: bool,
    ) -> Result<String> {
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
                Some(t) => self.qualify_table_name(t, &pipeline_state.state, per_rule_schema)?,
                None => default_table.to_string(),
            };
            table_to_rules
                .entry(qualified)
                .or_default()
                .push(rule_ref.clone());
        }

        if table_to_rules.len() <= 1 {
            let rule_names = rule
                .rules
                .iter()
                .map(|r| r.replace('\'', "''"))
                .collect::<Vec<_>>()
                .join("', '");
            let time_filter = if include_time_filter {
                format!(" AND {ts} >= NOW() - INTERVAL '{window_secs} seconds'")
            } else {
                String::new()
            };
            Ok(format!(
                "SELECT * FROM {default_table} \
                 WHERE rule_name IN ('{rule_names}'){time_filter}"
            ))
        } else {
            let time_filter = if include_time_filter {
                format!(" WHERE {ts} >= NOW() - INTERVAL '{window_secs} seconds'")
            } else {
                String::new()
            };
            let tf = time_filter.as_str();
            let union_parts: Vec<String> = table_to_rules
                .iter()
                .flat_map(|(tbl, rules)| {
                    rules.iter().map(move |rule_ref| {
                        let name = rule_ref.replace('\'', "''");
                        format!("SELECT *, '{name}' AS rule_name FROM {tbl}{tf}")
                    })
                })
                .collect();
            Ok(union_parts.join(" UNION ALL "))
        }
    }

    /// The CTEs that enforce `temporal_ordered`, chained after `source`.
    ///
    /// Each step takes the earliest hit of the next referenced rule at or after
    /// the previous step, within the window `partition`. A non-decreasing chain
    /// of hits in `rules` order exists exactly when the last step is not NULL,
    /// which is the returned `HAVING` predicate. Returns `None` for `temporal`.
    fn temporal_order_steps(
        rule: &CorrelationRule,
        source: &str,
        ts: &str,
        partition: &[String],
    ) -> Option<(String, String, String)> {
        if rule.correlation_type != CorrelationType::TemporalOrdered || rule.rules.is_empty() {
            return None;
        }
        let over = if partition.is_empty() {
            "()".to_string()
        } else {
            format!("(PARTITION BY {})", partition.join(", "))
        };
        let mut ctes = String::new();
        let mut prev = source.to_string();
        for (i, rule_ref) in rule.rules.iter().enumerate() {
            let step = i + 1;
            let name = rule_ref.replace('\'', "''");
            let after = if i == 0 {
                String::new()
            } else {
                format!(" AND {ts} >= __step_{i}")
            };
            ctes.push_str(&format!(
                ", ordered_{step} AS (SELECT *, \
                 MIN(CASE WHEN rule_name = '{name}'{after} THEN {ts} END) OVER {over} \
                 AS __step_{step} FROM {prev})"
            ));
            prev = format!("ordered_{step}");
        }
        let having = format!(" AND MAX(__step_{}) IS NOT NULL", rule.rules.len());
        Some((ctes, prev, having))
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
        group_by_cols: &[String],
        group_by_select: &str,
        group_by_clause: &str,
        having_clause: &str,
        rule_tables: &HashMap<String, String>,
        pipeline_state: &PipelineState,
    ) -> Result<String> {
        let agg = "COUNT(DISTINCT rule_name)";
        let having = having_clause.replace("{agg}", agg);
        let inner = self.build_temporal_matched_inner(
            rule,
            default_table,
            ts,
            window_secs,
            rule_tables,
            pipeline_state,
            true,
        )?;
        let (steps, source, order_having) =
            Self::temporal_order_steps(rule, "matched", ts, group_by_cols)
                .unwrap_or_else(|| (String::new(), "matched".to_string(), String::new()));

        Ok(format!(
            "WITH matched AS (\
             {inner}\
             ){steps} \
             SELECT {group_by_select}\
             {agg} AS distinct_rules, \
             MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
             FROM {source}\
             {group_by_clause} \
             HAVING {having}{order_having}"
        ))
    }

    /// Build a tumbling-window temporal correlation query: events from the
    /// referenced rules are grouped into fixed, boundary-aligned buckets of size
    /// `window_secs`, and each bucket counts the distinct referenced rules that
    /// fired.
    ///
    /// Like the default temporal path, this counts distinct `rule_name`s, and
    /// `temporal_ordered` adds the ordering steps within each bucket.
    #[allow(clippy::too_many_arguments)]
    fn build_temporal_tumbling(
        &self,
        rule: &CorrelationRule,
        default_table: &str,
        ts: &str,
        window_secs: u64,
        use_time_bucket: bool,
        having_clause: &str,
        rule_tables: &HashMap<String, String>,
        pipeline_state: &PipelineState,
    ) -> Result<String> {
        let agg = "COUNT(DISTINCT rule_name)";
        let having = having_clause.replace("{agg}", agg);
        let inner = self.build_temporal_matched_inner(
            rule,
            default_table,
            ts,
            window_secs,
            rule_tables,
            pipeline_state,
            false,
        )?;
        let bucket_expr = if use_time_bucket {
            format!("time_bucket('{window_secs} seconds', {ts})")
        } else {
            format!("date_bin('{window_secs} seconds', {ts}, TIMESTAMPTZ 'epoch')")
        };
        let group_exprs: Vec<String> = rule
            .group_by
            .iter()
            .map(|g| self.field_expr(g))
            .collect::<Result<_>>()?;
        let group_by_select = if group_exprs.is_empty() {
            String::new()
        } else {
            format!("{}, ", group_exprs.join(", "))
        };
        let mut gb = vec![bucket_expr.clone()];
        gb.extend(group_exprs);
        let group_by_clause = format!(" GROUP BY {}", gb.join(", "));
        let (steps, source, order_having) = Self::temporal_order_steps(rule, "matched", ts, &gb)
            .unwrap_or_else(|| (String::new(), "matched".to_string(), String::new()));

        Ok(format!(
            "WITH matched AS (\
             {inner}\
             ){steps} \
             SELECT {bucket_expr} AS correlation_bucket, {group_by_select}\
             {agg} AS distinct_rules, \
             MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
             FROM {source}\
             {group_by_clause} \
             HAVING {having}{order_having}"
        ))
    }

    /// Build a session-window temporal correlation query: the referenced rules'
    /// events are sessionized per group with the gaps-and-islands pattern, and
    /// each session counts the distinct referenced rules that fired.
    ///
    /// The `gap` is honored exactly; the `timespan` cap is a post-aggregation
    /// filter (recorded in `warnings`). `temporal_ordered` adds the ordering
    /// steps within each session.
    #[allow(clippy::too_many_arguments)]
    fn build_temporal_session(
        &self,
        rule: &CorrelationRule,
        default_table: &str,
        ts: &str,
        window_secs: u64,
        gap_secs: u64,
        having_clause: &str,
        rule_tables: &HashMap<String, String>,
        pipeline_state: &PipelineState,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        let agg = "COUNT(DISTINCT rule_name)";
        let having = having_clause.replace("{agg}", agg);
        let inner = self.build_temporal_matched_inner(
            rule,
            default_table,
            ts,
            window_secs,
            rule_tables,
            pipeline_state,
            false,
        )?;
        let group_exprs: Vec<String> = rule
            .group_by
            .iter()
            .map(|g| self.field_expr(g))
            .collect::<Result<_>>()?;
        let partition = if group_exprs.is_empty() {
            String::new()
        } else {
            format!("PARTITION BY {} ", group_exprs.join(", "))
        };
        let group_by_select = if group_exprs.is_empty() {
            String::new()
        } else {
            format!("{}, ", group_exprs.join(", "))
        };
        let mut final_group = group_exprs;
        final_group.push("session_id".to_string());
        let final_group_clause = final_group.join(", ");
        let (steps, source, order_having) =
            Self::temporal_order_steps(rule, "sessions", ts, &final_group)
                .unwrap_or_else(|| (String::new(), "sessions".to_string(), String::new()));

        warnings.push(format!(
            "PostgreSQL session window: the {gap_secs}s gap is exact, but the {window_secs}s \
             'timespan' cap is enforced as a post-aggregation filter (sessions exceeding it are \
             dropped, not split)"
        ));
        let cap_clause =
            format!(" AND (MAX({ts}) - MIN({ts})) <= INTERVAL '{window_secs} seconds'");

        Ok(format!(
            "WITH matched AS (\
             {inner}\
             ), \
             marked AS (\
             SELECT *, \
             CASE WHEN LAG({ts}) OVER ({partition}ORDER BY {ts}) IS NULL \
             OR {ts} - LAG({ts}) OVER ({partition}ORDER BY {ts}) > INTERVAL '{gap_secs} seconds' \
             THEN 1 ELSE 0 END AS is_new_session \
             FROM matched\
             ), \
             sessions AS (\
             SELECT *, SUM(is_new_session) OVER (\
             {partition}ORDER BY {ts} ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW\
             ) AS session_id \
             FROM marked\
             ){steps} \
             SELECT {group_by_select}session_id, {agg} AS distinct_rules, \
             MIN({ts}) AS first_seen, MAX({ts}) AS last_seen \
             FROM {source} \
             GROUP BY {final_group_clause} \
             HAVING {having}{cap_clause}{order_having}"
        ))
    }
}
