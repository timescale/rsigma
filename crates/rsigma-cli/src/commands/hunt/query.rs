//! Hunt SQL construction.
//!
//! Detection rules are converted with the shipped PostgreSQL backend and the
//! generated `SELECT` is wrapped, unmodified, as a subquery that adds the
//! hunt-owned time-window predicates, ordering, and row limit. The wrapper
//! never parses the generated SQL, so hunt correctness cannot drift from
//! backend correctness; the only coupling is the shared `timestamp_field`
//! option, read from the same `-O` map the backend gets.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use rsigma_convert::backends::postgres::PostgresBackend;

/// Default per-rule row limit when `--limit` is not passed.
pub(crate) const DEFAULT_LIMIT: usize = 1000;

/// A hunt time window. `--since 30d`-style relative values are resolved
/// against the wall clock when the flag is parsed, so by the time a window
/// reaches the wrapper both bounds are fixed instants.
#[derive(Debug, Default, Clone)]
pub(crate) struct HuntWindow {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl HuntWindow {
    /// Reject an empty window (`since` at or after `until`).
    pub(crate) fn validate(&self) -> Result<(), HuntQueryError> {
        if let (Some(since), Some(until)) = (&self.since, &self.until)
            && since >= until
        {
            return Err(HuntQueryError::EmptyWindow {
                since: since.to_rfc3339(),
                until: until.to_rfc3339(),
            });
        }
        Ok(())
    }
}

/// One executable hunt query: the wrapped SQL plus the rule it came from.
/// Attribution travels here (printed on stderr), never by mutating the
/// emitted event.
#[derive(Debug)]
pub(crate) struct HuntQuery {
    pub rule_title: String,
    pub rule_id: Option<String>,
    pub sql: String,
}

/// Everything a hunt execution needs that the wrapper already resolved:
/// the per-rule queries plus the effective backend options the row reshaper
/// must agree with.
#[derive(Debug)]
pub(crate) struct HuntPlan {
    pub queries: Vec<HuntQuery>,
    /// Effective timestamp column (backend default `time` unless overridden).
    pub timestamp_field: String,
    /// Effective JSONB column when the backend runs in JSONB mode.
    pub json_field: Option<String>,
    /// Per-rule row limit baked into the SQL (0 = unbounded). Only the
    /// gated executor reads it, to detect truncation.
    #[cfg(feature = "hunt-postgres")]
    pub limit: usize,
}

/// Failures while building hunt SQL. Each variant carries everything needed
/// for a pointed message; the command layer maps kinds to exit codes.
#[derive(Debug)]
pub(crate) enum HuntQueryError {
    /// The collection contains correlation rules.
    CorrelationRejected { titles: Vec<String> },
    /// `timestamp_field` or `json_field` is not a plain SQL identifier.
    InvalidIdentifier { option: String, value: String },
    /// `--since` is at or after `--until`.
    EmptyWindow { since: String, until: String },
    /// Conversion of the whole collection failed.
    Conversion(String),
    /// One or more rules failed to convert (`title: error` lines).
    RuleFailures(Vec<String>),
    /// A rule produced output that is not a plain `SELECT` (e.g. a pipeline
    /// `query_expression_template` replaced the default shape).
    NonSelectOutput { rule_title: String },
    /// A `--since`/`--until` value is neither RFC 3339 nor a humantime
    /// duration, or is out of range.
    InvalidTimeBound { value: String },
}

impl HuntQueryError {
    /// The pointed, operator-facing message.
    pub(crate) fn message(&self) -> String {
        match self {
            Self::CorrelationRejected { titles } => format!(
                "hunt run supports detection rules only; found {} correlation rule(s): {}. \
                 Correlation queries return aggregate rows, not events. \
                 Convert with `rsigma backend convert -t postgres` and run the query manually.",
                titles.len(),
                titles.join(", ")
            ),
            Self::InvalidIdentifier { option, value } => format!(
                "invalid {option} '{value}': expected a plain SQL identifier \
                 (letters, digits, `_`, `$`, not starting with a digit)"
            ),
            Self::EmptyWindow { since, until } => {
                format!("empty hunt window: --since {since} is not before --until {until}")
            }
            Self::Conversion(msg) => format!("conversion failed: {msg}"),
            Self::RuleFailures(lines) => format!(
                "{} rule(s) failed to convert:\n  {}",
                lines.len(),
                lines.join("\n  ")
            ),
            Self::NonSelectOutput { rule_title } => format!(
                "rule '{rule_title}' did not produce a plain SELECT; hunts require the \
                 backend's default format (a pipeline query_expression_template or custom \
                 attribute replaced it)"
            ),
            Self::InvalidTimeBound { value } => format!(
                "invalid time bound '{value}': expected an RFC 3339 instant or a duration \
                 like 30m, 12h, 7d"
            ),
        }
    }
}

/// Parse a `--since`/`--until` value: an RFC 3339 instant, or a humantime
/// duration (`30m`, `12h`, `7d`) relative to `now`.
pub(crate) fn parse_time_bound(
    value: &str,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, HuntQueryError> {
    if let Ok(ts) = DateTime::parse_from_rfc3339(value) {
        return Ok(ts.with_timezone(&Utc));
    }
    let duration = humantime::parse_duration(value)
        .map_err(|_| HuntQueryError::InvalidTimeBound {
            value: value.to_string(),
        })
        .and_then(|d| {
            chrono::Duration::from_std(d).map_err(|_| HuntQueryError::InvalidTimeBound {
                value: value.to_string(),
            })
        })?;
    Ok(now - duration)
}

/// The wrapper interpolates the timestamp column as a SQL identifier, so it
/// must be a plain identifier (the same rule the backend applies to table
/// names). Everything else is rejected before any SQL is built.
fn validate_identifier(option: &str, value: &str) -> Result<(), HuntQueryError> {
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(HuntQueryError::InvalidIdentifier {
            option: option.to_string(),
            value: value.to_string(),
        })
    }
}

/// Render an instant as a timestamptz literal. The text is chrono-formatted,
/// so there is no injection surface.
fn timestamp_literal(ts: &DateTime<Utc>) -> String {
    format!("'{}'::timestamptz", ts.to_rfc3339())
}

/// Wrap one generated `SELECT` with the hunt-owned predicates. The generated
/// query stays an opaque subquery; `timestamp_column` is the backend-quoted
/// identifier. `limit == 0` means unbounded (no `LIMIT` clause).
pub(crate) fn wrap_query(
    generated: &str,
    timestamp_column: &str,
    window: &HuntWindow,
    limit: usize,
) -> String {
    let inner = generated.trim().trim_end_matches(';');
    let mut sql = format!("SELECT * FROM ({inner}) AS __hunt");
    let mut predicates = Vec::new();
    if let Some(since) = &window.since {
        predicates.push(format!(
            "{timestamp_column} >= {}",
            timestamp_literal(since)
        ));
    }
    if let Some(until) = &window.until {
        predicates.push(format!("{timestamp_column} < {}", timestamp_literal(until)));
    }
    if !predicates.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&predicates.join(" AND "));
    }
    sql.push_str(&format!(" ORDER BY {timestamp_column}"));
    if limit > 0 {
        sql.push_str(&format!(" LIMIT {limit}"));
    }
    sql
}

/// Load rules and pipelines, convert with the postgres backend, and wrap each
/// generated query into an executable hunt statement.
///
/// A rule's `fields:` list is cleared before conversion: hunts want whole
/// rows, and a declared projection would both starve the exemplar contract
/// (flat mode) and replace the raw JSONB column with extractions (JSONB
/// mode). The generated SQL stays opaque to the wrapper either way.
pub(crate) fn build_hunt_plan(
    mut collection: rsigma_parser::SigmaCollection,
    pipeline_paths: &[PathBuf],
    options: &HashMap<String, String>,
    window: &HuntWindow,
    limit: usize,
) -> Result<HuntPlan, HuntQueryError> {
    window.validate()?;

    if !collection.correlations.is_empty() {
        let titles = collection
            .correlations
            .iter()
            .map(|c| c.title.clone())
            .collect();
        return Err(HuntQueryError::CorrelationRejected { titles });
    }
    for rule in &mut collection.rules {
        rule.fields.clear();
    }

    let pipelines = crate::load_pipelines(pipeline_paths);
    let backend = PostgresBackend::from_options(options);

    validate_identifier("timestamp_field", &backend.timestamp_field)?;
    if let Some(json_field) = &backend.json_field {
        validate_identifier("json_field", json_field)?;
    }

    let output = rsigma_convert::convert_collection(&backend, &collection, &pipelines, "default")
        .map_err(|e| HuntQueryError::Conversion(e.to_string()))?;
    if !output.errors.is_empty() {
        let lines = output
            .errors
            .iter()
            .map(|(title, err)| format!("{title}: {err}"))
            .collect();
        return Err(HuntQueryError::RuleFailures(lines));
    }
    for (rule_title, warning) in output.warnings() {
        eprintln!("Warning: rule '{rule_title}': {warning}");
    }

    // Quote the timestamp column with the backend's own field machinery so
    // the wrapper's identifier rendering matches the generated query's.
    let timestamp_column = rsigma_convert::backend::text_escape_and_quote_field(
        backend.config,
        &backend.timestamp_field,
    );

    let mut queries = Vec::new();
    for result in &output.queries {
        for query in &result.queries {
            if !query
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("SELECT")
            {
                return Err(HuntQueryError::NonSelectOutput {
                    rule_title: result.rule_title.clone(),
                });
            }
            queries.push(HuntQuery {
                rule_title: result.rule_title.clone(),
                rule_id: result.rule_id.clone(),
                sql: wrap_query(query, &timestamp_column, window, limit),
            });
        }
    }

    Ok(HuntPlan {
        queries,
        timestamp_field: backend.timestamp_field.clone(),
        json_field: backend.json_field.clone(),
        #[cfg(feature = "hunt-postgres")]
        limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-09T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn window(since: Option<&str>, until: Option<&str>) -> HuntWindow {
        HuntWindow {
            since: since.map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)),
            until: until.map(|s| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)),
        }
    }

    // -- time bounds ---------------------------------------------------------

    #[test]
    fn parse_rfc3339_instant() {
        let ts = parse_time_bound("2026-07-01T00:00:00Z", fixed_now()).unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-07-01T00:00:00+00:00");
    }

    #[test]
    fn parse_relative_duration() {
        let ts = parse_time_bound("30d", fixed_now()).unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-06-09T12:00:00+00:00");
    }

    #[test]
    fn parse_rejects_garbage() {
        let err = parse_time_bound("next tuesday", fixed_now()).unwrap_err();
        assert!(err.message().contains("invalid time bound 'next tuesday'"));
    }

    #[test]
    fn window_rejects_empty_range() {
        let w = window(Some("2026-07-02T00:00:00Z"), Some("2026-07-01T00:00:00Z"));
        let err = w.validate().unwrap_err();
        assert!(err.message().contains("empty hunt window"));
    }

    #[test]
    fn window_accepts_touching_bounds_excluded_by_check() {
        let w = window(Some("2026-07-01T00:00:00Z"), Some("2026-07-02T00:00:00Z"));
        w.validate().unwrap();
    }

    // -- identifiers ----------------------------------------------------------

    #[test]
    fn identifier_validation() {
        assert!(validate_identifier("timestamp_field", "time").is_ok());
        assert!(validate_identifier("timestamp_field", "_ts1$").is_ok());
        assert!(validate_identifier("timestamp_field", "1time").is_err());
        assert!(validate_identifier("timestamp_field", "time; DROP TABLE").is_err());
        assert!(validate_identifier("timestamp_field", "").is_err());
        let err = validate_identifier("json_field", "data col").unwrap_err();
        assert!(err.message().contains("invalid json_field 'data col'"));
    }

    // -- wrapper --------------------------------------------------------------

    #[test]
    fn wrap_since_only() {
        let sql = wrap_query(
            "SELECT * FROM security_events WHERE id = 1",
            "time",
            &window(Some("2026-07-01T00:00:00Z"), None),
            1000,
        );
        assert_eq!(
            sql,
            "SELECT * FROM (SELECT * FROM security_events WHERE id = 1) AS __hunt \
             WHERE time >= '2026-07-01T00:00:00+00:00'::timestamptz ORDER BY time LIMIT 1000"
        );
    }

    #[test]
    fn wrap_until_only() {
        let sql = wrap_query(
            "SELECT * FROM security_events WHERE id = 1",
            "time",
            &window(None, Some("2026-07-02T00:00:00Z")),
            1000,
        );
        assert_eq!(
            sql,
            "SELECT * FROM (SELECT * FROM security_events WHERE id = 1) AS __hunt \
             WHERE time < '2026-07-02T00:00:00+00:00'::timestamptz ORDER BY time LIMIT 1000"
        );
    }

    #[test]
    fn wrap_both_bounds() {
        let sql = wrap_query(
            "SELECT * FROM security_events WHERE id = 1",
            "time",
            &window(Some("2026-07-01T00:00:00Z"), Some("2026-07-02T00:00:00Z")),
            500,
        );
        assert_eq!(
            sql,
            "SELECT * FROM (SELECT * FROM security_events WHERE id = 1) AS __hunt \
             WHERE time >= '2026-07-01T00:00:00+00:00'::timestamptz \
             AND time < '2026-07-02T00:00:00+00:00'::timestamptz ORDER BY time LIMIT 500"
        );
    }

    #[test]
    fn wrap_no_bounds_no_limit() {
        let sql = wrap_query(
            "SELECT * FROM security_events WHERE id = 1;",
            "time",
            &HuntWindow::default(),
            0,
        );
        assert_eq!(
            sql,
            "SELECT * FROM (SELECT * FROM security_events WHERE id = 1) AS __hunt ORDER BY time"
        );
    }

    #[test]
    fn wrap_custom_timestamp_field() {
        let sql = wrap_query(
            "SELECT * FROM security_events WHERE id = 1",
            "event_time",
            &window(Some("2026-07-01T00:00:00Z"), None),
            10,
        );
        assert!(sql.contains("WHERE event_time >="));
        assert!(sql.contains("ORDER BY event_time"));
    }

    // -- goldens (full build_hunt_plan path) ----------------------------------

    fn golden_path(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(name)
    }

    /// Compare against the committed golden. Set `RSIGMA_UPDATE_GOLDEN=1` to
    /// rewrite after an intentional change.
    fn check_golden(name: &str, actual: &str) {
        let path = golden_path(name);
        if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(actual, expected, "hunt golden drifted for '{name}'");
    }

    const FLAT_RULE: &str = r#"
title: Suspicious Process Start
id: 00000000-0000-0000-0000-000000000101
logsource:
    category: process_creation
detection:
    selection:
        Image: /usr/bin/curl
        CommandLine|contains: "--insecure"
    condition: selection
level: medium
"#;

    /// A rule declaring `fields:` must still hunt whole rows: the projection
    /// is cleared on load, so the wrapped SQL keeps `SELECT *`.
    const FIELDS_RULE: &str = r#"
title: Field Listed Rule
id: 00000000-0000-0000-0000-000000000102
logsource:
    category: process_creation
detection:
    selection:
        Image: /bin/sh
    condition: selection
fields:
    - Image
    - CommandLine
level: low
"#;

    fn plan_for(rule_yaml: &str, options: &HashMap<String, String>) -> HuntPlan {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, rule_yaml.as_bytes()).unwrap();
        let window = window(Some("2026-07-01T00:00:00Z"), Some("2026-07-02T00:00:00Z"));
        build_hunt_plan(
            crate::load_collection_multi(std::slice::from_ref(&f.path().to_path_buf())),
            &[],
            options,
            &window,
            1000,
        )
        .unwrap()
    }

    #[test]
    fn golden_flat_mode_sql() {
        let plan = plan_for(FLAT_RULE, &HashMap::new());
        assert_eq!(plan.timestamp_field, "time");
        assert_eq!(plan.json_field, None);
        let actual = format!("{};\n", plan.queries[0].sql);
        check_golden("hunt_sql_flat.sql", &actual);
    }

    #[test]
    fn golden_jsonb_mode_sql() {
        let options: HashMap<String, String> = [
            ("table".to_string(), "events".to_string()),
            ("json_field".to_string(), "data".to_string()),
        ]
        .into_iter()
        .collect();
        let plan = plan_for(FLAT_RULE, &options);
        assert_eq!(plan.json_field.as_deref(), Some("data"));
        let actual = format!("{};\n", plan.queries[0].sql);
        check_golden("hunt_sql_jsonb.sql", &actual);
    }

    #[test]
    fn golden_fields_list_cleared() {
        let plan = plan_for(FIELDS_RULE, &HashMap::new());
        let actual = format!("{};\n", plan.queries[0].sql);
        check_golden("hunt_sql_fields_cleared.sql", &actual);
    }

    #[test]
    fn correlation_rules_are_rejected() {
        let yaml = format!(
            "{FLAT_RULE}\n---\ntitle: Repeated Hits\ncorrelation:\n    type: event_count\n    rules:\n        - Suspicious Process Start\n    group-by:\n        - Image\n    timespan: 10m\n    condition:\n        gte: 5\n"
        );
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, yaml.as_bytes()).unwrap();
        let err = build_hunt_plan(
            crate::load_collection_multi(&[f.path().to_path_buf()]),
            &[],
            &HashMap::new(),
            &HuntWindow::default(),
            1000,
        )
        .unwrap_err();
        let msg = err.message();
        assert!(msg.contains("detection rules only"), "{msg}");
        assert!(msg.contains("Repeated Hits"), "{msg}");
        assert!(msg.contains("rsigma backend convert"), "{msg}");
    }
}
