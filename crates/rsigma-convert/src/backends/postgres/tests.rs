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
        vec![r#"SELECT * FROM security_events WHERE "FieldA" = 'val1' AND NOT "FieldB" = 'val2'"#]
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
        vec![r#"SELECT * FROM security_events WHERE ("SourceIP")::inet <<= '10.0.0.0/8'::cidr"#]
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

#[test]
fn test_jsonb_nested_field_access() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        securityContext.isProxy: 'true'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'securityContext'->>'isProxy' = 'true'"]
    );
}

#[test]
fn test_jsonb_deeply_nested_field() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        a.b.c.d: val
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'a'->'b'->'c'->>'d' = 'val'"]
    );
}

#[test]
fn test_jsonb_nested_field_exists() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        securityContext.isProxy|exists: true
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'securityContext'->>'isProxy' IS NOT NULL"]
    );
}

#[test]
fn test_jsonb_nested_field_cidr() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        client.ipAddress|cidr: '10.0.0.0/8'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec![
            "SELECT * FROM security_events WHERE (data->'client'->>'ipAddress')::inet <<= '10.0.0.0/8'::cidr"
        ]
    );
}

#[test]
fn test_jsonb_nested_field_regex() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        actor.displayName|re: '.*admin.*'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'actor'->>'displayName' ~* '.*admin.*'"]
    );
}

#[test]
fn test_jsonb_flat_field_unchanged() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        eventType: user.session.start
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->>'eventType' = 'user.session.start'"]
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
        queries[0]
            .starts_with("CREATE OR REPLACE VIEW sigma_suspicious_process_cmdexe_c_t1059003 AS")
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

// --- Backend options (from_options) ---

#[test]
fn test_from_options_table() {
    let mut opts = HashMap::new();
    opts.insert("table".to_string(), "events".to_string());
    let backend = PostgresBackend::from_options(&opts);
    assert_eq!(backend.table, "events");
}

#[test]
fn test_from_options_schema() {
    let mut opts = HashMap::new();
    opts.insert("schema".to_string(), "siem".to_string());
    let backend = PostgresBackend::from_options(&opts);
    assert_eq!(backend.schema, Some("siem".to_string()));
}

#[test]
fn test_from_options_timestamp_field() {
    let mut opts = HashMap::new();
    opts.insert("timestamp_field".to_string(), "time_dt".to_string());
    let backend = PostgresBackend::from_options(&opts);
    assert_eq!(backend.timestamp_field, "time_dt");
}

#[test]
fn test_from_options_json_field() {
    let mut opts = HashMap::new();
    opts.insert("json_field".to_string(), "metadata".to_string());
    let backend = PostgresBackend::from_options(&opts);
    assert_eq!(backend.json_field, Some("metadata".to_string()));
}

#[test]
fn test_from_options_case_sensitive_re() {
    let mut opts = HashMap::new();
    opts.insert("case_sensitive_re".to_string(), "true".to_string());
    let backend = PostgresBackend::from_options(&opts);
    assert!(backend.case_sensitive_re);
}

#[test]
fn test_from_options_empty_uses_defaults() {
    let opts = HashMap::new();
    let backend = PostgresBackend::from_options(&opts);
    assert_eq!(backend.table, "security_events");
    assert_eq!(backend.timestamp_field, "time");
    assert_eq!(backend.json_field, None);
    assert!(!backend.case_sensitive_re);
    assert_eq!(backend.schema, None);
}

#[test]
fn test_from_options_affects_query_output() {
    let mut opts = HashMap::new();
    opts.insert("table".to_string(), "my_events".to_string());
    let backend = PostgresBackend::from_options(&opts);
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM my_events WHERE action = 'login'"]
    );
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

// --- SELECT column selection from Sigma `fields` attribute ---

#[test]
fn test_select_fields_basic() {
    let queries = convert(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
fields:
    - user_id
    - action
"#,
    );
    assert_eq!(
        queries,
        vec!["SELECT user_id, action FROM security_events WHERE action = 'login'"]
    );
}

#[test]
fn test_select_fields_with_alias() {
    let queries = convert(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
fields:
    - CommandLine as cmd
"#,
    );
    assert_eq!(
        queries,
        vec![r#"SELECT "CommandLine" AS cmd FROM security_events WHERE action = 'login'"#]
    );
}

#[test]
fn test_select_fields_with_function_passthrough() {
    let queries = convert(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
fields:
    - count(*)
    - user_id
"#,
    );
    assert_eq!(
        queries,
        vec!["SELECT count(*), user_id FROM security_events WHERE action = 'login'"]
    );
}

#[test]
fn test_select_fields_quoted_mixed_case() {
    let queries = convert(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
fields:
    - EventID
    - SourceIp
    - action
"#,
    );
    assert_eq!(
        queries,
        vec![r#"SELECT "EventID", "SourceIp", action FROM security_events WHERE action = 'login'"#]
    );
}

#[test]
fn test_select_fields_empty_defaults_to_star() {
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

// --- CTE-based pre-filtering for non-temporal correlations ---

#[test]
fn test_cte_prefilter_event_count() {
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

    let rule_queries = serde_json::json!({
        "rule_a": "SELECT * FROM security_events WHERE action = 'login'"
    });
    pipeline_state.set_state("_rule_queries".to_string(), rule_queries);

    let queries = backend
        .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
        .unwrap();
    let q = &queries[0];
    assert!(
        q.starts_with("WITH combined_events AS ("),
        "should use CTE: {q}"
    );
    assert!(
        q.contains("FROM combined_events"),
        "should read from CTE: {q}"
    );
    assert!(
        q.contains("action = 'login'"),
        "should include rule's WHERE clause: {q}"
    );
    assert!(
        !q.contains("NOW()"),
        "CTE path should not add time filter: {q}"
    );
}

#[test]
fn test_cte_prefilter_multi_rule_union() {
    let collection = parse_sigma_yaml(
        r#"
title: Multi Rule Count
correlation:
    type: event_count
    rules:
        - rule_a
        - rule_b
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 5
"#,
    )
    .unwrap();
    let backend = PostgresBackend::new();
    let mut pipeline_state = PipelineState::default();

    let rule_queries = serde_json::json!({
        "rule_a": "SELECT * FROM events WHERE EventID = 4625",
        "rule_b": "SELECT * FROM events WHERE EventID = 4624"
    });
    pipeline_state.set_state("_rule_queries".to_string(), rule_queries);

    let queries = backend
        .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
        .unwrap();
    let q = &queries[0];
    assert!(
        q.contains("UNION ALL"),
        "multi-rule should use UNION ALL: {q}"
    );
    assert!(
        q.contains("EventID = 4625"),
        "should include rule_a's condition: {q}"
    );
    assert!(
        q.contains("EventID = 4624"),
        "should include rule_b's condition: {q}"
    );
}

#[test]
fn test_cte_prefilter_fallback_without_queries() {
    let collection = parse_sigma_yaml(
        r#"
title: Fallback Count
correlation:
    type: event_count
    rules:
        - rule_a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 10
"#,
    )
    .unwrap();
    let backend = PostgresBackend::new();
    let pipeline_state = PipelineState::default();

    let queries = backend
        .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
        .unwrap();
    let q = &queries[0];
    assert!(
        !q.contains("WITH combined_events"),
        "no CTE without _rule_queries: {q}"
    );
    assert!(
        q.contains("FROM security_events"),
        "should use default table: {q}"
    );
    assert!(
        q.contains("NOW() - INTERVAL"),
        "should have time filter: {q}"
    );
}

#[test]
fn test_cte_prefilter_value_count() {
    let collection = parse_sigma_yaml(
        r#"
title: Value Count CTE
correlation:
    type: value_count
    rules:
        - rule_a
    group-by:
        - SourceIp
    timespan: 15m
    condition:
        field: User
        gte: 3
"#,
    )
    .unwrap();
    let backend = PostgresBackend::new();
    let mut pipeline_state = PipelineState::default();

    let rule_queries = serde_json::json!({
        "rule_a": "SELECT * FROM events WHERE action = 'auth'"
    });
    pipeline_state.set_state("_rule_queries".to_string(), rule_queries);

    let queries = backend
        .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
        .unwrap();
    let q = &queries[0];
    assert!(
        q.starts_with("WITH combined_events AS ("),
        "value_count should use CTE: {q}"
    );
    assert!(
        q.contains("COUNT(DISTINCT"),
        "should have value_count aggregate: {q}"
    );
}

// --- Sliding window format ---

#[test]
fn test_sliding_window_event_count_with_cte() {
    let collection = parse_sigma_yaml(
        r#"
title: Brute Force
correlation:
    type: event_count
    rules:
        - rule_a
    group-by:
        - SourceIp
    timespan: 10m
    condition:
        gte: 5
"#,
    )
    .unwrap();
    let backend = PostgresBackend::new();
    let mut pipeline_state = PipelineState::default();

    let rule_queries = serde_json::json!({
        "rule_a": "SELECT * FROM events WHERE EventID = 4625"
    });
    pipeline_state.set_state("_rule_queries".to_string(), rule_queries);

    let queries = backend
        .convert_correlation_rule(
            &collection.correlations[0],
            "sliding_window",
            &pipeline_state,
        )
        .unwrap();
    let q = &queries[0];
    assert!(
        q.contains("WITH combined_events AS ("),
        "should have combined_events CTE: {q}"
    );
    assert!(
        q.contains("event_counts AS ("),
        "should have event_counts CTE: {q}"
    );
    assert!(
        q.contains("COUNT(*) OVER ("),
        "should use window function: {q}"
    );
    assert!(
        q.contains("PARTITION BY"),
        "should partition by group_by: {q}"
    );
    assert!(
        q.contains("RANGE BETWEEN INTERVAL '600 seconds' PRECEDING AND CURRENT ROW"),
        "should have sliding window frame: {q}"
    );
    assert!(
        q.contains("correlation_event_count >= 5"),
        "should filter on threshold: {q}"
    );
}

#[test]
fn test_sliding_window_event_count_without_cte() {
    let collection = parse_sigma_yaml(
        r#"
title: Brute Force No CTE
correlation:
    type: event_count
    rules:
        - rule_a
    group-by:
        - SourceIp
    timespan: 5m
    condition:
        gte: 10
"#,
    )
    .unwrap();
    let backend = PostgresBackend::new();
    let pipeline_state = PipelineState::default();

    let queries = backend
        .convert_correlation_rule(
            &collection.correlations[0],
            "sliding_window",
            &pipeline_state,
        )
        .unwrap();
    let q = &queries[0];
    assert!(
        q.contains("WITH source AS ("),
        "should have source CTE from table: {q}"
    );
    assert!(
        q.contains("FROM security_events"),
        "source should read from default table: {q}"
    );
    assert!(
        q.contains("COUNT(*) OVER ("),
        "should use window function: {q}"
    );
    assert!(
        q.contains("correlation_event_count >= 10"),
        "should filter on threshold: {q}"
    );
}

#[test]
fn test_sliding_window_no_group_by() {
    let collection = parse_sigma_yaml(
        r#"
title: Global Count
correlation:
    type: event_count
    rules:
        - rule_a
    timespan: 5m
    condition:
        gte: 50
"#,
    )
    .unwrap();
    let backend = PostgresBackend::new();
    let pipeline_state = PipelineState::default();

    let queries = backend
        .convert_correlation_rule(
            &collection.correlations[0],
            "sliding_window",
            &pipeline_state,
        )
        .unwrap();
    let q = &queries[0];
    assert!(
        !q.contains("PARTITION BY"),
        "no group-by means no PARTITION BY: {q}"
    );
    assert!(
        q.contains("COUNT(*) OVER ("),
        "should still use window function: {q}"
    );
}

#[test]
fn test_sliding_window_default_format_unchanged() {
    let collection = parse_sigma_yaml(
        r#"
title: Default Format
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
    let pipeline_state = PipelineState::default();

    let queries = backend
        .convert_correlation_rule(&collection.correlations[0], "default", &pipeline_state)
        .unwrap();
    let q = &queries[0];
    assert!(
        !q.contains("OVER ("),
        "default format should NOT use window function: {q}"
    );
    assert!(q.contains("GROUP BY"), "default format uses GROUP BY: {q}");
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
