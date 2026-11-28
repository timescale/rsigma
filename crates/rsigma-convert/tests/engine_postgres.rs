//! Runs the PostgreSQL backend's SQL in a real PostgreSQL server.
//!
//! Each case runs in both storage modes the backend supports: events in one
//! JSONB column (`json_field`), and events spread over typed columns, one per
//! field (integers as `bigint`, everything else as `text`). The generated
//! query runs unmodified as a subquery, and the matched rows are compared with
//! the case expectations. A second test runs SigmaHQ rules whose conditions
//! need grouping against eval; it reads the checkout in `RSIGMA_SIGMA_CORPUS`.
//! Run with
//! `RSIGMA_SIGMA_CORPUS=<sigma checkout> cargo test -p rsigma-convert --test engine_postgres -- --ignored`.

mod engines;

use std::collections::{BTreeMap, HashMap};

use engines::{Case, IDX_FIELD, Outcome};
use rsigma_convert::backends::postgres::PostgresBackend;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

const POSTGRES_TAG: &str =
    "18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";

#[derive(Clone, Copy)]
enum Mode {
    Jsonb,
    Columns,
}

fn backend_for(table: &str, mode: Mode) -> PostgresBackend {
    let mut opts = HashMap::from([
        ("table".to_string(), table.to_string()),
        ("timestamp_field".to_string(), "time".to_string()),
    ]);
    if let Mode::Jsonb = mode {
        opts.insert("json_field".to_string(), "data".to_string());
    }
    PostgresBackend::from_options(&opts)
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn create_and_load(
    client: &tokio_postgres::Client,
    table: &str,
    mode: Mode,
    case: &Case,
) -> Result<(), tokio_postgres::Error> {
    let events = case.indexed_events();
    match mode {
        Mode::Jsonb => {
            client
                .batch_execute(&format!(
                    "CREATE TABLE {table} (time TIMESTAMPTZ NOT NULL DEFAULT now(), data JSONB NOT NULL)"
                ))
                .await?;
            for event in events {
                client
                    .execute(
                        &format!("INSERT INTO {table} (data) VALUES ($1::text::jsonb)"),
                        &[&event.to_string()],
                    )
                    .await?;
            }
        }
        Mode::Columns => {
            let mut columns: BTreeMap<String, &'static str> = BTreeMap::new();
            for event in &events {
                for (k, v) in event.as_object().unwrap() {
                    let ty = if v.is_i64() || v.is_u64() {
                        "bigint"
                    } else {
                        "text"
                    };
                    columns.entry(k.clone()).or_insert(ty);
                }
            }
            let defs: Vec<String> = columns
                .iter()
                .map(|(k, ty)| format!("{} {ty}", quote_ident(k)))
                .collect();
            client
                .batch_execute(&format!(
                    "CREATE TABLE {table} (time TIMESTAMPTZ NOT NULL DEFAULT now(), {})",
                    defs.join(", ")
                ))
                .await?;
            for event in events {
                // jsonb_populate_record casts each JSON value to its column type
                // and leaves absent keys NULL.
                client
                    .execute(
                        &format!(
                            "INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1::text::jsonb || '{{\"time\": \"2026-01-01T00:00:00Z\"}}')"
                        ),
                        &[&event.to_string()],
                    )
                    .await?;
            }
        }
    }
    Ok(())
}

async fn run_case(
    client: &tokio_postgres::Client,
    table: &str,
    mode: Mode,
    case: &Case,
) -> Result<Outcome, String> {
    let queries = match engines::convert(&backend_for(table, mode), case, &[], "default") {
        Ok(q) => q,
        Err(e) => return Ok(Outcome::ConversionRejected(e)),
    };
    create_and_load(client, table, mode, case)
        .await
        .map_err(|e| e.to_string())?;
    let idx = match mode {
        Mode::Jsonb => format!("(q.data->>'{IDX_FIELD}')::int"),
        Mode::Columns => format!("q.{IDX_FIELD}::int"),
    };
    let mut matched = Vec::new();
    for query in queries {
        let sql = format!(
            "SELECT {idx} FROM ({}) AS q",
            query.trim().trim_end_matches(';')
        );
        let rows = client
            .query(&sql, &[])
            .await
            .map_err(|e| format!("{}\n    query: {query}", db_error(&e)))?;
        matched.extend(rows.iter().map(|r| r.get::<_, i32>(0) as usize));
    }
    Ok(Outcome::Matched(matched))
}

fn db_error(e: &tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_string())
        .unwrap_or_else(|| e.to_string())
}

async fn start_postgres() -> (ContainerAsync<Postgres>, tokio_postgres::Client) {
    engines::require_docker();
    let container = Postgres::default()
        .with_tag(POSTGRES_TAG)
        .start()
        .await
        .expect("failed to start PostgreSQL");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres"),
        NoTls,
    )
    .await
    .expect("failed to connect to PostgreSQL");
    tokio::spawn(connection);
    (container, client)
}

/// Run every case in both storage modes and return the failures.
async fn run_cases(client: &tokio_postgres::Client, prefix: &str, cases: &[Case]) -> Vec<String> {
    let mut failures = Vec::new();
    for (mode, label) in [
        (Mode::Jsonb, "postgres-jsonb"),
        (Mode::Columns, "postgres-columns"),
    ] {
        let mut results = Vec::new();
        for (i, case) in cases.iter().enumerate() {
            let table = format!("{prefix}_{}_{i}", label.replace('-', "_"));
            results.push((case.clone(), run_case(client, &table, mode, case).await));
        }
        failures.extend(engines::check_outcomes(label, &results));
    }
    failures
}

#[tokio::test]
#[ignore = "engine test: needs Docker; run by the PostgreSQL engine workflow"]
async fn postgres_executes_cases() {
    let (_container, client) = start_postgres().await;
    let failures = run_cases(&client, "case", &engines::load_cases()).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

const TEMPORAL_ORDERED_RULES: &str = r#"
title: a
name: a
logsource: {category: test}
detection: {sel: {E: a}, condition: sel}
---
title: b
name: b
logsource: {category: test}
detection: {sel: {E: b}, condition: sel}
---
title: c
name: c
logsource: {category: test}
detection: {sel: {E: c}, condition: sel}
---
title: ordered
correlation:
  type: temporal_ordered
  rules: [a, b, c]
  group-by: [User]
  timespan: 1h
"#;

/// Per group, the rule hits as `(rule, seconds after the window start)`.
const TEMPORAL_ORDERED_HITS: &[(&str, &[(&str, i64)])] = &[
    ("in_order", &[("a", 10), ("b", 20), ("c", 30)]),
    ("reversed", &[("c", 10), ("b", 20), ("a", 30)]),
    ("interleaved", &[("b", 3), ("a", 5), ("b", 10), ("c", 11)]),
    ("tied", &[("a", 5), ("b", 5), ("c", 5)]),
    ("incomplete", &[("a", 5), ("b", 6)]),
    ("swapped_start", &[("b", 5), ("a", 6), ("c", 7)]),
];

/// `temporal_ordered` matches a group only when its rules hit in `rules`
/// order, in every window mode, and agrees with eval on which groups fire.
#[tokio::test]
#[ignore = "engine test: needs Docker; run by the PostgreSQL engine workflow"]
async fn postgres_temporal_ordered_agrees_with_eval() {
    use rsigma_eval::{CorrelationConfig, CorrelationEngine, JsonEvent};
    use std::collections::BTreeSet;

    let collection = rsigma_parser::parse_sigma_yaml(TEMPORAL_ORDERED_RULES).unwrap();
    let mut hits: Vec<(i64, &str, &str)> = TEMPORAL_ORDERED_HITS
        .iter()
        .flat_map(|(group, hits)| hits.iter().map(move |(rule, t)| (*t, *rule, *group)))
        .collect();
    hits.sort();

    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    let mut eval_groups = BTreeSet::new();
    for (t, rule, group) in &hits {
        let event = serde_json::json!({"E": rule, "User": group});
        for result in engine.process_event_at(&JsonEvent::borrow(&event), 1_000_000 + t) {
            if let Some(c) = result.as_correlation() {
                eval_groups.extend(c.group_key.iter().map(|(_, v)| v.clone()));
            }
        }
    }
    let expected: BTreeSet<String> = ["in_order", "interleaved", "tied"].map(String::from).into();
    assert_eq!(eval_groups, expected, "eval");

    let (_container, client) = start_postgres().await;
    client
        .batch_execute(
            r#"CREATE TABLE ordered (time TIMESTAMPTZ NOT NULL, rule_name TEXT, "User" TEXT)"#,
        )
        .await
        .unwrap();
    for (t, rule, group) in &hits {
        client
            .execute(
                "INSERT INTO ordered VALUES \
                 (date_bin('3600 seconds', now(), TIMESTAMPTZ 'epoch') + make_interval(secs => $1), $2, $3)",
                &[&(*t as f64), rule, group],
            )
            .await
            .unwrap();
    }
    for method in ["sliding", "tumbling", "session"] {
        let backend = PostgresBackend::from_options(&HashMap::from([
            ("table".to_string(), "ordered".to_string()),
            ("correlation_method".to_string(), method.to_string()),
            ("gap".to_string(), "1h".to_string()),
        ]));
        let output =
            rsigma_convert::convert_collection(&backend, &collection, &[], "default").unwrap();
        assert!(output.errors.is_empty(), "{method}: {:?}", output.errors);
        let queries: Vec<&String> = output.queries.iter().flat_map(|r| &r.queries).collect();
        assert_eq!(queries.len(), 1, "{method}: {queries:?}");
        let rows = client
            .query(queries[0].as_str(), &[])
            .await
            .unwrap_or_else(|e| panic!("{method}: {}\n{}", db_error(&e), queries[0]));
        let groups: BTreeSet<String> = rows.iter().map(|r| r.get("User")).collect();
        assert_eq!(groups, expected, "{method}: {}", queries[0]);
    }
}

/// A detection rule and correlations over columns named with reserved words,
/// with `fields` that select columns, aliases, and aggregates.
const RESERVED_RULES: &str = r#"
title: Reserved
id: reserved-words
logsource: {category: test}
detection:
  selection:
    user: alice
    group: admins
    order|startswith: '42'
    current_user: postgres
  condition: selection
fields:
  - user
  - group AS grp
  - CommandLine as cmd
  - c-uri
  - order
---
title: Totals
id: totals
logsource: {category: test}
detection:
  selection:
    group: admins
  condition: selection
fields:
  - count(*) AS hits
  - max(EventID) AS top
  - sum(bytes) AS total
  - min(user)
---
title: Per user
generate: true
correlation:
  type: event_count
  rules: [reserved-words]
  group-by: [user]
  timespan: 1h
  condition: {gte: 3}
---
title: Distinct orders
correlation:
  type: value_count
  rules: [reserved-words]
  group-by: [user, group]
  timespan: 1h
  condition: {gte: 3, field: order}
---
title: Bytes
correlation:
  type: value_sum
  rules: [totals]
  group-by: [user]
  timespan: 1h
  condition: {gte: 30, field: bytes}
---
title: Average
correlation:
  type: value_avg
  rules: [totals]
  group-by: [user]
  timespan: 1h
  condition: {gte: 10, field: bytes}
---
title: Median
correlation:
  type: value_median
  rules: [totals]
  group-by: [user]
  timespan: 1h
  condition: {gte: 10, field: bytes}
"#;

/// `(user, group, order, current_user, CommandLine, c-uri, EventID, bytes)`.
type ReservedRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    i64,
    i64,
);

const RESERVED_ROWS: &[ReservedRow] = &[
    ("alice", "admins", "42a", "postgres", "a1", "/a", 1, 10),
    ("alice", "admins", "42b", "postgres", "a2", "/b", 2, 10),
    ("alice", "admins", "42c", "postgres", "a3", "/c", 3, 15),
    ("bob", "admins", "17", "postgres", "b1", "/d", 9, 1),
];

/// Create a reserved schema and table holding [`RESERVED_ROWS`] in columns,
/// and a reserved table holding them in a reserved JSONB column with a
/// mixed-case timestamp column. Every row falls in the current hour.
async fn load_reserved(client: &tokio_postgres::Client, hypertables: bool) {
    client
        .batch_execute(
            r#"
            CREATE SCHEMA "select";
            CREATE TABLE "select"."user" (
                time TIMESTAMPTZ NOT NULL, "user" text, "group" text, "order" text,
                "current_user" text, "CommandLine" text, "c-uri" text, "EventID" bigint, bytes bigint
            );
            CREATE TABLE "order" ("EventTime" TIMESTAMPTZ NOT NULL, "user" jsonb);
            "#,
        )
        .await
        .unwrap();
    if hypertables {
        client
            .batch_execute(
                r#"
                SELECT create_hypertable('"select"."user"', 'time');
                SELECT create_hypertable('"order"', 'EventTime');
                "#,
            )
            .await
            .unwrap();
    }
    for (i, (user, group, order, current_user, cmd, uri, event_id, bytes)) in
        RESERVED_ROWS.iter().enumerate()
    {
        let at = "date_bin('3600 seconds', now(), TIMESTAMPTZ 'epoch') + make_interval(secs => $1)";
        client
            .execute(
                &format!(
                    r#"INSERT INTO "select"."user" VALUES ({at}, $2, $3, $4, $5, $6, $7, $8, $9)"#
                ),
                &[
                    &(i as f64 / 1e6),
                    user,
                    group,
                    order,
                    current_user,
                    cmd,
                    uri,
                    event_id,
                    bytes,
                ],
            )
            .await
            .unwrap();
        let event = serde_json::json!({
            "user": user, "group": group, "order": order, "current_user": current_user,
            "CommandLine": cmd, "c-uri": uri, "EventID": event_id, "bytes": bytes,
        });
        client
            .execute(
                &format!(r#"INSERT INTO "order" VALUES ({at}, $2::text::jsonb)"#),
                &[&(i as f64 / 1e6), &event.to_string()],
            )
            .await
            .unwrap();
    }
}

/// The two storage modes of [`load_reserved`], each as `(label, backend)`.
fn reserved_backends() -> [(&'static str, PostgresBackend); 2] {
    [
        (
            "columns",
            PostgresBackend::from_options(&HashMap::from([
                ("schema".to_string(), "select".to_string()),
                ("table".to_string(), "User".to_string()),
            ])),
        ),
        (
            "jsonb",
            PostgresBackend::from_options(&HashMap::from([
                ("table".to_string(), "order".to_string()),
                ("json_field".to_string(), "user".to_string()),
                ("timestamp_field".to_string(), "EventTime".to_string()),
            ])),
        ),
    ]
}

/// Run a generated query and return its rows. A view is created and read; a
/// continuous aggregate is created, refreshed, and read.
async fn run_generated(
    client: &tokio_postgres::Client,
    context: &str,
    sql: &str,
) -> Vec<tokio_postgres::Row> {
    let fail = |e: tokio_postgres::Error| -> ! { panic!("{context}: {}\n{sql}", db_error(&e)) };
    let view = sql
        .strip_prefix("CREATE OR REPLACE VIEW ")
        .or_else(|| sql.strip_prefix("CREATE MATERIALIZED VIEW "))
        .map(|rest| rest.split_once(' ').unwrap().0);
    let query = match view {
        Some(name) => {
            client.batch_execute(sql).await.unwrap_or_else(|e| fail(e));
            if sql.starts_with("CREATE MATERIALIZED VIEW ") {
                client
                    .batch_execute(&format!(
                        "CALL refresh_continuous_aggregate('{name}', NULL, NULL)"
                    ))
                    .await
                    .unwrap_or_else(|e| fail(e));
            }
            format!("SELECT * FROM {name}")
        }
        None => sql.to_string(),
    };
    client
        .query(query.as_str(), &[])
        .await
        .unwrap_or_else(|e| fail(e))
}

/// Run [`RESERVED_RULES`] in `formats` against the tables of
/// [`load_reserved`] and check every query's rows.
async fn check_reserved(client: &tokio_postgres::Client, formats: &[&str]) {
    use std::collections::BTreeSet;

    let collection = rsigma_parser::parse_sigma_yaml(RESERVED_RULES).unwrap();
    for (label, backend) in reserved_backends() {
        for format in formats {
            let output =
                rsigma_convert::convert_collection(&backend, &collection, &[], format).unwrap();
            let errors: Vec<_> = output
                .errors
                .iter()
                .filter(|(_, e)| !e.to_string().contains("unknown output format"))
                .collect();
            assert!(errors.is_empty(), "{label} {format}: {errors:?}");
            let query = |title: &str| {
                output
                    .queries
                    .iter()
                    .find(|r| r.rule_title == title)
                    .map(|r| {
                        r.queries[0].replacen(" VIEW sigma_", &format!(" VIEW sigma_{label}_"), 1)
                    })
            };
            let context = |title: &str| format!("{label} {format} {title}");

            if let Some(sql) = query("Reserved") {
                let rows = run_generated(client, &context("Reserved"), &sql).await;
                let seen: BTreeSet<(String, String, String, String, String)> = rows
                    .iter()
                    .map(|r| {
                        (
                            r.get("user"),
                            r.get("grp"),
                            r.get("cmd"),
                            r.get("c-uri"),
                            r.get("order"),
                        )
                    })
                    .collect();
                let expected: BTreeSet<_> = [
                    ("a1", "/a", "42a"),
                    ("a2", "/b", "42b"),
                    ("a3", "/c", "42c"),
                ]
                .map(|(cmd, uri, order)| {
                    (
                        "alice".to_string(),
                        "admins".to_string(),
                        cmd.to_string(),
                        uri.to_string(),
                        order.to_string(),
                    )
                })
                .into();
                assert_eq!(seen, expected, "{}", context("Reserved"));
            }

            if let Some(sql) = query("Totals") {
                let rows = run_generated(client, &context("Totals"), &sql).await;
                assert_eq!(rows.len(), 1, "{}", context("Totals"));
                let hits: i64 = rows[0].get("hits");
                let min_user: String = rows[0].get("min");
                assert_eq!(
                    (hits, min_user.as_str()),
                    (4, "alice"),
                    "{}",
                    context("Totals")
                );
                if label == "columns" {
                    let top: i64 = rows[0].get("top");
                    assert_eq!(top, 9, "{}", context("Totals"));
                }
            }

            let sql = query("Per user").expect("Per user");
            let rows = run_generated(client, &context("Per user"), &sql).await;
            if *format == "sliding_window" && label == "jsonb" {
                assert_eq!(rows.len(), 1, "{}", context("Per user"));
            } else {
                let users: BTreeSet<String> = rows.iter().map(|r| r.get("user")).collect();
                assert_eq!(
                    users,
                    ["alice".to_string()].into(),
                    "{}",
                    context("Per user")
                );
            }

            for title in ["Distinct orders", "Bytes", "Average", "Median"] {
                let sql = query(title).expect(title);
                let rows = run_generated(client, &context(title), &sql).await;
                let users: Vec<String> = rows.iter().map(|r| r.get("user")).collect();
                assert_eq!(users, ["alice"], "{}", context(title));
                if title == "Distinct orders" {
                    let group: String = rows[0].get("group");
                    assert_eq!(group, "admins", "{}", context(title));
                }
            }
        }
    }
}

/// Columns named with reserved words, a reserved schema and table, aliased
/// and aggregated `fields`, and correlations grouping by them run in
/// PostgreSQL, in columns mode and in JSONB mode with a reserved JSONB column
/// and a mixed-case timestamp column. The projected `user` column must hold
/// the event's value, not the session user.
#[tokio::test]
#[ignore = "engine test: needs Docker; run by the PostgreSQL engine workflow"]
async fn postgres_runs_reserved_words_and_select_fields() {
    let (_container, client) = start_postgres().await;
    load_reserved(&client, false).await;
    check_reserved(&client, &["default", "view", "sliding_window"]).await;
}

const TIMESCALEDB_TAG: &str =
    "2.24.0-pg18@sha256:5ab97a9fd9d7708f4c7472efcc771c34d6dfb0cf40ca278cae1c397c606ff5b6";

/// The `timescaledb` and `continuous_aggregate` formats run in TimescaleDB
/// over hypertables: every continuous aggregate is created, refreshed, and
/// read.
#[tokio::test]
#[ignore = "engine test: needs Docker; run by the PostgreSQL engine workflow"]
async fn timescaledb_runs_reserved_words_and_select_fields() {
    engines::require_docker();
    let container = Postgres::default()
        .with_name("timescale/timescaledb")
        .with_tag(TIMESCALEDB_TAG)
        .start()
        .await
        .expect("failed to start TimescaleDB");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres"),
        NoTls,
    )
    .await
    .expect("failed to connect to TimescaleDB");
    tokio::spawn(connection);
    load_reserved(&client, true).await;
    check_reserved(&client, &["timescaledb", "continuous_aggregate"]).await;

    // A rule without `fields` becomes an hourly event count.
    let rule = rsigma_parser::parse_sigma_yaml(
        "title: Admins\nlogsource: {category: test}\ndetection:\n  sel: {group: admins}\n  condition: sel\n",
    )
    .unwrap();
    for (label, backend) in reserved_backends() {
        let output =
            rsigma_convert::convert_collection(&backend, &rule, &[], "continuous_aggregate")
                .unwrap();
        let sql = output.queries[0].queries[0].replacen(
            " VIEW sigma_",
            &format!(" VIEW sigma_{label}_"),
            1,
        );
        let rows = run_generated(&client, label, &sql).await;
        let counts: Vec<i64> = rows.iter().map(|r| r.get("event_count")).collect();
        assert_eq!(counts, [4], "{label}: {sql}");
    }
}

/// Differential test against eval over the SigmaHQ rules whose conditions
/// need grouping (see `engines::corpus`).
#[tokio::test]
#[ignore = "engine test: needs Docker and a SigmaHQ checkout in RSIGMA_SIGMA_CORPUS; run by the PostgreSQL engine workflow"]
async fn postgres_agrees_with_eval_on_sigma_corpus() {
    let Some(corpus) = std::env::var_os("RSIGMA_SIGMA_CORPUS") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "set RSIGMA_SIGMA_CORPUS to a SigmaHQ checkout"
        );
        eprintln!("skipping: RSIGMA_SIGMA_CORPUS is not set");
        return;
    };
    let sample = engines::corpus::grouping_cases(std::path::Path::new(&corpus), |case| {
        engines::convert(&backend_for("t", Mode::Jsonb), case, &[], "default")
            .is_ok_and(|q| q.len() == 1)
    });
    let with_both = sample
        .cases
        .iter()
        .filter(|c| !c.matches.is_empty() && c.matches.len() < c.events.len())
        .count();
    eprintln!(
        "{} rule files, {} need grouping, {} use only plain string values, {} convert; {} have matching and non-matching events",
        sample.files,
        sample.needs_grouping,
        sample.plain_values,
        sample.cases.len(),
        with_both,
    );
    assert!(
        with_both >= 1000,
        "only {with_both} corpus rules have both matching and non-matching events"
    );

    let (_container, client) = start_postgres().await;
    let failures = run_cases(&client, "corpus", &sample.cases).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
