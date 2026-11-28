//! E2E tests for `rsigma hunt run --emit events` against a real PostgreSQL.
//!
//! Each test starts a postgres container via testcontainers, seeds it with a
//! plain-PostgreSQL subset of the reference `security_events` schema (the
//! TimescaleDB-specific statements like `create_hypertable` are skipped: the
//! generated SQL is plain SQL and TimescaleDB behavior is not what these
//! tests exercise), and runs the real binary against it.

#![cfg(feature = "hunt-postgres")]

use crate::common;

use common::{rsigma, temp_file};
use predicates::prelude::*;
use testcontainers::core::ExecCommand;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

fn can_run_linux_containers() -> bool {
    let output = std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim() == "linux",
        _ => false,
    }
}

macro_rules! skip_without_docker {
    () => {
        if !can_run_linux_containers() {
            eprintln!("Skipping: Docker with Linux container support is not available");
            return;
        }
    };
}

/// Run a SQL statement inside the container via psql, asserting success.
async fn psql(container: &testcontainers::ContainerAsync<Postgres>, sql: &str) {
    let mut exec = container
        .exec(ExecCommand::new(vec![
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-c",
            sql,
        ]))
        .await
        .expect("psql exec failed to start");
    let stdout = exec.stdout_to_vec().await.unwrap();
    let stderr = exec.stderr_to_vec().await.unwrap();
    let code = exec.exit_code().await.unwrap();
    assert_eq!(
        code,
        Some(0),
        "psql failed for {sql:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
}

/// The image's readiness log fires during the initdb phase too; poll until a
/// real query round-trips.
async fn wait_ready(container: &testcontainers::ContainerAsync<Postgres>) {
    for _ in 0..60 {
        let ready = container
            .exec(ExecCommand::new(vec![
                "psql", "-U", "postgres", "-d", "postgres", "-tAc", "SELECT 1",
            ]))
            .await;
        if let Ok(mut exec) = ready {
            // Draining stdout blocks until the command exits.
            let _ = exec.stdout_to_vec().await;
            if exec.exit_code().await.unwrap() == Some(0) {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("postgres did not become ready");
}

async fn start_postgres() -> (testcontainers::ContainerAsync<Postgres>, String) {
    let container = Postgres::default()
        .start()
        .await
        .expect("Failed to start postgres container");
    wait_ready(&container).await;
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get postgres port");
    let dsn = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    (container, dsn)
}

/// A plain-PostgreSQL subset of the reference schema, including a TSVECTOR
/// column (no decoder; the hunt must skip it with a one-time warning) and a
/// NUMERIC column (a JSON number when the value fits a double exactly,
/// otherwise the exact decimal text; 2^96 - 1 exercises the text path).
const SECURITY_EVENTS_DDL: &str = "
CREATE TABLE security_events (
    time TIMESTAMPTZ NOT NULL,
    event_id BIGINT,
    category TEXT,
    severity SMALLINT,
    src_ip INET,
    process_command_line TEXT,
    success BOOLEAN,
    score NUMERIC,
    metadata JSONB,
    search_vector TSVECTOR
);
INSERT INTO security_events VALUES
  ('2026-07-01T10:00:00Z', 1, 'process', 2, '10.0.0.8', 'curl --insecure https://a.example', true, 99.5, NULL, 'curl'::tsvector),
  ('2026-07-01T11:00:00Z', 2, 'process', 2, '10.0.0.9', 'curl --insecure https://b.example', false, NULL, NULL, 'curl'::tsvector),
  ('2026-07-01T12:00:00Z', 3, 'authentication', 1, '10.0.0.10', NULL, true, 0.25, NULL, 'auth'::tsvector),
  ('2026-07-05T10:00:00Z', 4, 'process', 3, '10.0.0.11', 'curl --insecure https://c.example', true, 79228162514264337593543950335, NULL, 'curl'::tsvector);
";

const CURL_RULE: &str = r#"
title: Suspicious Curl
id: 00000000-0000-0000-0000-000000000201
logsource:
    category: process
detection:
    selection:
        category: process
        process_command_line|contains: "--insecure"
    condition: selection
level: medium
"#;

#[tokio::test]
async fn hunt_returns_matching_rows_as_ndjson() {
    skip_without_docker!();
    let (container, dsn) = start_postgres().await;
    psql(&container, SECURITY_EVENTS_DDL).await;

    let rule = temp_file(".yml", CURL_RULE);
    let out = rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            &dsn,
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected the three curl rows: {stdout}");
    for line in &lines {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(event["category"], "process");
        assert!(
            event["process_command_line"]
                .as_str()
                .unwrap()
                .contains("--insecure")
        );
        // Typed mapping: ints stay numbers, bools stay bools, inet is text,
        // timestamptz is RFC 3339.
        assert!(event["event_id"].is_i64());
        assert!(event["success"].is_boolean());
        assert!(event["src_ip"].as_str().unwrap().contains('.'));
        let time = event["time"].as_str().unwrap();
        assert!(time.contains('T') && time.ends_with("+00:00"), "{time}");
        // NULL columns are dropped, and the undecodable tsvector is skipped.
        assert!(event.get("metadata").is_none());
        assert!(event.get("search_vector").is_none());
    }
    // numeric mapping: a number when it fits a double, exact text beyond.
    let by_id = |id: i64| -> serde_json::Value {
        lines
            .iter()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|e| e["event_id"] == id)
            .unwrap_or_else(|| panic!("no event with event_id {id}: {stdout}"))
    };
    assert_eq!(by_id(1)["score"], 99.5);
    assert!(by_id(2).get("score").is_none(), "NULL numeric is dropped");
    assert_eq!(by_id(4)["score"], "79228162514264337593543950335");
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("column 'search_vector' has unmapped type 'tsvector'"),
        "one-time unmapped-type warning: {stderr}"
    );
    assert!(
        stderr.matches("search_vector").count() == 1,
        "warning must fire once, not per row: {stderr}"
    );
    assert!(
        stderr.contains("rule 'Suspicious Curl': 3 row(s)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("hunted 3 row(s) from 1 rule(s)"),
        "{stderr}"
    );
    // The redacted DSN never carries the password.
    assert!(!stderr.contains("postgres:postgres@"), "{stderr}");
}

#[tokio::test]
async fn since_and_limit_narrow_the_hunt() {
    skip_without_docker!();
    let (container, dsn) = start_postgres().await;
    psql(&container, SECURITY_EVENTS_DDL).await;

    let rule = temp_file(".yml", CURL_RULE);
    // --since excludes the three July 1 rows; --limit is then not hit.
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            &dsn,
            "--since",
            "2026-07-03T00:00:00Z",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("c.example"))
        .stdout(predicate::str::contains("a.example").not());

    // --limit 1 truncates and says so on stderr.
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            &dsn,
            "--limit",
            "1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("a.example"))
        .stdout(predicate::str::contains("b.example").not())
        .stderr(predicate::str::contains(
            "reached --limit 1 (output may be truncated)",
        ));

    // A successful hunt with no matches still produces its output file,
    // truncated to empty (the "ran, nothing matched" signal).
    let out_file = temp_file(".ndjson", "stale content from a previous hunt\n");
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            &dsn,
            "--until",
            "2020-01-01T00:00:00Z",
            "-o",
            out_file.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("hunted 0 row(s)"));
    assert_eq!(std::fs::read_to_string(out_file.path()).unwrap(), "");
}

/// A hunt that fails before producing output must not clobber an existing
/// output file: the sink opens lazily on the first event. (No container:
/// the connection is refused.)
#[test]
fn failed_hunt_leaves_the_output_file_untouched() {
    let out_file = temp_file(".ndjson", "precious results from a previous hunt\n");
    let rule = temp_file(".yml", CURL_RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            "postgres://hunter@127.0.0.1:9/siem?connect_timeout=3",
            "-o",
            out_file.path().to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not connect"));
    assert_eq!(
        std::fs::read_to_string(out_file.path()).unwrap(),
        "precious results from a previous hunt\n"
    );
}

#[tokio::test]
async fn jsonb_mode_emits_the_stored_event_verbatim() {
    skip_without_docker!();
    let (container, dsn) = start_postgres().await;
    psql(
        &container,
        "
CREATE TABLE events (time TIMESTAMPTZ NOT NULL, data JSONB);
INSERT INTO events VALUES
  ('2026-07-01T10:00:00Z', '{\"category\": \"process\", \"Image\": \"/usr/bin/curl\", \"CommandLine\": \"curl --insecure https://a.example\", \"pid\": 4242}'),
  ('2026-07-01T11:00:00Z', '{\"category\": \"process\", \"Image\": \"/bin/sh\", \"CommandLine\": \"sh -c id\"}');
",
    )
    .await;

    // In JSONB mode the rule's fields name keys of the stored event.
    let rule = temp_file(
        ".yml",
        r#"
title: Suspicious Curl
id: 00000000-0000-0000-0000-000000000202
logsource:
    category: process
detection:
    selection:
        Image: /usr/bin/curl
        CommandLine|contains: "--insecure"
    condition: selection
level: medium
"#,
    );
    let out = rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "-O",
            "table=events",
            "-O",
            "json_field=data",
        ])
        // The DSN may also come from the environment.
        .env("RSIGMA_HUNT_DSN", &dsn)
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "only the curl event matches: {stdout}");
    let event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    // Verbatim body, with the timestamp column merged under its name.
    assert_eq!(event["Image"], "/usr/bin/curl");
    assert_eq!(event["pid"], 4242);
    assert_eq!(event["time"], "2026-07-01T10:00:00+00:00");
}

/// The read-only guarantee: a side-effecting function smuggled past the
/// shape check via a pipeline `query_expression_template` still cannot write,
/// because the session forced `default_transaction_read_only`.
#[tokio::test]
async fn read_only_session_rejects_writes() {
    skip_without_docker!();
    let (container, dsn) = start_postgres().await;
    psql(&container, SECURITY_EVENTS_DDL).await;
    psql(
        &container,
        "
CREATE OR REPLACE FUNCTION sabotage() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM security_events;
    RETURN true;
END $$;
",
    )
    .await;

    let rule = temp_file(".yml", CURL_RULE);
    let pipeline = temp_file(
        ".yml",
        r#"
name: sabotage
priority: 100
transformations:
  - type: set_state
    key: query_expression_template
    value: "SELECT * FROM security_events WHERE sabotage() AND ({query})"
"#,
    );
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            &dsn,
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("read-only transaction"));

    // And nothing was written or deleted: the rows survive.
    let mut exec = container
        .exec(ExecCommand::new(vec![
            "psql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-tAc",
            "SELECT count(*) FROM security_events",
        ]))
        .await
        .unwrap();
    let out = exec.stdout_to_vec().await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "4");
}

#[tokio::test]
async fn wrong_password_dsn_never_leaks_the_password() {
    skip_without_docker!();
    let (container, _dsn) = start_postgres().await;
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let bad = format!("postgres://hunter:sup3rsecret@127.0.0.1:{port}/postgres");

    let rule = temp_file(".yml", CURL_RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            &bad,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(format!(
            "could not connect to postgres://hunter@127.0.0.1:{port}/postgres"
        )))
        .stderr(predicate::str::contains("sup3rsecret").not());
}

#[tokio::test]
async fn events_mode_requires_a_dsn() {
    skip_without_docker!();
    let rule = temp_file(".yml", CURL_RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
        ])
        .env_remove("RSIGMA_HUNT_DSN")
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "pass --dsn or set RSIGMA_HUNT_DSN",
        ));
}
