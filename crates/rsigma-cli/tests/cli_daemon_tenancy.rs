//! End-to-end multi-tenant isolation: startup refusals, ingest binding, and
//! API scoping.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{
    DaemonProcess, http_delete_bearer, http_get_bearer, http_post_bearer, poll_until,
    spawn_expect_failure, spawn_expect_failure_with_env, temp_file,
};

const A_INGEST: &str = "tenant-a-ingest-0123456789abcdef0123";
const B_INGEST: &str = "tenant-b-ingest-0123456789abcdef0123";
const A_OPERATOR: &str = "tenant-a-operator-0123456789abcdef01";
const ADMIN: &str = "all-tenants-admin-0123456789abcdef01";

const RULES: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
level: high
---
title: Many logins
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;

fn write_rules(dir: &Path) -> PathBuf {
    let rules = dir.join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join("rules.yml"), RULES).unwrap();
    rules
}

/// A tenancy-enabled config with a shared ruleset, an HTTP source, an alert
/// pipeline for silences, and a per-tenant file sink.
fn tenancy_config(dir: &Path, extra_tenancy: &str) -> String {
    let rules = write_rules(dir);
    let out = dir.join("out.ndjson");
    let pipeline = dir.join("alert-pipeline.yml");
    std::fs::write(
        &pipeline,
        "dedup:\n  fingerprint: [match.EventType]\n  resolve_timeout: 1h\ngroup:\n  by: [match.EventType]\n  group_wait: 0s\n  resolve_timeout: 1h\n",
    )
    .unwrap();
    format!(
        r#"rulesets:
  shared:
    sources: ["{}"]
daemon:
  rulesets:
    - shared
  alert_pipeline: "{}"
  tenancy:
    enabled: true
    metrics_tenant_allowlist: [tenant-a]
{}
  input:
    source: http
  output:
    sinks: ["file://{}"]
  api:
    addr: 127.0.0.1:0
    auth:
      tokens:
        - name: a-ingest
          role: ingest
          token_env: A_INGEST
          tenant: tenant-a
        - name: b-ingest
          role: ingest
          token_env: B_INGEST
          tenant: tenant-b
        - name: a-operator
          role: operator
          token_env: A_OPERATOR
          tenant: tenant-a
        - name: admin
          role: admin
          token_env: ADMIN
          all_tenants: true
"#,
        yaml_path(&rules),
        yaml_path(&pipeline),
        extra_tenancy,
        yaml_path(&out),
    )
}

fn spawn_tenancy(dir: &Path, extra_tenancy: &str) -> DaemonProcess {
    spawn_tenancy_with_args(dir, extra_tenancy, &[])
}

fn spawn_tenancy_with_args(dir: &Path, extra_tenancy: &str, extra_args: &[&str]) -> DaemonProcess {
    let config = temp_file(".yaml", &tenancy_config(dir, extra_tenancy));
    let config_path = config.path().to_str().unwrap().to_string();
    let mut args = vec![
        "engine",
        "daemon",
        "--config",
        &config_path,
        "--api-addr",
        "127.0.0.1:0",
    ];
    args.extend_from_slice(extra_args);
    DaemonProcess::spawn_with_env(
        &args,
        &[
            ("A_INGEST", A_INGEST),
            ("B_INGEST", B_INGEST),
            ("A_OPERATOR", A_OPERATOR),
            ("ADMIN", ADMIN),
        ],
    )
}

/// A path for a YAML scalar: forward slashes, so a Windows path has no
/// backslash that a double-quoted scalar would read as an escape.
fn yaml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn event(user: &str) -> String {
    serde_json::json!({"EventType": "login", "User": user}).to_string()
}

#[test]
fn tenancy_without_auth_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  tenancy:\n    enabled: true\n  input:\n    source: http\n",
            yaml_path(&rules)
        ),
    );
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("daemon.api.auth"),
        "expected auth refusal, got: {stderr}"
    );
}

#[test]
fn tenancy_with_anonymous_permissions_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  tenancy:\n    enabled: true\n  input:\n    source: http\n  api:\n    auth:\n      anonymous_permissions: [\"*:read\"]\n      tokens:\n        - name: t\n          role: admin\n          token_env: ADMIN\n          all_tenants: true\n",
            yaml_path(&rules)
        ),
    );
    let stderr = spawn_expect_failure_with_env(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
        ],
        &[("ADMIN", ADMIN)],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("anonymous_permissions"),
        "expected anonymous refusal, got: {stderr}"
    );
}

#[test]
fn a_token_without_a_tenant_binding_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  tenancy:\n    enabled: true\n  input:\n    source: http\n  api:\n    auth:\n      tokens:\n        - name: t\n          role: admin\n          token_env: ADMIN\n",
            yaml_path(&rules)
        ),
    );
    let stderr = spawn_expect_failure_with_env(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
        ],
        &[("ADMIN", ADMIN)],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("all_tenants"),
        "expected token binding refusal, got: {stderr}"
    );
}

#[test]
fn a_project_layer_refuses_tenancy() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".config/rsigma")).unwrap();
    let rules = write_rules(dir.path());
    // Tenancy and auth come from the user layer; the project file carries the
    // ruleset binding that could otherwise drop a tenant.
    std::fs::write(
        home.join(".config/rsigma/config.yaml"),
        format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  tenancy:\n    enabled: true\n  input:\n    source: http\n  api:\n    auth:\n      tokens:\n        - name: admin\n          role: admin\n          token_env: ADMIN\n          all_tenants: true\n",
            yaml_path(&rules)
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("rsigma.yaml"),
        "daemon:\n  rulesets: [shared]\n",
    )
    .unwrap();

    let output = std::process::Command::new(common::rsigma_bin())
        .args(["engine", "daemon", "--api-addr", "127.0.0.1:0"])
        .current_dir(dir.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("ADMIN", ADMIN)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("project config layer"),
        "expected project-layer refusal, got: {stderr}"
    );
}

#[test]
fn ingest_stamps_the_token_tenant_and_all_tenants_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    let url = daemon.url("/api/v1/events");

    let (status, _) = http_post_bearer(&url, A_INGEST, &event("alice"));
    assert_eq!(status, 200);
    let (status, _) = http_post_bearer(&url, B_INGEST, &event("bob"));
    assert_eq!(status, 200);
    let (status, _) = http_post_bearer(&url, B_INGEST, &event("bob"));
    assert_eq!(status, 200);
    // The all_tenants admin token has no tenant to bind.
    let (status, _) = http_post_bearer(&url, ADMIN, &event("carol"));
    assert_eq!(status, 403);

    // A body field and a header named like a tenant do not override the token.
    let spoofed = serde_json::json!({
        "EventType": "login",
        "User": "alice",
        "tenant": "tenant-b",
        "tenant_id": "tenant-b",
    })
    .to_string();
    let (status, _) = http_post_bearer(&url, A_INGEST, &spoofed);
    assert_eq!(status, 200);

    let out = dir.path().join("out.ndjson");
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&out).ok()?;
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        (lines.len() >= 2).then_some(lines)
    })
    .expect("detections written");
    // alice reaches two events only if the spoofed event stayed in tenant A, so
    // her correlation must exist and carry tenant A; bob's carries tenant B.
    let tenant_of = |user: &str| {
        lines
            .iter()
            .find(|line| line.contains(user))
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["tenant_id"].as_str().unwrap().to_string()
            })
            .unwrap_or_else(|| panic!("no result for {user}: {lines:?}"))
    };
    assert_eq!(tenant_of("alice"), "tenant-a");
    assert_eq!(tenant_of("bob"), "tenant-b");
}

#[test]
fn a_cli_input_flag_cannot_bypass_the_source_binding() {
    // The config file selects the HTTP source, which needs no input.tenant;
    // the --input flag overrides it with stdin, which does.
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  tenancy:\n    enabled: true\n  input:\n    source: http\n  api:\n    auth:\n      tokens:\n        - name: t\n          role: admin\n          token_env: ADMIN\n          all_tenants: true\n",
            yaml_path(&rules)
        ),
    );
    let stderr = spawn_expect_failure_with_env(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
            "--input",
            "stdin",
        ],
        &[("ADMIN", ADMIN)],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("'stdin' requires daemon.input.tenant"),
        "expected source-binding refusal, got: {stderr}"
    );
}

#[test]
fn a_tenant_bound_ruleset_never_fires_for_another_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let config = tenancy_config(dir.path(), "").replace(
        "    - shared\n",
        "    - name: shared\n      tenants: [tenant-a]\n",
    );
    assert!(config.contains("tenants: [tenant-a]"));
    let config = temp_file(".yaml", &config);
    let daemon = DaemonProcess::spawn_with_env(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
        ],
        &[
            ("A_INGEST", A_INGEST),
            ("B_INGEST", B_INGEST),
            ("A_OPERATOR", A_OPERATOR),
            ("ADMIN", ADMIN),
        ],
    );

    // Tenant B's events go first, so they are processed before tenant A's
    // correlation is written.
    for _ in 0..2 {
        let (status, _) = http_post_bearer(&daemon.url("/api/v1/events"), B_INGEST, &event("bob"));
        assert_eq!(status, 200);
    }
    for _ in 0..2 {
        let (status, _) =
            http_post_bearer(&daemon.url("/api/v1/events"), A_INGEST, &event("alice"));
        assert_eq!(status, 200);
    }

    let out = dir.path().join("out.ndjson");
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&out).ok()?;
        text.contains("tenant-a")
            .then(|| text.lines().map(str::to_string).collect::<Vec<_>>())
    })
    .expect("tenant A's correlation written");
    assert!(
        lines.iter().all(|line| line.contains("tenant-a")),
        "{lines:?}"
    );

    // Tenant A sees its ruleset; a read narrowed to tenant B sees no rules
    // and no ruleset bound only to tenant A.
    let (status, body) = http_get_bearer(&daemon.url("/api/v1/rules"), A_OPERATOR);
    assert_eq!(status, 200);
    let rules: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(rules["rulesets"][0]["name"], "shared", "{body}");
    assert_eq!(rules["detection_rules"], 1, "{body}");

    let (status, body) = http_get_bearer(&daemon.url("/api/v1/rules?tenant=tenant-b"), ADMIN);
    assert_eq!(status, 200);
    let rules: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(rules["detection_rules"], 0, "{body}");
    assert_eq!(rules["correlation_rules"], 0, "{body}");
    assert_eq!(rules["rulesets"], serde_json::json!([]), "{body}");
    assert!(rules.get("rules_path").is_none(), "{body}");
}

#[test]
fn api_reads_are_scoped_to_the_token_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    let base = daemon.api_addr().to_string();

    // Two tenant silences, one per tenant.
    let a_silence = bounded_silence_for("tenant-a");
    let b_silence = bounded_silence_for("tenant-b");
    let (status, _) = http_post_bearer(
        &format!("http://{base}/api/v1/silences"),
        A_OPERATOR,
        &a_silence,
    );
    assert_eq!(status, 201);
    let (status, _) =
        http_post_bearer(&format!("http://{base}/api/v1/silences"), ADMIN, &b_silence);
    assert_eq!(status, 201);

    let (status, body) = http_get_bearer(&format!("http://{base}/api/v1/silences"), A_OPERATOR);
    assert_eq!(status, 200);
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["silences"][0]["tenant"], "tenant-a");

    // A tenant token may not ask for another tenant.
    let (status, _) = http_get_bearer(
        &format!("http://{base}/api/v1/silences?tenant=tenant-b"),
        A_OPERATOR,
    );
    assert_eq!(status, 403);

    // The all_tenants token sees both and narrows with ?tenant=.
    let (status, body) = http_get_bearer(&format!("http://{base}/api/v1/silences"), ADMIN);
    assert_eq!(status, 200);
    let all: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(all["count"], 2);
    let (status, body) = http_get_bearer(
        &format!("http://{base}/api/v1/silences?tenant=tenant-b"),
        ADMIN,
    );
    assert_eq!(status, 200);
    let narrowed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(narrowed["count"], 1);
    assert_eq!(narrowed["silences"][0]["tenant"], "tenant-b");

    // A tenant token may not read an operator-only endpoint.
    assert_eq!(
        http_get_bearer(&format!("http://{base}/api/v1/status"), A_OPERATOR).0,
        403
    );
    assert_eq!(
        http_get_bearer(&format!("http://{base}/metrics"), A_OPERATOR).0,
        403
    );
    assert_eq!(
        http_get_bearer(&format!("http://{base}/api/v1/status"), ADMIN).0,
        200
    );
}

fn bounded_silence_for(tenant: &str) -> String {
    let ends_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    serde_json::json!({
        "matchers": [{ "selector": "rule", "op": "=", "value": "login-rule" }],
        "ends_at": ends_at,
        "tenant": tenant,
        "created_by": "tests",
    })
    .to_string()
}

#[test]
fn silence_ids_are_unique_per_tenant_and_an_ambiguous_delete_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    let with_id = |tenant: &str| {
        let mut body: serde_json::Value =
            serde_json::from_str(&bounded_silence_for(tenant)).unwrap();
        body["id"] = "maint".into();
        body.to_string()
    };
    let silences = daemon.url("/api/v1/silences");
    assert_eq!(
        http_post_bearer(&silences, A_OPERATOR, &with_id("tenant-a")).0,
        201
    );
    assert_eq!(
        http_post_bearer(&silences, A_OPERATOR, &with_id("tenant-a")).0,
        409
    );
    assert_eq!(
        http_post_bearer(&silences, ADMIN, &with_id("tenant-b")).0,
        201,
        "another tenant may reuse the id"
    );

    let maint = daemon.url("/api/v1/silences/maint");
    assert_eq!(http_delete_bearer(&maint, ADMIN).0, 409);
    assert_eq!(
        http_delete_bearer(&format!("{maint}?tenant=tenant-b"), ADMIN).0,
        200
    );
    assert_eq!(http_delete_bearer(&maint, A_OPERATOR).0, 200);
}

#[test]
fn a_tenant_at_its_silence_quota_does_not_block_another_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "    quotas:\n      silences: 1");
    let silences = daemon.url("/api/v1/silences");
    let a = bounded_silence_for("tenant-a");
    assert_eq!(http_post_bearer(&silences, A_OPERATOR, &a).0, 201);
    let (status, body) = http_post_bearer(&silences, A_OPERATOR, &a);
    assert_eq!(status, 429, "{body}");
    assert!(body.contains("quotas.silences"), "{body}");
    assert_eq!(
        http_post_bearer(&silences, ADMIN, &bounded_silence_for("tenant-b")).0,
        201
    );
}

#[test]
fn an_all_tenants_write_is_audited_under_its_target_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let daemon = spawn_tenancy_with_args(dir.path(), "", &["--state-db", db.to_str().unwrap()]);
    let silences = daemon.url("/api/v1/silences");
    let (status, body) = http_post_bearer(&silences, ADMIN, &bounded_silence_for("tenant-a"));
    assert_eq!(status, 201, "{body}");
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let deleted = http_delete_bearer(&daemon.url(&format!("/api/v1/silences/{id}")), ADMIN);
    assert_eq!(deleted.0, 200, "{}", deleted.1);

    let audit = daemon.url("/api/v1/audit");
    let entries = |token: &str| {
        let (status, body) = http_get_bearer(&audit, token);
        assert_eq!(status, 200, "{body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["entries"]
            .as_array()
            .unwrap()
            .clone()
    };
    let seen_by_a = poll_until(Duration::from_secs(5), || {
        let rows = entries(A_OPERATOR);
        (rows.len() == 2).then_some(rows)
    })
    .expect("tenant-a sees both writes made on its behalf");
    for row in &seen_by_a {
        assert_eq!(row["token"], "admin");
        assert_eq!(row["tenant"], "tenant-a");
    }
}

#[test]
fn an_all_tenants_silence_without_a_tenant_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    let ends_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let body = serde_json::json!({
        "matchers": [{ "selector": "rule", "op": "=", "value": "login-rule" }],
        "ends_at": ends_at,
    })
    .to_string();
    let (status, _) = http_post_bearer(&daemon.url("/api/v1/silences"), ADMIN, &body);
    assert_eq!(status, 400);
}

#[test]
fn a_tenant_silence_mutes_only_its_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    let base = daemon.api_addr().to_string();
    let ends_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let body = serde_json::json!({
        "matchers": [{ "selector": "rule", "op": "=", "value": "many-logins" }],
        "ends_at": ends_at,
        "tenant": "tenant-a",
        "created_by": "tests",
    })
    .to_string();
    let (status, _) =
        http_post_bearer(&format!("http://{base}/api/v1/silences"), A_OPERATOR, &body);
    assert_eq!(status, 201);

    // Two events per tenant fire the correlation; tenant A's result is
    // silenced, so only tenant B's correlation reaches the file.
    for user in ["alice", "alice"] {
        http_post_bearer(&daemon.url("/api/v1/events"), A_INGEST, &event(user));
    }
    for user in ["bob", "bob"] {
        http_post_bearer(&daemon.url("/api/v1/events"), B_INGEST, &event(user));
    }

    let out = dir.path().join("out.ndjson");
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&out).ok()?;
        (!text.trim().is_empty()).then(|| text.lines().map(str::to_string).collect::<Vec<_>>())
    })
    .expect("a detection written");
    assert!(
        lines.iter().all(|line| line.contains("tenant-b")),
        "{lines:?}"
    );
}

#[test]
fn a_disabled_daemon_refuses_tenant_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  input:\n    source: http\n  api:\n    auth:\n      tokens:\n        - name: t\n          role: admin\n          token_env: ADMIN\n          tenant: tenant-a\n",
            yaml_path(&rules)
        ),
    );
    let stderr = spawn_expect_failure_with_env(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
        ],
        &[("ADMIN", ADMIN)],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("daemon.tenancy.enabled is false"),
        "expected disabled refusal, got: {stderr}"
    );
}

#[test]
fn a_disabled_daemon_refuses_a_tenant_sink() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  input:\n    source: http\n  output:\n    sinks: [\"file:///tmp/out.{{tenant}}.ndjson\"]\n",
            yaml_path(&rules)
        ),
    );
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("{tenant}"),
        "expected sink refusal, got: {stderr}"
    );
}

#[test]
fn a_disabled_daemon_checks_scoped_webhooks_in_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let hooks = dir.path().join("hooks");
    std::fs::create_dir(&hooks).unwrap();
    std::fs::write(
        hooks.join("scoped.yaml"),
        "webhooks:\n  - id: scoped\n    kind: detection\n    url: http://127.0.0.1:1/hook\n    scope:\n      tenants: [tenant-a]\n",
    )
    .unwrap();
    let config = temp_file(
        ".yaml",
        &format!(
            "rulesets:\n  shared:\n    sources: [\"{}\"]\ndaemon:\n  rulesets: [shared]\n  input:\n    source: http\n  output:\n    webhooks: [\"{}\"]\n",
            yaml_path(&rules),
            yaml_path(&hooks)
        ),
    );
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "--config",
            config.path().to_str().unwrap(),
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("scope.tenants is non-empty while daemon.tenancy.enabled is false"),
        "expected scope refusal, got: {stderr}"
    );
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn otlp_http_stamps_the_token_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    let url = daemon.url("/v1/logs");
    let body = serde_json::json!({
        "resourceLogs": [{
            "scopeLogs": [{
                "logRecords": [{
                    "attributes": [
                        {"key": "EventType", "value": {"stringValue": "login"}},
                        {"key": "User", "value": {"stringValue": "alice"}}
                    ]
                }]
            }]
        }]
    })
    .to_string();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    for _ in 0..2 {
        let response = agent
            .post(&url)
            .header("authorization", format!("Bearer {A_INGEST}"))
            .header("content-type", "application/json")
            .send(&body)
            .expect("OTLP HTTP request");
        assert_eq!(response.status().as_u16(), 200);
    }

    let out = dir.path().join("out.ndjson");
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&out).ok()?;
        (!text.trim().is_empty()).then(|| text.lines().map(str::to_string).collect::<Vec<_>>())
    })
    .expect("OTLP result written");
    assert!(
        lines.iter().all(|line| line.contains("tenant-a")),
        "{lines:?}"
    );
}

#[test]
fn restarting_without_tenancy_discards_tenanted_state() {
    let dir = tempfile::tempdir().unwrap();
    let rules = write_rules(dir.path());
    let out = dir.path().join("out.ndjson");
    let db = dir.path().join("state.db");

    let tenancy_config = temp_file(
        ".yaml",
        &format!(
            r#"rulesets:
  shared:
    sources: ["{}"]
daemon:
  rulesets: [shared]
  tenancy:
    enabled: true
  state:
    db: "{}"
    save_interval: 1
  input:
    source: http
  output:
    sinks: ["file://{}"]
  api:
    addr: 127.0.0.1:0
    auth:
      tokens:
        - name: a-ingest
          role: ingest
          token_env: A_INGEST
          tenant: tenant-a
"#,
            yaml_path(&rules),
            yaml_path(&db),
            yaml_path(&out)
        ),
    );
    let first = DaemonProcess::spawn_with_env(
        &[
            "engine",
            "daemon",
            "--config",
            tenancy_config.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
        ],
        &[("A_INGEST", A_INGEST)],
    );
    for user in ["alice", "alice"] {
        http_post_bearer(&first.url("/api/v1/events"), A_INGEST, &event(user));
    }
    poll_until(Duration::from_secs(5), || {
        std::fs::read_to_string(&out)
            .ok()
            .filter(|t| !t.trim().is_empty())
    })
    .expect("correlation written");
    // Windows kills the daemon without a shutdown save, so let a periodic
    // save (`save_interval: 1`) land first.
    std::thread::sleep(Duration::from_secs(2));
    drop(first);

    let plain_config = temp_file(
        ".yaml",
        &format!(
            r#"rulesets:
  shared:
    sources: ["{}"]
daemon:
  rulesets: [shared]
  state:
    db: "{}"
    save_interval: 1
  input:
    source: http
  output:
    sinks: ["file://{}"]
"#,
            yaml_path(&rules),
            yaml_path(&db),
            yaml_path(&out)
        ),
    );
    let second = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "--config",
        plain_config.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ]);
    let stderr = second.stderr_lines().join("\n");
    assert!(
        stderr.contains("Discarded correlation entries"),
        "expected discard warning, got: {stderr}"
    );
}

#[test]
fn tenant_metrics_are_exported() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = spawn_tenancy(dir.path(), "");
    // The extra `tenancy:` block merges over the base one.
    let base = daemon.api_addr().to_string();
    // A no_tenant rejection.
    let (status, _) = http_post_bearer(
        &format!("http://{base}/api/v1/events"),
        ADMIN,
        &event("carol"),
    );
    assert_eq!(status, 403);
    // A tenant match.
    http_post_bearer(&daemon.url("/api/v1/events"), A_INGEST, &event("alice"));
    http_post_bearer(&daemon.url("/api/v1/events"), A_INGEST, &event("alice"));

    let (status, body) = http_get_bearer(&format!("http://{base}/metrics"), ADMIN);
    assert_eq!(status, 200);
    assert!(
        body.contains(r#"rsigma_tenant_rejected_total{channel="rest",reason="no_tenant"}"#),
        "{body}"
    );
    assert!(
        body.contains(r#"rsigma_detection_matches_by_tenant_total{tenant="tenant-a"}"#),
        "{body}"
    );
    assert!(
        body.contains("rsigma_tenant_quota_evictions_total"),
        "{body}"
    );
}
