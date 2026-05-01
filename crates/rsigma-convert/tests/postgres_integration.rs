//! Integration tests that convert Sigma rules to SQL and execute the
//! generated queries against a real PostgreSQL instance via testcontainers.
//!
//! Uses the Okta detection scenario from the detection-layer-on-postgres
//! companion project: JSONB schema, 6 sample Okta System Log events, and
//! SigmaHQ rules for the cross-tenant impersonation attack chain.

use std::collections::HashMap;

use rsigma_convert::backends::postgres::PostgresBackend;
use rsigma_convert::convert_collection;
use rsigma_parser::parse_sigma_yaml;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

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

const SCHEMA: &str = r#"
CREATE TABLE okta_events (
    time  TIMESTAMPTZ NOT NULL,
    data  JSONB NOT NULL
);
CREATE INDEX ON okta_events USING GIN (data jsonb_path_ops);
"#;

const EVENTS: &[(&str, &str)] = &[
    // 1. Bob's normal login (noise, no detection)
    (
        "2023-08-15T13:55:00Z",
        r#"{"eventType":"user.session.start","actor":{"alternateId":"bob@acme.com","displayName":"Bob Smith","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"192.168.1.100"},"securityContext":{"isProxy":false}}"#,
    ),
    // 2. Attacker proxy session (detection: proxy rule)
    (
        "2023-08-15T14:05:00Z",
        r#"{"eventType":"user.session.start","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true}}"#,
    ),
    // 3. MFA deactivation (detection: MFA rule)
    (
        "2023-08-15T14:12:00Z",
        r#"{"eventType":"user.mfa.factor.deactivate","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true}}"#,
    ),
    // 4. Ops team app update (noise, no detection)
    (
        "2023-08-15T14:15:00Z",
        r#"{"eventType":"application.lifecycle.update","actor":{"alternateId":"ops@acme.com","displayName":"Ops Team","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"10.0.0.50"},"securityContext":{"isProxy":false}}"#,
    ),
    // 5. Admin privilege grant (detection: admin role rule)
    (
        "2023-08-15T14:18:00Z",
        r#"{"eventType":"user.account.privilege.grant","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true}}"#,
    ),
    // 6. Rogue IdP created (detection: IdP rule)
    (
        "2023-08-15T14:25:00Z",
        r#"{"eventType":"system.idp.lifecycle.create","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true}}"#,
    ),
];

const RULE_PROXY_SESSION: &str = r#"
title: Okta User Session Start Via An Anonymising Proxy Service
id: bde30855-5c53-4c18-ae90-1ff79ebc9578
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType: 'user.session.start'
        securityContext.isProxy: 'true'
    condition: selection
level: high
"#;

const RULE_MFA_DEACTIVATED: &str = r#"
title: Okta MFA Reset or Deactivated
id: 50e068d7-1e6b-4054-87e5-0a592c40c7e0
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType:
            - user.mfa.factor.deactivate
            - user.mfa.factor.reset_all
    condition: selection
level: medium
"#;

const RULE_ADMIN_ROLE: &str = r#"
title: Okta Admin Role Assigned to an User or Group
id: 413d4a81-6c98-4479-9863-014785fd579c
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType:
            - group.privilege.grant
            - user.account.privilege.grant
    condition: selection
level: medium
"#;

const RULE_IDP_CREATED: &str = r#"
title: Okta Identity Provider Created
id: 969c7590-8c19-4797-8c1b-23155de6e7ac
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType: 'system.idp.lifecycle.create'
    condition: selection
level: medium
"#;

const CORRELATION_EVENT_COUNT: &str = r#"
title: Okta Proxy Session Brute Force
id: f1a2b3c4-d5e6-7890-abcd-ef1234567891
correlation:
    type: event_count
    rules:
        - bde30855-5c53-4c18-ae90-1ff79ebc9578
    group-by:
        - actor
    timespan: 5m
    condition:
        gte: 1
level: high
"#;

fn okta_backend() -> PostgresBackend {
    let mut opts = HashMap::new();
    opts.insert("table".to_string(), "okta_events".to_string());
    opts.insert("json_field".to_string(), "data".to_string());
    opts.insert("timestamp_field".to_string(), "time".to_string());
    PostgresBackend::from_options(&opts)
}

async fn setup_db() -> (
    testcontainers::ContainerAsync<Postgres>,
    tokio_postgres::Client,
) {
    let container = Postgres::default()
        .with_init_sql(SCHEMA.to_string().into_bytes())
        .start()
        .await
        .expect("Failed to start Postgres container");

    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get Postgres port");
    let conn_str =
        format!("host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres");

    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("Failed to connect to Postgres");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Postgres connection error: {e}");
        }
    });

    for (ts, json) in EVENTS {
        client
            .execute(
                &format!("INSERT INTO okta_events (time, data) VALUES ('{ts}'::timestamptz, '{}'::jsonb)", json.replace('\'', "''")),
                &[],
            )
            .await
            .expect("Failed to insert event");
    }

    (container, client)
}

/// Convert a single Sigma rule and run the generated SQL against Postgres.
/// Returns the number of rows each query returned.
async fn convert_and_query(
    client: &tokio_postgres::Client,
    yaml: &str,
    format: &str,
) -> Vec<(String, u64)> {
    let collection = parse_sigma_yaml(yaml).expect("parse rule");
    let backend = okta_backend();
    let output = convert_collection(&backend, &collection, &[], format).expect("convert");

    let mut results = Vec::new();
    for result in &output.queries {
        for query in &result.queries {
            let rows = client
                .execute(query.as_str(), &[])
                .await
                .unwrap_or_else(|e| panic!("Query failed: {e}\nSQL: {query}"));
            results.push((result.rule_title.clone(), rows));
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_session_default_format() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;
    let results = convert_and_query(&client, RULE_PROXY_SESSION, "default").await;
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].1, 1,
        "only the attacker proxy session should match"
    );
}

#[tokio::test]
async fn mfa_deactivated_default_format() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;
    let results = convert_and_query(&client, RULE_MFA_DEACTIVATED, "default").await;
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].1, 1,
        "only the MFA deactivation event should match"
    );
}

#[tokio::test]
async fn admin_role_default_format() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;
    let results = convert_and_query(&client, RULE_ADMIN_ROLE, "default").await;
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].1, 1,
        "only the privilege grant event should match"
    );
}

#[tokio::test]
async fn idp_created_default_format() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;
    let results = convert_and_query(&client, RULE_IDP_CREATED, "default").await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, 1, "only the IdP creation event should match");
}

#[tokio::test]
async fn view_format_creates_queryable_view() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;
    let collection = parse_sigma_yaml(RULE_PROXY_SESSION).expect("parse");
    let backend = okta_backend();
    let output = convert_collection(&backend, &collection, &[], "view").expect("convert");

    let create_view_sql = &output.queries[0].queries[0];
    client
        .execute(create_view_sql.as_str(), &[])
        .await
        .unwrap_or_else(|e| panic!("CREATE VIEW failed: {e}\nSQL: {create_view_sql}"));

    let rows = client
        .execute(
            "SELECT * FROM sigma_bde30855_5c53_4c18_ae90_1ff79ebc9578",
            &[],
        )
        .await
        .expect("SELECT from view failed");
    assert_eq!(rows, 1, "view should return 1 matching row");
}

#[tokio::test]
async fn all_four_rules_together() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;

    let combined = format!(
        "{RULE_PROXY_SESSION}\n---\n{RULE_MFA_DEACTIVATED}\n---\n{RULE_ADMIN_ROLE}\n---\n{RULE_IDP_CREATED}"
    );
    let results = convert_and_query(&client, &combined, "default").await;
    assert_eq!(results.len(), 4);
    let total: u64 = results.iter().map(|(_, n)| n).sum();
    assert_eq!(
        total, 4,
        "4 events should match across 4 rules (2 noise events ignored)"
    );
}

#[tokio::test]
async fn correlation_event_count_against_postgres() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;

    let combined = format!("{RULE_PROXY_SESSION}\n---\n{CORRELATION_EVENT_COUNT}");
    let results = convert_and_query(&client, &combined, "default").await;

    // First result is the detection rule, second is the correlation
    assert_eq!(
        results.len(),
        2,
        "should have detection + correlation queries"
    );
    assert_eq!(
        results[0].1, 1,
        "detection rule should match 1 proxy session"
    );
    assert!(
        results[1].1 >= 1,
        "correlation should find at least 1 group meeting threshold (gte: 1)"
    );
}

#[tokio::test]
async fn no_match_returns_zero_rows() {
    skip_without_docker!();
    let (_container, client) = setup_db().await;

    let rule = r#"
title: Nonexistent Event Type
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType: 'does.not.exist'
    condition: selection
level: low
"#;
    let results = convert_and_query(&client, rule, "default").await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, 0, "non-matching rule should return 0 rows");
}
