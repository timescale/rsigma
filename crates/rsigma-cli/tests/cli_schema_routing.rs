//! Integration tests for `engine eval --schema-routing`.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const RULE: &str = r#"
title: Whoami
id: r-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;

const SCHEMA_CONFIG: &str = r#"
routing:
  on_unknown: warn
  bindings:
    - schema: ecs
      pipelines: [ecs_windows]
"#;

#[test]
fn routes_ecs_event_through_bound_pipeline() {
    let rule = temp_file(".yml", RULE);
    let schema = temp_file(".yml", SCHEMA_CONFIG);
    // ECS event: the rule field CommandLine is mapped to process.command_line
    // by the ecs_windows pipeline the `ecs` schema is bound to, so it matches.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--schema-routing",
            "--schema-config",
            schema.path().to_str().unwrap(),
            "-e",
            r#"{"ecs.version":"8.0.0","process.command_line":"cmd /c whoami"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_id\":\"r-whoami\""));
}

#[test]
fn ecs_event_without_routing_does_not_match() {
    let rule = temp_file(".yml", RULE);
    // Without routing the rule uses CommandLine, which the ECS event does not
    // carry (it has process.command_line), so nothing matches.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "-e",
            r#"{"ecs.version":"8.0.0","process.command_line":"cmd /c whoami"}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("rule_id").not());
}

const CORR_RULES: &str = r#"
title: Whoami
id: r-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Repeated whoami by user
correlation:
    type: event_count
    rules:
        - r-whoami
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 2
level: high
"#;

#[test]
fn cross_schema_correlation_groups_same_user() {
    let rule = temp_file(".yml", CORR_RULES);
    let schema = temp_file(".yml", SCHEMA_CONFIG);
    // One ECS event (user.name) and one Sigma-native event (User) for the same
    // user "alice". With schema-aware group-by over a shared store, they land
    // in the same window and fire the count>=2 correlation.
    let stdin = concat!(
        r#"{"ecs.version":"8.0.0","process.command_line":"cmd /c whoami","user.name":"alice"}"#,
        "\n",
        r#"{"CommandLine":"cmd /c whoami","User":"alice"}"#,
        "\n",
    );
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--schema-routing",
            "--schema-config",
            schema.path().to_str().unwrap(),
            "--output-format",
            "ndjson",
        ])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("Repeated whoami by user"));
}
