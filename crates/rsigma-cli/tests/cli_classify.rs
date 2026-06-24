//! Integration tests for the `engine classify` subcommand.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

#[test]
fn classifies_inline_ecs_event_as_json() {
    rsigma()
        .args([
            "engine",
            "classify",
            "-e",
            r#"{"ecs.version":"8.11.0","process":{"command_line":"whoami"}}"#,
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": \"ecs\""))
        .stdout(predicate::str::contains("\"specificity\": 100"));
}

#[test]
fn classifies_ndjson_stream_from_stdin() {
    let stdin = concat!(
        r#"{"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1}"#,
        "\n",
        r#"{"class_uid":1001,"metadata":{"version":"1.1.0"}}"#,
        "\n",
        r#"{"unrecognized":"blob"}"#,
        "\n",
        "{}",
        "\n",
    );
    rsigma()
        .args(["engine", "classify", "--output-format", "ndjson"])
        .write_stdin(stdin)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\":\"sysmon\""))
        .stdout(predicate::str::contains("\"schema\":\"ocsf\""))
        .stdout(predicate::str::contains("\"schema\":\"generic_json\""))
        // The empty object matches no signature: reported as null (unknown).
        .stdout(predicate::str::contains("\"schema\":null"));
}

#[test]
fn unknown_count_surfaces_in_summary() {
    rsigma()
        .args([
            "engine",
            "classify",
            "-e",
            "{}",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"unknown\": 1"))
        .stdout(predicate::str::contains("\"classified\": 0"));
}

#[test]
fn user_signature_overrides_via_schema_config() {
    let config = temp_file(
        ".yml",
        r#"
schemas:
  - name: my_vendor
    specificity: 120
    match:
      - field_present: vendor.product
      - equals:
          field: event_type
          value: alert
"#,
    );
    rsigma()
        .args([
            "engine",
            "classify",
            "-e",
            r#"{"vendor":{"product":"X"},"event_type":"ALERT"}"#,
            "--schema-config",
            config.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": \"my_vendor\""));
}

#[test]
fn invalid_inline_json_exits_nonzero() {
    rsigma()
        .args(["engine", "classify", "-e", "not json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid JSON event"));
}
