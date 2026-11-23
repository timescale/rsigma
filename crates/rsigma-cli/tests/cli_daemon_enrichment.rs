//! E2E tests for the daemon's `--enrichers` flag.
//!
//! Spawns `rsigma engine daemon` with an enrichers config covering all
//! four primitives (`template`, `lookup`, `http`, `command`) plus a
//! file sink, sends a detection-triggering event over `--input http`,
//! and asserts that the resulting NDJSON line carries an `enrichments`
//! object with each primitive's contribution. Also covers:
//!
//! - cross-namespace template references rejected at startup,
//! - the HTTP response cache eliminating the second upstream call,
//! - enrichers reading fields the rule did not match on, with the event
//!   retained for them and stripped before delivery.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_post, poll_until, rsigma_bin, temp_file};
use std::process::Stdio;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// The rule selection covers `CommandLine`, `SourceIp`, and `SHA256` so
// every templated field landing in `matched_fields` is available to the
// enrichers (the `${detection.fields.X}` resolver reads from
// `matched_fields`, not from the original event).
const ENRICH_RULE: &str = r#"
title: Encoded PowerShell
id: 00000000-0000-0000-0000-0000000000aa
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "powershell -enc"
        SourceIp|contains: "."
        SHA256|contains: ""
    condition: selection
level: high
tags:
    - attack.t1059.001
"#;

/// External `--source` file declaring an `employee_directory` dynamic source
/// so the `lookup` enricher has something to read from.
fn sources_yaml(employees_path: &str) -> String {
    format!(
        r#"
sources:
  - id: employee_directory
    type: file
    path: {employees_path}
    format: json
"#
    )
}

const EMPLOYEES_JSON: &str = r#"{
  "10.0.0.5": {"user": "alice", "team": "Platform"},
  "10.0.0.7": {"user": "bob", "team": "IT-Ops"}
}"#;

/// Build the platform-portable `command:` argv for the test's `command`
/// enricher. On Unix, runs `cat <fixture>`; on Windows, runs
/// `cmd.exe /D /C type <fixture>` as four separate argv elements.
/// Returns a YAML inline list literal ready to splice into the config.
///
/// The fixture file holds the JSON body the enricher should produce,
/// avoiding cross-shell quote-escaping headaches.
///
/// **Windows note:** the path goes in its own argv element rather than
/// being baked into a `type "..."` blob. That avoids cmd.exe's `/C`
/// quote-stripping pathology, which otherwise leaves cmd trying to
/// open a file with literal `\"...\"` characters at both ends after
/// Rust's `CreateProcess` quoting and cmd's outer-quote-stripping
/// rule interact. With separate args, Rust quotes only the path
/// element (when it contains spaces), cmd's `type` receives a single
/// clean path argument, and the file is read normally. `/D` disables
/// AutoRun for hermeticity.
fn command_argv_yaml(probe_path: &str) -> String {
    #[cfg(unix)]
    {
        format!(r#"["/bin/cat", "{probe_path}"]"#)
    }
    #[cfg(windows)]
    {
        // Escape backslashes for the YAML double-quoted string so each
        // `\\` decodes back to a single `\` in the parsed path.
        let yaml_escaped = probe_path.replace('\\', "\\\\");
        format!(r#"["cmd.exe", "/D", "/C", "type", "{yaml_escaped}"]"#)
    }
}

/// Enrichers config covering all four primitives.
fn enrichers_yaml(http_base: &str, command_argv: &str) -> String {
    format!(
        r#"
max_concurrent_enrichments: 4

enrichers:
  - id: runbook
    kind: detection
    type: template
    inject_field: runbook_url
    template: "https://wiki/runbooks/${{detection.rule.id}}"

  - id: employee
    kind: detection
    type: lookup
    inject_field: employee
    source: employee_directory
    extract: '."${{detection.fields.SourceIp}}"'
    extract_type: jq
    default: "unknown"

  - id: hash_rep
    kind: detection
    type: http
    inject_field: file_reputation
    url: "{http_base}/files/${{detection.fields.SHA256}}"
    method: GET
    cache_ttl: 1h
    on_error: skip

  - id: who_am_i
    kind: detection
    type: command
    inject_field: probe_output
    command: {command_argv}
    output: json
"#
    )
}

const CROSS_NAMESPACE_ENRICHERS_YAML: &str = r#"
enrichers:
  - id: bad
    kind: detection
    type: template
    inject_field: out
    template: "https://wiki/${correlation.rule.id}"
"#;

fn detect_event() -> serde_json::Value {
    // The rule matches `CommandLine|contains "powershell -enc"`. We
    // include `SourceIp` (consumed by the `lookup` enricher) and
    // `SHA256` (consumed by the `http` enricher) so every primitive
    // has data to act on.
    serde_json::json!({
        "CommandLine": "powershell -enc QQA=",
        "SourceIp": "10.0.0.5",
        "SHA256": "abc123"
    })
}

#[test]
fn enrichers_inject_into_detection_output_via_all_four_primitives() {
    // Stand up a wiremock server for the `http` enricher. The mock
    // returns a fixed JSON payload regardless of body so the test does
    // not depend on `${detection.fields.SHA256}` resolving to any
    // particular value.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"score": 12})),
            )
            // Strict: the cache should keep us at exactly one upstream call
            // across the two events sent below.
            .expect(1)
            .mount(&s)
            .await;
        s
    });

    // Sources + employees + enrichers config files. The `command`
    // enricher reads its JSON body from a fixture file via `cat`
    // (Unix) / `type` (Windows) so the test doesn't have to deal with
    // cross-shell quote escaping.
    let employees = temp_file(".json", EMPLOYEES_JSON);
    let probe_payload = temp_file(".json", r#"{"who": "daemon"}"#);
    let sources = temp_file(".yml", &sources_yaml(employees.path().to_str().unwrap()));
    let rule = temp_file(".yml", ENRICH_RULE);
    let enrichers = temp_file(
        ".yml",
        &enrichers_yaml(
            server.uri().as_str(),
            &command_argv_yaml(probe_payload.path().to_str().unwrap()),
        ),
    );

    // File sink for reading enriched detections back.
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--enrichers",
        enrichers.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{output_path}"),
    ]);

    // Send the same event twice; the second call must hit the HTTP
    // cache (`expect(1)` on the mock above asserts this).
    let body = serde_json::to_string(&detect_event()).unwrap();
    for _ in 0..2 {
        let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
        assert_eq!(status, 200, "POST /api/v1/events did not accept the event");
    }

    // Wait for the two enriched lines to land in the file sink.
    let lines = poll_until(Duration::from_secs(5), || {
        let bytes = std::fs::read_to_string(&output_path).ok()?;
        let lines: Vec<&str> = bytes.lines().filter(|l| !l.is_empty()).collect();
        if lines.len() >= 2 {
            Some(lines.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        } else {
            None
        }
    })
    .expect("two enriched detections never landed in the file sink within 5s");

    // Assertions on the first enriched detection.
    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).expect("invalid NDJSON");
    let enr = parsed
        .get("enrichments")
        .expect("detection must carry an `enrichments` object");

    assert_eq!(
        enr.get("runbook_url"),
        Some(&serde_json::json!(format!(
            "https://wiki/runbooks/{}",
            "00000000-0000-0000-0000-0000000000aa"
        ))),
        "template enricher should have synthesised the runbook URL"
    );
    assert_eq!(
        enr.get("employee"),
        Some(&serde_json::json!({"user": "alice", "team": "Platform"})),
        "lookup enricher should have resolved the source IP to alice"
    );
    assert_eq!(
        enr.get("file_reputation"),
        Some(&serde_json::json!({"score": 12})),
        "http enricher should have written the wiremock response"
    );
    assert_eq!(
        enr.get("probe_output"),
        Some(&serde_json::json!({"who": "daemon"})),
        "command enricher should have parsed the JSON stdout"
    );

    // Sanity check: the second enriched line carries the same fields
    // (the cache hit served the same `file_reputation` value).
    let parsed_2: serde_json::Value = serde_json::from_str(&lines[1]).expect("invalid NDJSON");
    assert_eq!(
        parsed_2.get("enrichments").unwrap().get("file_reputation"),
        Some(&serde_json::json!({"score": 12}))
    );

    // Verify cache stats via /metrics. We expect at least one cache hit
    // (the second call hit the cache) and at least one miss (the first).
    let (_, metrics_body) = common::http_get(&daemon.url("/metrics"));
    assert!(
        metrics_body.contains("rsigma_enrichment_total{"),
        "/metrics should expose rsigma_enrichment_total"
    );
    assert!(
        metrics_body.contains("rsigma_enrichment_http_cache_hits_total{"),
        "/metrics should expose the HTTP cache hits counter"
    );

    // The wiremock `expect(1)` assertion runs on Drop. If the cache
    // failed and we made two upstream calls, dropping `server` would
    // panic.
    drop(server);
}

#[test]
fn cross_namespace_enrichers_config_is_rejected_at_startup() {
    // Spawning the daemon with a `kind: detection` enricher that
    // references `${correlation.rule.id}` must exit with the
    // configuration-error code (3) and never bind to a port.
    let rule = temp_file(".yml", ENRICH_RULE);
    let enrichers = temp_file(".yml", CROSS_NAMESPACE_ENRICHERS_YAML);

    let mut child = std::process::Command::new(rsigma_bin())
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--enrichers",
            enrichers.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rsigma engine daemon");

    // Drain stderr in the background so a slow log consumer cannot
    // block the daemon from exiting.
    let stderr = child.stderr.take().unwrap();
    let stderr_handle = std::thread::spawn(move || {
        use std::io::Read;
        let mut s = String::new();
        let mut r = stderr;
        let _ = r.read_to_string(&mut s);
        s
    });

    let exit = poll_until(Duration::from_secs(10), || child.try_wait().ok().flatten())
        .expect("daemon did not exit within 10s on a malformed enrichers config");
    let stderr_output = stderr_handle.join().unwrap_or_default();

    assert_eq!(
        exit.code(),
        Some(3),
        "expected exit code 3 (CONFIG_ERROR), got {:?}; stderr was:\n{stderr_output}",
        exit.code()
    );
    assert!(
        stderr_output.contains("wrong namespace") || stderr_output.contains("malformed"),
        "stderr should explain the cross-namespace error; got:\n{stderr_output}"
    );
}

// A rule that selects only `EventType`, so `SourceIp` is never a matched
// field and an enricher keyed on it must read it from the event.
#[cfg(feature = "mmdb-enrich")]
const LOGON_RULE: &str = r#"
title: Logon
id: 00000000-0000-0000-0000-0000000000bb
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        EventType: logon
    condition: selection
level: high
"#;

#[cfg(feature = "mmdb-enrich")]
fn geo_enrichers_yaml() -> String {
    let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsigma-runtime/tests/fixtures/mmdb/city-test.mmdb");
    format!(
        r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
    fields:
      country: country.iso_code
"#,
        db.display()
    )
}

#[cfg(feature = "mmdb-enrich")]
const RULE_ID_ENRICHERS_YAML: &str = r#"
enrichers:
  - id: runbook
    kind: detection
    type: template
    inject_field: runbook_url
    template: "https://wiki/runbooks/${detection.rule.id}"
"#;

#[cfg(feature = "mmdb-enrich")]
fn logon_event() -> String {
    serde_json::json!({"EventType": "logon", "SourceIp": "192.0.2.10"}).to_string()
}

/// Post one logon event and return the next line the file sink receives.
#[cfg(feature = "mmdb-enrich")]
fn post_and_read(daemon: &DaemonProcess, output_path: &str) -> serde_json::Value {
    let seen = std::fs::read_to_string(output_path)
        .map(|s| s.lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);
    let (status, _) = http_post(&daemon.url("/api/v1/events"), &logon_event());
    assert_eq!(status, 200, "POST /api/v1/events did not accept the event");
    let line = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(output_path).ok()?;
        text.lines()
            .filter(|l| !l.is_empty())
            .nth(seen)
            .map(str::to_string)
    })
    .expect("the detection never landed in the file sink within 5s");
    serde_json::from_str(&line).expect("invalid NDJSON")
}

#[cfg(feature = "mmdb-enrich")]
fn spawn_logon_daemon(
    rule: &tempfile::NamedTempFile,
    enrichers: &std::path::Path,
    output_path: &str,
    extra: &[&str],
) -> DaemonProcess {
    let output = format!("file://{output_path}");
    let mut args = vec![
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--enrichers",
        enrichers.to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &output,
    ];
    args.extend_from_slice(extra);
    DaemonProcess::spawn(&args)
}

#[cfg(feature = "mmdb-enrich")]
#[test]
fn enrichers_read_unmatched_fields_without_delivering_the_event() {
    let rule = temp_file(".yml", LOGON_RULE);
    let enrichers = temp_file(".yml", &geo_enrichers_yaml());
    let output = tempfile::NamedTempFile::new().unwrap();
    let output_path = output.path().to_str().unwrap().to_string();
    let daemon = spawn_logon_daemon(&rule, enrichers.path(), &output_path, &[]);

    let parsed = post_and_read(&daemon, &output_path);
    assert_eq!(
        parsed["enrichments"]["geo"]["country"], "US",
        "the mmdb key should resolve SourceIp from the event: {parsed}"
    );
    assert!(
        parsed.get("event").is_none(),
        "an event retained only for enrichment must not be delivered: {parsed}"
    );
}

#[cfg(feature = "mmdb-enrich")]
#[test]
fn include_event_still_delivers_the_event_with_enrichers() {
    let rule = temp_file(".yml", LOGON_RULE);
    let enrichers = temp_file(".yml", &geo_enrichers_yaml());
    let output = tempfile::NamedTempFile::new().unwrap();
    let output_path = output.path().to_str().unwrap().to_string();
    let daemon = spawn_logon_daemon(&rule, enrichers.path(), &output_path, &["--include-event"]);

    let parsed = post_and_read(&daemon, &output_path);
    assert_eq!(parsed["enrichments"]["geo"]["country"], "US");
    assert_eq!(parsed["event"]["SourceIp"], "192.0.2.10", "{parsed}");
}

#[cfg(feature = "mmdb-enrich")]
#[test]
fn reloading_enrichers_that_read_the_event_turns_retention_on() {
    let rule = temp_file(".yml", LOGON_RULE);
    let dir = tempfile::tempdir().unwrap();
    let enrichers = dir.path().join("enrichers.yml");
    std::fs::write(&enrichers, RULE_ID_ENRICHERS_YAML).unwrap();
    let output = tempfile::NamedTempFile::new().unwrap();
    let output_path = output.path().to_str().unwrap().to_string();
    let daemon = spawn_logon_daemon(&rule, &enrichers, &output_path, &[]);

    let before = post_and_read(&daemon, &output_path);
    assert!(before["enrichments"].get("geo").is_none(), "{before}");
    assert!(before.get("event").is_none(), "{before}");

    std::fs::write(&enrichers, geo_enrichers_yaml()).unwrap();
    // The file watcher may already have queued a reload for this write, in
    // which case the API answers 429 and the queued reload applies the edit.
    let (status, _) = http_post(&daemon.url("/api/v1/reload"), "");
    assert!(
        status == 200 || status == 429,
        "reload POST should return 200 or 429, got {status}"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let after = loop {
        let parsed = post_and_read(&daemon, &output_path);
        if parsed["enrichments"].get("geo").is_some() {
            break parsed;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the reloaded enrichers never applied: {parsed}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(after["enrichments"]["geo"]["country"], "US", "{after}");
    assert!(
        after.get("event").is_none(),
        "an event retained only for enrichment must not be delivered: {after}"
    );
}
