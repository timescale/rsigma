//! End-to-end watchlist pushes: a changed indicator set rebuilds rules,
//! a lookup enricher reads the same set, and the state database keeps it.

#![cfg(feature = "daemon")]

mod common;

use std::time::{Duration, Instant};

use common::{
    DaemonProcess, http_get, http_get_bearer, http_post, http_post_bearer, poll_until, temp_file,
};

const RULE: &str = include_str!("fixtures/watchlist/rule.yml");
const PIPELINE: &str = include_str!("fixtures/watchlist/pipeline.yml");
const SOURCES: &str = include_str!("fixtures/watchlist/sources.yml");
const ENRICHERS: &str = include_str!("fixtures/watchlist/enrichers.yml");
const STATIC_RULE: &str = include_str!("fixtures/watchlist/static-rule.yml");

const AUTH_CONFIG: &str = r#"
daemon:
  api:
    auth:
      tokens:
        - name: op
          role: operator
          token_env: TEST_TOKEN_OPERATOR
        - name: reader
          role: reader
          token_env: TEST_TOKEN_READER
"#;

fn http_body(method: &str, url: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let req = match method {
        "POST" => agent.post(url),
        "PUT" => agent.put(url),
        other => panic!("unsupported method {other}"),
    };
    let req = match token {
        Some(token) => req.header("authorization", format!("Bearer {token}")),
        None => req,
    };
    let resp = req.send(body).expect("HTTP request failed");
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string().unwrap();
    (status, body)
}

fn http_delete_body(url: &str, body: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let rest = url.strip_prefix("http://").expect("http url");
    let (addr, path) = rest.split_once('/').expect("url path");
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    let request = format!(
        "DELETE /{path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn detections(daemon: &DaemonProcess) -> u64 {
    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let value: serde_json::Value = serde_json::from_str(&body).expect("status json");
    value["detection_matches"].as_u64().unwrap_or(0)
}

fn metric(body: &str, prefix: &str) -> u64 {
    body.lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn spawn_matching() -> (
    DaemonProcess,
    tempfile::NamedTempFile,
    tempfile::NamedTempFile,
    tempfile::NamedTempFile,
) {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", PIPELINE);
    let sources = temp_file(".yml", SOURCES);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "-p",
        pipeline.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);
    (daemon, rule, pipeline, sources)
}

fn push(daemon: &DaemonProcess, body: &str) -> (u16, String) {
    http_body(
        "POST",
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        None,
        body,
    )
}

fn wait_for_match(daemon: &DaemonProcess, event: &str, target: u64) {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        http_post(&daemon.url("/api/v1/events"), event);
        if detections(daemon) >= target {
            return;
        }
        if Instant::now() >= end {
            panic!("detection_matches did not reach {target}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn push_then_delete_and_replace_change_what_matches() {
    let (daemon, _rule, _pipeline, _sources) = spawn_matching();
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"DestinationIp":"198.51.100.7"}"#,
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(detections(&daemon), 0, "an empty watchlist must not match");

    let (status, body) = push(&daemon, r#"{"indicators":["198.51.100.7"]}"#);
    assert_eq!(status, 200, "{body}");
    wait_for_match(&daemon, r#"{"DestinationIp":"198.51.100.7"}"#, 1);

    let (status, body) = http_body(
        "PUT",
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        None,
        r#"{"indicators":["203.0.113.9"]}"#,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"removed\":1"), "{body}");
    wait_for_match(&daemon, r#"{"DestinationIp":"203.0.113.9"}"#, 2);
    let after_replace = detections(&daemon);
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"DestinationIp":"198.51.100.7"}"#,
    );
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        detections(&daemon),
        after_replace,
        "the replaced indicator must stop matching"
    );

    let (status, body) = http_delete_body(
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        r#"{"indicators":["203.0.113.9"]}"#,
    );
    assert_eq!(status, 200, "{body}");
    let end = Instant::now() + Duration::from_secs(10);
    let mut stable = 0;
    loop {
        let before = detections(&daemon);
        http_post(
            &daemon.url("/api/v1/events"),
            r#"{"DestinationIp":"203.0.113.9"}"#,
        );
        std::thread::sleep(Duration::from_millis(400));
        if detections(&daemon) == before {
            stable += 1;
            if stable >= 3 {
                break;
            }
        } else {
            stable = 0;
        }
        if Instant::now() >= end {
            panic!("deleted indicator kept matching");
        }
    }

    let metrics = http_get(&daemon.url("/metrics")).1;
    assert_eq!(
        metric(
            &metrics,
            "rsigma_watchlist_indicators{source_id=\"c2_ips\"}"
        ),
        0,
        "{metrics}"
    );
    assert!(
        metric(
            &metrics,
            "rsigma_watchlist_changes_total{op=\"add\",source_id=\"c2_ips\"}"
        ) >= 1,
        "{metrics}"
    );
}

#[test]
fn short_ttl_stops_matching() {
    let (daemon, _rule, _pipeline, _sources) = spawn_matching();
    let (status, body) = push(&daemon, r#"{"ttl":"2s","indicators":["198.51.100.7"]}"#);
    assert_eq!(status, 200, "{body}");
    wait_for_match(&daemon, r#"{"DestinationIp":"198.51.100.7"}"#, 1);

    let end = Instant::now() + Duration::from_secs(20);
    let mut saw_match = true;
    let mut stable = 0;
    loop {
        let before = detections(&daemon);
        http_post(
            &daemon.url("/api/v1/events"),
            r#"{"DestinationIp":"198.51.100.7"}"#,
        );
        std::thread::sleep(Duration::from_millis(400));
        if detections(&daemon) > before {
            saw_match = true;
            stable = 0;
        } else if saw_match {
            stable += 1;
            if stable >= 2 {
                return;
            }
        }
        if Instant::now() >= end {
            panic!("indicator still matched after its ttl");
        }
    }
}

#[test]
fn an_expired_indicator_stops_matching_when_another_watchlist_expires_too() {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", PIPELINE);
    let sources = temp_file(
        ".yml",
        r#"
sources:
  - id: c2_ips
    type: watchlist
  - id: zz_other
    type: watchlist
"#,
    );
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "-p",
        pipeline.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);
    let (status, response) = push(&daemon, r#"{"ttl":"4s","indicators":["198.51.100.7"]}"#);
    assert_eq!(status, 200, "{response}");
    let (status, response) = http_body(
        "POST",
        &daemon.url("/api/v1/sources/zz_other/indicators"),
        None,
        r#"{"ttl":"4s","indicators":["203.0.113.9"]}"#,
    );
    assert_eq!(status, 200, "{response}");
    wait_for_match(&daemon, r#"{"DestinationIp":"198.51.100.7"}"#, 1);

    let end = Instant::now() + Duration::from_secs(20);
    let mut stable = 0;
    loop {
        let before = detections(&daemon);
        http_post(
            &daemon.url("/api/v1/events"),
            r#"{"DestinationIp":"198.51.100.7"}"#,
        );
        std::thread::sleep(Duration::from_millis(400));
        if detections(&daemon) > before {
            stable = 0;
        } else {
            stable += 1;
            if stable >= 2 {
                return;
            }
        }
        if Instant::now() >= end {
            panic!("expired indicator kept matching after the other watchlist expired");
        }
    }
}

#[test]
fn lookup_enricher_reads_a_pushed_indicator() {
    let rule = temp_file(".yml", STATIC_RULE);
    let sources = temp_file(".yml", SOURCES);
    let enrichers = temp_file(".yml", ENRICHERS);
    let output = tempfile::NamedTempFile::new().unwrap();
    let output_path = output.path().to_str().unwrap().to_string();
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

    let (status, body) = push(&daemon, r#"{"indicators":["198.51.100.7"]}"#);
    assert_eq!(status, 200, "{body}");
    let event = r#"{"CommandLine":"malware.exe","DestinationIp":"198.51.100.7"}"#;
    let found = poll_until(Duration::from_secs(10), || {
        let _ = http_post(&daemon.url("/api/v1/events"), event);
        let text = std::fs::read_to_string(&output_path).ok()?;
        text.lines().find_map(|line| {
            let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
            (parsed["enrichments"]["c2_indicator"] == serde_json::json!(["198.51.100.7"]))
                .then_some(true)
        })
    });
    assert!(
        found.is_some(),
        "lookup did not see the pushed indicator:\n{}",
        std::fs::read_to_string(&output_path).unwrap_or_default()
    );
}

#[test]
fn reader_is_forbidden_and_errors_are_audited() {
    let dir = tempfile::tempdir().unwrap();
    let feed = dir.path().join("feed.txt");
    std::fs::write(&feed, "one\n").unwrap();
    let sources = temp_file(
        ".yml",
        &format!(
            r#"
sources:
  - id: c2_ips
    type: watchlist
    max_indicators: 1
  - id: feeds
    type: file
    path: {}
    format: lines
    refresh: once
"#,
            feed.display()
        ),
    );
    let rule = temp_file(".yml", STATIC_RULE);
    let config = temp_file(".yaml", AUTH_CONFIG);
    let db = dir.path().join("state.db");
    let daemon = DaemonProcess::spawn_with_env(
        &[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--source",
            sources.path().to_str().unwrap(),
            "--config",
            config.path().to_str().unwrap(),
            "--state-db",
            db.to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ],
        &[
            ("TEST_TOKEN_OPERATOR", "tok-operator"),
            ("TEST_TOKEN_READER", "tok-reader"),
        ],
    );

    let (status, _) = http_post_bearer(
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        "tok-reader",
        r#"{"indicators":["198.51.100.7"]}"#,
    );
    assert_eq!(status, 403);

    let (status, body) = http_body(
        "POST",
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        Some("tok-operator"),
        r#"{"indicators":["198.51.100.7"]}"#,
    );
    assert_eq!(status, 200, "{body}");

    let (status, _) = http_get_bearer(
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        "tok-reader",
    );
    assert_eq!(status, 200);

    let (status, _) = http_body(
        "POST",
        &daemon.url("/api/v1/sources/missing/indicators"),
        Some("tok-operator"),
        r#"{"indicators":["a"]}"#,
    );
    assert_eq!(status, 404);
    let (status, _) = http_body(
        "POST",
        &daemon.url("/api/v1/sources/feeds/indicators"),
        Some("tok-operator"),
        r#"{"indicators":["a"]}"#,
    );
    assert_eq!(status, 409);
    let (status, _) = http_body(
        "POST",
        &daemon.url("/api/v1/sources/c2_ips/indicators"),
        Some("tok-operator"),
        r#"{"indicators":["203.0.113.9","198.51.100.8"]}"#,
    );
    assert_eq!(status, 422);

    std::thread::sleep(Duration::from_millis(300));
    let (status, body) = http_get_bearer(&daemon.url("/api/v1/audit"), "tok-reader");
    assert_eq!(status, 200, "{body}");
    let audit: serde_json::Value = serde_json::from_str(&body).unwrap();
    let endpoints: Vec<&str> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["endpoint"].as_str())
        .collect();
    assert!(
        endpoints.contains(&"/api/v1/sources/{source_id}/indicators"),
        "{body}"
    );
}

#[test]
fn delete_with_state_db_removes_the_stored_indicator() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let rule = temp_file(".yml", STATIC_RULE);
    let sources = temp_file(".yml", SOURCES);
    let args = [
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--state-db",
        db.to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ];
    {
        let daemon = DaemonProcess::spawn(&args);
        let (status, response) = push(&daemon, r#"{"indicators":["198.51.100.7"]}"#);
        assert_eq!(status, 200, "{response}");
        let (status, body) = http_delete_body(
            &daemon.url("/api/v1/sources/c2_ips/indicators"),
            r#"{"indicators":["198.51.100.7"]}"#,
        );
        assert_eq!(status, 200, "{body}");
        let deleted: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(deleted["removed"], 1, "{body}");
        assert_eq!(deleted["total"], 0, "{body}");
        let (status, body) = http_get(&daemon.url("/api/v1/sources/c2_ips/indicators"));
        assert_eq!(status, 200, "{body}");
        let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(listed["total"], 0, "{body}");
    }
    let daemon = DaemonProcess::spawn(&args);
    let (status, body) = http_get(&daemon.url("/api/v1/sources/c2_ips/indicators"));
    assert_eq!(status, 200, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["total"], 0, "{body}");
}

const STATIC_PIPELINE: &str = r#"
name: watchlist-test
priority: 10
vars:
  c2_ips:
    - "203.0.113.9"
transformations:
  - type: value_placeholders
"#;

fn reload_count(daemon: &DaemonProcess) -> usize {
    daemon
        .stderr_lines()
        .iter()
        .filter(|line| line.contains("Rules and pipelines reloaded"))
        .count()
}

fn wait_for_another_reload(daemon: &DaemonProcess, before: usize) {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if reload_count(daemon) > before {
            return;
        }
        if Instant::now() >= end {
            panic!(
                "timed out waiting for a reload; stderr: {:?}",
                daemon.stderr_lines()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn many_indicators(count: usize) -> String {
    let mut body = String::from("{\"indicators\":[");
    for index in 0..count {
        if index > 0 {
            body.push(',');
        }
        body.push('"');
        body.push_str(&index.to_string());
        body.push('"');
    }
    body.push_str("]}");
    body
}

#[test]
fn a_reload_changes_the_cap_when_a_watchlist_becomes_referenced() {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", STATIC_PIPELINE);
    let sources = temp_file(
        ".yml",
        r#"
sources:
  - id: c2_ips
    type: watchlist
    max_indicators: 5000
"#,
    );
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "-p",
        pipeline.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let before = reload_count(&daemon);
    std::fs::write(pipeline.path(), PIPELINE).unwrap();
    wait_for_another_reload(&daemon, before);
    let (status, body) = push(&daemon, &many_indicators(4097));
    assert_eq!(status, 422, "{body}");
    assert!(
        body.contains("4096"),
        "the referenced cap must be the placeholder limit, got {body}"
    );
    let (status, body) = http_get(&daemon.url("/api/v1/sources/c2_ips/indicators"));
    assert_eq!(status, 200, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["total"], 0, "{body}");

    let before = reload_count(&daemon);
    std::fs::write(pipeline.path(), STATIC_PIPELINE).unwrap();
    wait_for_another_reload(&daemon, before);
    let (status, body) = push(&daemon, &many_indicators(4097));
    assert_eq!(status, 200, "{body}");
}

#[test]
fn restart_keeps_unexpired_indicators() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let rule = temp_file(".yml", STATIC_RULE);
    let sources = temp_file(".yml", SOURCES);
    let args = [
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--state-db",
        db.to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ];
    {
        let daemon = DaemonProcess::spawn(&args);
        let (status, response) = push(
            &daemon,
            r#"{"indicators":["198.51.100.7",{"value":"203.0.113.9","ttl":"1s"}]}"#,
        );
        assert_eq!(status, 200, "{response}");
        std::thread::sleep(Duration::from_secs(2));
    }
    let daemon = DaemonProcess::spawn(&args);
    let (status, body) = http_get(&daemon.url("/api/v1/sources/c2_ips/indicators"));
    assert_eq!(status, 200, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["total"], 1, "{body}");
    assert_eq!(listed["indicators"][0]["value"], "198.51.100.7");
}
