//! E2E tests for the daemon API listener guards: `Host` and `Origin`
//! validation, the connection cap, and the read timeout.

#![cfg(feature = "daemon")]

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{
    DaemonProcess, SIMPLE_RULE, bounded_silence, http_get, poll_until, rsigma,
    spawn_expect_failure, temp_file,
};
use predicates::prelude::*;

const EVENT: &str = r#"{"CommandLine":"malware.exe"}"#;

/// Send one raw HTTP/1.1 request with the given headers and return the
/// status code and body.
fn request(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut raw = format!("{method} {path} HTTP/1.1\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    stream.write_all(raw.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn metric(daemon: &DaemonProcess, name: &str) -> f64 {
    let (_, body) = http_get(&daemon.url("/metrics"));
    body.lines()
        .find_map(|line| {
            line.strip_prefix(name)?
                .strip_prefix(' ')?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0.0)
}

/// Spawn a daemon on `127.0.0.1:0` with a file sink. The rule sits in its
/// own directory so the reload watcher does not see other tests' files.
fn spawn_with_sink(extra: &[&str]) -> (DaemonProcess, tempfile::TempDir, tempfile::NamedTempFile) {
    let rules = tempfile::tempdir().unwrap();
    let rule = rules.path().join("rule.yml");
    std::fs::write(&rule, SIMPLE_RULE).unwrap();
    let output = tempfile::NamedTempFile::new().unwrap();
    let sink = format!("file://{}", output.path().display());
    let mut args = vec![
        "engine",
        "daemon",
        "-r",
        rule.to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &sink,
    ];
    args.extend_from_slice(extra);
    (DaemonProcess::spawn(&args), rules, output)
}

#[test]
fn foreign_host_is_refused_without_changing_state() {
    let (daemon, _rule, output) = spawn_with_sink(&[]);
    // The file watcher may run one reload right after startup.
    std::thread::sleep(Duration::from_millis(1500));
    let reloads = metric(&daemon, "rsigma_reloads_total");
    let addr = daemon.api_addr().to_string();
    let evil = [
        ("Host", "evil.example"),
        ("Content-Type", "application/json"),
    ];

    let silence = bounded_silence("from a rebinding page");
    let mut targets = vec![
        ("/api/v1/events", EVENT.to_string()),
        ("/api/v1/silences", silence),
        ("/api/v1/reload", String::new()),
        ("/api/v1/rules", String::new()),
    ];
    if cfg!(feature = "daemon-otlp") {
        targets.push(("/v1/logs", "{}".to_string()));
    }
    for (path, body) in &targets {
        let method = if *path == "/api/v1/rules" {
            "GET"
        } else {
            "POST"
        };
        let (status, response) = request(&addr, method, path, &evil, body);
        assert_eq!(status, 403, "{method} {path} answered {status}: {response}");
        assert!(
            response.contains("Host header is not allowed"),
            "{response}"
        );
    }

    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(metric(&daemon, "rsigma_events_processed_total"), 0.0);
    assert_eq!(metric(&daemon, "rsigma_reloads_total"), reloads);
    let (_, silences) = http_get(&daemon.url("/api/v1/silences"));
    assert!(!silences.contains("rebinding"), "{silences}");
    assert_eq!(std::fs::read_to_string(output.path()).unwrap(), "");
}

#[test]
fn cross_site_origin_is_refused_on_a_simple_post() {
    let (daemon, _rule, output) = spawn_with_sink(&[]);
    let headers = [
        ("Host", daemon.api_addr()),
        ("Origin", "https://evil.example"),
        ("Content-Type", "text/plain"),
    ];
    let (status, body) = request(daemon.api_addr(), "POST", "/api/v1/events", &headers, EVENT);
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("Origin header is not allowed"), "{body}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(std::fs::read_to_string(output.path()).unwrap(), "");

    let local_origin = format!("http://{}", daemon.api_addr());
    let headers = [
        ("Host", daemon.api_addr()),
        ("Origin", local_origin.as_str()),
    ];
    let (status, body) = request(daemon.api_addr(), "POST", "/api/v1/events", &headers, EVENT);
    assert_eq!(status, 200, "{body}");
}

#[test]
fn loopback_hosts_without_origin_are_accepted() {
    let (daemon, _rule, output) = spawn_with_sink(&[]);
    let port = daemon.api_addr().rsplit(':').next().unwrap().to_string();
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let host = format!("{host}:{port}");
        let (status, body) = request(
            daemon.api_addr(),
            "POST",
            "/api/v1/events",
            &[("Host", &host)],
            EVENT,
        );
        assert_eq!(status, 200, "Host {host}: {body}");
    }
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(output.path()).ok()?;
        (text.lines().count() >= 3).then_some(text)
    });
    assert!(
        lines.is_some(),
        "the accepted events never reached the sink"
    );
}

#[test]
fn probes_answer_any_host() {
    let (daemon, _rule, _output) = spawn_with_sink(&[]);
    for path in ["/healthz", "/readyz"] {
        let (status, body) = request(
            daemon.api_addr(),
            "GET",
            path,
            &[("Host", "10.1.2.3:9090")],
            "",
        );
        assert_eq!(status, 200, "{path}: {body}");
    }
}

#[test]
fn allowed_host_flag_extends_the_accepted_hosts() {
    let (daemon, _rule, _output) = spawn_with_sink(&["--api-allowed-host", "rsigma.internal"]);
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/api/v1/status",
        &[("Host", "rsigma.internal:9090")],
        "",
    );
    assert_eq!(status, 200);
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/api/v1/status",
        &[("Host", "other.internal")],
        "",
    );
    assert_eq!(status, 403);
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/api/v1/status",
        &[
            ("Host", "rsigma.internal"),
            ("Origin", "https://rsigma.internal"),
        ],
        "",
    );
    assert_eq!(status, 200);
}

#[test]
fn allowed_hosts_config_key_is_read() {
    let config = temp_file(
        ".yaml",
        "daemon:\n  api:\n    allowed_hosts: [\"rsigma.internal\"]\n",
    );
    let (daemon, _rule, _output) = spawn_with_sink(&["--config", config.path().to_str().unwrap()]);
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/api/v1/status",
        &[("Host", "rsigma.internal")],
        "",
    );
    assert_eq!(status, 200);
}

#[test]
fn wildcard_host_needs_authentication() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--api-allowed-host",
            "*",
        ],
        Duration::from_secs(5),
    );
    assert!(stderr.contains("needs authentication"), "{stderr}");
}

#[test]
fn wildcard_host_with_a_token_accepts_any_host_but_not_foreign_origins() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &[
            "--api-token-env",
            "GUARD_TEST_TOKEN",
            "--api-allowed-host",
            "*",
        ],
        &[("GUARD_TEST_TOKEN", "guard-secret")],
    );
    let auth = ("Authorization", "Bearer guard-secret");
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/api/v1/status",
        &[("Host", "anything.example"), auth],
        "",
    );
    assert_eq!(status, 200);
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/api/v1/status",
        &[
            ("Host", "anything.example"),
            ("Origin", "https://evil.example"),
            auth,
        ],
        "",
    );
    assert_eq!(status, 403);
}

#[test]
fn bundled_client_commands_reach_a_guarded_daemon() {
    let (daemon, _rule, _output) = spawn_with_sink(&[]);
    rsigma()
        .args(["engine", "status", "--addr", daemon.api_addr()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"running\""));
    let port = daemon.api_addr().rsplit(':').next().unwrap();
    rsigma()
        .args(["engine", "status", "--addr", &format!("localhost:{port}")])
        .assert()
        .success();
}

#[test]
fn silent_connection_is_closed_after_the_read_timeout() {
    let (daemon, _rule, _output) = spawn_with_sink(&["--api-read-timeout", "500ms"]);
    let mut silent = TcpStream::connect(daemon.api_addr()).unwrap();
    silent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 64];
    let closed = matches!(silent.read(&mut buf), Ok(0) | Err(_));
    assert!(
        closed && started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn connection_cap_queues_clients_until_a_slot_frees() {
    let (daemon, _rule, _output) =
        spawn_with_sink(&["--api-max-connections", "1", "--api-read-timeout", "1s"]);
    // The harness's readiness probe may still hold the slot; let it expire.
    std::thread::sleep(Duration::from_millis(1500));
    let _held = TcpStream::connect(daemon.api_addr()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let (status, _) = request(
        daemon.api_addr(),
        "GET",
        "/healthz",
        &[("Host", "localhost")],
        "",
    );
    let waited = started.elapsed();
    assert_eq!(status, 200);
    assert!(
        waited >= Duration::from_millis(500),
        "served while the only slot was held: {waited:?}"
    );
}

#[test]
fn invalid_listener_limits_refuse_to_start() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let base = [
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ];
    let mut zero_timeout = base.to_vec();
    zero_timeout.extend(["--api-read-timeout", "0s"]);
    let stderr = spawn_expect_failure(&zero_timeout, Duration::from_secs(5));
    assert!(stderr.contains("daemon.api.read_timeout"), "{stderr}");

    let mut bad_host = base.to_vec();
    bad_host.extend(["--api-allowed-host", "bad host"]);
    let stderr = spawn_expect_failure(&bad_host, Duration::from_secs(5));
    assert!(stderr.contains("bad host"), "{stderr}");
}
