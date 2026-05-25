//! Shared helpers and fixture constants for CLI integration tests.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::NamedTempFile;

#[allow(deprecated)]
pub fn rsigma() -> Command {
    Command::cargo_bin("rsigma").expect("binary not found")
}

/// Path to the freshly-built `rsigma` binary for tests that need to spawn
/// it directly via `std::process::Command` (long-running daemon processes).
pub fn rsigma_bin() -> String {
    assert_cmd::cargo::cargo_bin("rsigma")
        .to_str()
        .unwrap()
        .to_string()
}

/// Write `contents` to a temporary file with the given suffix and return it.
pub fn temp_file(suffix: &str, contents: &str) -> NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ---------------------------------------------------------------------------
// Daemon HTTP process helper
// ---------------------------------------------------------------------------

/// Events the spawn handshake waits for from the daemon's stderr.
enum StartupEvent {
    ApiAddr(String),
    SinkStarted,
}

/// Scope guard that owns a `Child` and kills + waits on drop. Used during
/// daemon startup so that a handshake panic does not leak a daemon process.
struct ChildGuard(Option<std::process::Child>);

impl ChildGuard {
    fn as_child_mut(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("guard already disarmed")
    }

    fn disarm(mut self) -> std::process::Child {
        self.0.take().expect("guard already disarmed")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A live `rsigma engine daemon` subprocess with a known API address. Killed and
/// reaped on drop.
pub struct DaemonProcess {
    child: std::process::Child,
    api_addr: String,
}

impl DaemonProcess {
    /// Spawn `rsigma` with `args` and block until the daemon's HTTP API
    /// is actually accepting connections.
    ///
    /// The startup handshake:
    /// 1. Drain stdout in a background thread so a busy sink can never fill
    ///    the OS pipe buffer and block the daemon on its own write.
    /// 2. Read stderr in a background thread, forwarding the
    ///    `API server listening` and `Sink started` log lines over a
    ///    channel.
    /// 3. Wait for both events, with a 10s deadline.
    /// 4. Probe the listening TCP socket with `connect_timeout` in a 5s,
    ///    25ms-tick retry loop. `Sink started` is emitted just before
    ///    `axum::serve` enters its accept loop, so the log line alone is
    ///    not a sufficient readiness signal.
    ///
    /// Any panic during the handshake is caught by `ChildGuard`, which
    /// kills + waits on the daemon process so we never leak one.
    pub fn spawn(args: &[&str]) -> Self {
        let child = StdCommand::new(rsigma_bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn rsigma engine daemon");
        let mut guard = ChildGuard(Some(child));

        if let Some(stdout) = guard.as_child_mut().stdout.take() {
            std::thread::spawn(move || {
                let mut sink = std::io::sink();
                let _ = std::io::copy(&mut BufReader::new(stdout), &mut sink);
            });
        }

        let stderr = guard.as_child_mut().stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<StartupEvent>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                if line.contains("API server listening")
                    && let Some(addr) = extract_addr(&line)
                {
                    let _ = tx.send(StartupEvent::ApiAddr(addr));
                }
                if line.contains("Sink started") {
                    let _ = tx.send(StartupEvent::SinkStarted);
                }
            }
        });

        let mut api_addr = String::new();
        let mut sink_started = false;
        let handshake_deadline = Instant::now() + Duration::from_secs(10);
        while !sink_started || api_addr.is_empty() {
            let remaining = handshake_deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            match rx.recv_timeout(remaining) {
                Ok(StartupEvent::ApiAddr(addr)) => api_addr = addr,
                Ok(StartupEvent::SinkStarted) => sink_started = true,
                Err(_) => panic!(
                    "daemon did not finish startup within 10s (api_addr={api_addr:?}, sink_started={sink_started})"
                ),
            }
        }

        // The daemon may log a wildcard bind address like `0.0.0.0:PORT`
        // (or `[::]:PORT`). Connecting to a wildcard address returns
        // `WSAEADDRNOTAVAIL` on Windows. Linux and macOS silently treat
        // it as loopback, so the same test was green there. Rewrite the
        // recorded address to the loopback equivalent before probing
        // and before exposing it via `url()`; the daemon listens on
        // every interface so loopback is always reachable.
        let api_addr = rewrite_wildcard_to_loopback(api_addr);

        let socket: std::net::SocketAddr = api_addr
            .parse()
            .unwrap_or_else(|e| panic!("invalid api_addr {api_addr:?}: {e}"));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_ok() {
                return Self {
                    child: guard.disarm(),
                    api_addr,
                };
            }
            if Instant::now() >= deadline {
                panic!("daemon API at {api_addr} never became reachable within 5s");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Spawn `rsigma engine daemon -r RULE --input http --api-addr 127.0.0.1:0`.
    pub fn spawn_http(rule_path: &str) -> Self {
        Self::spawn(&[
            "engine",
            "daemon",
            "-r",
            rule_path,
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ])
    }

    /// Spawn the daemon in HTTP-input mode with extra CLI flags appended
    /// after the standard scaffolding (`-r`, `--input http`,
    /// `--api-addr 127.0.0.1:0`). Useful for opt-in flags like
    /// `--observe-fields` that integration tests need to exercise.
    pub fn spawn_http_with_args(rule_path: &str, extra_args: &[&str]) -> Self {
        let mut args = vec![
            "engine",
            "daemon",
            "-r",
            rule_path,
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ];
        args.extend_from_slice(extra_args);
        Self::spawn(&args)
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.api_addr)
    }

    /// Convenience constructor that returns an `https://...` URL.
    pub fn https_url(&self, path: &str) -> String {
        format!("https://{}{path}", self.api_addr)
    }

    pub fn api_addr(&self) -> &str {
        &self.api_addr
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the daemon and return either a `DaemonProcess` on success or the
/// stderr line that caused the failure on a hard startup error.
///
/// Use this when a test wants to assert that a misconfigured invocation
/// (e.g. plaintext bind on `0.0.0.0` without `--allow-plaintext`) refuses
/// to start with a specific error message.
pub fn spawn_expect_failure(args: &[&str], deadline: Duration) -> String {
    let mut child = StdCommand::new(rsigma_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rsigma engine daemon");

    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            let _ = tx.send(line);
        }
    });

    let end = Instant::now() + deadline;
    let mut collected = Vec::new();
    while Instant::now() < end {
        let remaining = end
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(line) => {
                collected.push(line);
            }
            Err(_) => continue,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    collected.join("\n")
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Extract the `addr` field from a structured JSON log line of the form
/// `{"fields":{"message":"API server listening","addr":"127.0.0.1:PORT"},...}`.
fn extract_addr(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["fields"]["addr"].as_str().map(|s| s.to_string()))
}

/// Rewrite a wildcard bind address (`0.0.0.0:PORT` or `[::]:PORT`) to the
/// loopback equivalent. Connecting to a wildcard works on Linux/macOS
/// (silently routed to loopback) but fails with `WSAEADDRNOTAVAIL` on
/// Windows, which made `public_bind_with_allow_plaintext_starts` flake
/// only on Windows CI before this rewrite.
fn rewrite_wildcard_to_loopback(addr: String) -> String {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(parsed) if parsed.ip().is_unspecified() => {
            let port = parsed.port();
            match parsed {
                std::net::SocketAddr::V4(_) => format!("127.0.0.1:{port}"),
                std::net::SocketAddr::V6(_) => format!("[::1]:{port}"),
            }
        }
        _ => addr,
    }
}

// ---------------------------------------------------------------------------
// HTTP and polling helpers
// ---------------------------------------------------------------------------

/// GET `url`. Returns (status, body) for any HTTP response code
/// (including 4xx/5xx with their JSON error bodies). Panics on transport
/// errors only.
pub fn http_get(url: &str) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let resp = agent.get(url).call().expect("HTTP GET failed");
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string().unwrap();
    (status, body)
}

/// POST `body` to `url`. Returns (status, body) for both ok and
/// `StatusCode` responses; panics on transport errors.
pub fn http_post(url: &str, body: &str) -> (u16, String) {
    match ureq::post(url).send(body) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.into_body().read_to_string().unwrap();
            (status, body)
        }
        Err(ureq::Error::StatusCode(code)) => (code, String::new()),
        Err(e) => panic!("HTTP POST failed: {e}"),
    }
}

/// DELETE `url`. Returns (status, body) for any HTTP response code
/// (including 4xx/5xx with their JSON error bodies). Panics on transport
/// errors only.
pub fn http_delete(url: &str) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let resp = agent.delete(url).call().expect("HTTP DELETE failed");
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string().unwrap();
    (status, body)
}

/// Poll `check` every 50ms until it returns `Some(value)` or `deadline`
/// elapses. Use this in place of fixed sleeps when you want to wait for a
/// specific observable condition.
pub fn poll_until<T>(deadline: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + deadline;
    loop {
        if let Some(v) = check() {
            return Some(v);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub const SIMPLE_RULE: &str = r#"
title: Test Rule
id: 00000000-0000-0000-0000-000000000001
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
"#;

pub const PIPELINE_YAML: &str = r#"
name: test-pipeline
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#;
