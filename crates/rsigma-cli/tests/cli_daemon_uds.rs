//! E2E tests for the daemon's `--api-addr unix://` listener.
//!
//! The shared `DaemonProcess` harness is TCP-only (it probes with
//! `TcpStream::connect`), so these tests spawn the daemon directly and speak
//! raw HTTP/1.1 over a `UnixStream`.

#![cfg(all(feature = "daemon", unix))]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{SIMPLE_RULE, rsigma_bin, temp_file};

/// Kills + reaps the daemon on drop so a failed assertion never leaks it.
struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Send `GET <route>` over the Unix socket and return `(status, body)`.
fn uds_get(path: &std::path::Path, route: &str) -> std::io::Result<(u16, String)> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

#[test]
fn api_listener_serves_healthz_over_unix_socket() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("api.sock");

    let child = Command::new(rsigma_bin())
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            &format!("unix://{}", sock.display()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn daemon");
    let _daemon = Daemon(child);

    // Poll until the listener answers (the socket file appears at bind, but the
    // serve task starts a moment later).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok((200, body)) = uds_get(&sock, "/healthz") {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["status"], "ok");
            return;
        }
        if Instant::now() >= deadline {
            panic!("daemon /healthz never answered over the unix socket within 10s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(feature = "daemon-tls")]
#[test]
fn tls_cert_with_unix_api_addr_is_rejected() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("api.sock");

    // The rejection fires before any TLS material is loaded, so the cert/key
    // paths need not exist.
    let mut child = Command::new(rsigma_bin())
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            &format!("unix://{}", sock.display()),
            "--tls-cert",
            "/nonexistent/cert.pem",
            "--tls-key",
            "/nonexistent/key.pem",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn daemon");

    let stderr = child.stderr.take().unwrap();
    let mut message = String::new();
    for line in BufReader::new(stderr).lines() {
        let Ok(line) = line else { break };
        if line.contains("unix://") {
            message = line;
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        message.contains("cannot be combined with a unix://"),
        "expected a TLS-over-UDS rejection, got: {message:?}"
    );
}
