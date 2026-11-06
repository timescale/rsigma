//! `rsigma mcp serve --http` exposure checks: a non-loopback bind needs a
//! bearer token, and the accepted `Host` headers follow the bind and
//! `--allowed-host`.

#![cfg(feature = "mcp")]

mod common;

use std::net::TcpStream;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use common::{rsigma, rsigma_bin};
use predicates::prelude::*;

const TOKEN: &str = "exposure-test-token";
const INIT_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;

/// A running `rsigma mcp serve --http 0.0.0.0:<port>`, killed on drop.
struct McpHttp {
    child: Child,
    port: u16,
    stderr: tempfile::NamedTempFile,
    _rules: tempfile::TempDir,
}

impl McpHttp {
    fn spawn(extra: &[&str]) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let rules = tempfile::tempdir().unwrap();
        let stderr = tempfile::NamedTempFile::new().unwrap();
        let child = StdCommand::new(rsigma_bin())
            .args(["mcp", "serve", "--allow-plaintext", "--http"])
            .arg(format!("0.0.0.0:{port}"))
            .arg("--rules-dir")
            .arg(rules.path())
            .args(extra)
            .env_remove("RSIGMA_MCP_AUTH_TOKEN")
            .stdout(Stdio::null())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .expect("spawn rsigma mcp serve");
        let server = McpHttp {
            child,
            port,
            stderr,
            _rules: rules,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "MCP HTTP server did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        server
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.stderr.path()).unwrap()
    }

    /// POST an `initialize` request with the given `Host` header and optional
    /// bearer token, returning the status code.
    fn initialize(&self, host: &str, token: Option<&str>) -> u16 {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let mut request = agent
            .post(format!("http://127.0.0.1:{}/mcp", self.port))
            .header("host", host)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request
            .send(INIT_BODY)
            .expect("POST /mcp failed")
            .status()
            .as_u16()
    }
}

impl Drop for McpHttp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn public_bind_without_token_refuses_to_start() {
    let rules = tempfile::tempdir().unwrap();
    rsigma()
        .args([
            "mcp",
            "serve",
            "--allow-plaintext",
            "--http",
            "0.0.0.0:0",
            "--rules-dir",
        ])
        .arg(rules.path())
        .env_remove("RSIGMA_MCP_AUTH_TOKEN")
        .timeout(Duration::from_secs(10))
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "refusing to serve --http on non-loopback address 0.0.0.0:0 without --auth-token",
        ));
}

#[test]
fn empty_token_env_var_refuses_to_start() {
    let rules = tempfile::tempdir().unwrap();
    rsigma()
        .args(["mcp", "serve", "--http", "127.0.0.1:0", "--rules-dir"])
        .arg(rules.path())
        .env("RSIGMA_MCP_AUTH_TOKEN", "")
        .timeout(Duration::from_secs(10))
        .assert()
        .code(3)
        .stderr(predicate::str::contains("is empty"));
}

#[test]
fn public_plaintext_bind_refuses_to_start() {
    let rules = tempfile::tempdir().unwrap();
    rsigma()
        .args(["mcp", "serve", "--http", "0.0.0.0:0", "--auth-token", TOKEN])
        .arg("--rules-dir")
        .arg(rules.path())
        .timeout(Duration::from_secs(10))
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "refusing to bind plaintext on non-loopback address 0.0.0.0:0",
        ));
}

#[test]
fn token_guarded_public_bind_accepts_the_servers_own_address() {
    let server = McpHttp::spawn(&["--auth-token", TOKEN]);
    let host = format!("203.0.113.7:{}", server.port);
    assert_eq!(server.initialize(&host, Some(TOKEN)), 200);
    assert_eq!(server.initialize(&host, None), 401);
}

#[test]
fn allowed_host_narrows_a_token_guarded_bind() {
    let server = McpHttp::spawn(&["--auth-token", TOKEN, "--allowed-host", "mcp.example.com"]);
    assert_eq!(server.initialize("mcp.example.com", Some(TOKEN)), 200);
    assert_eq!(server.initialize("203.0.113.7", Some(TOKEN)), 403);
}

#[test]
fn unauthenticated_public_bind_keeps_host_validation() {
    let server = McpHttp::spawn(&["--allow-unauthenticated"]);
    let stderr = server.stderr();
    assert!(
        stderr.contains("only these Host headers are accepted"),
        "{stderr}"
    );
    assert_eq!(server.initialize("203.0.113.7", None), 403);
    let local = format!("localhost:{}", server.port);
    assert_eq!(server.initialize(&local, None), 200);
}
