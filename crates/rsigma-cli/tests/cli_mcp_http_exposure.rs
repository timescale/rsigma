//! `rsigma mcp serve --http` exposure checks: a non-loopback bind needs a
//! bearer token, and the accepted `Host` headers follow the bind and
//! `--allowed-host`.

#![cfg(feature = "mcp")]

use crate::common;

use std::io::{BufRead, BufReader, Write};
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
    /// Start a server on `0.0.0.0:0` and read the port it bound from its
    /// listening line. Picking a free port first and passing it in leaves a
    /// window in which a test in another binary can take the same port.
    fn spawn(extra: &[&str]) -> Self {
        let rules = tempfile::tempdir().unwrap();
        let stderr = tempfile::NamedTempFile::new().unwrap();
        let mut child = StdCommand::new(rsigma_bin())
            .args(["mcp", "serve", "--allow-plaintext", "--http", "0.0.0.0:0"])
            .arg("--rules-dir")
            .arg(rules.path())
            .args(extra)
            .env_remove("RSIGMA_MCP_AUTH_TOKEN")
            .stdout(Stdio::null())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .expect("spawn rsigma mcp serve");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = std::fs::read_to_string(stderr.path()).unwrap();
            if let Some(port) = listening_port(&log) {
                return McpHttp {
                    child,
                    port,
                    stderr,
                    _rules: rules,
                };
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("MCP HTTP server exited with {status}: {log}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("MCP HTTP server did not start: {log}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.stderr.path()).unwrap()
    }

    /// POST an `initialize` request with the given `Host` header and optional
    /// bearer token, returning the status code.
    ///
    /// The request goes out in a single write. The server answers 401 and 403
    /// without reading the body, and when it closes the connection with body
    /// bytes still unread, Windows resets it and the client loses the response.
    fn initialize(&self, host: &str, token: Option<&str>) -> u16 {
        let mut request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Accept: application/json, text/event-stream\r\nContent-Length: {}\r\n\
             Connection: close\r\n",
            INIT_BODY.len()
        );
        if let Some(token) = token {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(INIT_BODY);

        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect to /mcp");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(request.as_bytes())
            .expect("POST /mcp failed");
        let mut status_line = String::new();
        BufReader::new(stream)
            .read_line(&mut status_line)
            .expect("read the status line");
        status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("malformed status line {status_line:?}"))
    }
}

/// The port in `listening on http://0.0.0.0:<port>/mcp`.
fn listening_port(log: &str) -> Option<u16> {
    let rest = log.split("listening on http://0.0.0.0:").nth(1)?;
    rest.split('/').next()?.parse().ok()
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
