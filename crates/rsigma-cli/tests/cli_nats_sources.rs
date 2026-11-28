//! `pipeline resolve` and `rule validate --resolve-sources` connect `type: nats`
//! sources with the `--nats-*` flags: a required TLS connection never falls
//! back to cleartext, and the credentials reach the server.

#![cfg(feature = "daemon-nats")]

use crate::common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use common::{SIMPLE_RULE, rsigma, temp_file};

/// A NATS server without TLS that answers `PING` and records what clients
/// send.
struct FakeNats {
    url: String,
    received: Arc<Mutex<Vec<u8>>>,
}

impl FakeNats {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = received.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let log = log.clone();
                std::thread::spawn(move || {
                    let info = format!(
                        "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\"port\":{port},\"max_payload\":1048576,\"proto\":1,\"headers\":true}}\r\n"
                    );
                    if stream.write_all(info.as_bytes()).is_err() {
                        return;
                    }
                    let mut buffer = [0u8; 4096];
                    let mut pending = String::new();
                    while let Ok(read) = stream.read(&mut buffer) {
                        if read == 0 {
                            break;
                        }
                        log.lock().unwrap().extend_from_slice(&buffer[..read]);
                        pending.push_str(&String::from_utf8_lossy(&buffer[..read]));
                        while let Some(end) = pending.find("\r\n") {
                            let line: String = pending.drain(..end + 2).collect();
                            if line.starts_with("PING") && stream.write_all(b"PONG\r\n").is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        Self {
            url: format!("nats://127.0.0.1:{port}"),
            received,
        }
    }

    fn received(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap()).into_owned()
    }

    fn assert_nothing_sent(&self) {
        let received = self.received();
        for needle in ["CONNECT", "SUB ", "s3cr3t"] {
            assert!(
                !received.contains(needle),
                "sent {needle:?} to a server without TLS: {received:?}"
            );
        }
    }

    fn sources_file(&self) -> tempfile::NamedTempFile {
        temp_file(
            ".yml",
            &format!(
                "sources:\n  - id: iocs\n    type: nats\n    url: {}\n    subject: rsigma.iocs\n    format: json\n    required: true\n",
                self.url
            ),
        )
    }
}

const PIPELINE: &str = "name: p\npriority: 10\ntransformations:\n  - id: map\n    type: field_name_mapping\n    mapping:\n      CommandLine: process.command_line\n";

/// `rsigma` without NATS credentials from the developer's environment.
fn command() -> assert_cmd::Command {
    let mut command = rsigma();
    for name in [
        "NATS_CREDS",
        "NATS_TOKEN",
        "NATS_USER",
        "NATS_PASSWORD",
        "NATS_NKEY",
    ] {
        command.env_remove(name);
    }
    command
}

fn resolve(server: &FakeNats, flags: &[&str]) -> std::process::Output {
    let sources = server.sources_file();
    let pipeline = temp_file(".yml", PIPELINE);
    command()
        .args(["pipeline", "resolve", "-p"])
        .arg(pipeline.path())
        .arg("--source-file")
        .arg(sources.path())
        .args(flags)
        .output()
        .unwrap()
}

fn validate(server: &FakeNats, flags: &[&str]) -> std::process::Output {
    let sources = server.sources_file();
    let rule = temp_file(".yml", SIMPLE_RULE);
    command()
        .args(["rule", "validate"])
        .arg(rule.path())
        .arg("--source")
        .arg(sources.path())
        .arg("--resolve-sources")
        .args(flags)
        .output()
        .unwrap()
}

#[test]
fn pipeline_resolve_with_required_tls_refuses_a_plain_server() {
    let server = FakeNats::start();
    let output = resolve(&server, &["--nats-require-tls", "--nats-token", "s3cr3t"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"status\":\"error\""), "{stdout}");
    assert!(stdout.contains("does not offer"), "{stdout}");
    server.assert_nothing_sent();
}

#[test]
fn pipeline_resolve_presents_credentials() {
    let server = FakeNats::start();
    let output = resolve(
        &server,
        &["--nats-user", "rsigma", "--nats-password", "hunter2"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let received = server.received();
    assert!(received.contains(r#""user":"rsigma""#), "{received}");
    assert!(received.contains(r#""pass":"hunter2""#), "{received}");
    assert!(received.contains("SUB rsigma.iocs "), "{received}");
}

#[test]
fn rule_validate_with_required_tls_refuses_a_plain_server() {
    let server = FakeNats::start();
    let output = validate(&server, &["--nats-require-tls", "--nats-token", "s3cr3t"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Source resolution errors"), "{stderr}");
    server.assert_nothing_sent();
}

#[test]
fn rule_validate_presents_credentials() {
    let server = FakeNats::start();
    let output = validate(&server, &["--nats-token", "validate-token"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let received = server.received();
    assert!(
        received.contains(r#""auth_token":"validate-token""#),
        "{received}"
    );
}
