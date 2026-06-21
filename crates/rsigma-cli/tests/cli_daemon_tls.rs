//! E2E tests for the `daemon-tls` feature.
//!
//! Each test mints a self-signed CA and leaf certificate on the fly with
//! `rcgen`, spawns `rsigma engine daemon` with TLS termination enabled,
//! and asserts that the HTTPS handshake (and, where applicable, the mTLS
//! client-cert verification) behaves as expected.

#![cfg(feature = "daemon-tls")]

mod common;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use common::{DaemonProcess, SIMPLE_RULE, spawn_expect_failure, temp_file};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Materialized cert/key files produced by `mint_ca_and_leaf`. Holding the
/// `NamedTempFile`s and the CA key keeps the on-disk PEM material and the
/// signing material alive for the lifetime of the test, so the test can
/// later mint client certs from the same CA without re-parsing PEM.
struct TlsFixture {
    _ca_file: NamedTempFile,
    _cert_file: NamedTempFile,
    _key_file: NamedTempFile,
    ca_path: String,
    cert_path: String,
    key_path: String,
    root_store: Arc<RootCertStore>,
    /// Held so `mint_client_cert` can re-use the CA without re-parsing the
    /// PEM (rcgen 0.14's `Issuer::from_ca_cert_pem` is gated behind an
    /// optional feature we do not pull in for tests).
    ca_issuer: Issuer<'static, KeyPair>,
}

/// Mint a self-signed CA, then sign a leaf certificate for `127.0.0.1`
/// suitable for both `serverAuth` and `clientAuth`. Returns paths plus a
/// `RootCertStore` clients can use to verify the server.
fn mint_ca_and_leaf() -> TlsFixture {
    mint_ca_and_leaf_with_validity(time::Duration::days(30))
}

fn mint_ca_and_leaf_with_validity(validity: time::Duration) -> TlsFixture {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rsigma-test-ca");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let leaf = mint_leaf_pem(&ca_issuer, validity);

    let ca_file = temp_file(".pem", &ca_pem);
    let cert_file = temp_file(".pem", &leaf.cert);
    let key_file = temp_file(".pem", &leaf.key);

    let mut store = RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        store.add(cert.unwrap()).unwrap();
    }

    TlsFixture {
        ca_path: ca_file.path().to_str().unwrap().to_string(),
        cert_path: cert_file.path().to_str().unwrap().to_string(),
        key_path: key_file.path().to_str().unwrap().to_string(),
        root_store: Arc::new(store),
        ca_issuer,
        _ca_file: ca_file,
        _cert_file: cert_file,
        _key_file: key_file,
    }
}

struct LeafPem {
    cert: String,
    key: String,
}

/// Sign a fresh leaf certificate suitable for the test daemon
/// (`localhost` + `127.0.0.1`, `serverAuth` + `clientAuth`) with an
/// explicit validity window.
fn mint_leaf_pem(issuer: &Issuer<'_, KeyPair>, validity: time::Duration) -> LeafPem {
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ])));
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "rsigma-test-server");
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = time::OffsetDateTime::now_utc();
    leaf_params.not_before = now;
    leaf_params.not_after = now + validity;
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, issuer).unwrap();
    LeafPem {
        cert: leaf_cert.pem(),
        key: leaf_key.serialize_pem(),
    }
}

/// Mint a client certificate signed by the supplied CA issuer for mTLS
/// positive-path tests.
fn mint_client_cert(issuer: &Issuer<'_, KeyPair>) -> (NamedTempFile, NamedTempFile) {
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "rsigma-test-client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, issuer).unwrap();

    let cert_file = temp_file(".pem", &client_cert.pem());
    let key_file = temp_file(".pem", &client_key.serialize_pem());
    (cert_file, key_file)
}

/// Build a rustls client config that trusts only the server's CA.
fn client_config(roots: Arc<RootCertStore>) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Build a rustls client config with client auth.
fn client_config_with_auth(
    roots: Arc<RootCertStore>,
    cert_pem_path: &str,
    key_pem_path: &str,
) -> ClientConfig {
    let cert_chain: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(cert_pem_path)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key_pem_path).unwrap();
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .unwrap()
}

/// Synchronous HTTPS GET. Returns (status, body). Panics on transport
/// failure; HTTPS error codes are returned, not panicked.
fn https_get(
    addr: &str,
    path: &str,
    config: ClientConfig,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    https_request("GET", addr, path, None, config)
}

/// Synchronous HTTPS POST with an optional body. Returns (status, body).
fn https_post(
    addr: &str,
    path: &str,
    body: &str,
    config: ClientConfig,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    https_request("POST", addr, path, Some(body), config)
}

fn https_request(
    method: &str,
    addr: &str,
    path: &str,
    body: Option<&str>,
    config: ClientConfig,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let method = method.to_string();
    let addr = addr.to_string();
    let path = path.to_string();
    let body = body.map(|s| s.to_string());
    rt.block_on(async move {
        let host = addr.split(':').next().unwrap_or("127.0.0.1");
        let socket: std::net::SocketAddr = addr.parse()?;
        let tcp = TcpStream::connect(socket).await?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let mut tls = connector.connect(server_name, tcp).await?;
        let req = match body.as_ref() {
            Some(b) => format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{b}",
                b.len()
            ),
            None => format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            ),
        };
        tls.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf).into_owned();
        let status_line = response.split("\r\n").next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        Ok((status, body))
    })
}

/// Read the `rsigma_tls_certificate_expiry_seconds` gauge value (a
/// signed float, in seconds) from a Prometheus text-format scrape body.
fn parse_expiry_metric(body: &str) -> Option<f64> {
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("rsigma_tls_certificate_expiry_seconds ") {
            return rest.trim().parse::<f64>().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Plaintext refusal policy
// ---------------------------------------------------------------------------

#[test]
fn public_bind_without_tls_refuses_to_start() {
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
            "0.0.0.0:0",
        ],
        Duration::from_secs(5),
    );
    assert!(
        stderr.contains("refusing to bind plaintext"),
        "expected plaintext refusal in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("--allow-plaintext"),
        "stderr should mention the opt-out flag, got: {stderr}"
    );
}

#[test]
fn loopback_keeps_plaintext_without_flag() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());
    let (status, body) = common::http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
}

#[test]
fn public_bind_with_allow_plaintext_starts() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "0.0.0.0:0",
        "--allow-plaintext",
    ]);
    let (status, _) = common::http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
}

// ---------------------------------------------------------------------------
// HTTPS happy path
// ---------------------------------------------------------------------------

#[test]
fn https_healthz_succeeds_with_trusted_ca() {
    let fixture = mint_ca_and_leaf();
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
    ]);

    let (status, body) = https_get(
        daemon.api_addr(),
        "/healthz",
        client_config(fixture.root_store),
    )
    .expect("https handshake to /healthz failed");
    assert_eq!(status, 200, "body was: {body}");
    assert!(body.contains("\"ok\""), "body was: {body}");
}

#[test]
fn https_post_events_triggers_detection() {
    let fixture = mint_ca_and_leaf();
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
    ]);

    // Manually POST via raw HTTPS (the test crate's ureq helper is plaintext).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let posted = rt.block_on(async {
        let socket: std::net::SocketAddr = daemon.api_addr().parse().unwrap();
        let tcp = TcpStream::connect(socket).await.unwrap();
        let connector = TlsConnector::from(Arc::new(client_config(fixture.root_store.clone())));
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        let body = r#"{"CommandLine":"malware.exe"}"#;
        let req = format!(
            "POST /api/v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    });
    assert!(
        posted.starts_with("HTTP/1.1 200"),
        "expected 200 OK for /api/v1/events, got: {posted}"
    );
    assert!(posted.contains("\"accepted\":1"));
}

// ---------------------------------------------------------------------------
// mTLS verification
// ---------------------------------------------------------------------------

#[test]
fn mtls_rejects_client_without_certificate() {
    let fixture = mint_ca_and_leaf();
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
        "--tls-client-ca",
        &fixture.ca_path,
    ]);

    let err = https_get(
        daemon.api_addr(),
        "/healthz",
        client_config(fixture.root_store.clone()),
    )
    .expect_err("handshake without client cert should be rejected");
    let msg = err.to_string();
    let lower = msg.to_lowercase();
    // The server aborts the handshake because no client cert was presented.
    // Most platforms surface a TLS-level error (certificate / handshake / tls
    // / eof), but the abrupt teardown can also appear as a raw socket error:
    // Windows reports WSAECONNRESET ("forcibly closed by the remote host"),
    // and Linux can report "connection reset" or "broken pipe". All are valid
    // rejections of the certless client.
    assert!(
        lower.contains("certificate")
            || lower.contains("handshake")
            || lower.contains("tls")
            || lower.contains("eof")
            || lower.contains("closed")
            || lower.contains("reset")
            || lower.contains("broken pipe"),
        "expected TLS-level or connection-teardown rejection, got: {msg}"
    );
}

#[test]
fn mtls_accepts_client_with_valid_certificate() {
    let fixture = mint_ca_and_leaf();
    let (client_cert_file, client_key_file) = mint_client_cert(&fixture.ca_issuer);

    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
        "--tls-client-ca",
        &fixture.ca_path,
    ]);

    let config = client_config_with_auth(
        fixture.root_store,
        client_cert_file.path().to_str().unwrap(),
        client_key_file.path().to_str().unwrap(),
    );
    let (status, body) =
        https_get(daemon.api_addr(), "/healthz", config).expect("mTLS handshake should succeed");
    assert_eq!(status, 200, "body was: {body}");
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[test]
fn tls_certificate_expiry_metric_exposed() {
    let fixture = mint_ca_and_leaf();
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
    ]);
    let (status, body) = https_get(
        daemon.api_addr(),
        "/metrics",
        client_config(fixture.root_store),
    )
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        body.contains("rsigma_tls_certificate_expiry_seconds"),
        "metrics should expose the expiry gauge; body: {body}"
    );
    assert!(
        body.contains("rsigma_tls_active_connections"),
        "metrics should expose the active-connection gauge; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Misconfiguration
// ---------------------------------------------------------------------------

#[test]
fn missing_cert_file_refuses_to_start() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    // Write a valid key so the failure is specifically the missing cert.
    let key = KeyPair::generate().unwrap();
    let key_file = temp_file(".pem", &key.serialize_pem());

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
            "--tls-cert",
            "/nonexistent/cert.pem",
            "--tls-key",
            key_file.path().to_str().unwrap(),
        ],
        Duration::from_secs(5),
    );
    assert!(
        stderr.contains("Failed to initialize TLS") || stderr.contains("/nonexistent/cert.pem"),
        "expected TLS init failure in stderr, got: {stderr}"
    );
}

#[test]
fn encrypted_key_password_is_rejected_with_guidance() {
    let fixture = mint_ca_and_leaf();
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
            "--tls-cert",
            &fixture.cert_path,
            "--tls-key",
            &fixture.key_path,
            "--tls-key-password",
            "hunter2",
        ],
        Duration::from_secs(5),
    );
    assert!(
        stderr.contains("openssl"),
        "stderr should point at openssl for decryption, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Cross-platform cert hot-reload
// ---------------------------------------------------------------------------

#[test]
fn http_reload_endpoint_rotates_tls_certificate() {
    // Mint a CA + an initial leaf with a ~30 day validity, spawn the
    // daemon, then overwrite the cert/key files on disk with a freshly
    // signed leaf that has a deliberately longer validity. POSTing to
    // `/api/v1/reload` (which works on every platform, including
    // Windows, unlike SIGHUP) should atomically pick up the new
    // material and bump `rsigma_tls_certificate_expiry_seconds`
    // accordingly.
    let fixture = mint_ca_and_leaf_with_validity(time::Duration::days(30));
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
    ]);

    // Initial expiry should be around 30 days (2_592_000 seconds).
    let (status, body) = https_get(
        daemon.api_addr(),
        "/metrics",
        client_config(fixture.root_store.clone()),
    )
    .expect("initial /metrics scrape failed");
    assert_eq!(status, 200);
    let initial_expiry =
        parse_expiry_metric(&body).expect("expiry gauge missing from initial scrape");
    assert!(
        initial_expiry > 25.0 * 86_400.0 && initial_expiry < 31.0 * 86_400.0,
        "initial expiry should be ~30 days, got {initial_expiry} seconds"
    );

    // Sign a fresh leaf with the same CA but a 365-day validity and
    // overwrite the cert/key files in place.
    let new_leaf = mint_leaf_pem(&fixture.ca_issuer, time::Duration::days(365));
    std::fs::write(&fixture.cert_path, &new_leaf.cert).unwrap();
    std::fs::write(&fixture.key_path, &new_leaf.key).unwrap();

    // Trigger the cross-platform reload path. The handler queues the
    // reload; the actual cert swap happens after the 500 ms debounce
    // in the central reload task.
    let (status, body) = https_post(
        daemon.api_addr(),
        "/api/v1/reload",
        "",
        client_config(fixture.root_store.clone()),
    )
    .expect("reload POST failed");
    assert!(
        status == 200 || status == 429,
        "reload POST should return 200 or 429, got {status} ({body})"
    );

    // Wait for the debounced reload, then scrape /metrics again and
    // confirm the gauge moved to roughly 365 days. We use a generous
    // poll window because the reload task sleeps 500 ms before
    // draining; macOS file watchers also fire while we wait.
    let new_expiry = common::poll_until(std::time::Duration::from_secs(10), || {
        let (s, b) = https_get(
            daemon.api_addr(),
            "/metrics",
            client_config(fixture.root_store.clone()),
        )
        .ok()?;
        if s != 200 {
            return None;
        }
        let v = parse_expiry_metric(&b)?;
        // 365 days is ~31_536_000 seconds; anything past 60 days proves
        // the rotation took effect.
        (v > 60.0 * 86_400.0).then_some(v)
    })
    .expect("expiry gauge never reflected rotated certificate within 10s");
    assert!(
        new_expiry > 360.0 * 86_400.0 && new_expiry < 366.0 * 86_400.0,
        "post-reload expiry should be ~365 days, got {new_expiry} seconds"
    );
}

#[test]
fn http_reload_with_invalid_cert_keeps_previous_one() {
    // After a reload with a broken cert file, the previous chain stays
    // live and the daemon keeps serving HTTPS without an interruption.
    let fixture = mint_ca_and_leaf_with_validity(time::Duration::days(30));
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--tls-cert",
        &fixture.cert_path,
        "--tls-key",
        &fixture.key_path,
    ]);

    // Corrupt the cert file in place.
    std::fs::write(&fixture.cert_path, b"not a pem certificate\n").unwrap();

    // Best-effort reload trigger; status may be 200 (queued) or 429
    // (already pending from the on-startup file-watcher event).
    let _ = https_post(
        daemon.api_addr(),
        "/api/v1/reload",
        "",
        client_config(fixture.root_store.clone()),
    );

    // Wait past the 500 ms debounce so the reload task definitely
    // attempted (and rejected) the broken material.
    std::thread::sleep(std::time::Duration::from_millis(1_500));

    // The original certificate is still trusted, so a fresh HTTPS GET
    // against `/healthz` must still succeed.
    let (status, body) = https_get(
        daemon.api_addr(),
        "/healthz",
        client_config(fixture.root_store.clone()),
    )
    .expect("HTTPS should still succeed after a failed reload");
    assert_eq!(status, 200, "body: {body}");
}

// Avoid unused-write warning on rcgen's keypair pem helpers across cfg
// permutations.
#[allow(dead_code)]
fn _touch_write() {
    let _ = std::io::sink().write_all(b"");
}
