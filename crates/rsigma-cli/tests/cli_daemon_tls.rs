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
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_issuer).unwrap();

    let ca_file = temp_file(".pem", &ca_pem);
    let cert_file = temp_file(".pem", &leaf_cert.pem());
    let key_file = temp_file(".pem", &leaf_key.serialize_pem());

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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let host = addr.split(':').next().unwrap_or("127.0.0.1");
        let socket: std::net::SocketAddr = addr.parse()?;
        let tcp = TcpStream::connect(socket).await?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let mut tls = connector.connect(server_name, tcp).await?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf).into_owned();
        let mut lines = response.splitn(2, "\r\n");
        let status_line = lines.next().unwrap_or("");
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
    assert!(
        msg.to_lowercase().contains("certificate")
            || msg.to_lowercase().contains("handshake")
            || msg.to_lowercase().contains("tls")
            || msg.to_lowercase().contains("eof"),
        "expected TLS-level rejection, got: {msg}"
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

// Avoid unused-write warning on rcgen's keypair pem helpers across cfg
// permutations.
#[allow(dead_code)]
fn _touch_write() {
    let _ = std::io::sink().write_all(b"");
}
