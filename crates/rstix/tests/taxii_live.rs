//! Live TAXII integration tests (TLS, mTLS, DNS SRV, TLS 1.3, DANE, PKCS#12 mTLS).
//!
//! Start the stack with `./crates/rstix/tests/taxii-live/run-live-tests.sh`, then:
//!
//! ```bash
//! cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
//! ```
//!
//! See `tests/taxii-live/README.md`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ProtocolVersion;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rstix::taxii::{
    ClientCertificate, ServerTrustPolicy, SpkiPin, TaxiiClient, TaxiiClientConfig, TlsaCache,
    build_rustls_config,
};

const LIVE_BASE_URL: &str = "https://127.0.0.1:8443";
const LIVE_MTLS_URL: &str = "https://localhost:8444";
const LIVE_TLS13_URL: &str = "https://127.0.0.1:8445";
const LIVE_DANE_URL: &str = "https://dane.taxii.test:8443";
const LIVE_SRV_DOMAIN: &str = "taxii.test";
const LIVE_DNS_NAMESERVER: &str = "127.0.0.1:5353";
const PKCS12_PASSWORD: &str = "rstix-live";

fn live_harness_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/taxii-live")
}

fn live_cert(name: &str) -> PathBuf {
    live_harness_dir().join("fixtures/certs").join(name)
}

fn spki_pin_from_cert_pem(path: &Path) -> SpkiPin {
    let pem = std::fs::read(path).unwrap_or_else(|err| {
        panic!(
            "read server cert {}: {err} (run ./crates/rstix/tests/taxii-live/generate-certs.sh)",
            path.display()
        );
    });
    let cert = CertificateDer::pem_slice_iter(&pem)
        .next()
        .transpose()
        .unwrap_or_else(|err| panic!("parse PEM in {}: {err}", path.display()))
        .unwrap_or_else(|| panic!("no certificate in {}", path.display()));
    let ee = rustls_webpki::EndEntityCert::try_from(&cert).expect("parse end-entity cert");
    let digest: [u8; 32] = Sha256::digest(ee.subject_public_key_info()).into();
    SpkiPin(digest)
}

fn live_dns_nameserver() -> SocketAddr {
    LIVE_DNS_NAMESERVER
        .parse()
        .expect("live harness DNS nameserver address")
}

fn server_name(host: &str) -> ServerName<'static> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_owned()).expect("dns server name")
    }
}

async fn negotiated_tls_version(host: &str, port: u16, server_cert: &Path) -> ProtocolVersion {
    let pin = spki_pin_from_cert_pem(server_cert);
    let config = build_rustls_config(
        &ServerTrustPolicy::PinnedSpkiOnly(vec![pin]),
        &TlsaCache::default(),
        None,
    )
    .expect("rustls config");
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect((host, port))
        .await
        .unwrap_or_else(|err| panic!("connect to {host}:{port}: {err}"));
    let tls = connector
        .connect(server_name(host), stream)
        .await
        .expect("TLS handshake");
    tls.get_ref()
        .1
        .protocol_version()
        .expect("negotiated TLS version")
}

fn live_client(base_url: &str, server_cert: &Path) -> TaxiiClient {
    let pin = spki_pin_from_cert_pem(server_cert);
    TaxiiClient::new(
        TaxiiClientConfig::new(base_url).server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin])),
    )
    .expect("live client")
}

#[tokio::test]
#[ignore = "live TLS: run tests/taxii-live/run-live-tests.sh"]
async fn live_https_discovery_over_tls() {
    let server_cert = live_cert("server.pem");
    let client = live_client(LIVE_BASE_URL, &server_cert);
    let discovery = client.discover().await.expect("discovery over TLS");
    assert_eq!(discovery.title, "Live Wiremock TAXII");
    assert!(discovery.default_api_root().is_some());
}

#[tokio::test]
#[ignore = "live mTLS: run tests/taxii-live/run-live-tests.sh"]
async fn live_mtls_discovery() {
    let server_cert = live_cert("server.pem");
    let cert_pem = std::fs::read(live_cert("client.pem")).unwrap_or_else(|err| {
        panic!("client cert: {err} (run ./crates/rstix/tests/taxii-live/generate-certs.sh)");
    });
    let key_pem = std::fs::read(live_cert("client-key.pem")).unwrap_or_else(|err| {
        panic!(
            "client key: {err} — run ./crates/rstix/tests/taxii-live/generate-certs.sh (fixes permissions)"
        );
    });
    let pin = spki_pin_from_cert_pem(&server_cert);
    let client = TaxiiClient::new(
        TaxiiClientConfig::new(LIVE_MTLS_URL)
            .server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin]))
            .client_certificate(ClientCertificate::from_pem(&cert_pem, &key_pem).expect("mtls")),
    )
    .expect("mtls client");
    client.discover().await.expect("discovery over mTLS");
}

#[tokio::test]
#[ignore = "live PKCS#12 mTLS: run tests/taxii-live/run-live-tests.sh"]
async fn live_pkcs12_mtls_discovery() {
    let server_cert = live_cert("server.pem");
    let p12 = std::fs::read(live_cert("client.p12")).expect("client.p12");
    let pin = spki_pin_from_cert_pem(&server_cert);
    let client = TaxiiClient::new(
        TaxiiClientConfig::new(LIVE_MTLS_URL)
            .server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin]))
            .client_certificate(
                ClientCertificate::from_pkcs12_der(p12, SecretString::new(PKCS12_PASSWORD.into()))
                    .expect("pkcs12 client cert"),
            ),
    )
    .expect("pkcs12 mtls client");
    client
        .discover()
        .await
        .expect("discovery over mTLS with PKCS#12");
}

#[tokio::test]
#[ignore = "live DNS SRV: run tests/taxii-live/run-live-tests.sh"]
async fn live_discover_via_srv() {
    let server_cert = live_cert("server.pem");
    let pin = spki_pin_from_cert_pem(&server_cert);
    let config = TaxiiClientConfig::new("https://placeholder.invalid")
        .server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin]))
        .dns_nameserver(live_dns_nameserver());
    let discovery = TaxiiClient::discover_via_srv(LIVE_SRV_DOMAIN, config)
        .await
        .expect("discovery via SRV");
    assert_eq!(discovery.title, "Live Wiremock TAXII");
    assert!(discovery.default_api_root().is_some());
}

#[tokio::test]
#[ignore = "live TLS 1.3: run tests/taxii-live/run-live-tests.sh"]
async fn live_tls13_negotiated_version() {
    let server_cert = live_cert("server.pem");
    let version = negotiated_tls_version("127.0.0.1", 8445, &server_cert).await;
    assert_eq!(
        version,
        ProtocolVersion::TLSv1_3,
        "Caddy :8445 is configured for TLS 1.3 only"
    );

    let client = live_client(LIVE_TLS13_URL, &server_cert);
    client
        .discover()
        .await
        .expect("discovery over TLS 1.3-only listener");
}

#[tokio::test]
#[ignore = "live DANE: run tests/taxii-live/run-live-tests.sh"]
async fn live_dane_discovery() {
    let client = TaxiiClient::new(
        TaxiiClientConfig::new(LIVE_DANE_URL)
            .server_trust(ServerTrustPolicy::Dane)
            .dns_nameserver(live_dns_nameserver()),
    )
    .expect("dane client");
    let discovery = client.discover().await.expect("discovery over DANE");
    assert_eq!(discovery.title, "Live Wiremock TAXII");
    assert!(discovery.default_api_root().is_some());
}
