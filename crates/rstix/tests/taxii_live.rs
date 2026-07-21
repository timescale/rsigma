//! Live TAXII integration tests (TLS, mTLS, DNS SRV).
//!
//! Requires the Docker stack in `tests/taxii-live/`. Start it with
//! `./crates/rstix/tests/taxii-live/run-live-tests.sh`, then run:
//!
//! ```bash
//! cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;

use rstix::taxii::{
    ClientCertificate, ServerTrustPolicy, SpkiPin, TaxiiClient, TaxiiClientConfig,
};
use sha2::{Digest, Sha256};

const LIVE_BASE_URL: &str = "https://127.0.0.1:8443";
const LIVE_MTLS_URL: &str = "https://localhost:8444";
const LIVE_SRV_DOMAIN: &str = "taxii.test";
const LIVE_DNS_NAMESERVER: &str = "127.0.0.1:5353";

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
    let cert = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
        .next()
        .transpose()
        .unwrap_or_else(|err| panic!("parse PEM in {}: {err}", path.display()))
        .unwrap_or_else(|| panic!("no certificate in {}", path.display()));
    let ee = rustls_webpki::EndEntityCert::try_from(&cert).expect("parse end-entity cert");
    let digest: [u8; 32] = Sha256::digest(ee.subject_public_key_info()).into();
    SpkiPin(digest)
}

fn live_client(base_url: &str, server_cert: &Path) -> TaxiiClient {
    let pin = spki_pin_from_cert_pem(server_cert);
    TaxiiClient::new(
        TaxiiClientConfig::new(base_url).server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin])),
    )
    .expect("live client")
}

fn live_dns_nameserver() -> SocketAddr {
    LIVE_DNS_NAMESERVER
        .parse()
        .expect("live harness DNS nameserver address")
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
    let cert_pem = std::fs::read(live_cert("client.pem")).expect("client cert");
    let key_pem = std::fs::read(live_cert("client-key.pem")).expect("client key");
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
