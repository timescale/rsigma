//! TLS / trust-policy tests (not exercisable over wiremock HTTP).

use rstix::taxii::{ServerTrustPolicy, SpkiPin, TlsaCache, build_rustls_config};

#[test]
fn build_rustls_config_succeeds_for_all_policies() {
    build_rustls_config(&ServerTrustPolicy::SystemRoots, &TlsaCache::default(), None)
        .expect("system roots");
    let pin = SpkiPin::from_hex(&"ab".repeat(32)).expect("pin");
    build_rustls_config(
        &ServerTrustPolicy::PinnedSpki(vec![pin.clone()]),
        &TlsaCache::default(),
        None,
    )
    .expect("pinned spki");
    build_rustls_config(
        &ServerTrustPolicy::PinnedSpkiOnly(vec![pin]),
        &TlsaCache::default(),
        None,
    )
    .expect("pin only");
    build_rustls_config(&ServerTrustPolicy::Dane, &TlsaCache::default(), None).expect("dane");
}

#[test]
fn spki_pin_parses_valid_hex() {
    SpkiPin::from_hex(&"ab".repeat(32)).expect("pin");
}

#[test]
fn build_rustls_config_with_pem_client_auth() {
    let cert_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/taxii-live/fixtures/certs");
    let cert_pem = std::fs::read(cert_dir.join("client.pem")).ok();
    let key_pem = std::fs::read(cert_dir.join("client-key.pem")).ok();
    if cert_pem.is_none() || key_pem.is_none() {
        eprintln!("skip build_rustls_config_with_pem_client_auth: live harness certs missing");
        return;
    }
    let client_cert =
        rstix::taxii::ClientCertificate::from_pem(&cert_pem.unwrap(), &key_pem.unwrap())
            .expect("client cert");
    build_rustls_config(
        &ServerTrustPolicy::PinnedSpkiOnly(vec![SpkiPin::from_hex(&"ab".repeat(32)).expect("pin")]),
        &TlsaCache::default(),
        Some(&client_cert),
    )
    .expect("rustls config with client auth");
}

#[test]
fn client_certificate_from_pem_rejects_garbage() {
    let err = rstix::taxii::ClientCertificate::from_pem(b"not-a-cert", b"not-a-key")
        .expect_err("invalid pem");
    assert!(matches!(
        err,
        rstix::taxii::TaxiiError::InvalidClientCertificate { .. }
    ));
}
