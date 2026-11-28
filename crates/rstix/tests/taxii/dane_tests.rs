//! DANE and SRV discovery against a local DNS responder and TLS server.
//!
//! The DNS responder serves unsigned answers, so a validating client sees no
//! Secure record. The TLS server counts connections and records the request
//! head it receives, so a test can prove no credential left the client.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_resolver::proto::op::{Message, MessageType};
use hickory_resolver::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_resolver::proto::rr::rdata::{SRV, TLSA};
use hickory_resolver::proto::rr::{Name, RData, Record};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rstix::taxii::{BearerAuth, ServerTrustPolicy, TaxiiClient, TaxiiClientConfig, TaxiiError};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Answer every query with the records whose owner name and type match.
async fn spawn_dns(records: Vec<Record>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind dns");
    let addr = socket.local_addr().expect("dns addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::response(query.metadata.id, query.metadata.op_code);
            response.metadata.message_type = MessageType::Response;
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            response.metadata.recursion_available = true;
            for q in &query.queries {
                response.add_query(q.clone());
                for record in &records {
                    if record.name.eq_case(q.name()) && record.record_type() == q.query_type() {
                        response.add_answer(record.clone());
                    }
                }
            }
            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    addr
}

fn record(name: &str, data: RData) -> Record {
    Record::from_rdata(Name::from_ascii(name).expect("name"), 300, data)
}

fn tlsa_record(host: &str, port: u16, usage: u8, cert: &CertificateDer<'_>) -> Record {
    record(
        &format!("_{port}._tcp.{host}."),
        RData::TLSA(TLSA::new(
            CertUsage::from(usage),
            Selector::from(0),
            Matching::from(1),
            Sha256::digest(cert.as_ref()).to_vec(),
        )),
    )
}

struct Ca {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

fn mint_ca() -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params
        .distinguished_name
        .push(DnType::CommonName, "rstix-dane-test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().expect("ca key");
    let der = params.self_signed(&key).expect("ca cert").der().clone();
    Ca {
        der,
        issuer: Issuer::new(params, key),
    }
}

fn mint_leaf(names: &[&str], ca: &Ca) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .expect("leaf params");
    let key = KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, &ca.issuer).expect("leaf cert");
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

struct TlsServer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Serve discovery over TLS with `chain`, recording each request head.
async fn spawn_tls(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> TlsServer {
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tls");
    let port = listener.local_addr().expect("tls addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (accepted_task, requests_task) = (accepted.clone(), requests.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let requests = requests_task.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                requests
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).to_ascii_lowercase());
                let body = br#"{"title":"DANE test server","api_roots":[]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/taxii+json;version=2.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.write_all(body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    TlsServer {
        port,
        accepted,
        requests,
    }
}

fn dane_config(base: String, nameserver: SocketAddr, require_dnssec: bool) -> TaxiiClientConfig {
    TaxiiClientConfig::new(base)
        .server_trust(ServerTrustPolicy::Dane)
        .dns_nameserver(nameserver)
        .dane_require_dnssec(require_dnssec)
        .auth(BearerAuth::new("srv-secret-token"))
        .timeout(Duration::from_secs(10))
}

#[tokio::test]
async fn unsigned_tlsa_fails_closed_before_connecting() {
    let ca = mint_ca();
    let (leaf, key) = mint_leaf(&["127.0.0.1"], &ca);
    let server = spawn_tls(vec![leaf.clone()], key).await;
    let dns = spawn_dns(vec![tlsa_record("127.0.0.1", server.port, 3, &leaf)]).await;

    let client = TaxiiClient::new(dane_config(
        format!("https://127.0.0.1:{}/", server.port),
        dns,
        true,
    ))
    .expect("client");
    let err = client.discover().await.expect_err("unsigned TLSA");
    assert!(
        matches!(err, TaxiiError::InvalidServerTrust { .. }),
        "expected a trust error, got {err}"
    );
    assert_eq!(server.accepted.load(Ordering::SeqCst), 0, "no TCP connect");
}

#[tokio::test]
async fn unsigned_tlsa_is_used_when_dnssec_is_not_required() {
    let ca = mint_ca();
    let (leaf, key) = mint_leaf(&["127.0.0.1"], &ca);
    let server = spawn_tls(vec![leaf.clone()], key).await;
    let dns = spawn_dns(vec![tlsa_record("127.0.0.1", server.port, 3, &leaf)]).await;

    let client = TaxiiClient::new(dane_config(
        format!("https://127.0.0.1:{}/", server.port),
        dns,
        false,
    ))
    .expect("client");
    let discovery = client.discover().await.expect("DANE-EE match");
    assert_eq!(discovery.title, "DANE test server");
}

fn srv_record(port: u16) -> Record {
    record(
        "_taxii2._tcp.example.test.",
        RData::SRV(SRV::new(
            0,
            1,
            port,
            Name::from_ascii("localhost.").expect("target"),
        )),
    )
}

#[tokio::test]
async fn unsigned_srv_target_must_present_the_source_domain() {
    let ca = mint_ca();
    let (leaf, key) = mint_leaf(&["localhost"], &ca);
    let server = spawn_tls(vec![leaf, ca.der.clone()], key).await;
    let dns = spawn_dns(vec![
        srv_record(server.port),
        tlsa_record("example.test", server.port, 2, &ca.der),
    ])
    .await;

    let err = TaxiiClient::discover_via_srv(
        "example.test",
        dane_config("https://placeholder.invalid/".into(), dns, false),
    )
    .await
    .expect_err("certificate names only the SRV target");
    assert!(
        matches!(err, TaxiiError::NetworkError(_)),
        "expected a TLS failure, got {err}"
    );
    assert!(server.accepted.load(Ordering::SeqCst) >= 1);
    let requests = server.requests.lock().unwrap();
    assert!(
        requests.is_empty(),
        "no request may reach the server: {requests:?}"
    );
}

#[tokio::test]
async fn unsigned_srv_target_with_a_source_domain_certificate_gets_credentials() {
    let ca = mint_ca();
    let (leaf, key) = mint_leaf(&["example.test"], &ca);
    let server = spawn_tls(vec![leaf, ca.der.clone()], key).await;
    let dns = spawn_dns(vec![
        srv_record(server.port),
        tlsa_record("example.test", server.port, 2, &ca.der),
    ])
    .await;

    let discovery = TaxiiClient::discover_via_srv(
        "example.test",
        dane_config("https://placeholder.invalid/".into(), dns, false),
    )
    .await
    .expect("certificate names the source domain");
    assert_eq!(discovery.title, "DANE test server");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("get /taxii2/ "), "{}", requests[0]);
    assert!(
        requests[0].contains("authorization: bearer srv-secret-token"),
        "{}",
        requests[0]
    );
}

#[tokio::test]
async fn explicit_server_identity_overrides_the_source_domain() {
    let ca = mint_ca();
    let (leaf, key) = mint_leaf(&["pinned.example.test"], &ca);
    let server = spawn_tls(vec![leaf, ca.der.clone()], key).await;
    let dns = spawn_dns(vec![
        srv_record(server.port),
        tlsa_record("pinned.example.test", server.port, 2, &ca.der),
    ])
    .await;

    TaxiiClient::discover_via_srv(
        "example.test",
        dane_config("https://placeholder.invalid/".into(), dns, false)
            .server_identity("pinned.example.test"),
    )
    .await
    .expect("caller-configured identity");
}
