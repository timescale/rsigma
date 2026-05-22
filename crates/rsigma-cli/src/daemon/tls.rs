//! Server-side TLS termination for the daemon API listener.
//!
//! This module loads PEM-encoded certificates and keys from disk, builds a
//! `rustls::ServerConfig` with the `aws-lc-rs` provider (matching the rest
//! of the rsigma TLS surface), and exposes a small `TlsState` handle that
//! the daemon hot-reload path can swap in-place without dropping inflight
//! connections.
//!
//! Inspecting certificate expiry uses `x509-parser` so we can emit a single
//! WARN at startup when the leaf certificate expires within 30 days and
//! keep the `rsigma_tls_certificate_expiry_seconds` Prometheus gauge in
//! sync with the active certificate.
//!
//! Gated behind the `daemon-tls` Cargo feature.

#![cfg(feature = "daemon-tls")]

use std::fs;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::FromDer;

/// Operator-supplied configuration assembled from CLI flags.
///
/// `cert_path` / `key_path` are required; the rest are optional.
/// Validation (loopback bypass, `--allow-plaintext`, file existence)
/// happens at `TlsState::from_paths` and `enforce_plaintext_policy`.
#[derive(Debug, Clone)]
pub struct TlsCliConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub key_password: Option<String>,
    pub client_ca_path: Option<PathBuf>,
    pub min_version: TlsMinVersion,
}

/// Minimum TLS protocol version accepted by the server.
///
/// Default is TLS 1.3. Operators can drop to TLS 1.2 for legacy agents
/// (Fluent Bit on old distros, ancient OpenSSL builds) by passing
/// `--tls-min-version 1.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMinVersion {
    V1_2,
    #[default]
    V1_3,
}

impl std::str::FromStr for TlsMinVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.2" | "tls1.2" | "TLS1.2" => Ok(Self::V1_2),
            "1.3" | "tls1.3" | "TLS1.3" => Ok(Self::V1_3),
            other => Err(format!(
                "invalid --tls-min-version '{other}', expected '1.2' or '1.3'"
            )),
        }
    }
}

/// Live TLS state shared between the accept loop and the SIGHUP reload path.
///
/// The `ArcSwap` holds the active `rustls::ServerConfig` so the reload path
/// can publish a new chain atomically without coordinating with in-flight
/// handshakes or connections. The CLI args are kept around so SIGHUP knows
/// where to read replacement certs from.
#[derive(Clone)]
pub struct TlsState {
    /// Atomically swappable `ServerConfig` used by every new handshake.
    pub config: Arc<ArcSwap<ServerConfig>>,
    /// Original CLI config so SIGHUP can re-read cert/key from disk.
    pub cli: TlsCliConfig,
    /// Unix timestamp (seconds) at which the active cert expires. Updated
    /// on every successful reload so the Prometheus gauge stays accurate.
    pub expiry_unix: Arc<std::sync::atomic::AtomicI64>,
}

impl TlsState {
    /// Build a fresh `TlsState` from operator-supplied paths.
    pub fn from_paths(cli: TlsCliConfig) -> Result<Self, TlsError> {
        let config = build_server_config(&cli)?;
        let expiry = read_cert_expiry(&cli.cert_path)?;
        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            cli,
            expiry_unix: Arc::new(std::sync::atomic::AtomicI64::new(expiry)),
        })
    }

    /// Re-read cert/key from disk and atomically swap the active config.
    ///
    /// Returns the new expiry timestamp so callers can update the
    /// Prometheus gauge. The previous config remains active if the
    /// reload fails, mirroring the rules-reload contract.
    pub fn reload(&self) -> Result<i64, TlsError> {
        let new_config = build_server_config(&self.cli)?;
        let new_expiry = read_cert_expiry(&self.cli.cert_path)?;
        self.config.store(Arc::new(new_config));
        self.expiry_unix
            .store(new_expiry, std::sync::atomic::Ordering::Relaxed);
        Ok(new_expiry)
    }
}

/// Errors that can be produced while loading or parsing TLS material.
#[derive(Debug)]
pub enum TlsError {
    Io(io::Error, PathBuf),
    NoCertificates(PathBuf),
    NoPrivateKey(PathBuf),
    EncryptedKeyUnsupported(PathBuf),
    Rustls(rustls::Error),
    InvalidClientCa(PathBuf, String),
    InvalidCertificate(PathBuf, String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e, p) => write!(f, "I/O error reading {}: {e}", p.display()),
            Self::NoCertificates(p) => write!(f, "no certificates found in {}", p.display()),
            Self::NoPrivateKey(p) => write!(f, "no private key found in {}", p.display()),
            Self::EncryptedKeyUnsupported(p) => write!(
                f,
                "encrypted private key in {} is not supported yet; decrypt with `openssl rsa -in key.pem -out key-decrypted.pem` first",
                p.display()
            ),
            Self::Rustls(e) => write!(f, "rustls error: {e}"),
            Self::InvalidClientCa(p, e) => {
                write!(f, "invalid client CA bundle {}: {e}", p.display())
            }
            Self::InvalidCertificate(p, e) => {
                write!(f, "invalid certificate {}: {e}", p.display())
            }
        }
    }
}

impl std::error::Error for TlsError {}

/// Build a `rustls::ServerConfig` from the CLI config.
fn build_server_config(cli: &TlsCliConfig) -> Result<ServerConfig, TlsError> {
    if cli.key_password.is_some() {
        return Err(TlsError::EncryptedKeyUnsupported(cli.key_path.clone()));
    }

    let certs = load_certs(&cli.cert_path)?;
    let key = load_private_key(&cli.key_path)?;

    // Pin the aws-lc-rs provider for consistency with NATS client TLS
    // and to inherit upstream FIPS-mode work.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let protocol_versions: &[&rustls::SupportedProtocolVersion] = match cli.min_version {
        TlsMinVersion::V1_2 => rustls::ALL_VERSIONS,
        TlsMinVersion::V1_3 => &[&rustls::version::TLS13],
    };

    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(protocol_versions)
        .map_err(TlsError::Rustls)?;

    let builder = if let Some(ca_path) = cli.client_ca_path.as_ref() {
        let roots = load_client_ca_roots(ca_path)?;
        // Pass the aws-lc-rs provider explicitly so the builder does not
        // try (and fail, when both `ring` and `aws-lc-rs` are in the
        // dependency tree) to discover the process-level
        // `CryptoProvider`.
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .map_err(|e| TlsError::InvalidClientCa(ca_path.clone(), e.to_string()))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };

    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(TlsError::Rustls)?;

    // Advertise both HTTP/2 (for OTLP/gRPC and modern HTTP/2 clients) and
    // HTTP/1.1 (for legacy REST clients and OTLP/HTTP/1.1 agents).
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

/// Read a PEM bundle of one or more certificates.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = fs::File::open(path).map_err(|e| TlsError::Io(e, path.to_path_buf()))?;
    let mut reader = BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| TlsError::Io(e, path.to_path_buf()))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(path.to_path_buf()));
    }
    Ok(certs)
}

/// Read a PEM-encoded private key (PKCS#8, RSA, or SEC1/EC).
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = fs::File::open(path).map_err(|e| TlsError::Io(e, path.to_path_buf()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsError::Io(e, path.to_path_buf()))?
        .ok_or_else(|| TlsError::NoPrivateKey(path.to_path_buf()))?;
    Ok(key)
}

/// Load a PEM bundle of trusted CA certificates for mTLS verification.
fn load_client_ca_roots(path: &Path) -> Result<RootCertStore, TlsError> {
    let file = fs::File::open(path).map_err(|e| TlsError::Io(e, path.to_path_buf()))?;
    let mut reader = BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| TlsError::Io(e, path.to_path_buf()))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(path.to_path_buf()));
    }
    let mut roots = RootCertStore::empty();
    for (idx, cert) in certs.into_iter().enumerate() {
        roots.add(cert).map_err(|e| {
            TlsError::InvalidClientCa(path.to_path_buf(), format!("cert #{idx}: {e}"))
        })?;
    }
    Ok(roots)
}

/// Read the leaf certificate from `path` and return its `not_after` as a
/// Unix timestamp.
pub fn read_cert_expiry(path: &Path) -> Result<i64, TlsError> {
    let certs = load_certs(path)?;
    let leaf = certs
        .first()
        .ok_or_else(|| TlsError::NoCertificates(path.to_path_buf()))?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| TlsError::InvalidCertificate(path.to_path_buf(), e.to_string()))?;
    Ok(parsed.validity().not_after.timestamp())
}

/// Decide whether the operator may bind plaintext on `addr` without TLS.
///
/// Loopback addresses (`127.0.0.0/8`, `::1`) are always allowed for local
/// development. Public binds require an explicit `--allow-plaintext`
/// opt-in so a careless `--api-addr 0.0.0.0:9090` never silently ships
/// detection events over cleartext.
pub fn enforce_plaintext_policy(addr: SocketAddr, allow_plaintext: bool) -> Result<(), String> {
    if is_loopback(addr) || allow_plaintext {
        return Ok(());
    }
    Err(format!(
        "refusing to bind plaintext on non-loopback address {addr}; \
         pass --tls-cert/--tls-key to enable TLS or --allow-plaintext to opt out \
         (e.g. when terminating TLS at a sidecar reverse proxy)"
    ))
}

fn is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// An `axum::serve::Listener` adapter that performs a TLS handshake on
/// every accepted TCP connection.
///
/// Handshake failures are logged and ignored; the listener keeps polling
/// the underlying `TcpListener` so a single bad client cannot stall the
/// server. The active `ServerConfig` is loaded from the shared
/// `ArcSwap` on every new connection so SIGHUP-triggered cert rotation
/// takes effect on the next handshake without dropping inflight TLS
/// connections.
pub struct RustlsListener {
    tcp: TcpListener,
    config: Arc<ArcSwap<ServerConfig>>,
    active_connections: Arc<prometheus::IntGauge>,
}

impl RustlsListener {
    pub fn new(
        tcp: TcpListener,
        config: Arc<ArcSwap<ServerConfig>>,
        active_connections: Arc<prometheus::IntGauge>,
    ) -> Self {
        Self {
            tcp,
            config,
            active_connections,
        }
    }
}

impl axum::serve::Listener for RustlsListener {
    type Io = TrackedTlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, peer) = match self.tcp.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept failed, retrying after backoff");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let cfg = self.config.load_full();
            let acceptor = TlsAcceptor::from(cfg);
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    self.active_connections.inc();
                    return (
                        TrackedTlsStream {
                            inner: tls,
                            counter: self.active_connections.clone(),
                        },
                        peer,
                    );
                }
                Err(e) => {
                    tracing::warn!(peer = %peer, error = %e, "TLS handshake failed");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// `TlsStream<TcpStream>` wrapper that decrements the active-connection
/// gauge on drop. The gauge sits on the hot path so we use a cheap
/// `IntGauge` rather than a histogram.
pub struct TrackedTlsStream {
    inner: TlsStream<tokio::net::TcpStream>,
    counter: Arc<prometheus::IntGauge>,
}

impl Drop for TrackedTlsStream {
    fn drop(&mut self) {
        self.counter.dec();
    }
}

impl tokio::io::AsyncRead for TrackedTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TrackedTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_min_version() {
        assert_eq!("1.2".parse::<TlsMinVersion>().unwrap(), TlsMinVersion::V1_2);
        assert_eq!("1.3".parse::<TlsMinVersion>().unwrap(), TlsMinVersion::V1_3);
        assert!("1.1".parse::<TlsMinVersion>().is_err());
    }

    #[test]
    fn loopback_bypasses_plaintext_check() {
        let addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert!(enforce_plaintext_policy(addr_v4, false).is_ok());

        let addr_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        assert!(enforce_plaintext_policy(addr_v6, false).is_ok());
    }

    #[test]
    fn public_bind_requires_explicit_opt_in() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9090);
        let err = enforce_plaintext_policy(addr, false).unwrap_err();
        assert!(err.contains("refusing to bind plaintext"));
        assert!(err.contains("--allow-plaintext"));

        assert!(enforce_plaintext_policy(addr, true).is_ok());
    }

    #[test]
    fn missing_cert_file_is_clear_error() {
        let cli = TlsCliConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
            key_password: None,
            client_ca_path: None,
            min_version: TlsMinVersion::V1_3,
        };
        let err = TlsState::from_paths(cli).err().expect("expected an error");
        assert!(matches!(err, TlsError::Io(_, _)));
    }

    #[test]
    fn encrypted_key_is_rejected_with_guidance() {
        let cli = TlsCliConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
            key_password: Some("hunter2".to_string()),
            client_ca_path: None,
            min_version: TlsMinVersion::V1_3,
        };
        let err = TlsState::from_paths(cli).err().expect("expected an error");
        assert!(matches!(err, TlsError::EncryptedKeyUnsupported(_)));
        assert!(err.to_string().contains("openssl"));
    }
}
