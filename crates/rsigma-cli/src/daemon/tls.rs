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

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
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
    /// Original CLI config so the reload path can re-read cert/key
    /// from disk on every `POST /api/v1/reload`, file-watcher event,
    /// or SIGHUP (the three triggers all funnel through the daemon's
    /// central reload task).
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
    /// reload fails, mirroring the rules-reload contract. Invoked
    /// cross-platform from the central reload task on every reload
    /// trigger (SIGHUP, file-watcher, `POST /api/v1/reload`).
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
///
/// Uses the `PemObject` API from `rustls-pki-types` directly. The
/// `rustls-pemfile` crate is unmaintained as of RUSTSEC-2025-0134 and
/// was always a thin wrapper around this same code; consuming it
/// straight from `rustls-pki-types` avoids the advisory without
/// changing behavior.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| pem_error_to_tls(e, path))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem_error_to_tls(e, path))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(path.to_path_buf()));
    }
    Ok(certs)
}

/// Read a PEM-encoded private key (PKCS#8, RSA, or SEC1/EC).
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| match e {
        rustls::pki_types::pem::Error::NoItemsFound => TlsError::NoPrivateKey(path.to_path_buf()),
        other => pem_error_to_tls(other, path),
    })
}

/// Load a PEM bundle of trusted CA certificates for mTLS verification.
fn load_client_ca_roots(path: &Path) -> Result<RootCertStore, TlsError> {
    let certs = load_certs(path)?;
    let mut roots = RootCertStore::empty();
    for (idx, cert) in certs.into_iter().enumerate() {
        roots.add(cert).map_err(|e| {
            TlsError::InvalidClientCa(path.to_path_buf(), format!("cert #{idx}: {e}"))
        })?;
    }
    Ok(roots)
}

/// Translate a `rustls-pki-types` PEM error to our `TlsError` variant,
/// preserving the source path so the operator-facing message names the
/// file that failed.
fn pem_error_to_tls(err: rustls::pki_types::pem::Error, path: &Path) -> TlsError {
    match err {
        rustls::pki_types::pem::Error::Io(io_err) => TlsError::Io(io_err, path.to_path_buf()),
        other => TlsError::InvalidCertificate(path.to_path_buf(), other.to_string()),
    }
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

/// Handshakes in progress at once. Past this the listener stops accepting
/// TCP connections until a handshake finishes or times out.
pub const MAX_PENDING_HANDSHAKES: usize = 256;

/// Counters the TLS listener reports into.
#[derive(Clone)]
pub struct TlsListenerMetrics {
    /// Open TLS connections.
    pub active_connections: Arc<prometheus::IntGauge>,
    /// Failed handshakes, by `reason` (`timeout` or `error`).
    pub handshake_failures: prometheus::IntCounterVec,
}

impl TlsListenerMetrics {
    /// Metrics that are not registered anywhere, for listeners outside the
    /// daemon.
    #[cfg(feature = "mcp")]
    pub fn unregistered(prefix: &str) -> Self {
        Self {
            active_connections: Arc::new(
                prometheus::IntGauge::new(
                    format!("{prefix}_tls_active_connections"),
                    "Active TLS connections",
                )
                .expect("valid gauge"),
            ),
            handshake_failures: prometheus::IntCounterVec::new(
                prometheus::Opts::new(
                    format!("{prefix}_tls_handshake_failures_total"),
                    "Failed TLS handshakes",
                ),
                &["reason"],
            )
            .expect("valid counter"),
        }
    }
}

/// An `axum::serve::Listener` that terminates TLS.
///
/// A background task accepts TCP connections and runs each handshake in its
/// own task, bounded by [`MAX_PENDING_HANDSHAKES`] and a per-handshake
/// timeout, so a client that connects and never sends a `ClientHello` holds
/// one slot for at most the timeout instead of blocking every other client.
/// `accept` hands out connections whose handshake completed.
///
/// The active `ServerConfig` is loaded from the shared `ArcSwap` for every
/// new connection, so a certificate reload takes effect on the next handshake
/// without dropping in-flight TLS connections.
pub struct RustlsListener {
    local_addr: SocketAddr,
    ready: mpsc::Receiver<(TrackedTlsStream, SocketAddr)>,
    acceptor: tokio::task::JoinHandle<()>,
}

impl RustlsListener {
    pub fn new(
        tcp: TcpListener,
        config: Arc<ArcSwap<ServerConfig>>,
        metrics: TlsListenerMetrics,
        handshake_timeout: Duration,
    ) -> io::Result<Self> {
        let local_addr = tcp.local_addr()?;
        let (tx, ready) = mpsc::channel(MAX_PENDING_HANDSHAKES);
        let acceptor = tokio::spawn(accept_loop(tcp, config, metrics, handshake_timeout, tx));
        Ok(Self {
            local_addr,
            ready,
            acceptor,
        })
    }
}

impl Drop for RustlsListener {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

async fn accept_loop(
    tcp: TcpListener,
    config: Arc<ArcSwap<ServerConfig>>,
    metrics: TlsListenerMetrics,
    handshake_timeout: Duration,
    ready: mpsc::Sender<(TrackedTlsStream, SocketAddr)>,
) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let failures = Arc::new(Mutex::new(FailureLog::default()));
    loop {
        let Ok(permit) = pending.clone().acquire_owned().await else {
            return;
        };
        let (stream, peer) = tokio::select! {
            accepted = tcp.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept failed, retrying after backoff");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = ready.closed() => return,
        };
        let acceptor = TlsAcceptor::from(config.load_full());
        let metrics = metrics.clone();
        let ready = ready.clone();
        let failures = failures.clone();
        tokio::spawn(async move {
            let reason = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream))
                .await
            {
                Ok(Ok(tls)) => {
                    metrics.active_connections.inc();
                    let stream = TrackedTlsStream {
                        inner: tls,
                        counter: metrics.active_connections.clone(),
                    };
                    let _ = ready.send((stream, peer)).await;
                    drop(permit);
                    return;
                }
                Ok(Err(e)) => {
                    let suppressed = failures.lock().unwrap_or_else(|e| e.into_inner()).record();
                    if let Some(suppressed) = suppressed {
                        tracing::warn!(peer = %peer, error = %e, suppressed, "TLS handshake failed");
                    }
                    "error"
                }
                Err(_) => {
                    let suppressed = failures.lock().unwrap_or_else(|e| e.into_inner()).record();
                    if let Some(suppressed) = suppressed {
                        tracing::warn!(
                            peer = %peer,
                            timeout = ?handshake_timeout,
                            suppressed,
                            "TLS handshake timed out"
                        );
                    }
                    "timeout"
                }
            };
            metrics
                .handshake_failures
                .with_label_values(&[reason])
                .inc();
            drop(permit);
        });
    }
}

/// Folds handshake failure warnings into at most one per interval, so a
/// flood of bad clients cannot flood the log.
#[derive(Default)]
struct FailureLog {
    last_warn: Option<std::time::Instant>,
    suppressed: u64,
}

impl FailureLog {
    const INTERVAL: Duration = Duration::from_secs(10);

    /// Returns the failures suppressed since the last warning when this one
    /// should be logged, or `None` to suppress it.
    fn record(&mut self) -> Option<u64> {
        let now = std::time::Instant::now();
        if self
            .last_warn
            .is_some_and(|last| now.duration_since(last) < Self::INTERVAL)
        {
            self.suppressed += 1;
            return None;
        }
        self.last_warn = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

impl axum::serve::Listener for RustlsListener {
    type Io = TrackedTlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // The accept task only ends when this listener is dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
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

    #[test]
    fn parse_min_version() {
        assert_eq!("1.2".parse::<TlsMinVersion>().unwrap(), TlsMinVersion::V1_2);
        assert_eq!("1.3".parse::<TlsMinVersion>().unwrap(), TlsMinVersion::V1_3);
        assert!("1.1".parse::<TlsMinVersion>().is_err());
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
