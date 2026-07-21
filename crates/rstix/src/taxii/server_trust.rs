//! Server TLS trust policies: PKIX, SPKI pinning, and DANE (TAXII 2.1 spec section 8.5.2).
//!
//! Default verification follows PKIX (RFC 5280 / RFC 6125). Optional policies:
//!
//! - **SPKI pinning** — [`ServerTrustPolicy::PinnedSpki`] adds a pin check before PKIX;
//!   [`ServerTrustPolicy::PinnedSpkiOnly`] accepts a matching pin **without** hostname (SAN)
//!   or notAfter validation (intentional for self-signed or test pins; see spec section 8.5.2
//!   certificate pinning).
//! - **DANE** — [`ServerTrustPolicy::Dane`] is fail-closed (RFC 7671): missing TLSA data or
//!   non-matching usable records reject the handshake. Usage 3 (DANE-EE) and verified usage 2
//!   (DANE-TA) bypass PKIX and therefore also skip hostname and expiry checks (RFC 7671 §5.1).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::version::{TLS12, TLS13};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use rustls_pki_types::CertificateDer as CertDer;
use webpki_roots::TLS_SERVER_ROOTS;

use super::TaxiiError;
use super::dane::{DaneDecision, TlsaRecord, evaluate_dane, spki_sha256};
use super::tls::ClientCertificate;

/// SHA-256 SPKI pin for certificate pinning.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SpkiPin(pub [u8; 32]);

impl SpkiPin {
    /// Create a pin from a hex-encoded SHA-256 hash (64 hex chars).
    pub fn from_hex(hex: &str) -> Result<Self, TaxiiError> {
        let hex = hex.trim();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TaxiiError::InvalidServerTrust {
                reason: "SPKI pin must be 64 hex characters".into(),
            });
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
                TaxiiError::InvalidServerTrust {
                    reason: "invalid SPKI pin hex".into(),
                }
            })?;
        }
        Ok(Self(out))
    }
}

/// Server certificate trust policy (spec section 8.5.2).
#[derive(Clone, Default)]
pub enum ServerTrustPolicy {
    /// System/Web PKI roots (default).
    #[default]
    SystemRoots,
    /// Require SPKI SHA-256 pins (checked in addition to PKIX).
    PinnedSpki(Vec<SpkiPin>),
    /// Validate using DNSSEC TLSA records (RFC 7671). Fail-closed when TLSA is missing or no
    /// record matches.
    Dane,
    /// SPKI pins without PKIX fallback. Accepts a matching pin without hostname or expiry
    /// checks (spec section 8.5.2 certificate pinning for non-PKIX deployments).
    PinnedSpkiOnly(Vec<SpkiPin>),
}

/// Shared TLSA cache populated before requests when using [`ServerTrustPolicy::Dane`].
#[derive(Clone, Default)]
pub struct TlsaCache(Arc<RwLock<HashMap<String, Vec<TlsaRecord>>>>);

impl TlsaCache {
    /// Insert TLSA records for `host`.
    pub fn insert(&self, host: String, records: Vec<TlsaRecord>) {
        if let Ok(mut guard) = self.0.write() {
            guard.insert(host, records);
        }
    }

    pub(crate) fn get(&self, host: &str) -> Option<Vec<TlsaRecord>> {
        self.0.read().ok()?.get(host).cloned()
    }
}

/// Build a rustls [`ClientConfig`] enforcing TLS 1.2+ (spec section 8.5.1).
pub fn build_rustls_config(
    policy: &ServerTrustPolicy,
    tlsa_cache: &TlsaCache,
    client_certificate: Option<&ClientCertificate>,
) -> Result<ClientConfig, TaxiiError> {
    let provider = Arc::new(default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());

    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|err| TaxiiError::InvalidServerTrust {
            reason: err.to_string(),
        })?;

    let (pins, pin_only, use_dane) = match policy {
        ServerTrustPolicy::SystemRoots => (HashSet::new(), false, false),
        ServerTrustPolicy::PinnedSpki(pins) => (pins.iter().map(|p| p.0).collect(), false, false),
        ServerTrustPolicy::PinnedSpkiOnly(pins) => {
            (pins.iter().map(|p| p.0).collect(), true, false)
        }
        ServerTrustPolicy::Dane => (HashSet::new(), false, true),
    };

    let verifier: Arc<dyn ServerCertVerifier> = if pins.is_empty() && !use_dane {
        webpki
    } else {
        Arc::new(PolicyVerifier {
            inner: webpki,
            pins,
            pin_only,
            tlsa_cache: tlsa_cache.clone(),
            use_dane,
            provider: provider.clone(),
        })
    };

    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS12, &TLS13])
        .map_err(|err| TaxiiError::InvalidServerTrust {
            reason: err.to_string(),
        })?
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    if let Some((certs, key)) = client_certificate.and_then(|cert| cert.rustls_auth()) {
        builder
            .with_client_auth_cert(certs.clone(), key.clone_key())
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))
    } else {
        Ok(builder.with_no_client_auth())
    }
}

struct PolicyVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: HashSet<[u8; 32]>,
    pin_only: bool,
    tlsa_cache: TlsaCache,
    use_dane: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl fmt::Debug for PolicyVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyVerifier")
            .field("pins", &self.pins.len())
            .field("pin_only", &self.pin_only)
            .field("use_dane", &self.use_dane)
            .finish()
    }
}

impl ServerCertVerifier for PolicyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertDer<'_>,
        intermediates: &[CertDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let host = server_name_to_str(server_name);

        if self.use_dane {
            let Some(records) = self.tlsa_cache.get(&host) else {
                return Err(Error::General(format!(
                    "DANE: no TLSA records cached for {host} (prefetch TLSA before connect)"
                )));
            };
            if records.is_empty() {
                return Err(Error::General(format!(
                    "DANE: empty TLSA record set for {host}"
                )));
            }
            match evaluate_dane(
                &records,
                end_entity,
                intermediates,
                server_name,
                now,
                &self.provider,
            ) {
                Ok(DaneDecision::AcceptWithoutPkix) => {
                    // RFC 7671 §5.1: DANE-EE / verified DANE-TA — no hostname or expiry check.
                    return Ok(ServerCertVerified::assertion());
                }
                Ok(DaneDecision::RequirePkix) => {
                    return self.inner.verify_server_cert(
                        end_entity,
                        intermediates,
                        server_name,
                        ocsp_response,
                        now,
                    );
                }
                Err(reason) => return Err(Error::General(reason)),
            }
        }

        if !self.pins.is_empty() {
            let Some(hash) = spki_sha256(end_entity) else {
                return Err(Error::General("failed to hash SPKI".into()));
            };
            if !self.pins.contains(&hash) {
                return Err(Error::General("certificate SPKI pin mismatch".into()));
            }
            if self.pin_only {
                // Pin-only: intentional bypass of hostname (SAN) and notAfter checks.
                return Ok(ServerCertVerified::assertion());
            }
        }

        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn server_name_to_str(name: &ServerName<'_>) -> String {
    match name {
        ServerName::DnsName(d) => d.as_ref().to_owned(),
        ServerName::IpAddress(ip) => match ip {
            rustls_pki_types::IpAddr::V4(v4) => std::net::Ipv4Addr::from(*v4.as_ref()).to_string(),
            rustls_pki_types::IpAddr::V6(v6) => std::net::Ipv6Addr::from(*v6.as_ref()).to_string(),
        },
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_rustls_config_with_system_roots() {
        build_rustls_config(&ServerTrustPolicy::SystemRoots, &TlsaCache::default(), None)
            .expect("config");
    }

    #[test]
    fn builder_accepts_tls12_and_tls13() {
        // `build_rustls_config` passes `[&TLS12, &TLS13]` to rustls; rejection would fail here.
        build_rustls_config(&ServerTrustPolicy::SystemRoots, &TlsaCache::default(), None)
            .expect("tls12+tls13");
    }

    #[test]
    fn parses_spki_pin_hex() {
        SpkiPin::from_hex(&"ab".repeat(32)).expect("pin");
    }
}
