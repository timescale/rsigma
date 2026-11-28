//! TLSA record matching for DANE (RFC 6698 / RFC 7671; TAXII 2.1 spec section 8.5.2).
//!
//! When [`ServerTrustPolicy::Dane`] is selected, verification is **fail-closed**: missing
//! TLSA data or non-matching usable records reject the handshake (RFC 7671 sections 5–6).

use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls_webpki::{EndEntityCert, VerifiedPath, spki_for_anchor};
use sha2::{Digest, Sha256};

/// Parsed TLSA association data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsaRecord {
    /// Certificate usage field (RFC 6698).
    pub cert_usage: u8,
    /// Selector field.
    pub selector: u8,
    /// Matching type field.
    pub matching: u8,
    /// Certificate association data.
    pub cert_data: Vec<u8>,
}

impl TlsaRecord {
    /// Returns true when `cert` matches this record's selector and matching type.
    pub fn association_matches(&self, cert: &CertificateDer<'_>) -> bool {
        match self.selector {
            0 => self.data_matches(cert.as_ref()),
            1 => spki_bytes(cert).is_some_and(|spki| self.data_matches(&spki)),
            _ => false,
        }
    }

    /// Compare already-selected `data` (full certificate or SPKI) under this
    /// record's matching type.
    fn data_matches(&self, data: &[u8]) -> bool {
        match self.matching {
            0 => data == self.cert_data.as_slice(),
            1 => Sha256::digest(data).as_slice() == self.cert_data.as_slice(),
            _ => false,
        }
    }

    /// Usages and wire fields this client implements (RFC 7671 TLS client).
    pub fn is_usable_for_tls_client(&self) -> bool {
        matches!(self.cert_usage, 0..=3)
            && matches!(self.selector, 0..=1)
            && matches!(self.matching, 0..=1)
    }
}

fn spki_bytes(end_entity: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let ee = EndEntityCert::try_from(end_entity).ok()?;
    Some(ee.subject_public_key_info().to_vec())
}

/// Compute SHA-256 hash of the end-entity SPKI (for certificate pinning).
pub fn spki_sha256(end_entity: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let spki = spki_bytes(end_entity)?;
    Some(Sha256::digest(&spki).into())
}

fn chain_certs<'a>(
    end_entity: &'a CertificateDer<'_>,
    intermediates: &'a [CertificateDer<'_>],
) -> Vec<&'a CertificateDer<'a>> {
    std::iter::once(end_entity)
        .chain(intermediates.iter())
        .collect()
}

fn chain_associates(
    record: &TlsaRecord,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> bool {
    chain_certs(end_entity, intermediates)
        .into_iter()
        .any(|cert| record.association_matches(cert))
}

/// Outcome of evaluating TLSA records for the presented chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DaneDecision {
    /// Usage 3 (DANE-EE) or verified usage 2 (DANE-TA): accept without PKIX (RFC 7671 §5.1).
    AcceptWithoutPkix,
    /// Usage 1 (PKIX-EE) association matched: caller MUST run PKIX.
    RequirePkix,
    /// Usage 0 (PKIX-TA): caller MUST run PKIX, and the validated path MUST pass
    /// through a CA that matches one of these records (RFC 6698 §2.1.1).
    RequirePkixTrustAnchor(Vec<TlsaRecord>),
}

/// Whether the validated `path` passes through a CA matching one of the usage 0 `records`.
///
/// Only the path's intermediates and its trust anchor count, so a matching
/// certificate the peer sent but the path does not use is ignored. The trust
/// anchor is known by its SPKI; a full-certificate record matches it through a
/// presented certificate that carries the anchor's key.
pub(crate) fn path_matches_pkix_ta(
    records: &[TlsaRecord],
    path: &VerifiedPath<'_>,
    presented: &[CertificateDer<'_>],
) -> bool {
    let through_intermediate = path.intermediate_certificates().any(|cert| {
        let der = cert.der();
        records
            .iter()
            .any(|record| record.association_matches(&der))
    });
    if through_intermediate {
        return true;
    }
    let anchor_spki = spki_for_anchor(path.anchor());
    records.iter().any(|record| match record.selector {
        0 => presented.iter().any(|cert| {
            spki_bytes(cert).as_deref() == Some(anchor_spki.as_ref())
                && record.association_matches(cert)
        }),
        1 => record.data_matches(anchor_spki.as_ref()),
        _ => false,
    })
}

/// Evaluate TLSA records fail-closed (RFC 7671 §5–6).
///
/// Returns [`Err`] when usable records exist but none match, or when no usable records exist.
pub(crate) fn evaluate_dane(
    records: &[TlsaRecord],
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    now: UnixTime,
    provider: &Arc<CryptoProvider>,
) -> Result<DaneDecision, String> {
    let usable: Vec<_> = records
        .iter()
        .filter(|r| r.is_usable_for_tls_client())
        .collect();
    if usable.is_empty() {
        return Err(
            "DANE: TLSA records present but none use supported usage/selector/matching values"
                .into(),
        );
    }

    // Usage 3 (DANE-EE): EE match bypasses PKIX entirely (RFC 7671 §5.1).
    if usable
        .iter()
        .any(|r| r.cert_usage == 3 && r.association_matches(end_entity))
    {
        return Ok(DaneDecision::AcceptWithoutPkix);
    }

    // Usage 2 (DANE-TA): verify chain to matching trust anchor (RFC 7671 §5.1).
    for record in usable.iter().filter(|r| r.cert_usage == 2) {
        if chain_associates(record, end_entity, intermediates)
            && verify_dane_ta_chain(
                record,
                end_entity,
                intermediates,
                server_name,
                now,
                provider,
            )
            .is_ok()
        {
            return Ok(DaneDecision::AcceptWithoutPkix);
        }
    }

    // Usage 1 (PKIX-EE): EE must match TLSA and PKIX MUST succeed (handled by caller).
    if usable
        .iter()
        .any(|r| r.cert_usage == 1 && r.association_matches(end_entity))
    {
        return Ok(DaneDecision::RequirePkix);
    }

    // Usage 0 (PKIX-TA): the caller matches these against the PKIX-validated path.
    let pkix_ta: Vec<TlsaRecord> = usable
        .iter()
        .filter(|r| r.cert_usage == 0)
        .map(|r| (*r).clone())
        .collect();
    if !pkix_ta.is_empty() {
        return Ok(DaneDecision::RequirePkixTrustAnchor(pkix_ta));
    }

    Err("DANE: usable TLSA records present but none matched the server certificate or chain".into())
}

fn verify_dane_ta_chain(
    record: &TlsaRecord,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    now: UnixTime,
    provider: &Arc<CryptoProvider>,
) -> Result<(), String> {
    let anchor = chain_certs(end_entity, intermediates)
        .into_iter()
        .find(|cert| record.association_matches(cert))
        .ok_or_else(|| "DANE-TA: no certificate in chain matches TLSA association".to_string())?
        .clone();

    let mut roots = RootCertStore::empty();
    roots
        .add(anchor)
        .map_err(|err| format!("DANE-TA: invalid trust anchor: {err}"))?;

    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|err| format!("DANE-TA: verifier build failed: {err}"))?;

    verifier
        .verify_server_cert(end_entity, intermediates, server_name, &[], now)
        .map_err(|err| format!("DANE-TA: chain verification failed: {err}"))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_cert_association_matches() {
        let cert = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        let record = TlsaRecord {
            cert_usage: 3,
            selector: 0,
            matching: 0,
            cert_data: cert.as_ref().to_vec(),
        };
        assert!(record.association_matches(&cert));
    }

    #[test]
    fn dane_ee_match_accepts_without_pkix() {
        let cert = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        let records = vec![TlsaRecord {
            cert_usage: 3,
            selector: 0,
            matching: 0,
            cert_data: cert.as_ref().to_vec(),
        }];
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let decision = evaluate_dane(
            &records,
            &cert,
            &[],
            &ServerName::try_from("example.com".to_owned()).unwrap(),
            UnixTime::now(),
            &provider,
        )
        .expect("dane-ee");
        assert_eq!(decision, DaneDecision::AcceptWithoutPkix);
    }

    #[test]
    fn usable_records_with_no_match_fail_closed() {
        let cert = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        let records = vec![TlsaRecord {
            cert_usage: 3,
            selector: 0,
            matching: 0,
            cert_data: vec![0xde, 0xad],
        }];
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let err = evaluate_dane(
            &records,
            &cert,
            &[],
            &ServerName::try_from("example.com".to_owned()).unwrap(),
            UnixTime::now(),
            &provider,
        )
        .expect_err("must fail");
        assert!(err.contains("none matched"));
    }

    #[test]
    fn pkix_ee_match_requires_pkix() {
        let cert = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        let records = vec![TlsaRecord {
            cert_usage: 1,
            selector: 0,
            matching: 0,
            cert_data: cert.as_ref().to_vec(),
        }];
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let decision = evaluate_dane(
            &records,
            &cert,
            &[],
            &ServerName::try_from("example.com".to_owned()).unwrap(),
            UnixTime::now(),
            &provider,
        )
        .expect("pkix-ee");
        assert_eq!(decision, DaneDecision::RequirePkix);
    }

    #[test]
    fn unsupported_usage_is_not_usable() {
        let record = TlsaRecord {
            cert_usage: 9,
            selector: 0,
            matching: 0,
            cert_data: vec![1],
        };
        assert!(!record.is_usable_for_tls_client());
    }
}
