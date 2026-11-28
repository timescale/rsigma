//! Entry points for the `cargo-fuzz` harnesses. Not a stable API.

use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::op::Message;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use super::TaxiiError;
use super::dane::{TlsaRecord, evaluate_dane};
use super::dns::{srv_targets_from_answers, tlsa_from_answers};

/// Parse a `Retry-After` header value.
pub fn retry_after(value: &str) -> Option<Duration> {
    super::error::parse_retry_after(value)
}

/// Seconds between an HTTP `Date` header value and the local clock.
pub fn date_skew(value: &str) -> Option<i64> {
    super::request::parse_http_date_skew(value)
}

/// One SRV target as a lookup would return it: host, port, DNSSEC-secure.
pub type SrvTargetParts = (String, u16, bool);

/// TLSA records and SRV targets selected from one DNS message.
pub type DnsSelection = (
    Result<Vec<TlsaRecord>, TaxiiError>,
    Result<Vec<SrvTargetParts>, TaxiiError>,
);

/// TLSA and SRV records a lookup would take from the answers in `message`.
///
/// `proofs` assigns each answer a DNSSEC proof state in turn, since the wire
/// format does not carry one.
pub fn dns_answers(message: &[u8], proofs: &[u8], require_secure: bool) -> Option<DnsSelection> {
    let mut message = Message::from_vec(message).ok()?;
    for (index, answer) in message.answers.iter_mut().enumerate() {
        let state = proofs
            .get(index % proofs.len().max(1))
            .copied()
            .unwrap_or(0);
        answer.proof = match state % 4 {
            0 => Proof::Secure,
            1 => Proof::Insecure,
            2 => Proof::Bogus,
            _ => Proof::Indeterminate,
        };
    }
    let tlsa = tlsa_from_answers(&message.answers, require_secure);
    let srv = srv_targets_from_answers(&message.answers, require_secure).map(|targets| {
        targets
            .into_iter()
            .map(|target| {
                assert!(
                    target.base_url().is_ok(),
                    "SRV target {} must form a URL",
                    target.host
                );
                (target.host, target.port, target.dnssec_secure)
            })
            .collect()
    });
    Some((tlsa, srv))
}

/// Evaluate TLSA `records` against a presented chain; `true` when DANE accepts
/// it without PKIX.
pub fn evaluate_tlsa(records: &[TlsaRecord], end_entity: &[u8], intermediates: &[&[u8]]) -> bool {
    let end_entity = CertificateDer::from(end_entity.to_vec());
    let intermediates: Vec<CertificateDer<'static>> = intermediates
        .iter()
        .map(|der| CertificateDer::from(der.to_vec()))
        .collect();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let Ok(name) = ServerName::try_from("taxii.fuzz.test") else {
        return false;
    };
    matches!(
        evaluate_dane(
            records,
            &end_entity,
            &intermediates,
            &name,
            UnixTime::now(),
            &provider,
        ),
        Ok(super::dane::DaneDecision::AcceptWithoutPkix)
    )
}
