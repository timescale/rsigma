//! DNS SRV discovery and TLSA lookup for TAXII servers (spec sections 1.6.1, 3.9, 8.4.2, 8.5.2).

use std::net::SocketAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, Record};
use url::Url;

use super::TaxiiError;
use super::dane::TlsaRecord;
use super::url::{DISCOVERY_PATH, ensure_trailing_slash};

/// Service name for TAXII 2.1 DNS SRV records (`_taxii2._tcp`).
pub const TAXII2_SRV_SERVICE: &str = "_taxii2._tcp";

/// Options for DNS SRV and TLSA lookups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsLookupOptions {
    /// When `true`, require DNSSEC validation (hickory-resolver, ICANN root anchor).
    pub validate_dnssec: bool,
}

impl DnsLookupOptions {
    /// Require DNSSEC-validated answers.
    pub const fn require_dnssec() -> Self {
        Self {
            validate_dnssec: true,
        }
    }

    /// DNS lookup options for DANE TLSA/SRV prefetch on [`TaxiiClient`](super::TaxiiClient).
    pub fn for_dane(dane_require_dnssec: bool) -> Self {
        Self {
            validate_dnssec: dane_require_dnssec,
        }
    }
}

/// Resolve TAXII discovery base URLs from `_taxii2._tcp.{domain}` SRV records.
///
/// Returns HTTPS URLs ending in `/taxii2/` ordered by SRV priority with RFC 2782
/// weighted random selection within each priority group.
pub async fn resolve_taxii_srv(domain: &str) -> Result<Vec<Url>, TaxiiError> {
    resolve_taxii_srv_with(domain, None).await
}

/// Like [`resolve_taxii_srv`], but queries `nameserver` instead of the system resolver when set.
pub async fn resolve_taxii_srv_with(
    domain: &str,
    nameserver: Option<SocketAddr>,
) -> Result<Vec<Url>, TaxiiError> {
    resolve_taxii_srv_with_options(domain, nameserver, DnsLookupOptions::default()).await
}

/// Like [`resolve_taxii_srv_with`], with explicit DNS lookup options.
///
/// With [`DnsLookupOptions::validate_dnssec`], only records the resolver proves
/// Secure are used, and an answer with none is a trust error.
pub async fn resolve_taxii_srv_with_options(
    domain: &str,
    nameserver: Option<SocketAddr>,
    options: DnsLookupOptions,
) -> Result<Vec<Url>, TaxiiError> {
    resolve_taxii_srv_targets(domain, nameserver, options)
        .await?
        .iter()
        .map(SrvTarget::discovery_url)
        .collect()
}

/// One SRV target, in the order a client should try it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SrvTarget {
    /// Target host name without the trailing dot.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// The resolver proved the SRV record with DNSSEC.
    pub dnssec_secure: bool,
}

impl SrvTarget {
    pub(crate) fn base_url(&self) -> Result<Url, TaxiiError> {
        Url::parse(&format!("https://{}:{}/", self.host, self.port))
            .map_err(|err| TaxiiError::InvalidUrl(err.to_string()))
    }

    fn discovery_url(&self) -> Result<Url, TaxiiError> {
        let mut url = self.base_url()?;
        url.set_path(DISCOVERY_PATH);
        ensure_trailing_slash(&mut url);
        Ok(url)
    }
}

pub(crate) async fn resolve_taxii_srv_targets(
    domain: &str,
    nameserver: Option<SocketAddr>,
    options: DnsLookupOptions,
) -> Result<Vec<SrvTarget>, TaxiiError> {
    let domain = domain.trim().trim_end_matches('.');
    let lookup = format!("{TAXII2_SRV_SERVICE}.{domain}");

    let resolver = build_resolver(nameserver, options)?;
    let response = resolver
        .srv_lookup(lookup)
        .await
        .map_err(|err| map_dns_error(err, options.validate_dnssec))?;
    srv_targets_from_answers(response.answers(), options.validate_dnssec)
}

fn srv_targets_from_answers(
    answers: &[Record],
    require_secure: bool,
) -> Result<Vec<SrvTarget>, TaxiiError> {
    let answers = select_answers(
        answers,
        |data| matches!(data, RData::SRV(_)),
        require_secure,
        "SRV",
    )?;
    let mut records = Vec::new();
    for answer in answers {
        let RData::SRV(srv) = &answer.data else {
            continue;
        };
        let target = srv.target.to_ascii();
        let host = target.trim_end_matches('.');
        if host.is_empty() || srv.port == 0 || !is_plain_host_name(host) {
            continue;
        }
        records.push((
            srv.priority,
            srv.weight,
            SrvTarget {
                host: host.to_ascii_lowercase(),
                port: srv.port,
                dnssec_secure: answer.proof.is_secure(),
            },
        ));
    }
    Ok(order_srv_records(records))
}

/// A DNS host name a URL can carry as its host unchanged.
fn is_plain_host_name(host: &str) -> bool {
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Records of the wanted type, keeping only DNSSEC-Secure ones when required.
///
/// With `require_secure`, an answer that has records of the type but none
/// proven Secure (Insecure, Bogus, or Indeterminate) is a trust error.
fn select_answers<'a>(
    answers: &'a [Record],
    wanted: impl Fn(&RData) -> bool,
    require_secure: bool,
    record_type: &str,
) -> Result<Vec<&'a Record>, TaxiiError> {
    let typed: Vec<&Record> = answers
        .iter()
        .filter(|answer| wanted(&answer.data))
        .collect();
    if !require_secure {
        return Ok(typed);
    }
    let secure: Vec<&Record> = typed
        .iter()
        .copied()
        .filter(|answer| answer.proof.is_secure())
        .collect();
    if secure.is_empty()
        && let Some(first) = typed.first()
    {
        return Err(TaxiiError::InvalidServerTrust {
            reason: format!(
                "DNSSEC: {record_type} answer for {} is {:?}, not Secure",
                first.name, first.proof
            ),
        });
    }
    Ok(secure)
}

/// Resolve TLSA records for DANE (`_{port}._tcp.{host}`).
pub async fn resolve_tlsa(host: &str, port: u16) -> Result<Vec<TlsaRecord>, TaxiiError> {
    resolve_tlsa_with(host, port, None).await
}

/// Like [`resolve_tlsa`], but queries `nameserver` instead of the system resolver when set.
pub async fn resolve_tlsa_with(
    host: &str,
    port: u16,
    nameserver: Option<SocketAddr>,
) -> Result<Vec<TlsaRecord>, TaxiiError> {
    resolve_tlsa_with_options(host, port, nameserver, DnsLookupOptions::default()).await
}

/// Like [`resolve_tlsa_with`], with explicit DNS lookup options.
pub async fn resolve_tlsa_with_options(
    host: &str,
    port: u16,
    nameserver: Option<SocketAddr>,
    options: DnsLookupOptions,
) -> Result<Vec<TlsaRecord>, TaxiiError> {
    let host = host.trim().trim_end_matches('.');
    let lookup = format!("_{port}._tcp.{host}");

    let resolver = build_resolver(nameserver, options)?;
    let response = resolver
        .tlsa_lookup(lookup)
        .await
        .map_err(|err| map_dns_error(err, options.validate_dnssec))?;
    tlsa_from_answers(response.answers(), options.validate_dnssec)
}

fn tlsa_from_answers(
    answers: &[Record],
    require_secure: bool,
) -> Result<Vec<TlsaRecord>, TaxiiError> {
    let answers = select_answers(
        answers,
        |data| matches!(data, RData::TLSA(_)),
        require_secure,
        "TLSA",
    )?;
    Ok(answers
        .into_iter()
        .filter_map(|answer| match &answer.data {
            RData::TLSA(tlsa) => Some(TlsaRecord {
                cert_usage: tlsa.cert_usage.into(),
                selector: tlsa.selector.into(),
                matching: tlsa.matching.into(),
                cert_data: tlsa.cert_data.to_vec(),
            }),
            _ => None,
        })
        .collect())
}

fn build_resolver(
    nameserver: Option<SocketAddr>,
    options: DnsLookupOptions,
) -> Result<TokioResolver, TaxiiError> {
    let mut builder = if let Some(addr) = nameserver {
        let mut udp = ConnectionConfig::udp();
        udp.port = addr.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = addr.port();
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        config.add_name_server(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
    } else {
        TokioResolver::builder_tokio().map_err(|err| TaxiiError::DnsDiscovery(err.to_string()))?
    };
    apply_dns_lookup_options(builder.options_mut(), options);
    builder
        .build()
        .map_err(|err| TaxiiError::DnsDiscovery(err.to_string()))
}

fn apply_dns_lookup_options(opts: &mut ResolverOpts, options: DnsLookupOptions) {
    opts.validate = options.validate_dnssec;
}

fn map_dns_error(err: NetError, validate_dnssec: bool) -> TaxiiError {
    let message = err.to_string();
    if validate_dnssec {
        TaxiiError::InvalidServerTrust {
            reason: format!("DNSSEC-validated DNS lookup failed: {message}"),
        }
    } else {
        TaxiiError::DnsDiscovery(message)
    }
}

fn order_srv_records<T>(mut records: Vec<(u16, u16, T)>) -> Vec<T> {
    records.sort_by_key(|a| a.0);
    let mut ordered = Vec::new();
    let mut records = records.into_iter().peekable();
    while let Some((priority, weight, item)) = records.next() {
        let mut group = vec![(weight, item)];
        while let Some((_, weight, item)) = records.next_if(|next| next.0 == priority) {
            group.push((weight, item));
        }
        ordered.extend(select_weighted_srv_group(group));
    }
    ordered
}

fn select_weighted_srv_group<T>(group: Vec<(u16, T)>) -> Vec<T> {
    let mut remaining = group;
    let mut selected = Vec::new();
    while !remaining.is_empty() {
        let sum: u32 = remaining.iter().map(|(weight, _)| u32::from(*weight)).sum();
        let pick = if sum == 0 {
            0
        } else {
            (random_u32() % sum) as usize
        };
        let mut running = 0u32;
        let mut chosen = 0;
        for (idx, (weight, _)) in remaining.iter().enumerate() {
            running = running.saturating_add(u32::from(*weight));
            if sum == 0 || pick < running as usize {
                chosen = idx;
                break;
            }
        }
        let (_, url) = remaining.remove(chosen);
        selected.push(url);
    }
    selected
}

fn random_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    hasher.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv_service_constant_matches_spec() {
        assert_eq!(TAXII2_SRV_SERVICE, "_taxii2._tcp");
    }

    #[test]
    fn dns_lookup_options_default_is_opportunistic() {
        assert!(!DnsLookupOptions::default().validate_dnssec);
        assert!(DnsLookupOptions::require_dnssec().validate_dnssec);
    }

    #[test]
    fn build_resolver_sets_validate_when_requested() {
        let resolver =
            build_resolver(None, DnsLookupOptions::require_dnssec()).expect("system resolver");
        assert!(resolver.options().validate);
    }

    #[test]
    fn build_resolver_leaves_validate_off_by_default() {
        let resolver = build_resolver(None, DnsLookupOptions::default()).expect("system resolver");
        assert!(!resolver.options().validate);
    }

    #[test]
    fn weighted_selection_returns_all_group_members() {
        let urls = vec![
            (1u16, Url::parse("https://a.example/taxii2/").unwrap()),
            (1u16, Url::parse("https://b.example/taxii2/").unwrap()),
        ];
        let selected = select_weighted_srv_group(urls);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn order_srv_skips_dot_target() {
        let records = vec![(
            0u16,
            1u16,
            Url::parse("https://valid.example/taxii2/").unwrap(),
        )];
        let ordered = order_srv_records(records);
        assert_eq!(ordered.len(), 1);
    }

    use hickory_resolver::proto::dnssec::Proof;
    use hickory_resolver::proto::rr::Name;
    use hickory_resolver::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
    use hickory_resolver::proto::rr::rdata::{A, SRV, TLSA};

    const ALL_PROOFS: [Proof; 4] = [
        Proof::Secure,
        Proof::Insecure,
        Proof::Bogus,
        Proof::Indeterminate,
    ];

    fn with_proof(name: &str, data: RData, proof: Proof) -> Record {
        let mut record = Record::from_rdata(Name::from_ascii(name).unwrap(), 300, data);
        record.proof = proof;
        record
    }

    fn tlsa(proof: Proof, byte: u8) -> Record {
        with_proof(
            "_443._tcp.taxii.test.",
            RData::TLSA(TLSA::new(
                CertUsage::from(3),
                Selector::from(1),
                Matching::from(1),
                vec![byte; 32],
            )),
            proof,
        )
    }

    fn srv(proof: Proof, priority: u16, target: &str) -> Record {
        with_proof(
            "_taxii2._tcp.example.test.",
            RData::SRV(SRV::new(
                priority,
                1,
                8443,
                Name::from_ascii(target).unwrap(),
            )),
            proof,
        )
    }

    #[test]
    fn required_dnssec_uses_only_secure_tlsa_records() {
        for proof in ALL_PROOFS {
            let answers = [tlsa(proof, 1)];
            let result = tlsa_from_answers(&answers, true);
            if proof == Proof::Secure {
                assert_eq!(result.expect("secure").len(), 1);
            } else {
                let err = result.expect_err("not secure");
                assert!(
                    matches!(&err, TaxiiError::InvalidServerTrust { reason } if reason.contains("not Secure")),
                    "{proof:?}: {err}"
                );
            }
        }
    }

    #[test]
    fn required_dnssec_drops_unproven_records_beside_secure_ones() {
        let answers = [
            tlsa(Proof::Insecure, 1),
            tlsa(Proof::Secure, 2),
            tlsa(Proof::Bogus, 3),
        ];
        let records = tlsa_from_answers(&answers, true).expect("one secure record");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].cert_data, vec![2; 32]);
    }

    #[test]
    fn opportunistic_lookup_keeps_every_record() {
        let answers: Vec<_> = ALL_PROOFS
            .iter()
            .enumerate()
            .map(|(i, proof)| tlsa(*proof, i as u8))
            .collect();
        assert_eq!(tlsa_from_answers(&answers, false).unwrap().len(), 4);
    }

    #[test]
    fn other_record_types_do_not_count() {
        let answers = [with_proof(
            "_443._tcp.taxii.test.",
            RData::A(A::new(127, 0, 0, 1)),
            Proof::Secure,
        )];
        assert!(tlsa_from_answers(&answers, true).unwrap().is_empty());
        assert!(srv_targets_from_answers(&answers, true).unwrap().is_empty());
    }

    #[test]
    fn srv_targets_record_their_proof_state() {
        for proof in ALL_PROOFS {
            let answers = [srv(proof, 0, "taxii.example.test.")];
            let targets = srv_targets_from_answers(&answers, false).expect("targets");
            assert_eq!(
                targets,
                vec![SrvTarget {
                    host: "taxii.example.test".into(),
                    port: 8443,
                    dnssec_secure: proof == Proof::Secure,
                }]
            );
            let required = srv_targets_from_answers(&answers, true);
            assert_eq!(required.is_ok(), proof == Proof::Secure, "{proof:?}");
        }
    }

    #[test]
    fn srv_targets_follow_priority_and_skip_unusable_targets() {
        let answers = [
            srv(Proof::Indeterminate, 10, "second.example.test."),
            srv(Proof::Indeterminate, 0, "first.example.test."),
            srv(Proof::Indeterminate, 0, "."),
            with_proof(
                "_taxii2._tcp.example.test.",
                RData::SRV(SRV::new(
                    0,
                    1,
                    0,
                    Name::from_ascii("zero-port.example.test.").unwrap(),
                )),
                Proof::Indeterminate,
            ),
        ];
        let hosts: Vec<_> = srv_targets_from_answers(&answers, false)
            .unwrap()
            .into_iter()
            .map(|t| t.host)
            .collect();
        assert_eq!(hosts, ["first.example.test", "second.example.test"]);
    }

    #[test]
    fn srv_target_names_must_be_plain_host_names() {
        assert!(is_plain_host_name("taxii.example.test"));
        assert!(is_plain_host_name("_svc.example-1.test"));
        for bad in ["a/b.test", "a@b.test", "a\\b", "a..b", "a b", "a:443"] {
            assert!(!is_plain_host_name(bad), "{bad}");
        }
        let target = SrvTarget {
            host: "taxii.example.test".into(),
            port: 8443,
            dnssec_secure: false,
        };
        assert_eq!(
            target.discovery_url().unwrap().as_str(),
            "https://taxii.example.test:8443/taxii2/"
        );
    }
}
