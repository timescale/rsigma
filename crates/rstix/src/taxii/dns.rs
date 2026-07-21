//! DNS SRV discovery and TLSA lookup for TAXII servers (spec sections 1.6.1, 3.9, 8.4.2, 8.5.2).

use std::net::SocketAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use url::Url;

use super::TaxiiError;
use super::dane::TlsaRecord;
use super::url::{DISCOVERY_PATH, ensure_trailing_slash};

/// Service name for TAXII 2.1 DNS SRV records (`_taxii2._tcp`).
pub const TAXII2_SRV_SERVICE: &str = "_taxii2._tcp";

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
    let domain = domain.trim().trim_end_matches('.');
    let lookup = format!("{TAXII2_SRV_SERVICE}.{domain}");

    let resolver = build_resolver(nameserver)?;
    let response = resolver
        .srv_lookup(lookup)
        .await
        .map_err(|err| TaxiiError::DnsDiscovery(err.to_string()))?;

    let mut records = Vec::new();
    for answer in response.answers() {
        let RData::SRV(srv) = &answer.data else {
            continue;
        };
        let target = srv.target.to_utf8();
        if target == "." {
            continue;
        }
        let port = srv.port;
        let mut url = Url::parse(&format!("https://{target}:{port}{DISCOVERY_PATH}"))
            .map_err(|err| TaxiiError::InvalidUrl(err.to_string()))?;
        ensure_trailing_slash(&mut url);
        records.push((srv.priority, srv.weight, url));
    }

    Ok(order_srv_records(records))
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
    let host = host.trim().trim_end_matches('.');
    let lookup = format!("_{port}._tcp.{host}");

    let resolver = build_resolver(nameserver)?;
    let response = resolver
        .tlsa_lookup(lookup)
        .await
        .map_err(|err| TaxiiError::DnsDiscovery(err.to_string()))?;

    let mut records = Vec::new();
    for answer in response.answers() {
        let RData::TLSA(tlsa) = &answer.data else {
            continue;
        };
        records.push(TlsaRecord {
            cert_usage: tlsa.cert_usage.into(),
            selector: tlsa.selector.into(),
            matching: tlsa.matching.into(),
            cert_data: tlsa.cert_data.to_vec(),
        });
    }
    Ok(records)
}

fn build_resolver(nameserver: Option<SocketAddr>) -> Result<TokioResolver, TaxiiError> {
    let resolver = if let Some(addr) = nameserver {
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
    resolver
        .build()
        .map_err(|err| TaxiiError::DnsDiscovery(err.to_string()))
}

fn order_srv_records(mut records: Vec<(u16, u16, Url)>) -> Vec<Url> {
    records.sort_by_key(|a| a.0);
    let mut ordered = Vec::new();
    let mut index = 0;
    while index < records.len() {
        let priority = records[index].0;
        let mut group = Vec::new();
        while index < records.len() && records[index].0 == priority {
            group.push((records[index].1, records[index].2.clone()));
            index += 1;
        }
        ordered.extend(select_weighted_srv_group(group));
    }
    ordered
}

fn select_weighted_srv_group(group: Vec<(u16, Url)>) -> Vec<Url> {
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
}
