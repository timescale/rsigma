//! Destination filter for TAXII HTTP.
//!
//! When a caller installs a filter, name resolution drops rejected addresses and
//! IP literals are checked before the request is sent. Redirects and proxies are
//! disabled for that client so a later hop cannot bypass the filter.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::Url;

use super::TaxiiError;

pub(crate) type AddressFilter = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

pub(crate) struct FilteringResolver {
    pub permit: AddressFilter,
}

#[derive(Debug)]
struct NoPermittedAddress(String);

impl std::fmt::Display for NoPermittedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no permitted address for {}", self.0)
    }
}

impl std::error::Error for NoPermittedAddress {}

impl Resolve for FilteringResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let permit = Arc::clone(&self.permit);
        Box::pin(async move {
            let lookup_host = host.clone();
            let joined =
                tokio::task::spawn_blocking(move || (lookup_host.as_str(), 0u16).to_socket_addrs())
                    .await;
            let looked_up = match joined {
                Ok(Ok(addrs)) => addrs,
                Ok(Err(err)) => {
                    return Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>);
                }
                Err(err) => {
                    return Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>);
                }
            };
            let permitted: Vec<SocketAddr> = looked_up.filter(|addr| permit(addr.ip())).collect();
            if permitted.is_empty() {
                return Err(
                    Box::new(NoPermittedAddress(host)) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            Ok(Box::new(permitted.into_iter()) as Addrs)
        })
    }
}

pub(crate) fn reject_literal_host(url: &Url, filter: &AddressFilter) -> Result<(), TaxiiError> {
    let ip = match url.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => return Ok(()),
    };
    if filter(ip) {
        Ok(())
    } else {
        Err(TaxiiError::DestinationRejected {
            host: url.host_str().unwrap_or_default().to_owned(),
        })
    }
}
