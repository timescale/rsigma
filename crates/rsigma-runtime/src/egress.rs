//! Egress policy enforcement for outbound HTTP traffic.
//!
//! Both the [pipeline source resolver](crate::sources::http) and the
//! [HTTP enricher](crate::enrichment::HttpEnricher) call out to operator-
//! configured URLs. Without a policy gate, any user with write access to
//! a Sigma rule or pipeline could point the daemon at well-known
//! sensitive endpoints (cloud metadata services at `169.254.169.254`,
//! internal admin APIs on link-local addresses, etc.) and trigger SSRF.
//!
//! [`EgressPolicy`] expresses a deny list of address classes (cloud
//! metadata, link-local, optionally loopback / private) and is applied
//! at *DNS resolution time* via [`EgressFilteredResolver`], so a DNS
//! rebinding attack that swaps the upstream's IP after a host-string
//! check cannot defeat it: the connect itself never sees a denied
//! address.
//!
//! ## Defaults
//!
//! [`EgressPolicy::default()`] blocks link-local addresses (which
//! includes the canonical cloud-metadata endpoints `169.254.169.254`
//! and `fe80::/10`) and known cloud-metadata IPv6 addresses, but
//! leaves loopback and RFC1918 private addresses reachable. This
//! matches typical real-world deployments where the daemon may need
//! to reach an internal threat-intel API on a private IP while still
//! refusing to talk to a cloud metadata service.
//!
//! Operators can tighten the policy with
//! [`EgressPolicy::strict()`] (blocks loopback and private too) or
//! relax it with [`EgressPolicy::permissive()`] when running in a
//! controlled environment where SSRF is not a concern.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Process-wide egress policy used by the daemon's default HTTP clients
/// (sources and enrichers). Configured at startup via
/// [`set_default_egress_policy`]; defaults to [`EgressPolicy::default()`]
/// when unset.
static DEFAULT_EGRESS_POLICY: OnceLock<EgressPolicy> = OnceLock::new();

/// Install the process-wide egress policy. Returns an error if a policy
/// was already installed; first-set wins so the daemon's startup config
/// loader can call this once and library consumers can call it before
/// any client is built.
pub fn set_default_egress_policy(policy: EgressPolicy) -> Result<(), EgressPolicy> {
    DEFAULT_EGRESS_POLICY.set(policy)
}

/// Return the configured process-wide egress policy, or
/// [`EgressPolicy::default()`] if none was installed.
pub fn default_egress_policy() -> EgressPolicy {
    DEFAULT_EGRESS_POLICY
        .get()
        .copied()
        .unwrap_or_else(EgressPolicy::default)
}

/// Outbound HTTP egress policy.
///
/// Toggled via the [`Self::with_block_*`](EgressPolicy::with_block_link_local)
/// builder helpers, with [`Self::default()`], [`Self::permissive()`], and
/// [`Self::strict()`] as presets.
#[derive(Debug, Clone, Copy)]
pub struct EgressPolicy {
    block_link_local: bool,
    block_cloud_metadata: bool,
    block_loopback: bool,
    block_private: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            block_link_local: true,
            block_cloud_metadata: true,
            block_loopback: false,
            block_private: false,
        }
    }
}

impl EgressPolicy {
    /// Permit every address. Intended for tests and tightly-controlled
    /// environments where the operator has already vetted every URL.
    pub fn permissive() -> Self {
        Self {
            block_link_local: false,
            block_cloud_metadata: false,
            block_loopback: false,
            block_private: false,
        }
    }

    /// Block every category: link-local, cloud metadata, loopback, and
    /// RFC1918 private. The daemon can still reach public endpoints,
    /// which is what most production deployments want.
    pub fn strict() -> Self {
        Self {
            block_link_local: true,
            block_cloud_metadata: true,
            block_loopback: true,
            block_private: true,
        }
    }

    pub fn with_block_link_local(mut self, block: bool) -> Self {
        self.block_link_local = block;
        self
    }
    pub fn with_block_cloud_metadata(mut self, block: bool) -> Self {
        self.block_cloud_metadata = block;
        self
    }
    pub fn with_block_loopback(mut self, block: bool) -> Self {
        self.block_loopback = block;
        self
    }
    pub fn with_block_private(mut self, block: bool) -> Self {
        self.block_private = block;
        self
    }

    /// Decide whether `ip` is permitted under the policy.
    pub fn permit_ip(&self, ip: IpAddr) -> Result<(), EgressDenial> {
        match ip {
            IpAddr::V4(v4) => {
                if self.block_link_local && v4.is_link_local() {
                    return Err(EgressDenial::LinkLocal(ip));
                }
                if self.block_loopback && v4.is_loopback() {
                    return Err(EgressDenial::Loopback(ip));
                }
                if self.block_private && v4.is_private() {
                    return Err(EgressDenial::Private(ip));
                }
                // Broadcast / multicast / unspecified rarely come back
                // from DNS, but they are equally unsafe as link-local
                // when they do. Treat as link-local for the purpose of
                // the deny reason.
                if self.block_link_local
                    && (v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified())
                {
                    return Err(EgressDenial::LinkLocal(ip));
                }
            }
            IpAddr::V6(v6) => {
                let segs = v6.segments();
                if self.block_link_local && (segs[0] & 0xffc0) == 0xfe80 {
                    return Err(EgressDenial::LinkLocal(ip));
                }
                if self.block_cloud_metadata && is_known_cloud_metadata_v6(v6) {
                    return Err(EgressDenial::CloudMetadata(ip));
                }
                if self.block_loopback && v6.is_loopback() {
                    return Err(EgressDenial::Loopback(ip));
                }
                // Unique local addresses (fc00::/7) are the IPv6 RFC4193
                // analog of RFC1918.
                if self.block_private && (segs[0] & 0xfe00) == 0xfc00 {
                    return Err(EgressDenial::Private(ip));
                }
                if self.block_link_local && (v6.is_multicast() || v6.is_unspecified()) {
                    return Err(EgressDenial::LinkLocal(ip));
                }
                // Recurse on IPv4-mapped IPv6 (::ffff:a.b.c.d) so a host
                // that resolves to a v4-in-v6 wrapper does not bypass
                // the v4 deny rules.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return self.permit_ip(IpAddr::V4(v4));
                }
            }
        }
        Ok(())
    }
}

fn is_known_cloud_metadata_v6(v6: Ipv6Addr) -> bool {
    // AWS IPv6 instance metadata: fd00:ec2::254. The address lives in
    // the unique-local space but is published as the IMDS endpoint, so
    // we deny it independently of the broader private-address toggle.
    v6 == Ipv6Addr::new(0xfd00, 0x00ec, 0x0002, 0, 0, 0, 0, 0x0254)
}

/// Reason an address was denied by an [`EgressPolicy`].
#[derive(Debug, Clone)]
pub enum EgressDenial {
    LinkLocal(IpAddr),
    CloudMetadata(IpAddr),
    Loopback(IpAddr),
    Private(IpAddr),
}

impl std::fmt::Display for EgressDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinkLocal(ip) => {
                write!(f, "egress policy denied link-local address {ip}")
            }
            Self::CloudMetadata(ip) => {
                write!(f, "egress policy denied cloud-metadata address {ip}")
            }
            Self::Loopback(ip) => write!(f, "egress policy denied loopback address {ip}"),
            Self::Private(ip) => write!(f, "egress policy denied private address {ip}"),
        }
    }
}

impl std::error::Error for EgressDenial {}

/// A [`reqwest::dns::Resolve`] implementation that delegates to
/// `tokio::net::lookup_host` and then filters the resolved addresses
/// through an [`EgressPolicy`]. Used by both the HTTP source resolver
/// and the HTTP enricher so they share one safe deny list.
pub struct EgressFilteredResolver {
    policy: EgressPolicy,
}

impl EgressFilteredResolver {
    pub fn new(policy: EgressPolicy) -> Self {
        Self { policy }
    }

    /// Wrap the resolver in the shared `Arc<EgressFilteredResolver>` shape
    /// [`reqwest::ClientBuilder::dns_resolver`] expects. Reqwest's
    /// `dns_resolver` is generic over `R: Resolve + 'static + Sized`, so
    /// the resolver type must be concrete (not `dyn Resolve`).
    pub fn into_dns_resolver(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl Resolve for EgressFilteredResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy;
        let host = name.as_str().to_string();
        Box::pin(async move {
            // `tokio::net::lookup_host` needs a `host:port`; the port
            // is replaced by reqwest with the URL's port.
            let lookup_target = format!("{host}:0");
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host(lookup_target)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            let mut allowed: Vec<SocketAddr> = Vec::with_capacity(resolved.len());
            let mut first_denial: Option<EgressDenial> = None;
            for sa in resolved {
                match policy.permit_ip(sa.ip()) {
                    Ok(()) => allowed.push(sa),
                    Err(denial) => {
                        if first_denial.is_none() {
                            first_denial = Some(denial);
                        }
                    }
                }
            }
            if allowed.is_empty() {
                let message: String = match first_denial {
                    Some(d) => d.to_string(),
                    None => format!("no addresses resolved for '{host}'"),
                };
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(message));
            }
            let addrs: Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[allow(clippy::too_many_arguments)]
    fn v6(s0: u16, s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7))
    }

    #[test]
    fn default_blocks_link_local_and_cloud_metadata() {
        let p = EgressPolicy::default();
        assert!(matches!(
            p.permit_ip(v4(169, 254, 169, 254)),
            Err(EgressDenial::LinkLocal(_))
        ));
        assert!(matches!(
            p.permit_ip(v6(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            Err(EgressDenial::LinkLocal(_))
        ));
        assert!(matches!(
            p.permit_ip(v6(0xfd00, 0x00ec, 0x0002, 0, 0, 0, 0, 0x0254)),
            Err(EgressDenial::CloudMetadata(_))
        ));
    }

    #[test]
    fn default_allows_loopback_and_private() {
        // Internal threat-intel services commonly live on private
        // addresses; the default policy must let them through.
        let p = EgressPolicy::default();
        assert!(p.permit_ip(v4(127, 0, 0, 1)).is_ok());
        assert!(p.permit_ip(v4(10, 0, 0, 1)).is_ok());
        assert!(p.permit_ip(v4(192, 168, 1, 1)).is_ok());
        assert!(p.permit_ip(v4(8, 8, 8, 8)).is_ok());
        assert!(p.permit_ip(v6(0, 0, 0, 0, 0, 0, 0, 1)).is_ok());
    }

    #[test]
    fn strict_blocks_loopback_and_private() {
        let p = EgressPolicy::strict();
        assert!(matches!(
            p.permit_ip(v4(127, 0, 0, 1)),
            Err(EgressDenial::Loopback(_))
        ));
        assert!(matches!(
            p.permit_ip(v4(10, 0, 0, 1)),
            Err(EgressDenial::Private(_))
        ));
        assert!(matches!(
            p.permit_ip(v6(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            Err(EgressDenial::Private(_))
        ));
        // Public addresses still allowed.
        assert!(p.permit_ip(v4(8, 8, 8, 8)).is_ok());
    }

    #[test]
    fn permissive_allows_everything() {
        let p = EgressPolicy::permissive();
        assert!(p.permit_ip(v4(169, 254, 169, 254)).is_ok());
        assert!(p.permit_ip(v4(127, 0, 0, 1)).is_ok());
        assert!(p.permit_ip(v4(10, 0, 0, 1)).is_ok());
        assert!(
            p.permit_ip(v6(0xfd00, 0x00ec, 0x0002, 0, 0, 0, 0, 0x0254))
                .is_ok()
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_inherits_v4_rules() {
        // ::ffff:169.254.169.254 must be denied as link-local even
        // though its IPv6 representation does not match fe80::/10.
        let p = EgressPolicy::default();
        let mapped = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        assert!(matches!(
            p.permit_ip(IpAddr::V6(mapped)),
            Err(EgressDenial::LinkLocal(_))
        ));
    }

    #[test]
    fn builder_overrides_individual_categories() {
        // Operators may want metadata blocked but private allowed
        // (typical case); flipping link-local to false should not
        // accidentally re-enable cloud metadata, since the IPv6
        // cloud-metadata address has its own toggle.
        let p = EgressPolicy::default().with_block_link_local(false);
        assert!(p.permit_ip(v4(169, 254, 169, 254)).is_ok());
        assert!(matches!(
            p.permit_ip(v6(0xfd00, 0x00ec, 0x0002, 0, 0, 0, 0, 0x0254)),
            Err(EgressDenial::CloudMetadata(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn filtered_resolver_denies_link_local_lookup() {
        // Resolving a literal IP via getaddrinfo returns that IP; the
        // resolver filter must reject it just like any other deny case.
        let resolver = EgressFilteredResolver::new(EgressPolicy::default());
        let name: reqwest::dns::Name = "169.254.169.254".parse().unwrap();
        let result = resolver.resolve(name).await;
        // `Addrs` is `Box<dyn Iterator>` which has no `Debug`, so we
        // cannot use `expect_err`. Match the result manually instead.
        let err = match result {
            Ok(_) => panic!("policy must deny link-local literal"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("link-local"),
            "expected link-local denial, got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn filtered_resolver_permits_public_lookup() {
        // 8.8.8.8 is a literal public IP; the lookup short-circuits in
        // tokio's resolver without hitting DNS.
        let resolver = EgressFilteredResolver::new(EgressPolicy::default());
        let name: reqwest::dns::Name = "8.8.8.8".parse().unwrap();
        if resolver.resolve(name).await.is_err() {
            panic!("public IP must be permitted by default policy");
        }
    }
}
