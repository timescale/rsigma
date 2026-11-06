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
//! in three places:
//!
//! - At *DNS resolution time* via [`EgressFilteredResolver`], so a DNS
//!   rebinding attack that swaps the upstream's IP after a host-string
//!   check cannot defeat it.
//! - Before each request, via [`EgressPolicy::check_url`]. A URL whose host
//!   is an IP literal (`http://169.254.169.254/`, `http://[::1]/`) never
//!   reaches the resolver, because the HTTP client connects to the literal
//!   directly.
//! - On every redirect hop, via the redirect policy installed by
//!   `egress_client_builder`, so an allowed upstream cannot bounce the
//!   request to a denied IP literal.
//!
//! ## Defaults
//!
//! [`EgressPolicy::default()`] blocks link-local addresses (which
//! includes the canonical cloud-metadata endpoints `169.254.169.254`
//! and `fe80::/10`) and other known cloud-metadata addresses, but
//! leaves loopback and RFC1918 private addresses reachable. This
//! matches typical real-world deployments where the daemon may need
//! to reach an internal threat-intel API on a private IP while still
//! refusing to talk to a cloud metadata service.
//!
//! Operators can tighten the policy with
//! [`EgressPolicy::strict()`] (blocks loopback and private too) or
//! relax it with [`EgressPolicy::permissive()`] when running in a
//! controlled environment where SSRF is not a concern.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

    /// Decide whether the host of `url` is permitted when it is an IP literal.
    ///
    /// The HTTP client connects to an IP-literal host without consulting the
    /// resolver, so [`EgressFilteredResolver`] never sees it; callers check the
    /// URL with this method before sending. Hostnames return `Ok` because the
    /// resolver filters their addresses at connect time, and a string that
    /// does not parse as a URL returns `Ok` because the HTTP client rejects
    /// it on its own. IPv4 hosts written in shorthand, octal, or hex
    /// (`http://0x7f.1/`) are normalized by the URL parser before the check.
    pub fn check_url(&self, url: &str) -> Result<(), EgressDenial> {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return Ok(());
        };
        let Some(host) = parsed.host_str() else {
            return Ok(());
        };
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match host.parse::<IpAddr>() {
            Ok(ip) => self.permit_ip(ip),
            Err(_) => Ok(()),
        }
    }

    /// Decide whether `ip` is permitted under the policy.
    pub fn permit_ip(&self, ip: IpAddr) -> Result<(), EgressDenial> {
        match ip {
            IpAddr::V4(v4) => {
                if self.block_cloud_metadata && is_known_cloud_metadata_v4(v4) {
                    return Err(EgressDenial::CloudMetadata(ip));
                }
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
                // An IPv6 address that carries an IPv4 address (mapped,
                // compatible, NAT64, 6to4) can reach that IPv4 host, so it
                // inherits the v4 deny rules.
                if let Some(v4) = embedded_ipv4(v6) {
                    return self.permit_ip(IpAddr::V4(v4));
                }
            }
        }
        Ok(())
    }
}

fn is_known_cloud_metadata_v4(v4: Ipv4Addr) -> bool {
    // Alibaba Cloud instance metadata sits in shared address space
    // (100.64.0.0/10), which neither the link-local nor the private toggle
    // covers. The 169.254.169.254 endpoints are link-local.
    v4 == Ipv4Addr::new(100, 100, 100, 200)
}

fn is_known_cloud_metadata_v6(v6: Ipv6Addr) -> bool {
    // AWS (fd00:ec2::254) and GCP (fd20:ce::254) IPv6 instance metadata.
    // Both live in the unique-local space but are published as metadata
    // endpoints, so we deny them independently of the private toggle.
    v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        || v6 == Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254)
}

/// The IPv4 address an IPv6 address forwards to, if any: IPv4-mapped
/// (`::ffff:0:0/96`), IPv4-compatible (`::/96`, except `::` and `::1`),
/// NAT64 (`64:ff9b::/96`, and `/96` prefixes in `64:ff9b:1::/48`), and
/// 6to4 (`2002::/16`).
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    let low = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    match s {
        [0, 0, 0, 0, 0, 0, hi, lo] if (hi, lo) != (0, 0) && (hi, lo) != (0, 1) => Some(low(hi, lo)),
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] | [0x64, 0xff9b, 1, _, _, _, hi, lo] => {
            Some(low(hi, lo))
        }
        [0x2002, hi, lo, ..] => Some(low(hi, lo)),
        _ => None,
    }
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

/// Redirect hops followed before giving up, matching reqwest's default policy.
const MAX_REDIRECTS: usize = 10;

/// Start a `reqwest` client builder that enforces `policy` on every address
/// it connects to: the [`EgressFilteredResolver`] filters resolved hostnames,
/// and a redirect policy re-checks each hop's URL with
/// [`EgressPolicy::check_url`] so a redirect to a denied IP literal is
/// refused. The first hop's URL is not covered; check it with
/// [`EgressPolicy::check_url`] before sending.
pub(crate) fn egress_client_builder(policy: EgressPolicy) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(EgressFilteredResolver::new(policy).into_dns_resolver())
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            // `previous` starts with the original URL, so it holds one more
            // entry than the hops followed so far.
            if attempt.previous().len() > MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if let Err(denial) = policy.check_url(attempt.url().as_str()) {
                attempt.error(denial)
            } else {
                attempt.follow()
            }
        }))
}

/// Render `err` followed by each error in its source chain, so a resolver or
/// redirect denial wrapped inside a `reqwest::Error` reaches the operator.
pub(crate) fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

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
            p.permit_ip(v6(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
            Err(EgressDenial::CloudMetadata(_))
        ));
        assert!(matches!(
            p.permit_ip("fd00:ec2::254".parse().unwrap()),
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
            p.permit_ip(v6(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254))
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
            p.permit_ip(v6(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
            Err(EgressDenial::CloudMetadata(_))
        ));
    }

    #[test]
    fn check_url_denies_ip_literal_hosts() {
        let p = EgressPolicy::default();
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254:8080/",
            "https://[fe80::1]/",
            "http://[fd00:ec2::254]/",
            "http://[::ffff:169.254.169.254]/",
            "http://0xa9.0xfe.0xa9.0xfe/",
            "http://0xa9fea9fe/",
            "http://2852039166/",
            "http://[fd20:ce::254]/",
            "http://100.100.100.200/",
            "http://[::169.254.169.254]/",
            "http://[64:ff9b::169.254.169.254]/",
            "http://[64:ff9b:1:abcd::169.254.169.254]/",
            "http://[2002:a9fe:a9fe::]/",
        ] {
            assert!(p.check_url(url).is_err(), "{url} must be denied");
        }
        assert!(matches!(
            p.check_url("http://[fd20:ce::254]/"),
            Err(EgressDenial::CloudMetadata(_))
        ));
        let strict = EgressPolicy::strict();
        assert!(matches!(
            strict.check_url("http://127.0.0.1:9090/"),
            Err(EgressDenial::Loopback(_))
        ));
        assert!(matches!(
            strict.check_url("http://[::1]/"),
            Err(EgressDenial::Loopback(_))
        ));
        assert!(matches!(
            strict.check_url("http://0x7f.1/"),
            Err(EgressDenial::Loopback(_))
        ));
        assert!(matches!(
            strict.check_url("http://10.1.2.3/"),
            Err(EgressDenial::Private(_))
        ));
        for url in [
            "http://[::127.0.0.1]/",
            "http://[64:ff9b::10.0.0.1]/",
            "http://[2002:0a00:0001::]/",
        ] {
            assert!(strict.check_url(url).is_err(), "{url} must be denied");
        }
    }

    #[test]
    fn embedded_ipv4_decodes_only_forwarding_prefixes() {
        let v4 = |s: &str| embedded_ipv4(s.parse().unwrap());
        let meta = Some(Ipv4Addr::new(169, 254, 169, 254));
        assert_eq!(v4("::ffff:169.254.169.254"), meta);
        assert_eq!(v4("::169.254.169.254"), meta);
        assert_eq!(v4("64:ff9b::169.254.169.254"), meta);
        assert_eq!(v4("64:ff9b:1:abcd::169.254.169.254"), meta);
        assert_eq!(v4("2002:a9fe:a9fe::1"), meta);
        assert_eq!(v4("::"), None);
        assert_eq!(v4("::1"), None);
        assert_eq!(v4("2001:db8::a9fe:a9fe"), None);
        assert_eq!(v4("64:ff9b:2::a9fe:a9fe"), None);
    }

    #[test]
    fn check_url_leaves_hostnames_and_allowed_literals_to_the_client() {
        let p = EgressPolicy::default();
        assert!(p.check_url("http://127.0.0.1:9090/").is_ok());
        assert!(p.check_url("https://8.8.8.8/").is_ok());
        assert!(p.check_url("https://metadata.google.internal/").is_ok());
        assert!(p.check_url("not a url").is_ok());
        assert!(
            EgressPolicy::permissive()
                .check_url("http://169.254.169.254/")
                .is_ok()
        );
    }

    #[test]
    fn error_chain_appends_causes_once() {
        #[derive(Debug)]
        struct Outer(EgressDenial);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("error sending request")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let err = Outer(EgressDenial::LinkLocal(v4(169, 254, 169, 254)));
        assert_eq!(
            error_chain(&err),
            "error sending request: egress policy denied link-local address 169.254.169.254"
        );
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
