//! `Host` and `Origin` validation for HTTP listeners.
//!
//! A server bound to a local address is reachable from any web page the user
//! opens: a cross-origin `fetch` can send a `text/plain` POST without a CORS
//! preflight, and a DNS-rebinding page can point its own name at `127.0.0.1`
//! and read the responses. [`HostGuard`] closes both paths. It accepts a
//! request only when its `Host` names one of the configured hosts, and, when
//! the request carries an `Origin` header, only when that origin is `http` or
//! `https` on one of those hosts. Requests without an `Origin` header (curl,
//! log shippers, SDK clients) pass the origin check.
//!
//! The daemon API and the MCP HTTP transport share these rules. The module is
//! free of HTTP framework types so it can be checked and fuzzed on its own;
//! each server wraps [`HostGuard::check`] in its own middleware.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// The host names a default [`HostGuard`] accepts, on any port.
pub const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// The value that turns host validation off in an allowed-host list.
pub const ANY_HOST: &str = "*";

/// A host name or address, with an optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority {
    /// Lowercase, without the brackets of an IPv6 literal.
    host: String,
    port: Option<u16>,
}

impl Authority {
    /// Parse a `Host` header value or an allowed-host entry: `name`,
    /// `name:port`, an IPv4 address, or a bracketed IPv6 address, each with an
    /// optional port.
    fn parse(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > 1024 {
            return None;
        }
        if let Some(rest) = value.strip_prefix('[') {
            let (literal, after) = rest.split_once(']')?;
            let ip = literal.parse::<Ipv6Addr>().ok()?;
            let port = match after {
                "" => None,
                _ => parse_port(after.strip_prefix(':')?)?,
            };
            return Some(Self {
                host: ip.to_string(),
                port,
            });
        }
        let (host, port) = match value.split_once(':') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (value, None),
        };
        if host.is_empty() || !host.bytes().all(is_reg_name_byte) {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// Parse an allowed-host entry, which may also be a bare IPv6 address.
    fn parse_entry(value: &str) -> Option<Self> {
        let value = value.trim();
        if let Ok(ip) = value.parse::<Ipv6Addr>() {
            return Some(Self {
                host: ip.to_string(),
                port: None,
            });
        }
        Self::parse(value)
    }
}

/// A port: empty (no port) or one to five digits that fit in a `u16`.
fn parse_port(port: &str) -> Option<Option<u16>> {
    if port.is_empty() {
        return Some(None);
    }
    if port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse().ok().map(Some)
}

/// A byte allowed in a URI `reg-name` or IPv4 address (RFC 3986).
fn is_reg_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        )
}

/// A serialized `Origin` header naming an `http` or `https` site.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    https: bool,
    authority: Authority,
}

impl Origin {
    /// Parse `scheme://host[:port]`. `null`, other schemes, and anything with
    /// a path, query, or user info are not web origins this guard accepts.
    fn parse(value: &str) -> Option<Self> {
        let (scheme, rest) = value.split_once("://")?;
        let https = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return None;
        };
        let authority = Authority::parse(rest.strip_suffix('/').unwrap_or(rest))?;
        Some(Self { https, authority })
    }

    /// The port the origin talks to, filling in the scheme default.
    fn effective_port(&self) -> u16 {
        self.authority
            .port
            .unwrap_or(if self.https { 443 } else { 80 })
    }
}

/// Why [`HostGuard::check`] refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The `Host` header is missing, not UTF-8, or malformed.
    MalformedHost,
    /// The `Host` header names a host outside the allowed set.
    ForbiddenHost,
    /// The `Origin` header is malformed or names a site outside the allowed
    /// set.
    ForbiddenOrigin,
}

impl Rejection {
    /// The HTTP status code to answer with.
    pub fn status(self) -> u16 {
        match self {
            Rejection::MalformedHost => 400,
            Rejection::ForbiddenHost | Rejection::ForbiddenOrigin => 403,
        }
    }

    /// A short response body naming the problem.
    pub fn message(self) -> &'static str {
        match self {
            Rejection::MalformedHost => "missing or malformed Host header",
            Rejection::ForbiddenHost => "Host header is not allowed",
            Rejection::ForbiddenOrigin => "Origin header is not allowed",
        }
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// The set of `Host` header values a listener accepts.
///
/// An entry without a port matches every port; `name:port` matches only that
/// port. Built with [`HostGuard::any`], the guard accepts every host and
/// accepts an `Origin` only when it names the request's own `Host`, so a
/// cross-origin page still cannot drive the endpoint through the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGuard {
    /// `None` accepts every host.
    allowed: Option<Vec<Authority>>,
}

impl Default for HostGuard {
    fn default() -> Self {
        Self::loopback()
    }
}

impl HostGuard {
    /// Accept [`LOOPBACK_HOSTS`] on any port.
    pub fn loopback() -> Self {
        Self::new(LOOPBACK_HOSTS).expect("loopback hosts parse")
    }

    /// Accept every host. Origins must still match the request's `Host`.
    pub fn any() -> Self {
        Self { allowed: None }
    }

    /// Accept exactly `hosts`: host names, IP addresses (IPv6 bare or in
    /// brackets), each with an optional `:port`. An empty list means
    /// [`HostGuard::loopback`]. Returns the first entry that does not parse.
    pub fn new<I, S>(hosts: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowed = Vec::new();
        for host in hosts {
            let host = host.as_ref();
            let authority = Authority::parse_entry(host)
                .ok_or_else(|| format!("invalid allowed host '{host}'"))?;
            if !allowed.contains(&authority) {
                allowed.push(authority);
            }
        }
        if allowed.is_empty() {
            return Ok(Self::loopback());
        }
        Ok(Self {
            allowed: Some(allowed),
        })
    }

    /// The default guard for a listener bound to `bind`: [`LOOPBACK_HOSTS`],
    /// the bind IP when it is a specific address, and `extra`.
    pub fn for_bind<S: AsRef<str>>(bind: IpAddr, extra: &[S]) -> Result<Self, String> {
        Self::new(default_hosts(bind, extra))
    }

    /// Whether this guard accepts every host.
    pub fn is_any(&self) -> bool {
        self.allowed.is_none()
    }

    /// The accepted hosts as configured, or `None` for [`HostGuard::any`].
    /// IPv6 addresses come back without brackets.
    pub fn hosts(&self) -> Option<Vec<String>> {
        self.allowed.as_ref().map(|list| {
            list.iter()
                .map(|a| match a.port {
                    Some(port) if a.host.contains(':') => format!("[{}]:{port}", a.host),
                    Some(port) => format!("{}:{port}", a.host),
                    None => a.host.clone(),
                })
                .collect()
        })
    }

    /// Check one request.
    ///
    /// `host` is the raw `Host` header; `authority` is the request target's
    /// authority, which HTTP/2 carries instead of `Host`; `origin` is the raw
    /// `Origin` header.
    pub fn check(
        &self,
        host: Option<&[u8]>,
        authority: Option<&str>,
        origin: Option<&[u8]>,
    ) -> Result<(), Rejection> {
        let request_host = match host {
            Some(raw) => Some(
                std::str::from_utf8(raw)
                    .ok()
                    .and_then(Authority::parse)
                    .ok_or(Rejection::MalformedHost)?,
            ),
            None => authority.and_then(Authority::parse),
        };
        if let Some(allowed) = &self.allowed {
            let request_host = request_host.as_ref().ok_or(Rejection::MalformedHost)?;
            if !allowed.iter().any(|a| host_matches(a, request_host)) {
                return Err(Rejection::ForbiddenHost);
            }
        }
        let Some(raw) = origin else {
            return Ok(());
        };
        let origin = std::str::from_utf8(raw)
            .ok()
            .and_then(Origin::parse)
            .ok_or(Rejection::ForbiddenOrigin)?;
        let accepted = match &self.allowed {
            Some(allowed) => allowed.iter().any(|a| origin_matches(a, &origin)),
            None => request_host
                .as_ref()
                .is_some_and(|host| same_site(host, &origin)),
        };
        if accepted {
            Ok(())
        } else {
            Err(Rejection::ForbiddenOrigin)
        }
    }
}

/// [`LOOPBACK_HOSTS`], then `bind` when it is a specific address, then
/// `extra`, without duplicates.
pub fn default_hosts<S: AsRef<str>>(bind: IpAddr, extra: &[S]) -> Vec<String> {
    let mut hosts: Vec<String> = LOOPBACK_HOSTS.iter().map(|h| h.to_string()).collect();
    if !bind.is_unspecified() {
        hosts.push(bind.to_string());
    }
    hosts.extend(extra.iter().map(|h| h.as_ref().to_string()));
    let mut seen = std::collections::HashSet::new();
    hosts.retain(|host| seen.insert(host.clone()));
    hosts
}

/// The default guard for `bind` when authentication is configured: a
/// non-loopback bind accepts every host unless `extra` narrows it.
pub fn guard_for_listener<S: AsRef<str>>(
    bind: SocketAddr,
    extra: &[S],
    authenticated: bool,
) -> Result<HostGuard, String> {
    let any = extra.iter().any(|h| h.as_ref().trim() == ANY_HOST);
    if any {
        if extra.len() > 1 {
            return Err(format!(
                "allowed host '{ANY_HOST}' cannot be combined with other hosts"
            ));
        }
        if !authenticated {
            return Err(format!(
                "allowed host '{ANY_HOST}' turns off Host validation and needs authentication"
            ));
        }
        return Ok(HostGuard::any());
    }
    if extra.is_empty() && authenticated && !bind.ip().is_loopback() {
        return Ok(HostGuard::any());
    }
    HostGuard::for_bind(bind.ip(), extra)
}

fn host_matches(allowed: &Authority, host: &Authority) -> bool {
    allowed.host == host.host && allowed.port.is_none_or(|port| host.port == Some(port))
}

fn origin_matches(allowed: &Authority, origin: &Origin) -> bool {
    allowed.host == origin.authority.host
        && allowed
            .port
            .is_none_or(|port| origin.effective_port() == port)
}

/// The origin names the same host and port as the request's `Host`.
fn same_site(host: &Authority, origin: &Origin) -> bool {
    host.host == origin.authority.host
        && host.port.unwrap_or(if origin.https { 443 } else { 80 }) == origin.effective_port()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(guard: &HostGuard, host: &str, origin: Option<&str>) -> Result<(), Rejection> {
        guard.check(Some(host.as_bytes()), None, origin.map(str::as_bytes))
    }

    #[test]
    fn loopback_names_pass_on_any_port() {
        let guard = HostGuard::loopback();
        for host in [
            "localhost",
            "LOCALHOST:9090",
            "127.0.0.1:1",
            "[::1]",
            "[::1]:9090",
        ] {
            assert_eq!(check(&guard, host, None), Ok(()), "{host}");
        }
    }

    #[test]
    fn foreign_and_malformed_hosts_are_refused() {
        let guard = HostGuard::loopback();
        assert_eq!(
            check(&guard, "evil.example", None),
            Err(Rejection::ForbiddenHost)
        );
        assert_eq!(
            check(&guard, "127.0.0.2:9090", None),
            Err(Rejection::ForbiddenHost)
        );
        assert_eq!(
            check(&guard, "localhost.evil.example", None),
            Err(Rejection::ForbiddenHost)
        );
        for host in [
            "",
            "::1",
            "[::1",
            "local host",
            "localhost:99999",
            "localhost:x",
            "a:1:2",
        ] {
            assert_eq!(
                check(&guard, host, None),
                Err(Rejection::MalformedHost),
                "{host:?}"
            );
        }
        assert_eq!(
            guard.check(Some(b"\xffhost"), None, None),
            Err(Rejection::MalformedHost)
        );
        assert_eq!(guard.check(None, None, None), Err(Rejection::MalformedHost));
    }

    #[test]
    fn http2_authority_stands_in_for_a_missing_host() {
        let guard = HostGuard::loopback();
        assert_eq!(guard.check(None, Some("127.0.0.1:9090"), None), Ok(()));
        assert_eq!(
            guard.check(None, Some("evil.example"), None),
            Err(Rejection::ForbiddenHost)
        );
    }

    #[test]
    fn entries_with_a_port_match_only_that_port() {
        let guard = HostGuard::new(["api.example:8443", "[::1]:3000", "10.0.0.5"]).unwrap();
        assert_eq!(check(&guard, "api.example:8443", None), Ok(()));
        assert_eq!(
            check(&guard, "api.example", None),
            Err(Rejection::ForbiddenHost)
        );
        assert_eq!(
            check(&guard, "api.example:443", None),
            Err(Rejection::ForbiddenHost)
        );
        assert_eq!(check(&guard, "[::1]:3000", None), Ok(()));
        assert_eq!(
            check(&guard, "[::1]:3001", None),
            Err(Rejection::ForbiddenHost)
        );
        assert_eq!(check(&guard, "10.0.0.5:1", None), Ok(()));
    }

    #[test]
    fn origins_must_name_an_allowed_host() {
        let guard = HostGuard::loopback();
        for origin in [
            "http://localhost:3000",
            "https://127.0.0.1",
            "http://[::1]:8080",
        ] {
            assert_eq!(check(&guard, "localhost", Some(origin)), Ok(()), "{origin}");
        }
        for origin in [
            "https://evil.example",
            "null",
            "file://",
            "chrome-extension://abc",
            "http://localhost/path",
            "http://user@localhost",
            "",
        ] {
            assert_eq!(
                check(&guard, "localhost", Some(origin)),
                Err(Rejection::ForbiddenOrigin),
                "{origin:?}"
            );
        }
    }

    #[test]
    fn origin_ports_follow_scheme_defaults() {
        let guard = HostGuard::new(["app.example:443"]).unwrap();
        assert_eq!(
            check(&guard, "app.example:443", Some("https://app.example")),
            Ok(())
        );
        assert_eq!(
            check(&guard, "app.example:443", Some("http://app.example")),
            Err(Rejection::ForbiddenOrigin)
        );
    }

    #[test]
    fn any_host_still_requires_a_same_site_origin() {
        let guard = HostGuard::any();
        assert_eq!(check(&guard, "evil.example", None), Ok(()));
        assert_eq!(guard.check(None, None, None), Ok(()));
        assert_eq!(
            check(
                &guard,
                "rsigma.internal:9090",
                Some("https://rsigma.internal:9090")
            ),
            Ok(())
        );
        assert_eq!(
            check(&guard, "rsigma.internal", Some("https://rsigma.internal")),
            Ok(())
        );
        assert_eq!(
            check(&guard, "rsigma.internal:9090", Some("https://evil.example")),
            Err(Rejection::ForbiddenOrigin)
        );
        assert_eq!(
            check(
                &guard,
                "rsigma.internal:9090",
                Some("https://rsigma.internal:9091")
            ),
            Err(Rejection::ForbiddenOrigin)
        );
        assert_eq!(
            guard.check(None, None, Some(b"https://rsigma.internal")),
            Err(Rejection::ForbiddenOrigin)
        );
    }

    #[test]
    fn default_hosts_add_a_specific_bind_ip_and_extras() {
        let v4: IpAddr = "10.0.0.5".parse().unwrap();
        assert_eq!(
            default_hosts(v4, &["api.example", "localhost"]),
            ["localhost", "127.0.0.1", "::1", "10.0.0.5", "api.example"]
        );
        let any: IpAddr = "0.0.0.0".parse().unwrap();
        assert_eq!(default_hosts::<&str>(any, &[]), LOOPBACK_HOSTS);
        let v6: IpAddr = "fd00::1".parse().unwrap();
        let guard = HostGuard::for_bind::<&str>(v6, &[]).unwrap();
        assert_eq!(check(&guard, "[fd00::1]:9090", None), Ok(()));
    }

    #[test]
    fn listener_guard_follows_bind_and_authentication() {
        let public: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let none: [&str; 0] = [];
        assert!(guard_for_listener(public, &none, true).unwrap().is_any());
        assert!(!guard_for_listener(public, &none, false).unwrap().is_any());
        assert!(!guard_for_listener(loopback, &none, true).unwrap().is_any());
        assert!(guard_for_listener(public, &["*"], true).unwrap().is_any());
        assert!(guard_for_listener(loopback, &["*"], true).unwrap().is_any());
        let err = guard_for_listener(public, &["*"], false).unwrap_err();
        assert!(err.contains("needs authentication"), "{err}");
        let err = guard_for_listener(public, &["*", "a.example"], true).unwrap_err();
        assert!(err.contains("cannot be combined"), "{err}");
        let narrowed = guard_for_listener(public, &["a.example"], true).unwrap();
        assert_eq!(
            narrowed.hosts().unwrap(),
            ["localhost", "127.0.0.1", "::1", "a.example"]
        );
    }

    #[test]
    fn invalid_entries_are_reported() {
        let err = HostGuard::new(["ok.example", "bad host"]).unwrap_err();
        assert!(err.contains("bad host"), "{err}");
        assert_eq!(
            HostGuard::new(Vec::<String>::new()).unwrap(),
            HostGuard::loopback()
        );
        assert_eq!(
            HostGuard::new(["[::1]:8080", "::1"])
                .unwrap()
                .hosts()
                .unwrap(),
            ["[::1]:8080", "::1"]
        );
    }

    #[test]
    fn an_entry_accepts_its_own_spelling_as_a_host() {
        for entry in [
            "Example.COM",
            "example.com:8080",
            "[fe80::1]:1",
            "192.0.2.1",
        ] {
            let guard = HostGuard::new([entry]).unwrap();
            assert_eq!(check(&guard, entry, None), Ok(()), "{entry}");
        }
    }
}
