//! Downloads of the remote inputs commands accept in place of a local file:
//! the `rule coverage` Atomic Red Team index and baseline layer, the
//! `rule visibility` mapping table, and the `rule scorecard` and
//! `rule hygiene` metrics source.
//!
//! Every download follows the daemon's default egress policy: a link-local
//! or cloud-metadata address is refused whether the URL names it, a hostname
//! resolves to it, or a redirect leads to it.

/// Whether `spec` names a remote input (an `http` or `https` URL) rather
/// than a local path.
pub(crate) fn is_remote(spec: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        spec.get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    })
}

/// Download `url` as text under the default egress policy. The error does
/// not repeat the URL.
pub(crate) fn get_text(url: &str) -> Result<String, String> {
    #[cfg(feature = "ocsf")]
    {
        http::warn_about_proxy();
        http::get_text(
            url,
            rsigma_runtime::default_egress_policy(),
            ureq::Proxy::try_from_env(),
        )
    }
    #[cfg(not(feature = "ocsf"))]
    {
        let _ = url;
        Err("downloads need the egress policy of the default `daemon` feature (or `ocsf`); rebuild with it or pass a local file".to_string())
    }
}

#[cfg(feature = "ocsf")]
mod http {
    use std::io;

    use rsigma_runtime::EgressPolicy;
    use ureq::config::Config;
    use ureq::http::Uri;
    use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
    use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

    /// Redirect hops followed before giving up, as the daemon's clients do.
    const MAX_REDIRECTS: usize = 10;

    /// Resolves hostnames and keeps only the addresses `policy` permits, so
    /// the connection goes to an address that passed the check even when DNS
    /// answers differently on a second lookup.
    #[derive(Debug)]
    struct EgressResolver {
        policy: EgressPolicy,
        inner: DefaultResolver,
    }

    impl Resolver for EgressResolver {
        fn resolve(
            &self,
            uri: &Uri,
            config: &Config,
            timeout: NextTimeout,
        ) -> Result<ResolvedSocketAddrs, ureq::Error> {
            let resolved = self.inner.resolve(uri, config, timeout)?;
            let mut permitted = self.inner.empty();
            let mut denial = None;
            for address in resolved.iter() {
                match self.policy.permit_ip(address.ip()) {
                    Ok(()) => permitted.push(*address),
                    Err(error) => {
                        denial.get_or_insert(error);
                    }
                }
            }
            match denial {
                Some(error) if permitted.is_empty() => Err(ureq::Error::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    error.to_string(),
                ))),
                _ => Ok(permitted),
            }
        }
    }

    /// Download `url` under `policy`, following redirects one hop at a time
    /// so each target is checked before it is requested.
    pub(super) fn get_text(
        url: &str,
        policy: EgressPolicy,
        proxy: Option<ureq::Proxy>,
    ) -> Result<String, String> {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .proxy(proxy)
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            DefaultConnector::new(),
            EgressResolver {
                policy,
                inner: DefaultResolver::default(),
            },
        );
        let mut current = url::Url::parse(url).map_err(|error| format!("invalid URL: {error}"))?;
        for _ in 0..=MAX_REDIRECTS {
            policy
                .check_url(current.as_str())
                .map_err(|denial| denial.to_string())?;
            let response = agent
                .get(current.as_str())
                .call()
                .map_err(|error| error.to_string())?;
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| format!("HTTP {} redirect has no Location", status.as_u16()))?;
                current = current
                    .join(location)
                    .map_err(|error| format!("invalid redirect to {location}: {error}"))?;
                continue;
            }
            if !status.is_success() {
                return Err(format!("http status: {}", status.as_u16()));
            }
            return response
                .into_body()
                .read_to_string()
                .map_err(|error| format!("reading the response: {error}"));
        }
        Err("too many redirects".to_string())
    }

    /// Say once that a configured proxy resolves hostnames itself, so only
    /// IP-literal URLs and redirect targets stay under the policy.
    pub(super) fn warn_about_proxy() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        let proxies: Vec<&str> = [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ]
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .collect();
        if !proxies.is_empty() {
            WARNED.call_once(|| {
                eprintln!(
                    "warning: an HTTP proxy is configured ({}): it resolves hostnames, so the egress policy checks only IP-literal URLs and redirect targets",
                    proxies.join(",")
                );
            });
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Serve `responses` in order, one per connection, on 127.0.0.1, and
        /// count the connections.
        fn serve(responses: Vec<String>) -> (String, Arc<AtomicUsize>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let connections = Arc::new(AtomicUsize::new(0));
            let counter = connections.clone();
            std::thread::spawn(move || {
                for (stream, response) in listener.incoming().zip(responses) {
                    let Ok(mut stream) = stream else { break };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                        line.clear();
                    }
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            (format!("127.0.0.1:{port}"), connections)
        }

        fn redirect(to: &str) -> String {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        }

        fn ok(body: &str) -> String {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        #[test]
        fn downloads_and_follows_an_allowed_redirect() {
            let (addr, connections) = serve(vec![redirect("/next"), ok("payload")]);
            let body = get_text(
                &format!("http://{addr}/start"),
                EgressPolicy::default(),
                None,
            )
            .unwrap();
            assert_eq!(body, "payload");
            assert_eq!(connections.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn refuses_link_local_and_metadata_literals() {
            for url in [
                "http://169.254.169.254/latest/meta-data/",
                "http://[fd00:ec2::254]/",
                "http://100.100.100.200/",
                "http://[::ffff:169.254.169.254]/",
            ] {
                let error = get_text(url, EgressPolicy::default(), None).unwrap_err();
                assert!(error.contains("egress policy denied"), "{url}: {error}");
            }
        }

        #[test]
        fn refuses_a_redirect_to_a_metadata_address() {
            for target in [
                "http://169.254.169.254/latest/meta-data/iam/",
                "http://[fd00:ec2::254]/latest/",
                "http://[fe80::1]/",
            ] {
                let (addr, connections) = serve(vec![redirect(target)]);
                let error = get_text(&format!("http://{addr}/"), EgressPolicy::default(), None)
                    .unwrap_err();
                assert!(error.contains("egress policy denied"), "{target}: {error}");
                assert_eq!(connections.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn filters_the_addresses_a_hostname_resolves_to() {
            let (addr, connections) = serve(vec![ok("never")]);
            let port = addr.rsplit_once(':').unwrap().1;
            let error = get_text(
                &format!("http://localhost:{port}/"),
                EgressPolicy::default().with_block_loopback(true),
                None,
            )
            .unwrap_err();
            assert!(
                error.contains("egress policy denied loopback address"),
                "{error}"
            );
            assert_eq!(connections.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn reports_an_error_status() {
            let (addr, _) = serve(vec![
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
            ]);
            let error =
                get_text(&format!("http://{addr}/"), EgressPolicy::default(), None).unwrap_err();
            assert_eq!(error, "http status: 404");
        }

        #[test]
        fn stops_after_too_many_redirects() {
            let (addr, _) = serve(vec![redirect("/again"); MAX_REDIRECTS + 1]);
            let error =
                get_text(&format!("http://{addr}/"), EgressPolicy::default(), None).unwrap_err();
            assert_eq!(error, "too many redirects");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_remote;

    #[test]
    fn remote_specs_are_http_and_https_urls_in_any_case() {
        for spec in [
            "http://x/metrics",
            "https://x",
            "HTTPS://X/index.yaml",
            "Http://x",
        ] {
            assert!(is_remote(spec), "{spec}");
        }
        for spec in [
            "./metrics.txt",
            "/srv/http/index.yaml",
            "file:///x",
            "ftp://x",
            "http:/x",
            "",
        ] {
            assert!(!is_remote(spec), "{spec}");
        }
    }
}
