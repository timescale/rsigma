//! Listen address for the daemon API server: a TCP `host:port` or, on Unix, a
//! `unix:///path/to.sock` domain socket.
//!
//! A Unix socket is gated by filesystem permissions rather than TLS, so it is
//! treated as a local trust boundary: TLS is rejected on a `unix://` address
//! and the plaintext-bind refusal does not apply.

use std::fmt;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;

/// Where the daemon API server listens.
#[derive(Clone, Debug)]
pub(crate) enum ListenAddr {
    /// A TCP socket address.
    Tcp(SocketAddr),
    /// A Unix domain socket path (Unix only).
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenAddr {
    /// Parse `--api-addr`: a `unix://` URI becomes [`ListenAddr::Unix`],
    /// anything else is parsed as a TCP `SocketAddr`.
    pub(crate) fn parse(spec: &str) -> Result<Self, String> {
        if let Some(path) = spec.strip_prefix("unix://") {
            #[cfg(unix)]
            {
                if path.is_empty() {
                    return Err("unix:// socket path is empty".to_string());
                }
                return Ok(ListenAddr::Unix(PathBuf::from(path)));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(
                    "unix:// API addresses are only supported on Unix platforms".to_string()
                );
            }
        }
        spec.parse::<SocketAddr>()
            .map(ListenAddr::Tcp)
            .map_err(|e| format!("expected host:port or unix://path: {e}"))
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenAddr::Tcp(addr) => write!(f, "{addr}"),
            #[cfg(unix)]
            ListenAddr::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_addr() {
        let addr = ListenAddr::parse("127.0.0.1:9090").unwrap();
        assert!(matches!(addr, ListenAddr::Tcp(_)));
        assert_eq!(addr.to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn rejects_garbage() {
        assert!(ListenAddr::parse("not-an-addr").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parses_unix_path() {
        let addr = ListenAddr::parse("unix:///run/rsigma/api.sock").unwrap();
        assert!(matches!(addr, ListenAddr::Unix(_)));
        assert_eq!(addr.to_string(), "unix:///run/rsigma/api.sock");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_empty_unix_path() {
        assert!(ListenAddr::parse("unix://").is_err());
    }
}
