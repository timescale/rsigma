use std::path::PathBuf;

/// NATS connection configuration shared between source and sink.
///
/// Holds optional authentication and TLS fields. When no auth is configured,
/// connects without credentials (suitable for local development).
#[derive(Debug, Clone, Default)]
pub struct NatsConnectConfig {
    pub url: String,
    pub credentials_file: Option<PathBuf>,
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub nkey: Option<String>,
    pub tls_client_cert: Option<PathBuf>,
    pub tls_client_key: Option<PathBuf>,
    pub require_tls: bool,
}

impl NatsConnectConfig {
    pub fn new(url: String) -> Self {
        Self {
            url,
            ..Default::default()
        }
    }

    /// Build an `async_nats::Client` from this configuration.
    ///
    /// Auth methods are mutually exclusive; the first one found wins
    /// (credentials file > token > user/password > nkey).
    pub async fn connect(&self) -> Result<async_nats::Client, async_nats::Error> {
        let options = if let Some(ref path) = self.credentials_file {
            async_nats::ConnectOptions::with_credentials_file(path).await?
        } else if let Some(ref token) = self.token {
            async_nats::ConnectOptions::with_token(token.clone())
        } else if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            async_nats::ConnectOptions::with_user_and_password(user.clone(), pass.clone())
        } else if let Some(ref seed) = self.nkey {
            async_nats::ConnectOptions::with_nkey(seed.clone())
        } else {
            async_nats::ConnectOptions::new()
        };

        let mut options = options;

        if let (Some(cert), Some(key)) = (&self.tls_client_cert, &self.tls_client_key) {
            options = options.add_client_certificate(cert.clone(), key.clone());
        }

        if self.require_tls {
            options = options.require_tls(true);
        }

        ensure_crypto_provider();

        options.connect(&self.url).await.map_err(|e| e.into())
    }
}

/// Pin the process-default rustls `CryptoProvider` before async-nats builds its
/// TLS client config, which it does from the process default whenever the
/// connection is upgraded: `require_tls`, a `tls://` URL, or a server whose
/// INFO requires TLS.
///
/// With the `otlp` feature, tonic pulls aws-lc-rs and async-nats pulls ring, so
/// rustls cannot auto-select a default and the upgrade would panic; pin
/// aws-lc-rs to match the daemon's other TLS surfaces. Without `otlp` this
/// crate brings a single provider, so this is a no-op.
fn ensure_crypto_provider() {
    #[cfg(feature = "otlp")]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A server whose INFO requires TLS makes the client upgrade, which builds
    /// its rustls config. With aws-lc-rs and ring both compiled in, that
    /// panicked until a default provider was pinned; now the failed handshake
    /// is returned as an error.
    #[tokio::test]
    async fn tls_upgrade_returns_an_error_instead_of_panicking() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let info = format!(
                "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\
                 \"port\":{port},\"max_payload\":1048576,\"proto\":1,\"tls_required\":true}}\r\n"
            );
            socket.write_all(info.as_bytes()).await.unwrap();
            // Not a TLS server: closing the socket ends the client's handshake.
        });
        let config = NatsConnectConfig::new(format!("nats://127.0.0.1:{port}"));
        let result = tokio::time::timeout(Duration::from_secs(10), config.connect())
            .await
            .expect("connect did not return");
        assert!(result.is_err());
        server.await.unwrap();
    }
}
