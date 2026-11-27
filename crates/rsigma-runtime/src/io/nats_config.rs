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
/// INFO requires TLS. Called before every NATS connection in this crate:
/// [`NatsConnectConfig::connect`] and the dynamic sources' own clients
/// (`sources::nats`, `sources::refresh`).
///
/// With the `otlp` feature, tonic pulls aws-lc-rs and async-nats pulls ring, so
/// rustls cannot auto-select a default and the upgrade would panic; pin
/// aws-lc-rs to match the daemon's other TLS surfaces. Without `otlp` this
/// crate brings a single provider, so this is a no-op, and a binary that links
/// another installs its own default (the CLI does at startup).
pub(crate) fn ensure_crypto_provider() {
    #[cfg(feature = "otlp")]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}
