use std::path::PathBuf;

use rdkafka::ClientConfig;

/// Kafka connection configuration shared between source and sink.
///
/// Holds optional authentication and TLS fields. When no SASL/SSL is configured,
/// connects in PLAINTEXT mode (suitable for local development).
#[derive(Debug, Clone, Default)]
pub struct KafkaConnectConfig {
    pub bootstrap_servers: String,
    pub consumer_group: String,
    pub security_protocol: Option<String>,
    pub sasl_mechanism: Option<String>,
    pub sasl_username: Option<String>,
    pub sasl_password: Option<String>,
    pub ssl_ca_cert: Option<PathBuf>,
    pub ssl_client_cert: Option<PathBuf>,
    pub ssl_client_key: Option<PathBuf>,
    pub auto_offset_reset: Option<String>,
    pub session_timeout_ms: Option<u32>,
    pub max_poll_interval_ms: Option<u32>,
}

impl KafkaConnectConfig {
    pub fn new(bootstrap_servers: String, consumer_group: String) -> Self {
        Self {
            bootstrap_servers,
            consumer_group,
            ..Default::default()
        }
    }

    /// Build an `rdkafka::ClientConfig` from this configuration.
    ///
    /// Always disables auto-commit (manual commit on ack for at-least-once).
    pub fn to_client_config(&self) -> ClientConfig {
        let mut cfg = ClientConfig::new();
        cfg.set("bootstrap.servers", &self.bootstrap_servers);
        cfg.set("group.id", &self.consumer_group);
        cfg.set("enable.auto.commit", "false");
        cfg.set(
            "auto.offset.reset",
            self.auto_offset_reset.as_deref().unwrap_or("earliest"),
        );

        if let Some(ref protocol) = self.security_protocol {
            cfg.set("security.protocol", protocol);
        }
        if let Some(ref mechanism) = self.sasl_mechanism {
            cfg.set("sasl.mechanism", mechanism);
        }
        if let Some(ref username) = self.sasl_username {
            cfg.set("sasl.username", username);
        }
        if let Some(ref password) = self.sasl_password {
            cfg.set("sasl.password", password);
        }
        if let Some(ref ca) = self.ssl_ca_cert {
            cfg.set("ssl.ca.location", ca.display().to_string());
        }
        if let Some(ref cert) = self.ssl_client_cert {
            cfg.set("ssl.certificate.location", cert.display().to_string());
        }
        if let Some(ref key) = self.ssl_client_key {
            cfg.set("ssl.key.location", key.display().to_string());
        }
        if let Some(timeout) = self.session_timeout_ms {
            cfg.set("session.timeout.ms", timeout.to_string());
        }
        if let Some(interval) = self.max_poll_interval_ms {
            cfg.set("max.poll.interval.ms", interval.to_string());
        }

        cfg
    }
}
