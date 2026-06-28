//! YAML schema, validation, and loader for a webhooks config file.
//!
//! Declared via `--webhook <PATH>` (repeatable; file or directory) and the
//! layered `daemon.output.webhooks` key. Loaded once at daemon startup. The
//! validator rejects startup with a clear, field-scoped error when:
//!
//! - `kind` is not `detection` or `correlation` (`incident` arrives with
//!   roadmap item #48),
//! - a templated field (`url`, a header value, `body`) references the wrong
//!   namespace for the declared `kind`, or is malformed,
//! - `url` is empty, the `method` is invalid, `retry.attempts` is zero, a
//!   duration fails to parse, or `scope` fails to compile.
//!
//! Core logic (template render, classification, rate limiting) lives in
//! [`super::sink`]; the queue, retry/backoff, and DLQ routing are the shared
//! `crate::io::delivery` layer, not re-implemented here.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsigma_eval::ResultBody;
use serde::Deserialize;

use crate::enrichment::{
    EnricherKind, HttpEnricherClient, Scope, TemplateError, build_default_http_client,
    validate_template_namespace,
};
use crate::io::DeliveryConfig;
use crate::metrics::MetricsHook;

use super::signing::{Algorithm, CustomScheme, Encoding, SigningScheme, WebhookSigner};
use super::sink::{TokenBucket, WebhookSink};

/// Default per-request timeout when `timeout:` is omitted.
pub const DEFAULT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
/// Default total attempts (one initial try plus retries).
pub const DEFAULT_WEBHOOK_ATTEMPTS: u32 = 3;
/// Default exponential backoff base.
pub const DEFAULT_WEBHOOK_BACKOFF: Duration = Duration::from_secs(1);
/// Default backoff ceiling.
pub const DEFAULT_WEBHOOK_MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Default bounded queue depth between the dispatcher and the worker.
pub const DEFAULT_WEBHOOK_QUEUE_SIZE: usize = 1024;

/// Top-level webhooks config file.
///
/// ```yaml
/// webhooks:
///   - id: slack-critical
///     kind: detection
///     url: https://hooks.slack.com/services/${SLACK_WEBHOOK_PATH}
///     body: |
///       {"text": "Sigma: ${detection.rule.title} (${detection.rule.level})"}
///     scope:
///       levels: [high, critical]
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct WebhooksFile {
    /// Per-webhook configurations. An empty list (or missing key) is allowed
    /// so an operator can keep a webhooks file around during a rollout.
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

/// One webhook's YAML config block.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// Stable identifier; used as the metric label and in config errors.
    pub id: String,
    /// `detection` or `correlation`. Deserialized as a free-form string so an
    /// unknown value (e.g. `incident`) produces the forward-looking error
    /// rather than a generic serde "unknown variant".
    pub kind: String,
    /// Target URL template (`${detection.*}` / `${correlation.*}` / `${ENV}`).
    pub url: String,
    /// HTTP method. Defaults to `POST`.
    #[serde(default)]
    pub method: Option<String>,
    /// Header templates. Values are rendered per result (identity escaping).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Request body template. Rendered with JSON-string escaping so
    /// interpolated values cannot break the document.
    #[serde(default)]
    pub body: Option<String>,
    /// Per-request timeout. Accepts humantime strings (`5s`, `200ms`).
    #[serde(default, with = "humantime_opt")]
    pub timeout: Option<Duration>,
    /// Retry tuning. Overrides the daemon's `--sink-*` delivery defaults.
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Optional per-entry rate limit (token bucket).
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Optional scope filter (same axes as enrichers: rules/tags/levels).
    #[serde(default)]
    pub scope: Option<ScopeConfig>,
    /// Bounded queue depth. Defaults to [`DEFAULT_WEBHOOK_QUEUE_SIZE`].
    #[serde(default)]
    pub queue_size: Option<usize>,
    /// Optional TLS material for the endpoint: a custom CA bundle and/or a
    /// client identity for mutual TLS. Omit it to use the system roots (the
    /// common case for public services like Slack).
    #[serde(default)]
    pub tls: Option<WebhookTlsConfig>,
    /// Optional HMAC request signing. Adds signature headers a receiving
    /// endpoint can verify; see [`SigningConfig`].
    #[serde(default)]
    pub signing: Option<SigningConfig>,
}

/// `tls:` block. PEM file paths read at startup.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WebhookTlsConfig {
    /// Custom CA bundle (PEM file path) to trust in addition to the system
    /// roots. Use for an internal relay served by a private CA.
    #[serde(default)]
    pub ca: Option<String>,
    /// Client certificate chain (PEM file path) for mutual TLS. Requires
    /// `client_key`.
    #[serde(default)]
    pub client_cert: Option<String>,
    /// Client private key (PEM file path) for mutual TLS. Requires
    /// `client_cert`.
    #[serde(default)]
    pub client_key: Option<String>,
}

/// `signing:` block. HMAC-signs each request so a receiver can verify it.
///
/// The secret never lives in the YAML: `secret_env` names an environment
/// variable, resolved once at startup so a missing key fails fast.
///
/// ```yaml
/// signing:
///   secret_env: RSIGMA_WEBHOOK_SECRET
///   scheme: standard            # standard (default) | github | custom
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct SigningConfig {
    /// Environment variable holding the HMAC key. Required.
    pub secret_env: String,
    /// How the env value is decoded into key bytes: `utf8` (default) treats it
    /// as raw bytes; `base64` decodes it (stripping an optional `whsec_`
    /// prefix) so a Standard Webhooks secret can be pasted verbatim.
    #[serde(default)]
    pub secret_encoding: Option<String>,
    /// Signing convention: `standard` (default), `github`, or `custom`.
    #[serde(default)]
    pub scheme: Option<String>,
    /// Optional second key (from another env var) emitted as a second
    /// signature during a key rollover. Not supported by `github`.
    #[serde(default)]
    pub rotate_secret_env: Option<String>,
    /// Knobs honored only when `scheme: custom`.
    #[serde(default)]
    pub custom: Option<CustomSigningConfig>,
}

/// `signing.custom:` block. Honored only when `scheme: custom`.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomSigningConfig {
    /// HMAC hash: `sha256` (default) or `sha512`.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Signature encoding: `hex` (default) or `base64`.
    #[serde(default)]
    pub encoding: Option<String>,
    /// Header name carrying the signature value.
    pub signature_header: String,
    /// Header value template; must contain `{signature}`. Also supports
    /// `{timestamp}` and `{id}`.
    pub value_format: String,
    /// What gets HMAC'd. Supports `{body}`, `{timestamp}`, and `{id}`.
    pub signed_payload: String,
    /// Optional separate header carrying the unix-seconds timestamp.
    #[serde(default)]
    pub timestamp_header: Option<String>,
    /// Optional separate header carrying the per-delivery id.
    #[serde(default)]
    pub id_header: Option<String>,
}

/// `retry:` block. Each field overrides a delivery-layer default.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RetryConfig {
    /// Total tries (one initial plus retries). Defaults to
    /// [`DEFAULT_WEBHOOK_ATTEMPTS`]; must be at least 1.
    #[serde(default)]
    pub attempts: Option<u32>,
    /// Exponential backoff base. Defaults to [`DEFAULT_WEBHOOK_BACKOFF`].
    #[serde(default, with = "humantime_opt")]
    pub backoff: Option<Duration>,
    /// Backoff ceiling. Defaults to [`DEFAULT_WEBHOOK_MAX_BACKOFF`].
    #[serde(default, with = "humantime_opt")]
    pub max_backoff: Option<Duration>,
}

/// `rate_limit:` block. `requests` per `per`, burst = `requests`.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Sustained request budget per window.
    pub requests: u32,
    /// Window length. Accepts humantime strings (`1m`, `30s`).
    #[serde(with = "humantime_dur")]
    pub per: Duration,
}

/// `scope:` block. Mirrors the enrichment scope axes.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScopeConfig {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub levels: Vec<String>,
}

/// Parsed `kind:` discriminator.
///
/// Deliberately a closed enum so #48 can add `Incident` additively without any
/// existing config key changing meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookKind {
    /// Fires on detection results ([`ResultBody::Detection`]).
    Detection,
    /// Fires on correlation results ([`ResultBody::Correlation`]).
    Correlation,
}

impl WebhookKind {
    /// String label used in config errors and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            WebhookKind::Detection => "detection",
            WebhookKind::Correlation => "correlation",
        }
    }

    /// Map onto the shared [`EnricherKind`] so the template-namespace validator
    /// (which is kind-agnostic past detection/correlation) can be reused.
    pub(crate) fn as_enricher_kind(self) -> EnricherKind {
        match self {
            WebhookKind::Detection => EnricherKind::Detection,
            WebhookKind::Correlation => EnricherKind::Correlation,
        }
    }

    /// True when this kind matches the given result body variant.
    pub fn matches(self, body: &ResultBody) -> bool {
        self.as_enricher_kind().matches(body)
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "detection" => Some(WebhookKind::Detection),
            "correlation" => Some(WebhookKind::Correlation),
            _ => None,
        }
    }
}

/// A webhook sink plus the per-sink delivery config the dispatcher drives it
/// with. The full-queue policy is fixed to `Drop` by the caller (the lossy
/// seam that keeps a third-party HTTP endpoint off the at-least-once path).
pub struct BuiltWebhook {
    pub sink: WebhookSink,
    pub delivery: DeliveryConfig,
}

/// Errors produced while loading or validating a webhooks config.
#[derive(Debug)]
pub enum WebhookConfigError {
    /// File could not be read.
    Io(std::io::Error, std::path::PathBuf),
    /// YAML failed to deserialize.
    Yaml(yaml_serde::Error),
    /// `kind` was not `detection` or `correlation`.
    UnknownKind { webhook_id: String, kind: String },
    /// A required field was empty or missing.
    MissingField {
        webhook_id: String,
        field: &'static str,
    },
    /// `method` was not a valid HTTP method token.
    InvalidMethod { webhook_id: String, method: String },
    /// A templated field referenced the wrong namespace for the declared kind.
    CrossNamespace {
        webhook_id: String,
        kind: &'static str,
        reference: String,
        field: &'static str,
    },
    /// A templated field had a malformed `${...}` reference.
    MalformedTemplate {
        webhook_id: String,
        reference: String,
        field: &'static str,
    },
    /// `retry` settings were invalid (e.g. zero attempts).
    InvalidRetry { webhook_id: String, message: String },
    /// `rate_limit` settings were invalid.
    InvalidRateLimit { webhook_id: String, message: String },
    /// `scope` failed to compile.
    Scope { webhook_id: String, message: String },
    /// `tls` material was invalid or unreadable.
    Tls { webhook_id: String, message: String },
    /// A signing `secret_env` was unset or empty in the environment.
    MissingSecretEnv { webhook_id: String, var: String },
    /// A `signing` block was otherwise invalid (scheme, encoding, tokens,
    /// header collision).
    InvalidSigning { webhook_id: String, message: String },
    /// The shared HTTP client could not be built.
    Client { message: String },
}

impl std::fmt::Display for WebhookConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookConfigError::Io(e, p) => {
                write!(f, "failed to read webhooks config '{}': {e}", p.display())
            }
            WebhookConfigError::Yaml(e) => write!(f, "invalid webhooks YAML: {e}"),
            WebhookConfigError::UnknownKind { webhook_id, kind } => write!(
                f,
                "webhook '{webhook_id}': unknown kind '{kind}' (valid kinds: detection, correlation; incident arrives with roadmap item #48)"
            ),
            WebhookConfigError::MissingField { webhook_id, field } => {
                write!(
                    f,
                    "webhook '{webhook_id}': missing required field '{field}'"
                )
            }
            WebhookConfigError::InvalidMethod { webhook_id, method } => {
                write!(f, "webhook '{webhook_id}': invalid HTTP method '{method}'")
            }
            WebhookConfigError::CrossNamespace {
                webhook_id,
                kind,
                reference,
                field,
            } => write!(
                f,
                "webhook '{webhook_id}' (kind: {kind}): template reference '${{{reference}}}' in field '{field}' is the wrong namespace for a {kind} webhook"
            ),
            WebhookConfigError::MalformedTemplate {
                webhook_id,
                reference,
                field,
            } => write!(
                f,
                "webhook '{webhook_id}': malformed template reference '${{{reference}}}' in field '{field}'; expected ${{detection.*}}, ${{correlation.*}}, or ${{ENV_VAR}}"
            ),
            WebhookConfigError::InvalidRetry {
                webhook_id,
                message,
            } => write!(f, "webhook '{webhook_id}': {message}"),
            WebhookConfigError::InvalidRateLimit {
                webhook_id,
                message,
            } => write!(f, "webhook '{webhook_id}': {message}"),
            WebhookConfigError::Scope {
                webhook_id,
                message,
            } => write!(f, "webhook '{webhook_id}': {message}"),
            WebhookConfigError::Tls {
                webhook_id,
                message,
            } => write!(f, "webhook '{webhook_id}': {message}"),
            WebhookConfigError::MissingSecretEnv { webhook_id, var } => write!(
                f,
                "webhook '{webhook_id}': signing secret environment variable '{var}' is unset or empty"
            ),
            WebhookConfigError::InvalidSigning {
                webhook_id,
                message,
            } => write!(f, "webhook '{webhook_id}': {message}"),
            WebhookConfigError::Client { message } => {
                write!(f, "webhook HTTP client build failed: {message}")
            }
        }
    }
}

impl std::error::Error for WebhookConfigError {}

/// Read and deserialize a webhooks config file (no validation; see
/// [`build_webhooks`]).
pub fn load_webhooks_file(path: &Path) -> Result<WebhooksFile, WebhookConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| WebhookConfigError::Io(e, path.to_path_buf()))?;
    let parsed: WebhooksFile = yaml_serde::from_str(&text).map_err(WebhookConfigError::Yaml)?;
    Ok(parsed)
}

/// Validate and build every webhook in `file` into a [`BuiltWebhook`].
///
/// All webhooks share one process-level egress-filtered `reqwest::Client`
/// (via [`build_default_http_client`]) so connection pooling and the SSRF
/// defense are wired once. `metrics` receives the webhook-specific request /
/// rate-limit events; its labels are pre-seeded here so panels render before
/// traffic.
pub fn build_webhooks(
    file: WebhooksFile,
    metrics: Arc<dyn MetricsHook>,
) -> Result<Vec<BuiltWebhook>, WebhookConfigError> {
    let client =
        build_default_http_client().map_err(|message| WebhookConfigError::Client { message })?;
    let mut built = Vec::with_capacity(file.webhooks.len());
    for cfg in file.webhooks {
        built.push(build_one(cfg, client.clone(), metrics.clone())?);
    }
    Ok(built)
}

fn build_one(
    cfg: WebhookConfig,
    default_client: HttpEnricherClient,
    metrics: Arc<dyn MetricsHook>,
) -> Result<BuiltWebhook, WebhookConfigError> {
    let kind = WebhookKind::parse(&cfg.kind).ok_or_else(|| WebhookConfigError::UnknownKind {
        webhook_id: cfg.id.clone(),
        kind: cfg.kind.clone(),
    })?;
    if cfg.url.trim().is_empty() {
        return Err(WebhookConfigError::MissingField {
            webhook_id: cfg.id.clone(),
            field: "url",
        });
    }

    let ek = kind.as_enricher_kind();
    check_template(&cfg.url, ek, &cfg.id, "url")?;
    for (name, value) in &cfg.headers {
        let field: &'static str = Box::leak(format!("headers.{name}").into_boxed_str());
        check_template(value, ek, &cfg.id, field)?;
    }
    if let Some(body) = &cfg.body {
        check_template(body, ek, &cfg.id, "body")?;
    }

    let method = match &cfg.method {
        Some(m) => {
            reqwest::Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|_| {
                WebhookConfigError::InvalidMethod {
                    webhook_id: cfg.id.clone(),
                    method: m.clone(),
                }
            })?
        }
        None => reqwest::Method::POST,
    };

    let scope =
        match &cfg.scope {
            Some(s) => Scope::new(s.rules.clone(), s.tags.clone(), s.levels.clone()).map_err(
                |message| WebhookConfigError::Scope {
                    webhook_id: cfg.id.clone(),
                    message,
                },
            )?,
            None => Scope::default(),
        };

    let limiter = match &cfg.rate_limit {
        Some(rl) => {
            if rl.requests == 0 {
                return Err(WebhookConfigError::InvalidRateLimit {
                    webhook_id: cfg.id.clone(),
                    message: "rate_limit.requests must be at least 1".to_string(),
                });
            }
            if rl.per.is_zero() {
                return Err(WebhookConfigError::InvalidRateLimit {
                    webhook_id: cfg.id.clone(),
                    message: "rate_limit.per must be greater than zero".to_string(),
                });
            }
            Some(TokenBucket::new(rl.requests, rl.per))
        }
        None => None,
    };

    let retry = cfg.retry.clone().unwrap_or_default();
    let attempts = retry.attempts.unwrap_or(DEFAULT_WEBHOOK_ATTEMPTS);
    if attempts == 0 {
        return Err(WebhookConfigError::InvalidRetry {
            webhook_id: cfg.id.clone(),
            message: "retry.attempts must be at least 1".to_string(),
        });
    }

    let delivery = DeliveryConfig {
        queue_depth: cfg.queue_size.unwrap_or(DEFAULT_WEBHOOK_QUEUE_SIZE),
        // One rendered body per result; multi-result digest posts are out of
        // scope. The shared worker still owns the queue and retry schedule.
        batch_max: 1,
        batch_flush: DeliveryConfig::default().batch_flush,
        retry_max: attempts.saturating_sub(1),
        backoff_base: retry.backoff.unwrap_or(DEFAULT_WEBHOOK_BACKOFF),
        backoff_max: retry.max_backoff.unwrap_or(DEFAULT_WEBHOOK_MAX_BACKOFF),
    };

    let timeout = cfg.timeout.unwrap_or(DEFAULT_WEBHOOK_TIMEOUT);
    let headers: Vec<(String, String)> = cfg
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // A webhook with a `tls:` block gets a dedicated egress-filtered client
    // carrying its CA and/or client identity; the rest share the default.
    let client = match &cfg.tls {
        Some(tls) => build_tls_client(&cfg.id, tls)?,
        None => default_client,
    };

    let signer = match &cfg.signing {
        Some(s) => Some(build_signer(&cfg.id, s, &cfg.headers)?),
        None => None,
    };

    metrics.register_webhook(&cfg.id);
    let sink = WebhookSink::new(
        cfg.id, kind, method, cfg.url, headers, cfg.body, timeout, scope, limiter, client, metrics,
        signer,
    );
    Ok(BuiltWebhook { sink, delivery })
}

/// Build an egress-filtered `reqwest` client carrying a webhook's TLS material.
///
/// The CA bundle is trusted in addition to the system roots; a client cert and
/// key together enable mutual TLS. Egress filtering (SSRF defense) is preserved
/// via the same DNS resolver the default client uses.
fn build_tls_client(
    id: &str,
    tls: &WebhookTlsConfig,
) -> Result<HttpEnricherClient, WebhookConfigError> {
    let err = |message: String| WebhookConfigError::Tls {
        webhook_id: id.to_string(),
        message,
    };
    match (&tls.client_cert, &tls.client_key) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(err(
                "tls.client_cert and tls.client_key must be set together for mutual TLS"
                    .to_string(),
            ));
        }
    }

    ensure_crypto_provider();
    let resolver =
        crate::egress::EgressFilteredResolver::new(crate::egress::default_egress_policy())
            .into_dns_resolver();
    let mut builder = reqwest::Client::builder().dns_resolver(resolver);

    if let Some(ca_path) = &tls.ca {
        let pem = std::fs::read(ca_path)
            .map_err(|e| err(format!("failed to read tls.ca '{ca_path}': {e}")))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| err(format!("invalid tls.ca PEM: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }

    if let (Some(cert_path), Some(key_path)) = (&tls.client_cert, &tls.client_key) {
        let cert = std::fs::read(cert_path)
            .map_err(|e| err(format!("failed to read tls.client_cert '{cert_path}': {e}")))?;
        let key = std::fs::read(key_path)
            .map_err(|e| err(format!("failed to read tls.client_key '{key_path}': {e}")))?;
        // reqwest's rustls identity wants a single PEM buffer of cert + key.
        let mut pem = cert;
        pem.push(b'\n');
        pem.extend_from_slice(&key);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|e| err(format!("invalid client identity PEM: {e}")))?;
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map(|c| HttpEnricherClient::from_reqwest(std::sync::Arc::new(c)))
        .map_err(|e| err(format!("TLS client build failed: {e}")))
}

/// Pin the process-default rustls `CryptoProvider` when more than one is in the
/// dependency tree.
///
/// With the `otlp` feature, tonic pulls aws-lc-rs and reqwest pulls ring, so
/// rustls cannot auto-select a default and a TLS client build would panic; pin
/// aws-lc-rs to match the daemon's other TLS surfaces. Without `otlp` there is
/// a single provider and reqwest self-configures, so this is a no-op.
fn ensure_crypto_provider() {
    #[cfg(feature = "otlp")]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn check_template(
    text: &str,
    kind: EnricherKind,
    id: &str,
    field: &'static str,
) -> Result<(), WebhookConfigError> {
    validate_template_namespace(text, kind, id, field).map_err(|te| match te {
        TemplateError::CrossNamespace {
            reference, field, ..
        } => WebhookConfigError::CrossNamespace {
            webhook_id: id.to_string(),
            kind: kind.as_str(),
            reference,
            field,
        },
        TemplateError::Malformed {
            reference, field, ..
        } => WebhookConfigError::MalformedTemplate {
            webhook_id: id.to_string(),
            reference,
            field,
        },
    })
}

/// Validate a `signing:` block and build its [`WebhookSigner`].
///
/// Resolves the secret(s) from the environment, parses the scheme and its
/// knobs, and rejects a signing header that would collide with a user header.
fn build_signer(
    id: &str,
    cfg: &SigningConfig,
    headers: &HashMap<String, String>,
) -> Result<WebhookSigner, WebhookConfigError> {
    let err = |message: String| WebhookConfigError::InvalidSigning {
        webhook_id: id.to_string(),
        message,
    };

    // Structural validation first, so a malformed block is reported even when
    // the secret happens to be missing from the environment.
    let scheme_name = cfg.scheme.as_deref().unwrap_or("standard");
    if cfg.rotate_secret_env.is_some() && scheme_name == "github" {
        return Err(err(
            "rotate_secret_env is not supported for the github scheme (it carries a single signature value)"
                .to_string(),
        ));
    }

    let scheme = match scheme_name {
        "standard" => SigningScheme::Standard,
        "github" => SigningScheme::Github,
        "custom" => {
            let custom = cfg
                .custom
                .as_ref()
                .ok_or_else(|| err("scheme 'custom' requires a 'custom:' block".to_string()))?;
            SigningScheme::Custom(build_custom_scheme(id, custom)?)
        }
        other => {
            return Err(err(format!(
                "unknown signing scheme '{other}' (valid: standard, github, custom)"
            )));
        }
    };

    for sig_name in scheme.header_names() {
        if headers.keys().any(|h| h.eq_ignore_ascii_case(&sig_name)) {
            return Err(err(format!(
                "signing header '{sig_name}' collides with a configured header"
            )));
        }
    }

    // Resolve secret material last.
    let encoding = cfg.secret_encoding.as_deref();
    let mut keys = vec![read_secret(id, &cfg.secret_env, encoding)?];
    if let Some(rot_env) = &cfg.rotate_secret_env {
        keys.push(read_secret(id, rot_env, encoding)?);
    }

    Ok(WebhookSigner::new(scheme, keys))
}

/// Read and decode a signing secret from the environment.
fn read_secret(id: &str, var: &str, encoding: Option<&str>) -> Result<Vec<u8>, WebhookConfigError> {
    let raw = std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| WebhookConfigError::MissingSecretEnv {
            webhook_id: id.to_string(),
            var: var.to_string(),
        })?;
    let key = match encoding.unwrap_or("utf8") {
        "utf8" => raw.into_bytes(),
        "base64" => {
            let trimmed = raw.strip_prefix("whsec_").unwrap_or(&raw);
            BASE64
                .decode(trimmed.as_bytes())
                .map_err(|e| WebhookConfigError::InvalidSigning {
                    webhook_id: id.to_string(),
                    message: format!("secret in '{var}' is not valid base64: {e}"),
                })?
        }
        other => {
            return Err(WebhookConfigError::InvalidSigning {
                webhook_id: id.to_string(),
                message: format!("unknown secret_encoding '{other}' (valid: utf8, base64)"),
            });
        }
    };
    // A zero-length HMAC key is accepted by the primitive but is effectively no
    // key at all; reject it so a misconfigured `base64` secret (e.g. a bare
    // `whsec_` prefix) cannot silently weaken signing.
    if key.is_empty() {
        return Err(WebhookConfigError::InvalidSigning {
            webhook_id: id.to_string(),
            message: format!("signing secret in '{var}' decoded to an empty key"),
        });
    }
    Ok(key)
}

/// Validate and resolve a `signing.custom:` block.
fn build_custom_scheme(
    id: &str,
    cfg: &CustomSigningConfig,
) -> Result<CustomScheme, WebhookConfigError> {
    let err = |message: String| WebhookConfigError::InvalidSigning {
        webhook_id: id.to_string(),
        message,
    };

    let algorithm = match cfg.algorithm.as_deref().unwrap_or("sha256") {
        "sha256" => Algorithm::Sha256,
        "sha512" => Algorithm::Sha512,
        other => {
            return Err(err(format!(
                "unknown custom.algorithm '{other}' (valid: sha256, sha512)"
            )));
        }
    };
    let encoding = match cfg.encoding.as_deref().unwrap_or("hex") {
        "hex" => Encoding::Hex,
        "base64" => Encoding::Base64,
        other => {
            return Err(err(format!(
                "unknown custom.encoding '{other}' (valid: hex, base64)"
            )));
        }
    };
    if cfg.signature_header.trim().is_empty() {
        return Err(err("custom.signature_header must not be empty".to_string()));
    }
    validate_signing_tokens(
        id,
        &cfg.value_format,
        &["signature", "timestamp", "id"],
        "custom.value_format",
    )?;
    if !cfg.value_format.contains("{signature}") {
        return Err(err(
            "custom.value_format must contain the {signature} token".to_string(),
        ));
    }
    validate_signing_tokens(
        id,
        &cfg.signed_payload,
        &["body", "timestamp", "id"],
        "custom.signed_payload",
    )?;

    Ok(CustomScheme {
        algorithm,
        encoding,
        signature_header: cfg.signature_header.clone(),
        value_format: cfg.value_format.clone(),
        signed_payload: cfg.signed_payload.clone(),
        timestamp_header: cfg.timestamp_header.clone(),
        id_header: cfg.id_header.clone(),
    })
}

/// Reject any `{token}` in `template` outside `allowed`.
fn validate_signing_tokens(
    id: &str,
    template: &str,
    allowed: &[&str],
    field: &str,
) -> Result<(), WebhookConfigError> {
    let err = |message: String| WebhookConfigError::InvalidSigning {
        webhook_id: id.to_string(),
        message,
    };
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let close = after
            .find('}')
            .ok_or_else(|| err(format!("{field} has an unclosed '{{'")))?;
        let token = &after[..close];
        if !allowed.contains(&token) {
            return Err(err(format!(
                "{field} has unknown token '{{{token}}}' (allowed: {})",
                allowed.join(", ")
            )));
        }
        rest = &after[close + 1..];
    }
    Ok(())
}

/// humantime serde adapter for `Option<Duration>`.
mod humantime_opt {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Option<String> = Option::deserialize(d)?;
        match raw {
            Some(s) => humantime::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// humantime serde adapter for a required `Duration`.
mod humantime_dur {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::NoopMetrics;

    fn build(yaml: &str) -> Result<Vec<BuiltWebhook>, WebhookConfigError> {
        let file: WebhooksFile = yaml_serde::from_str(yaml).expect("yaml parses");
        build_webhooks(file, Arc::new(NoopMetrics))
    }

    // `BuiltWebhook` is not `Debug` (it holds a reqwest client and a `dyn`
    // metrics hook), so error tests discard the Ok payload before `unwrap_err`.
    fn build_err(yaml: &str) -> WebhookConfigError {
        build(yaml).map(|_| ()).unwrap_err()
    }

    #[test]
    fn minimal_detection_webhook_builds() {
        let built = build(
            r#"
webhooks:
  - id: slack
    kind: detection
    url: https://example.test/hook
    body: '{"text":"${detection.rule.title}"}'
"#,
        )
        .expect("valid config");
        assert_eq!(built.len(), 1);
        // Defaults: 3 total tries -> retry_max 2, queue 1024.
        assert_eq!(built[0].delivery.retry_max, 2);
        assert_eq!(built[0].delivery.batch_max, 1);
        assert_eq!(built[0].delivery.queue_depth, 1024);
    }

    #[test]
    fn unknown_kind_is_rejected_with_incident_hint() {
        let err = build_err(
            r#"
webhooks:
  - id: pd
    kind: incident
    url: https://example.test/hook
"#,
        );
        let msg = err.to_string();
        assert!(msg.contains("unknown kind 'incident'"), "{msg}");
        assert!(msg.contains("roadmap item #48"), "{msg}");
    }

    #[test]
    fn missing_url_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: "   "
"#,
        );
        assert!(err.to_string().contains("missing required field 'url'"));
    }

    #[test]
    fn cross_namespace_template_points_at_the_field() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    body: '{"t":"${correlation.rule.title}"}'
"#,
        );
        let msg = err.to_string();
        assert!(
            msg.contains("wrong namespace for a detection webhook"),
            "{msg}"
        );
        assert!(msg.contains("field 'body'"), "{msg}");
    }

    #[test]
    fn zero_attempts_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    retry:
      attempts: 0
"#,
        );
        assert!(
            err.to_string()
                .contains("retry.attempts must be at least 1")
        );
    }

    #[test]
    fn retry_and_queue_override_delivery_defaults() {
        let built = build(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    retry:
      attempts: 5
      backoff: 2s
      max_backoff: 45s
    queue_size: 256
"#,
        )
        .expect("valid config");
        let d = &built[0].delivery;
        assert_eq!(d.retry_max, 4);
        assert_eq!(d.backoff_base, Duration::from_secs(2));
        assert_eq!(d.backoff_max, Duration::from_secs(45));
        assert_eq!(d.queue_depth, 256);
    }

    #[test]
    fn malformed_duration_is_rejected() {
        let file: Result<WebhooksFile, _> = yaml_serde::from_str(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    timeout: "not-a-duration"
"#,
        );
        assert!(file.is_err(), "humantime parse should fail at deserialize");
    }

    #[test]
    fn tls_webhook_with_ca_and_identity_builds() {
        use std::io::Write;

        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();

        let client_key = KeyPair::generate().unwrap();
        let client_pem = CertificateParams::new(vec!["client".to_string()])
            .unwrap()
            .self_signed(&client_key)
            .unwrap()
            .pem();
        let client_key_pem = client_key.serialize_pem();

        let write = |contents: &str| {
            let mut f = tempfile::Builder::new().suffix(".pem").tempfile().unwrap();
            f.write_all(contents.as_bytes()).unwrap();
            f.flush().unwrap();
            f
        };
        let ca = write(&ca_pem);
        let cert = write(&client_pem);
        let key = write(&client_key_pem);

        let yaml = format!(
            r#"
webhooks:
  - id: internal
    kind: detection
    url: https://relay.internal/hook
    tls:
      ca: {ca}
      client_cert: {cert}
      client_key: {key}
"#,
            ca = ca.path().display(),
            cert = cert.path().display(),
            key = key.path().display(),
        );
        let built = build(&yaml).expect("a webhook with a CA and client identity should build");
        assert_eq!(built.len(), 1);
    }

    #[test]
    fn tls_client_cert_without_key_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: internal
    kind: detection
    url: https://relay.internal/hook
    tls:
      client_cert: /nonexistent/cert.pem
"#,
        );
        assert!(
            err.to_string()
                .contains("must be set together for mutual TLS"),
            "{err}"
        );
    }

    #[test]
    fn tls_unreadable_ca_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: internal
    kind: detection
    url: https://relay.internal/hook
    tls:
      ca: /nonexistent/ca.pem
"#,
        );
        assert!(err.to_string().contains("failed to read tls.ca"), "{err}");
    }

    #[test]
    fn rate_limit_requires_positive_budget() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    rate_limit:
      requests: 0
      per: 1m
"#,
        );
        assert!(
            err.to_string()
                .contains("rate_limit.requests must be at least 1")
        );
    }

    // Signing validation. These cases are reached without the secret present in
    // the environment because structural checks run before secret resolution;
    // the one case that needs an unset secret uses a name that is never set.

    #[test]
    fn signing_missing_secret_env_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    signing:
      secret_env: RSIGMA_DEFINITELY_UNSET_SIGNING_SECRET
"#,
        );
        assert!(
            err.to_string()
                .contains("environment variable 'RSIGMA_DEFINITELY_UNSET_SIGNING_SECRET' is unset"),
            "{err}"
        );
    }

    #[test]
    fn signing_unknown_scheme_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    signing:
      secret_env: RSIGMA_UNUSED
      scheme: hocus-pocus
"#,
        );
        assert!(
            err.to_string()
                .contains("unknown signing scheme 'hocus-pocus'"),
            "{err}"
        );
    }

    #[test]
    fn signing_github_with_rotation_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    signing:
      secret_env: RSIGMA_UNUSED
      scheme: github
      rotate_secret_env: RSIGMA_UNUSED_OLD
"#,
        );
        assert!(
            err.to_string()
                .contains("rotate_secret_env is not supported for the github scheme"),
            "{err}"
        );
    }

    #[test]
    fn signing_custom_unknown_payload_token_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    signing:
      secret_env: RSIGMA_UNUSED
      scheme: custom
      custom:
        signature_header: X-Sig
        value_format: "v1={signature}"
        signed_payload: "{timestamp}.{nope}"
"#,
        );
        let msg = err.to_string();
        assert!(msg.contains("custom.signed_payload"), "{msg}");
        assert!(msg.contains("{nope}"), "{msg}");
    }

    #[test]
    fn signing_custom_value_format_requires_signature_token() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    signing:
      secret_env: RSIGMA_UNUSED
      scheme: custom
      custom:
        signature_header: X-Sig
        value_format: "t={timestamp}"
        signed_payload: "{body}"
"#,
        );
        assert!(
            err.to_string()
                .contains("custom.value_format must contain the {signature} token"),
            "{err}"
        );
    }

    #[test]
    fn signing_empty_base64_secret_is_rejected() {
        // A bare `whsec_` prefix decodes to an empty key; reject it rather than
        // sign with effectively no key.
        // SAFETY: single-threaded test; the var is unique to this case.
        unsafe { std::env::set_var("RSIGMA_TEST_EMPTY_B64_SECRET", "whsec_") };
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    signing:
      secret_env: RSIGMA_TEST_EMPTY_B64_SECRET
      secret_encoding: base64
"#,
        );
        unsafe { std::env::remove_var("RSIGMA_TEST_EMPTY_B64_SECRET") };
        assert!(err.to_string().contains("decoded to an empty key"), "{err}");
    }

    #[test]
    fn signing_header_collision_is_rejected() {
        let err = build_err(
            r#"
webhooks:
  - id: x
    kind: detection
    url: https://example.test/hook
    headers:
      Webhook-Signature: spoofed
    signing:
      secret_env: RSIGMA_UNUSED
"#,
        );
        assert!(
            err.to_string()
                .contains("signing header 'webhook-signature' collides"),
            "{err}"
        );
    }
}
