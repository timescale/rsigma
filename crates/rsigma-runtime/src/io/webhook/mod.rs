//! Generic, template-driven webhook output sink (roadmap item #54).
//!
//! One configurable HTTP sink, not a handful of bespoke service integrations:
//! Slack, Teams, Discord, and PagerDuty ship as field-parametric YAML recipes
//! in the docs, while the engine stays service-agnostic. Each webhook renders
//! a templated URL, headers, and body per detection / correlation result and
//! posts it over the shared egress-filtered HTTP client.
//!
//! The webhook is a leaf on the shared async delivery layer
//! (`crate::io::delivery`): the dispatcher owns the bounded queue, the
//! retry/backoff schedule, terminal-failure-to-DLQ routing, and drain on
//! shutdown. [`WebhookSink`] owns only the webhook-specific request behavior
//! (template render, retryable-vs-permanent classification, per-entry token
//! bucket). Webhooks run in the lossy `on_full=drop` mode so a third-party
//! chat or paging endpoint never blocks the at-least-once token release for
//! durable sinks (NATS, file); anything undeliverable lands in the DLQ.

mod config;
mod signing;
mod sink;

pub use config::{
    BuiltWebhook, CustomSigningConfig, DEFAULT_WEBHOOK_ATTEMPTS, DEFAULT_WEBHOOK_BACKOFF,
    DEFAULT_WEBHOOK_MAX_BACKOFF, DEFAULT_WEBHOOK_QUEUE_SIZE, DEFAULT_WEBHOOK_TIMEOUT,
    RateLimitConfig, RetryConfig, ScopeConfig, SigningConfig, WebhookConfig, WebhookConfigError,
    WebhookKind, WebhooksFile, build_webhooks, load_webhooks_file,
};
pub use sink::WebhookSink;
