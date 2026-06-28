//! `WebhookSink`: render a templated HTTP request per result and classify the
//! response. The queue, retry/backoff, and DLQ routing belong to the shared
//! `crate::io::delivery` layer; this type owns only the webhook-specific
//! request behavior (render, rate limit, retryable-vs-permanent classification).

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rsigma_eval::{EvaluationResult, ProcessResult};

use crate::enrichment::{HttpEnricherClient, render_template, render_template_json};
use crate::error::RuntimeError;
use crate::io::DeliveryContext;
use crate::metrics::MetricsHook;

use super::config::WebhookKind;
use super::signing::WebhookSigner;

/// Cap on the response bytes drained (and discarded) per request. Webhook
/// responses are never parsed; draining a bounded prefix lets reqwest reuse
/// the connection without letting a hostile endpoint stream an unbounded body.
const DRAIN_CAP: usize = 64 * 1024;

/// Ceiling applied to a `Retry-After` header so a hostile or misconfigured
/// endpoint cannot pin a worker for an arbitrarily long sleep.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// A per-entry token bucket: `capacity` tokens, refilled at `refill_per_sec`.
///
/// Driven from `WebhookSink::deliver_one` under `&mut self`, so the worker
/// processes one request at a time and the bucket needs no interior locking.
/// Uses [`tokio::time::Instant`] so it stays consistent under paused time in
/// tests.
pub(crate) struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: tokio::time::Instant,
}

impl TokenBucket {
    /// `requests` tokens per `per` window; starts full (burst = `requests`).
    /// Callers must ensure `requests >= 1` and `per > 0`.
    pub(crate) fn new(requests: u32, per: Duration) -> Self {
        let capacity = f64::from(requests);
        let refill_per_sec = capacity / per.as_secs_f64();
        TokenBucket {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last: tokio::time::Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = tokio::time::Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// Acquire one token, sleeping until the bucket refills if empty. Returns
    /// `true` if it had to wait (so the caller can record the rate-limit metric).
    async fn acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return false;
        }
        let needed = 1.0 - self.tokens;
        let wait = Duration::from_secs_f64(needed / self.refill_per_sec);
        tokio::time::sleep(wait).await;
        self.refill();
        self.tokens = (self.tokens - 1.0).max(0.0);
        true
    }
}

/// One configured webhook. Filters each result by kind and scope, then renders
/// and posts a templated request, classifying the outcome for the delivery
/// layer.
pub struct WebhookSink {
    id: String,
    /// `id` leaked to `&'static str` so it can serve as the shared per-sink
    /// delivery label (queue depth, retries, DLQ), giving a one-to-one mapping
    /// to the webhook-specific `rsigma_webhook_*` series. Bounded by the
    /// configured webhook count, leaked once at startup.
    label: &'static str,
    kind: WebhookKind,
    method: reqwest::Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    timeout: Duration,
    scope: crate::enrichment::Scope,
    limiter: Option<TokenBucket>,
    client: HttpEnricherClient,
    metrics: Arc<dyn MetricsHook>,
    /// Optional HMAC request signer. When set, every delivery carries
    /// signature headers over the rendered body bytes.
    signer: Option<WebhookSigner>,
}

impl WebhookSink {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: String,
        kind: WebhookKind,
        method: reqwest::Method,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
        timeout: Duration,
        scope: crate::enrichment::Scope,
        limiter: Option<TokenBucket>,
        client: HttpEnricherClient,
        metrics: Arc<dyn MetricsHook>,
        signer: Option<WebhookSigner>,
    ) -> Self {
        let label: &'static str = Box::leak(id.clone().into_boxed_str());
        WebhookSink {
            id,
            label,
            kind,
            method,
            url,
            headers,
            body,
            timeout,
            scope,
            limiter,
            client,
            metrics,
            signer,
        }
    }

    /// The webhook id, used as the webhook-specific metric label.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The webhook id as a `&'static str`, used as the shared per-sink
    /// delivery label so its queue/retry/DLQ series map one-to-one to the
    /// `rsigma_webhook_*` series.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Deliver every matching result in `result`.
    ///
    /// Results that do not match this webhook's `kind` or `scope` are skipped
    /// (a no-op success). On the first delivery error the call short-circuits
    /// with that error so the shared worker can apply retry/backoff (for a
    /// retryable error) or route to the DLQ (for a [`RuntimeError::Permanent`]
    /// or after the retry budget is spent).
    pub async fn send(
        &mut self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        for (idx, eval) in result.iter().enumerate() {
            if !self.kind.matches(&eval.body) || !self.scope.matches(eval) {
                continue;
            }
            self.deliver_one(eval, ctx, idx).await?;
        }
        Ok(())
    }

    async fn deliver_one(
        &mut self,
        eval: &EvaluationResult,
        ctx: &DeliveryContext,
        idx: usize,
    ) -> Result<(), RuntimeError> {
        let waited = match &mut self.limiter {
            Some(limiter) => limiter.acquire().await,
            None => false,
        };
        if waited {
            self.metrics.on_webhook_rate_limited(&self.id);
        }

        let url = render_template(&self.url, eval);
        // Reserve for the user headers plus up to three signing headers
        // (webhook-id/timestamp/signature is the widest scheme) so a signed
        // request does not reallocate the map.
        let signing_headroom = if self.signer.is_some() { 3 } else { 0 };
        let mut header_map = HeaderMap::with_capacity(self.headers.len() + signing_headroom);
        for (name, value_template) in &self.headers {
            let rendered = render_template(value_template, eval);
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                RuntimeError::Permanent(format!(
                    "webhook {}: invalid header name '{name}': {e}",
                    self.id
                ))
            })?;
            let header_value = HeaderValue::from_str(&rendered).map_err(|e| {
                RuntimeError::Permanent(format!(
                    "webhook {}: invalid header value for '{name}': {e}",
                    self.id
                ))
            })?;
            header_map.insert(header_name, header_value);
        }
        let body = self.body.as_ref().map(|b| render_template_json(b, eval));

        // Sign the exact body bytes that go on the wire. The id and timestamp
        // come from the per-delivery context, so a retry reproduces the same
        // signature. The id is unique per result within the delivery.
        if let Some(signer) = &self.signer {
            let request_id = format!("{}-{idx}", ctx.id_base());
            for (name, value) in signer.sign(
                body.as_deref().unwrap_or(""),
                ctx.first_attempt(),
                &request_id,
            ) {
                let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    RuntimeError::Permanent(format!(
                        "webhook {}: invalid signing header name '{name}': {e}",
                        self.id
                    ))
                })?;
                let header_value = HeaderValue::from_str(&value).map_err(|e| {
                    RuntimeError::Permanent(format!(
                        "webhook {}: invalid signing header value for '{name}': {e}",
                        self.id
                    ))
                })?;
                header_map.insert(header_name, header_value);
            }
        }

        let mut req = self
            .client
            .inner()
            .request(self.method.clone(), &url)
            .headers(header_map)
            .timeout(self.timeout);
        if let Some(b) = &body {
            req = req.body(b.clone());
        }

        let started = std::time::Instant::now();
        let resp = match req.send().await {
            Ok(r) => r,
            // Transport-level failures (connect, DNS/egress block, timeout)
            // heal on retry, so they are retryable, not permanent.
            Err(e) => {
                return Err(RuntimeError::Io(std::io::Error::other(format!(
                    "webhook {}: request error: {e}",
                    self.id
                ))));
            }
        };

        let status = resp.status();
        let elapsed = started.elapsed().as_secs_f64();

        if status.is_success() {
            drain_body(resp).await;
            self.metrics
                .on_webhook_request(&self.id, "success", elapsed);
            return Ok(());
        }

        let retry_after = parse_retry_after(&resp);
        drain_body(resp).await;

        if status.as_u16() == 429 || status.is_server_error() {
            // Retryable: honor Retry-After (capped) before yielding to the
            // shared worker's own backoff schedule.
            if let Some(wait) = retry_after {
                tokio::time::sleep(wait.min(MAX_RETRY_AFTER)).await;
            }
            return Err(RuntimeError::Io(std::io::Error::other(format!(
                "webhook {}: HTTP {status}",
                self.id
            ))));
        }

        // Other 4xx (and any non-2xx, non-429, non-5xx): a misrendered payload
        // or bad endpoint will not heal on retry.
        self.metrics
            .on_webhook_request(&self.id, "permanent_failure", elapsed);
        Err(RuntimeError::Permanent(format!(
            "webhook {}: HTTP {status}",
            self.id
        )))
    }
}

/// Read and discard up to [`DRAIN_CAP`] bytes of the response body.
async fn drain_body(mut resp: reqwest::Response) {
    let mut read = 0usize;
    while read < DRAIN_CAP {
        match resp.chunk().await {
            Ok(Some(chunk)) => read += chunk.len(),
            _ => break,
        }
    }
}

/// Parse a numeric `Retry-After` header (delay in seconds). The HTTP-date form
/// is intentionally not supported; chat/paging endpoints use delay-seconds.
fn parse_retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use hmac::{Hmac, KeyInit, Mac};
    use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use sha2::Sha256;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::signing::SigningScheme;
    use crate::metrics::NoopMetrics;

    fn detection(title: &str) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: title.to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["sel".to_string()],
                matched_fields: vec![],
                event: None,
            }),
        }
    }

    fn sink_to(url: String) -> WebhookSink {
        WebhookSink::new(
            "test".to_string(),
            WebhookKind::Detection,
            reqwest::Method::POST,
            url,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(r#"{"text":"${detection.rule.title}"}"#.to_string()),
            Duration::from_secs(5),
            crate::enrichment::Scope::default(),
            None,
            crate::enrichment::build_default_http_client().unwrap(),
            Arc::new(NoopMetrics),
            None,
        )
    }

    fn ctx() -> DeliveryContext {
        DeliveryContext::new()
    }

    fn signed_sink_to(url: String, signer: WebhookSigner) -> WebhookSink {
        WebhookSink::new(
            "test".to_string(),
            WebhookKind::Detection,
            reqwest::Method::POST,
            url,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(r#"{"text":"${detection.rule.title}"}"#.to_string()),
            Duration::from_secs(5),
            crate::enrichment::Scope::default(),
            None,
            crate::enrichment::build_default_http_client().unwrap(),
            Arc::new(NoopMetrics),
            Some(signer),
        )
    }

    #[tokio::test]
    async fn success_2xx_is_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let mut sink = sink_to(format!("{}/hook", server.uri()));
        let result: ProcessResult = vec![detection("hi")];
        assert!(sink.send(&result, &ctx()).await.is_ok());
    }

    #[tokio::test]
    async fn server_error_is_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let mut sink = sink_to(format!("{}/hook", server.uri()));
        let result: ProcessResult = vec![detection("hi")];
        match sink.send(&result, &ctx()).await {
            Err(RuntimeError::Io(_)) => {}
            other => panic!("expected retryable Io error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_error_is_permanent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let mut sink = sink_to(format!("{}/hook", server.uri()));
        let result: ProcessResult = vec![detection("hi")];
        match sink.send(&result, &ctx()).await {
            Err(RuntimeError::Permanent(_)) => {}
            other => panic!("expected permanent error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_matching_kind_is_skipped_without_request() {
        // No mock mounted: any request would 404 and fail. A correlation-only
        // result must be skipped by a detection webhook, so send() is a no-op.
        let server = MockServer::start().await;
        let mut sink = sink_to(format!("{}/hook", server.uri()));
        let correlation = EvaluationResult {
            header: RuleHeader {
                rule_title: "corr".to_string(),
                rule_id: None,
                level: None,
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Correlation(rsigma_eval::result::CorrelationBody {
                correlation_type: rsigma_parser::CorrelationType::EventCount,
                aggregated_value: 1.0,
                timespan_secs: 60,
                group_key: vec![],
                events: None,
                event_refs: None,
            }),
        };
        let result: ProcessResult = vec![correlation];
        assert!(sink.send(&result, &ctx()).await.is_ok());
    }

    #[test]
    fn slack_recipe_body_renders_to_pinned_json() {
        // Pin the template-engine-plus-JSON-escaping contract for a realistic
        // Slack-style body: the matched CommandLine carries embedded quotes
        // that must be escaped so the rendered body stays valid JSON.
        let body = r#"{"text":":rotating_light: ${detection.rule.title} (${detection.rule.level}) cmd=${detection.fields.CommandLine}"}"#;
        let mut r = detection("Encoded PowerShell");
        if let ResultBody::Detection(d) = &mut r.body {
            d.matched_fields.push(rsigma_eval::result::FieldMatch::new(
                "CommandLine",
                serde_json::json!(r#"powershell -enc "AAA""#),
            ));
        }
        let rendered = crate::enrichment::render_template_json(body, &r);
        assert_eq!(
            rendered,
            r#"{"text":":rotating_light: Encoded PowerShell (high) cmd=powershell -enc \"AAA\""}"#,
        );
        // The escaped body must parse as JSON despite the embedded quotes.
        let _: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    }

    #[tokio::test]
    async fn signed_request_carries_a_verifiable_signature() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let secret = b"shared-secret".to_vec();
        let signer = WebhookSigner::new(SigningScheme::Standard, vec![secret.clone()]);
        let mut sink = signed_sink_to(format!("{}/hook", server.uri()), signer);
        sink.send(&vec![detection("hi")], &ctx()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let req = &reqs[0];
        let header = |name: &str| {
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let id = header("webhook-id");
        let ts = header("webhook-timestamp");
        let sig = header("webhook-signature");
        assert!(id.starts_with("msg_"), "id should be msg_<uuid>: {id}");

        // Recompute the HMAC over the exact bytes the receiver would: the
        // signed content is "{id}.{timestamp}.{body}" and body is the wire body.
        let body = std::str::from_utf8(&req.body).unwrap();
        let signed = format!("{id}.{ts}.{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(signed.as_bytes());
        let expected = format!("v1,{}", BASE64.encode(mac.finalize().into_bytes()));
        assert_eq!(sig, expected, "signature must verify over the wire body");
    }

    #[tokio::test]
    async fn retries_with_the_same_context_reproduce_the_signature() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let signer = WebhookSigner::new(SigningScheme::Standard, vec![b"k".to_vec()]);
        let mut sink = signed_sink_to(format!("{}/hook", server.uri()), signer);
        let result: ProcessResult = vec![detection("hi")];

        // The delivery worker reuses one context across retries; emulate that by
        // sending twice with the same context.
        let context = ctx();
        sink.send(&result, &context).await.unwrap();
        sink.send(&result, &context).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2);
        let pick = |i: usize, name: &str| {
            reqs[i]
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        for name in ["webhook-id", "webhook-timestamp", "webhook-signature"] {
            assert_eq!(
                pick(0, name),
                pick(1, name),
                "{name} must be identical across retries"
            );
        }
    }

    #[tokio::test]
    async fn token_bucket_waits_when_empty() {
        // 2 tokens per 100ms => one token refills in ~50ms.
        let mut tb = TokenBucket::new(2, Duration::from_millis(100));
        assert!(!tb.acquire().await, "first token is free");
        assert!(!tb.acquire().await, "second token is free");
        let start = std::time::Instant::now();
        assert!(tb.acquire().await, "third token must wait");
        assert!(start.elapsed() >= Duration::from_millis(40));
    }
}
