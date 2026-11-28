//! `WebhookSink`: render a templated HTTP request per result and classify the
//! response. The queue, retry/backoff, and DLQ routing belong to the shared
//! `crate::io::delivery` layer; this type owns only the webhook-specific
//! request behavior (render, rate limit, retryable-vs-permanent classification).

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rsigma_eval::{EvaluationResult, ProcessResult, TenantId};

use crate::enrichment::{
    HttpEnricherClient, render_template, render_template_json_with_ocsf, render_template_url,
    sanitize_header_value,
};
use crate::error::RuntimeError;
use crate::io::DeliveryContext;
use crate::io::delivery::{DeadLetters, DeliveryScope};
use crate::io::lines::ResumeMap;
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

/// The results a webhook posts: its kind and its scope.
struct WebhookScope {
    kind: WebhookKind,
    scope: crate::enrichment::Scope,
}

impl WebhookScope {
    fn admits(&self, eval: &EvaluationResult) -> bool {
        self.kind.matches(&eval.body) && self.scope.matches(eval)
    }
}

impl DeliveryScope for WebhookScope {
    fn accepts_result(&self, result: &EvaluationResult) -> bool {
        self.admits(result)
    }

    fn accepts_incident(&self, _tenant: Option<&TenantId>) -> bool {
        false
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
    scope: Arc<WebhookScope>,
    method: reqwest::Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    timeout: Duration,
    limiter: Option<TokenBucket>,
    client: HttpEnricherClient,
    metrics: Arc<dyn MetricsHook>,
    /// Optional HMAC request signer. When set, every delivery carries
    /// signature headers over the rendered body bytes.
    signer: Option<WebhookSigner>,
    ocsf: crate::ocsf::OcsfOptions,
    /// Index of the result a failed delivery stopped at; every result before
    /// it was posted or parked.
    posted: ResumeMap<usize>,
    /// Where a result that fails for good is parked while the rest of its
    /// delivery goes on.
    dead_letters: DeadLetters,
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
        let dead_letters = DeadLetters::new(None, metrics.clone(), label);
        WebhookSink {
            id,
            label,
            scope: Arc::new(WebhookScope { kind, scope }),
            method,
            url,
            headers,
            body,
            timeout,
            limiter,
            client,
            metrics,
            signer,
            ocsf: crate::ocsf::OcsfOptions::default(),
            posted: ResumeMap::default(),
            dead_letters,
        }
    }

    /// The results this webhook posts, so the dispatcher queues nothing it
    /// would skip. Webhooks take no incidents.
    pub(crate) fn delivery_scope(&self) -> Arc<dyn DeliveryScope> {
        self.scope.clone()
    }

    pub(crate) fn attach_dead_letters(&mut self, dead_letters: DeadLetters) {
        self.dead_letters = dead_letters;
    }

    /// The in-scope results of a delivery the worker gave up on that were
    /// neither posted nor parked.
    pub(crate) fn abandon<'r>(
        &mut self,
        result: &'r ProcessResult,
        ctx: &DeliveryContext,
    ) -> Vec<&'r EvaluationResult> {
        let start = self.posted.take(ctx).unwrap_or(0);
        result
            .iter()
            .skip(start)
            .filter(|eval| self.scope.admits(eval))
            .collect()
    }

    #[must_use]
    pub(crate) fn with_ocsf_options(mut self, ocsf: crate::ocsf::OcsfOptions) -> Self {
        self.ocsf = ocsf;
        self
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
    /// Results that do not match this webhook's `kind` or `scope` are skipped.
    /// A result that fails for good (a render error, a 4xx other than 429)
    /// is parked on its own (on the DLQ when one is configured) and the rest
    /// of the results still go out. A retryable failure stops the call with
    /// that error so the shared worker can apply retry and backoff; a retry
    /// with the same `ctx` starts at the result that failed, so results
    /// already posted or parked are not sent again.
    pub async fn send(
        &mut self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        let start = self.posted.start(Some(ctx));
        for (idx, eval) in result.iter().enumerate().skip(start) {
            if !self.scope.admits(eval) {
                continue;
            }
            match self.deliver_one(eval, ctx, idx).await {
                Ok(()) => {}
                Err(err @ RuntimeError::Permanent(_)) => {
                    self.dead_letters.park_results(&[eval], &err).await;
                }
                Err(err) => {
                    self.posted.record(Some(ctx), idx);
                    return Err(err);
                }
            }
        }
        self.posted.clear(Some(ctx));
        Ok(())
    }

    /// Deliver a batch of deliveries one at a time, one outcome per attempted
    /// delivery, stopping at the first failure so later deliveries keep their
    /// order.
    pub(crate) async fn send_batch(
        &mut self,
        items: &[(&ProcessResult, &DeliveryContext)],
    ) -> Vec<Result<(), RuntimeError>> {
        self.posted.retain(items.iter().map(|(_, ctx)| *ctx));
        let mut outcomes = Vec::with_capacity(items.len());
        for (result, ctx) in items {
            let outcome = self.send(result, ctx).await;
            let failed = outcome.is_err();
            outcomes.push(outcome);
            if failed {
                break;
            }
        }
        outcomes
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

        let url = render_template_url(&self.url, eval);
        // Reserve for the user headers plus up to three signing headers
        // (webhook-id/timestamp/signature is the widest scheme) so a signed
        // request does not reallocate the map.
        let signing_headroom = if self.signer.is_some() { 3 } else { 0 };
        let mut header_map = HeaderMap::with_capacity(self.headers.len() + signing_headroom);
        for (name, value_template) in &self.headers {
            let rendered = sanitize_header_value(render_template(value_template, eval));
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
        // The finding uses the delivery context, so its identity matches the
        // OCSF line and OTLP sinks of the same dispatch.
        let body = self.body.as_ref().map(|b| {
            render_template_json_with_ocsf(b, eval, || {
                let options = crate::ocsf::OcsfOptions::new(self.ocsf.version());
                let finding = crate::io::ocsf_finding(eval, Some((ctx, idx)), &options);
                serde_json::to_string(&finding).unwrap_or_else(|_| "null".to_string())
            })
        });

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

        // A denied IP-literal URL will not change on retry.
        if let Err(denial) = self.client.check_url(&url) {
            return Err(RuntimeError::Permanent(format!(
                "webhook {}: {denial}",
                self.id
            )));
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
                    "webhook {}: request error: {}",
                    self.id,
                    crate::egress::error_chain(&e)
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

    use zeroize::Zeroizing;

    use super::super::signing::SigningScheme;
    use crate::metrics::NoopMetrics;

    fn detection(title: &str) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: title.to_string(),
                rule_id: Some("rule-1".to_string()),
                tenant_id: None,
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
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

    /// Route the results `sink` parks to a channel the test reads.
    fn park_into_channel(
        sink: &mut WebhookSink,
    ) -> tokio::sync::mpsc::Receiver<crate::io::DeliveryFailure> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        sink.attach_dead_letters(DeadLetters::new(Some(tx), Arc::new(NoopMetrics), "test"));
        rx
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
    async fn a_title_outside_a_body_string_cannot_add_keys() {
        let server = MockServer::start().await;
        let title = r#"1, "admin": true"#;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "title": title,
                "finding": {"rsigma": true},
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let mut sink = WebhookSink::new(
            "siem".to_string(),
            WebhookKind::Detection,
            reqwest::Method::POST,
            format!("{}/hook", server.uri()),
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(r#"{"title": ${detection.rule.title}, "finding": {"rsigma": true}}"#.to_string()),
            Duration::from_secs(5),
            crate::enrichment::Scope::default(),
            None,
            crate::enrichment::build_default_http_client().unwrap(),
            Arc::new(NoopMetrics),
            None,
        );
        sink.send(&vec![detection(title)], &ctx()).await.unwrap();
    }

    #[tokio::test]
    async fn ocsf_body_reference_posts_a_conformant_finding() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .expect(2)
            .mount(&server)
            .await;
        let mut sink = WebhookSink::new(
            "siem".to_string(),
            WebhookKind::Detection,
            reqwest::Method::POST,
            format!("{}/hook", server.uri()),
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(
                r#"{"title": "${detection.rule.title}", "finding": ${detection.ocsf}}"#.to_string(),
            ),
            Duration::from_secs(5),
            crate::enrichment::Scope::default(),
            None,
            crate::enrichment::build_default_http_client().unwrap(),
            Arc::new(NoopMetrics),
            None,
        );
        let ctx = ctx();
        let result: ProcessResult = vec![detection("first \"quoted\""), detection("second")];
        sink.send(&result, &ctx).await.unwrap();

        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ocsf/1.1.0/class_2004.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let received = server.received_requests().await.unwrap();
        for (index, request) in received.iter().enumerate() {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let finding = &body["finding"];
            let errors: Vec<String> = validator
                .iter_errors(finding)
                .map(|e| e.to_string())
                .collect();
            assert!(errors.is_empty(), "non-conformant finding: {errors:#?}");
            assert_eq!(
                finding["finding_info"]["uid"],
                ctx.finding_uid(index).as_str(),
                "the finding identity matches the other sinks of the dispatch",
            );
            assert_eq!(body["title"], finding["finding_info"]["title"]);
        }
        assert_eq!(received.len(), 2);
    }

    #[tokio::test]
    async fn url_template_values_are_percent_encoded() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook/..%2F..%2Fadmin"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let mut sink = sink_to(format!("{}/hook/${{detection.rule.title}}", server.uri()));
        let result: ProcessResult = vec![detection("../../admin")];
        assert!(sink.send(&result, &ctx()).await.is_ok());
    }

    #[tokio::test]
    async fn control_characters_in_a_header_value_cannot_add_a_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let mut sink = WebhookSink::new(
            "test".to_string(),
            WebhookKind::Detection,
            reqwest::Method::POST,
            format!("{}/hook", server.uri()),
            vec![(
                "X-Command".to_string(),
                "cmd=${detection.fields.CommandLine}".to_string(),
            )],
            Some(r#"{"text":"${detection.rule.title}"}"#.to_string()),
            Duration::from_secs(5),
            crate::enrichment::Scope::default(),
            None,
            crate::enrichment::build_default_http_client().unwrap(),
            Arc::new(NoopMetrics),
            None,
        );
        let mut r = detection("hi");
        if let ResultBody::Detection(d) = &mut r.body {
            d.matched_fields.push(rsigma_eval::result::FieldMatch::new(
                "CommandLine",
                serde_json::json!("whoami\r\nX-Injected: 1\u{0}\u{7f}\tend"),
            ));
        }

        sink.send(&vec![r], &ctx()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let headers = &reqs[0].headers;
        assert!(headers.get("x-injected").is_none(), "{headers:?}");
        assert_eq!(
            headers.get("x-command").unwrap().to_str().unwrap(),
            "cmd=whoami  X-Injected: 1  \tend"
        );
    }

    #[test]
    fn header_sanitising_keeps_tabs_and_non_ascii_text() {
        assert_eq!(
            sanitize_header_value("a\tb é\u{1b}[0m\r\n".to_string()),
            "a\tb é [0m  "
        );
        let clean = "plain value".to_string();
        assert_eq!(sanitize_header_value(clean.clone()), clean);
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
        let mut parked = park_into_channel(&mut sink);
        let result: ProcessResult = vec![detection("hi")];
        sink.send(&result, &ctx()).await.unwrap();
        let failure = parked.try_recv().expect("the result is parked");
        assert!(failure.error.contains("HTTP 400"), "{}", failure.error);
        assert!(parked.try_recv().is_err());
    }

    #[tokio::test]
    async fn denied_ip_literal_url_is_permanent() {
        let mut sink = sink_to("http://169.254.169.254/hook".to_string());
        let mut parked = park_into_channel(&mut sink);
        let result: ProcessResult = vec![detection("hi")];
        sink.send(&result, &ctx()).await.unwrap();
        let failure = parked.try_recv().expect("the result is parked");
        assert!(
            failure
                .error
                .contains("egress policy denied link-local address 169.254.169.254"),
            "{}",
            failure.error
        );
    }

    #[tokio::test]
    async fn redirect_to_denied_ip_literal_is_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("Location", "http://169.254.169.254/"),
            )
            .mount(&server)
            .await;
        let mut sink = sink_to(format!("{}/hook", server.uri()));
        let result: ProcessResult = vec![detection("hi")];
        let err = sink
            .send(&result, &ctx())
            .await
            .expect_err("redirect must be refused");
        assert!(
            err.to_string()
                .contains("egress policy denied link-local address 169.254.169.254"),
            "{err}"
        );
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
                tenant_id: None,
                level: None,
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
            },
            body: ResultBody::Correlation(rsigma_eval::result::CorrelationBody {
                correlation_type: rsigma_parser::CorrelationType::EventCount,
                aggregated_value: 1.0,
                timespan_secs: 60,
                group_key: vec![],
                events: None,
                event_refs: None,
                event_sources: None,
                absence: None,
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
        let signer = WebhookSigner::new(
            SigningScheme::Standard,
            vec![Zeroizing::new(secret.clone())],
        );
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
    async fn a_custom_signature_covers_a_body_that_contains_signing_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let scheme = SigningScheme::Custom(super::super::signing::CustomScheme {
            algorithm: super::super::signing::Algorithm::Sha256,
            encoding: super::super::signing::Encoding::Hex,
            signature_header: "X-Signature".to_string(),
            value_format: "t={timestamp},v1={signature}".to_string(),
            signed_payload: "{id}.{timestamp}.{body}".to_string(),
            timestamp_header: None,
            id_header: Some("X-Webhook-Id".to_string()),
        });
        let secret = b"shared-secret".to_vec();
        let signer = WebhookSigner::new(scheme, vec![Zeroizing::new(secret.clone())]);
        let mut sink = signed_sink_to(format!("{}/hook", server.uri()), signer);
        sink.send(
            &vec![detection("{timestamp} {id} {body} {signature}")],
            &ctx(),
        )
        .await
        .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let req = &reqs[0];
        let header = |name: &str| req.headers.get(name).unwrap().to_str().unwrap().to_string();
        let id = header("X-Webhook-Id");
        let signature = header("X-Signature");
        let ts = signature
            .strip_prefix("t=")
            .and_then(|rest| rest.split(',').next())
            .unwrap()
            .to_string();
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(
            body.contains("{timestamp} {id} {body} {signature}"),
            "{body}"
        );

        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(format!("{id}.{ts}.{body}").as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(signature, format!("t={ts},v1={expected}"));
    }

    #[tokio::test]
    async fn retries_with_the_same_context_reproduce_the_signature() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let signer =
            WebhookSigner::new(SigningScheme::Standard, vec![Zeroizing::new(b"k".to_vec())]);
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
    async fn a_retry_posts_only_the_results_that_did_not_go_out() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let signer =
            WebhookSigner::new(SigningScheme::Standard, vec![Zeroizing::new(b"k".to_vec())]);
        let mut sink = signed_sink_to(format!("{}/hook", server.uri()), signer);
        let result: ProcessResult =
            vec![detection("first"), detection("second"), detection("third")];
        let context = ctx();

        assert!(sink.send(&result, &context).await.is_err());
        sink.send(&result, &context).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let posted: Vec<(String, String)> = reqs
            .iter()
            .map(|req| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                let id = req
                    .headers
                    .get("webhook-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                (body["text"].as_str().unwrap().to_string(), id)
            })
            .collect();
        let id = |idx: usize| format!("{}-{idx}", context.id_base());
        assert_eq!(
            posted,
            [
                ("first".to_string(), id(0)),
                ("second".to_string(), id(1)),
                ("second".to_string(), id(1)),
                ("third".to_string(), id(2)),
            ],
            "the retry starts at the failed result and keeps its signing id"
        );
    }

    #[tokio::test]
    async fn a_new_delivery_posts_every_result() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let mut sink = sink_to(format!("{}/hook", server.uri()));
        let result: ProcessResult = vec![detection("first"), detection("second")];

        let failed = ctx();
        assert!(sink.send(&result, &failed).await.is_err());
        let next = ctx();
        sink.send_batch(&[(&result, &next)])
            .await
            .pop()
            .unwrap()
            .unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    fn detection_at(title: &str, level: Level) -> EvaluationResult {
        let mut r = detection(title);
        r.header.level = Some(level);
        r
    }

    #[derive(Default)]
    struct DeliveryCounters {
        dropped: std::sync::atomic::AtomicUsize,
        failed: std::sync::atomic::AtomicUsize,
    }

    impl MetricsHook for DeliveryCounters {
        fn on_sink_dropped(&self, _sink: &str) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        fn on_sink_delivery_failed(&self, _sink: &str) {
            self.failed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        fn on_parse_error(&self) {}
        fn on_events_processed(&self, _: u64) {}
        fn on_detection_matches(&self, _: u64) {}
        fn on_correlation_matches(&self, _: u64) {}
        fn observe_processing_latency(&self, _: f64) {}
        fn on_input_queue_depth_change(&self, _: i64) {}
        fn on_back_pressure(&self) {}
        fn observe_batch_size(&self, _: u64) {}
        fn on_output_queue_depth_change(&self, _: i64) {}
        fn observe_pipeline_latency(&self, _: f64) {}
        fn set_correlation_state_entries(&self, _: u64) {}
    }

    fn scoped_sink(url: String, scope: crate::enrichment::Scope) -> WebhookSink {
        WebhookSink::new(
            "scoped".to_string(),
            WebhookKind::Detection,
            reqwest::Method::POST,
            url,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(r#"{"text":"${detection.rule.title}"}"#.to_string()),
            Duration::from_secs(5),
            scope,
            None,
            crate::enrichment::build_default_http_client().unwrap(),
            Arc::new(NoopMetrics),
            None,
        )
    }

    fn fast_delivery(queue_depth: usize) -> crate::io::DeliveryConfig {
        crate::io::DeliveryConfig {
            queue_depth,
            batch_max: 1,
            batch_flush: Duration::ZERO,
            retry_max: 2,
            backoff_base: Duration::from_millis(1),
            backoff_max: Duration::from_millis(5),
        }
    }

    async fn posted_titles(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|req| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                body["text"].as_str().unwrap().to_string()
            })
            .collect()
    }

    fn parked_titles(failure: &crate::io::DeliveryFailure) -> Vec<String> {
        let parked: Vec<serde_json::Value> = serde_json::from_str(&failure.serialized).unwrap();
        parked
            .iter()
            .map(|r| r["rule_title"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn out_of_scope_results_never_take_a_webhook_queue_slot() {
        use crate::io::{AckToken, Dispatcher, OnFull, Sink};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)))
            .mount(&server)
            .await;
        let scope =
            crate::enrichment::Scope::new(vec![], vec![], vec!["critical".to_string()]).unwrap();
        let sink = scoped_sink(format!("{}/hook", server.uri()), scope);
        let counters = Arc::new(DeliveryCounters::default());
        let (ack_tx, mut ack_rx) = tokio::sync::mpsc::unbounded_channel();
        let queue_size = 2;
        let dispatcher = Dispatcher::spawn(
            vec![(
                Sink::Webhook(Box::new(sink)),
                OnFull::Drop,
                fast_delivery(queue_size),
            )],
            None,
            ack_tx,
            counters.clone(),
        );

        dispatcher
            .dispatch(
                vec![detection_at("busy", Level::Critical)],
                vec![AckToken::Noop],
            )
            .await;
        for _ in 0..queue_size * 5 {
            dispatcher
                .dispatch(
                    vec![detection_at("noise", Level::Low)],
                    vec![AckToken::Noop],
                )
                .await;
        }
        dispatcher
            .dispatch(
                vec![detection_at("page", Level::Critical)],
                vec![AckToken::Noop],
            )
            .await;
        dispatcher.shutdown().await;

        assert_eq!(
            counters.dropped.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "out-of-scope results never reach the queue, so nothing is dropped"
        );
        assert_eq!(posted_titles(&server).await, ["busy", "page"]);
        let mut acks = 0;
        while ack_rx.try_recv().is_ok() {
            acks += 1;
        }
        assert_eq!(acks, queue_size * 5 + 2, "every event is still acked");
    }

    #[tokio::test]
    async fn a_permanent_failure_does_not_stop_the_other_results() {
        use crate::io::{AckToken, Dispatcher, OnFull, Sink};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let sink = sink_to(format!("{}/hook", server.uri()));
        let counters = Arc::new(DeliveryCounters::default());
        let (dlq_tx, mut dlq_rx) = tokio::sync::mpsc::channel(8);
        let (ack_tx, mut ack_rx) = tokio::sync::mpsc::unbounded_channel();
        let dispatcher = Dispatcher::spawn(
            vec![(
                Sink::Webhook(Box::new(sink)),
                OnFull::Drop,
                fast_delivery(8),
            )],
            Some(dlq_tx),
            ack_tx,
            counters.clone(),
        );

        dispatcher
            .dispatch(
                vec![detection("first"), detection("second")],
                vec![AckToken::Noop],
            )
            .await;
        dispatcher.shutdown().await;

        assert_eq!(
            posted_titles(&server).await,
            ["first", "second"],
            "the second result is delivered exactly once"
        );
        let failure = dlq_rx.try_recv().expect("the rejected result is parked");
        assert_eq!(parked_titles(&failure), ["first"]);
        assert!(failure.error.contains("HTTP 400"), "{}", failure.error);
        assert!(dlq_rx.try_recv().is_err(), "nothing else is parked");
        assert_eq!(counters.failed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(ack_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn a_retry_after_a_parked_result_resends_neither_it_nor_what_went_out() {
        use crate::io::{AckToken, Dispatcher, OnFull, Sink};

        let server = MockServer::start().await;
        for status in [400, 503] {
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status))
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let sink = sink_to(format!("{}/hook", server.uri()));
        let (dlq_tx, mut dlq_rx) = tokio::sync::mpsc::channel(8);
        let (ack_tx, _ack_rx) = tokio::sync::mpsc::unbounded_channel();
        let dispatcher = Dispatcher::spawn(
            vec![(
                Sink::Webhook(Box::new(sink)),
                OnFull::Drop,
                fast_delivery(8),
            )],
            Some(dlq_tx),
            ack_tx,
            Arc::new(NoopMetrics),
        );

        dispatcher
            .dispatch(
                vec![detection("first"), detection("second"), detection("third")],
                vec![AckToken::Noop],
            )
            .await;
        dispatcher.shutdown().await;

        assert_eq!(
            posted_titles(&server).await,
            ["first", "second", "second", "third"]
        );
        assert_eq!(parked_titles(&dlq_rx.try_recv().unwrap()), ["first"]);
        assert!(dlq_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn giving_up_parks_only_the_in_scope_results_not_yet_posted() {
        use crate::io::{AckToken, Dispatcher, OnFull, Sink};
        use wiremock::matchers::body_string_contains;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("second"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let scope =
            crate::enrichment::Scope::new(vec![], vec![], vec!["high".to_string()]).unwrap();
        let sink = scoped_sink(format!("{}/hook", server.uri()), scope);
        let (dlq_tx, mut dlq_rx) = tokio::sync::mpsc::channel(8);
        let (ack_tx, _ack_rx) = tokio::sync::mpsc::unbounded_channel();
        let cfg = fast_delivery(8);
        let dispatcher = Dispatcher::spawn(
            vec![(Sink::Webhook(Box::new(sink)), OnFull::Drop, cfg)],
            Some(dlq_tx),
            ack_tx,
            Arc::new(NoopMetrics),
        );

        dispatcher
            .dispatch(
                vec![
                    detection("first"),
                    detection("second"),
                    detection_at("quiet", Level::Low),
                    detection("third"),
                ],
                vec![AckToken::Noop],
            )
            .await;
        dispatcher.shutdown().await;

        let attempts = cfg.retry_max as usize + 1;
        let mut expected = vec!["first".to_string()];
        expected.extend(std::iter::repeat_n("second".to_string(), attempts));
        assert_eq!(posted_titles(&server).await, expected);
        let failure = dlq_rx.try_recv().expect("the delivery is parked");
        assert_eq!(parked_titles(&failure), ["second", "third"]);
        assert!(failure.error.contains("HTTP 503"), "{}", failure.error);
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
