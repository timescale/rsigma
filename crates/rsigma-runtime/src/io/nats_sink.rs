use std::collections::HashSet;

use async_nats::jetstream;
use async_nats::subject::Subject;
use futures::future::join_all;
use parking_lot::Mutex;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::lines::ResumeMap;
use crate::io::{DeliveryContext, SinkFormat, serialize_result};

use super::nats_config::NatsConnectConfig;
use super::nats_source::derive_nats_name;

/// A NATS subject that may carry a `{tenant}` token rendered per result.
pub(crate) enum SubjectTemplate {
    /// A literal subject.
    Static(String),
    /// A subject with `{tenant}` as one dot-separated token.
    PerTenant { before: String, after: String },
}

impl SubjectTemplate {
    fn parse(subject: &str) -> Result<Self, String> {
        super::validate_nats_subject_template(subject)?;
        let tokens: Vec<&str> = subject.split('.').collect();
        Ok(match tokens.iter().position(|token| *token == "{tenant}") {
            Some(position) => SubjectTemplate::PerTenant {
                before: tokens[..position].join("."),
                after: tokens[position + 1..].join("."),
            },
            None => SubjectTemplate::Static(subject.to_string()),
        })
    }

    /// The JetStream stream that holds this template's subjects: the literal
    /// subject, or one stream over every tenant (`{tenant}` as `*`).
    fn stream(&self) -> (String, String) {
        match self {
            SubjectTemplate::Static(subject) => {
                (derive_nats_name("rsigma", subject), subject.clone())
            }
            SubjectTemplate::PerTenant { .. } => {
                let wildcard = self.render_token("*");
                (derive_nats_name("rsigma-tenants", &wildcard), wildcard)
            }
        }
    }

    fn render_token(&self, token: &str) -> String {
        match self {
            SubjectTemplate::Static(subject) => subject.clone(),
            SubjectTemplate::PerTenant { before, after } => {
                match (before.is_empty(), after.is_empty()) {
                    (true, true) => token.to_string(),
                    (true, false) => format!("{token}.{after}"),
                    (false, true) => format!("{before}.{token}"),
                    (false, false) => format!("{before}.{token}.{after}"),
                }
            }
        }
    }

    fn render(&self, tenant: Option<&TenantId>) -> Option<String> {
        match self {
            SubjectTemplate::Static(subject) => Some(subject.clone()),
            SubjectTemplate::PerTenant { .. } => Some(self.render_token(tenant?.as_str())),
        }
    }
}

/// Publishes ProcessResult as NDJSON to a NATS JetStream subject.
///
/// Uses JetStream `publish` with publish-ack confirmation to guarantee that the
/// NATS server has persisted each message. This completes the at-least-once
/// guarantee end-to-end: the source acks only after this sink's JetStream
/// publish is confirmed.
pub struct NatsSink {
    jetstream: jetstream::Context,
    subject: SubjectTemplate,
    /// Subjects whose JetStream stream has been ensured, so an incident subject
    /// override only triggers stream creation once.
    ensured: Mutex<HashSet<String>>,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
    tenant_filter: Option<TenantId>,
    /// Result indexes of a failed delivery that JetStream already confirmed.
    acked: Mutex<ResumeMap<Vec<usize>>>,
}

/// Publishes awaited together before their acks; well under the JetStream
/// context's default limit of 5,000 publishes waiting for an ack.
const ACK_WINDOW: usize = 1024;

/// One message of a batch, with the delivery and result index it belongs to.
struct PendingMessage {
    item: usize,
    index: usize,
    subject: String,
    json: String,
}

impl NatsSink {
    /// Connect to NATS and prepare to publish to a JetStream subject.
    ///
    /// Creates or reuses the JetStream stream for the subject. A `{tenant}`
    /// subject uses one stream whose subject has `*` in place of `{tenant}`.
    pub async fn connect(
        config: &NatsConnectConfig,
        subject: &str,
    ) -> Result<Self, async_nats::Error> {
        let template = SubjectTemplate::parse(subject)?;
        let client = config.connect().await?;
        let js = jetstream::new(client);

        let mut ensured = HashSet::new();
        let (stream_name, stream_subject) = template.stream();
        js.get_or_create_stream(jetstream::stream::Config {
            name: stream_name,
            subjects: vec![stream_subject.clone()],
            ..Default::default()
        })
        .await?;
        ensured.insert(stream_subject);

        Ok(NatsSink {
            jetstream: js,
            subject: template,
            ensured: Mutex::new(ensured),
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            tenant_filter: None,
            acked: Mutex::new(ResumeMap::default()),
        })
    }

    /// Select the wire format this sink serializes results into.
    #[must_use]
    pub fn with_format(mut self, format: SinkFormat) -> Self {
        self.format = format;
        self
    }

    #[must_use]
    pub fn with_ocsf_options(mut self, ocsf: crate::ocsf::OcsfOptions) -> Self {
        self.ocsf = ocsf;
        self
    }

    /// Only deliver results of `tenant`.
    #[must_use]
    pub fn with_tenant_filter(mut self, tenant: Option<TenantId>) -> Self {
        self.tenant_filter = tenant;
        self
    }

    /// The wire format this sink serializes results into.
    pub fn format(&self) -> SinkFormat {
        self.format
    }

    pub fn ocsf_options(&self) -> &crate::ocsf::OcsfOptions {
        &self.ocsf
    }

    /// Serialize and publish a ProcessResult to the configured JetStream subject.
    ///
    /// Each message is published with publish-ack: the call blocks until the
    /// server confirms persistence, or returns an error on failure.
    pub async fn send(&self, result: &ProcessResult) -> Result<(), RuntimeError> {
        self.send_inner(result, None).await
    }

    pub(crate) async fn send_with_context(
        &self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.send_inner(result, Some(ctx)).await
    }

    async fn send_inner(
        &self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
    ) -> Result<(), RuntimeError> {
        self.publish_results(&[(result, ctx)])
            .await
            .pop()
            .unwrap_or(Ok(()))
    }

    /// Publish a batch of deliveries, one outcome per delivery.
    pub(crate) async fn send_batch(
        &self,
        items: &[(&ProcessResult, &DeliveryContext)],
    ) -> Vec<Result<(), RuntimeError>> {
        // The worker has finished with every earlier delivery. Its retries of
        // this batch's failures go through `send_with_context`, which must
        // keep the other failures' progress.
        self.acked.lock().retain(items.iter().map(|(_, ctx)| *ctx));
        self.publish_results(items).await
    }

    /// Publish every message of every delivery, then await their acks
    /// together, so one slow ack does not hold up the rest. A delivery
    /// succeeds when all its messages are confirmed; the confirmed messages
    /// of a failed one are remembered, so its retry publishes only the rest.
    async fn publish_results<'c, C>(
        &self,
        items: &[(&ProcessResult, C)],
    ) -> Vec<Result<(), RuntimeError>>
    where
        C: Copy + Into<Option<&'c DeliveryContext>>,
    {
        let mut outcomes = Vec::with_capacity(items.len());
        let mut acked: Vec<Vec<usize>> = Vec::with_capacity(items.len());
        let mut messages = Vec::new();
        {
            let progress = self.acked.lock();
            for (item, (result, ctx)) in items.iter().enumerate() {
                let ctx = (*ctx).into();
                let done = progress.get(ctx).cloned().unwrap_or_default();
                match self.messages(result, ctx, &done) {
                    Ok(pending) => {
                        messages.extend(pending.into_iter().map(|(index, subject, json)| {
                            PendingMessage {
                                item,
                                index,
                                subject,
                                json,
                            }
                        }));
                        outcomes.push(Ok(()));
                    }
                    Err(err) => outcomes.push(Err(err)),
                }
                acked.push(done);
            }
        }

        if !messages.is_empty() {
            let confirmed = match self.ensure_stream(&self.subject).await {
                Ok(()) => self.publish_all(&messages).await,
                Err(err) => messages.iter().map(|_| Err(err.duplicate())).collect(),
            };
            let mut published = 0_usize;
            for (message, outcome) in messages.iter().zip(confirmed) {
                match outcome {
                    Ok(()) => {
                        acked[message.item].push(message.index);
                        published += 1;
                    }
                    Err(err) => {
                        if outcomes[message.item].is_ok() {
                            outcomes[message.item] = Err(err);
                        }
                    }
                }
            }
            if published > 0 {
                tracing::debug!(messages = published, "NATS messages published");
            }
        }

        let mut progress = self.acked.lock();
        for ((_, ctx), (outcome, done)) in items.iter().zip(outcomes.iter().zip(acked)) {
            let ctx = (*ctx).into();
            if outcome.is_ok() {
                progress.clear(ctx);
            } else if !done.is_empty() {
                progress.record(ctx, done);
            }
        }
        outcomes
    }

    /// The `(index, subject, json)` of each message of `result` this sink
    /// publishes, leaving out the confirmed indexes in `done`. Every subject
    /// is rendered first, so an untenanted result fails the delivery without
    /// a partial publish.
    fn messages(
        &self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
        done: &[usize],
    ) -> Result<Vec<(usize, String, String)>, RuntimeError> {
        let mut targets = Vec::new();
        for (index, m) in result.iter().enumerate() {
            if let Some(filter) = &self.tenant_filter
                && m.header.tenant_id.as_ref() != Some(filter)
            {
                continue;
            }
            let Some(subject) = self.subject.render(m.header.tenant_id.as_ref()) else {
                return Err(RuntimeError::Permanent(format!(
                    "subject '{}' needs a tenant but the result has none",
                    self.subject_label()
                )));
            };
            targets.push((index, m, subject));
        }
        targets
            .into_iter()
            .filter(|(index, _, _)| !done.contains(index))
            .map(|(index, m, subject)| {
                serialize_result(
                    m,
                    self.format,
                    false,
                    ctx.map(|ctx| (ctx, index)),
                    &self.ocsf,
                )
                .map(|json| (index, subject, json))
            })
            .collect()
    }

    /// Publish `messages` and await every ack, keeping each outcome. Acks
    /// are awaited every [`ACK_WINDOW`] messages, since the JetStream context
    /// lets only a bounded number of publishes wait for their ack.
    async fn publish_all(&self, messages: &[PendingMessage]) -> Vec<Result<(), RuntimeError>> {
        let mut outcomes = Vec::with_capacity(messages.len());
        let mut failed = 0_usize;
        let mut first_error = None;
        for window in messages.chunks(ACK_WINDOW) {
            let mut acks = Vec::with_capacity(window.len());
            for message in window {
                acks.push(
                    self.jetstream
                        .publish(
                            Subject::from(message.subject.clone()),
                            message.json.clone().into(),
                        )
                        .await,
                );
            }
            let confirmed = join_all(acks.into_iter().map(|ack| async move {
                match ack {
                    Ok(ack) => ack.await.map(|_| ()).map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }))
            .await;
            for (message, outcome) in window.iter().zip(confirmed) {
                outcomes.push(outcome.map_err(|e| {
                    failed += 1;
                    first_error.get_or_insert_with(|| (message.subject.clone(), e.clone()));
                    RuntimeError::Io(std::io::Error::other(e))
                }));
            }
        }
        if let Some((subject, error)) = first_error {
            tracing::warn!(subject, failed, error, "NATS publish failed");
        }
        outcomes
    }

    fn subject_label(&self) -> String {
        match &self.subject {
            SubjectTemplate::Static(subject) => subject.clone(),
            SubjectTemplate::PerTenant { before, after } => format!("{before}.{{tenant}}.{after}"),
        }
    }

    /// Publish a pre-serialized JSON string directly to the JetStream subject.
    pub async fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        let Some(subject) = self.subject.render(None) else {
            return Err(RuntimeError::Permanent(format!(
                "subject '{}' needs a tenant but a raw line has none",
                self.subject_label()
            )));
        };
        self.ensure_stream(&self.subject).await?;
        self.publish_one(&subject, json).await?;
        tracing::debug!(subject = %subject, "NATS message published (raw)");
        Ok(())
    }

    /// Publish an incident line, optionally to a dedicated subject override so
    /// incident consumers can subscribe without filtering the detection stream.
    /// A `{tenant}` token in either subject is rendered from `tenant`.
    pub async fn send_incident(
        &self,
        json: &str,
        subject_override: Option<&str>,
        tenant: Option<&TenantId>,
    ) -> Result<(), RuntimeError> {
        if let Some(filter) = &self.tenant_filter
            && tenant != Some(filter)
        {
            return Ok(());
        }
        let template = match subject_override {
            Some(subject) => SubjectTemplate::parse(subject).map_err(RuntimeError::Permanent)?,
            None => match &self.subject {
                SubjectTemplate::Static(subject) => SubjectTemplate::Static(subject.clone()),
                SubjectTemplate::PerTenant { before, after } => SubjectTemplate::PerTenant {
                    before: before.clone(),
                    after: after.clone(),
                },
            },
        };
        let Some(subject) = template.render(tenant) else {
            return Err(RuntimeError::Permanent(
                "an incident subject needs a tenant but the incident has none".to_string(),
            ));
        };
        self.ensure_stream(&template).await?;
        self.publish_one(&subject, json).await
    }

    /// Ensure the JetStream stream for `template` exists, once per stream
    /// subject.
    async fn ensure_stream(&self, template: &SubjectTemplate) -> Result<(), RuntimeError> {
        let (stream_name, stream_subject) = template.stream();
        if self.ensured.lock().contains(&stream_subject) {
            return Ok(());
        }
        self.jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: stream_name,
                subjects: vec![stream_subject.clone()],
                ..Default::default()
            })
            .await
            .map_err(|e| {
                tracing::warn!(subject = %stream_subject, error = %e, "NATS stream ensure failed");
                RuntimeError::Io(std::io::Error::other(e))
            })?;
        self.ensured.lock().insert(stream_subject);
        Ok(())
    }

    /// Publish a single JSON payload to `subject`, logging on failure.
    async fn publish_one(&self, subject: &str, json: &str) -> Result<(), RuntimeError> {
        let ack = self
            .jetstream
            .publish(Subject::from(subject.to_string()), json.to_string().into())
            .await
            .map_err(|e| {
                tracing::warn!(subject, error = %e, "NATS publish failed");
                RuntimeError::Io(std::io::Error::other(e))
            })?;
        ack.await.map_err(|e| {
            tracing::warn!(subject, error = %e, "NATS publish ack failed");
            RuntimeError::Io(std::io::Error::other(e))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_subject_is_static() {
        let template = SubjectTemplate::parse("rsigma.detections").unwrap();
        assert!(matches!(template, SubjectTemplate::Static(_)));
        assert_eq!(
            template.render(Some(&TenantId::new("a").unwrap())),
            Some("rsigma.detections".to_string())
        );
    }

    #[test]
    fn a_tenant_token_is_rendered_per_tenant() {
        let template = SubjectTemplate::parse("rsigma.detections.{tenant}").unwrap();
        assert!(matches!(template, SubjectTemplate::PerTenant { .. }));
        assert_eq!(
            template.render(Some(&TenantId::new("a").unwrap())),
            Some("rsigma.detections.a".to_string())
        );
        assert_eq!(template.render(None), None);
    }

    #[test]
    fn a_tenant_token_in_the_middle_keeps_its_neighbours() {
        let template = SubjectTemplate::parse("tenants.{tenant}.detections").unwrap();
        assert_eq!(
            template.render(Some(&TenantId::new("tenant-a").unwrap())),
            Some("tenants.tenant-a.detections".to_string())
        );
    }

    #[test]
    fn a_partial_or_repeated_tenant_token_is_refused() {
        assert!(SubjectTemplate::parse("rsigma.det-{tenant}").is_err());
        assert!(SubjectTemplate::parse("rsigma.{tenant}x.det").is_err());
        assert!(SubjectTemplate::parse("{tenant}.det.{tenant}").is_err());
        assert!(SubjectTemplate::parse("rsigma.{tenant}").is_ok());
    }

    fn titled(titles: &[&str]) -> ProcessResult {
        use std::collections::HashMap;
        use std::sync::Arc;

        use rsigma_eval::EvaluationResult;
        use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};

        titles
            .iter()
            .map(|title| EvaluationResult {
                header: RuleHeader {
                    rule_title: title.to_string(),
                    rule_id: None,
                    tenant_id: None,
                    level: None,
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
            })
            .collect()
    }

    fn can_run_linux_containers() -> bool {
        std::process::Command::new("docker")
            .args(["info", "--format", "{{.OSType}}"])
            .output()
            .is_ok_and(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux"
            })
    }

    #[tokio::test]
    async fn a_retry_publishes_only_the_messages_jetstream_did_not_confirm() {
        use testcontainers::ImageExt;
        use testcontainers::runners::AsyncRunner;
        use testcontainers_modules::nats::{Nats, NatsServerCmd};

        if !can_run_linux_containers() {
            eprintln!("Skipping: Docker with Linux container support is not available");
            return;
        }
        let cmd = NatsServerCmd::default().with_jetstream();
        let container = Nats::default().with_cmd(&cmd).start().await.unwrap();
        let port = container.get_host_port_ipv4(4222).await.unwrap();
        let cfg = NatsConnectConfig::new(format!("nats://127.0.0.1:{port}"));
        let subject = "rsigma.batch";

        // A stream that refuses its third message, so the third publish of
        // the batch gets a failed ack.
        let js = jetstream::new(cfg.connect().await.unwrap());
        let (name, stream_subject) = SubjectTemplate::parse(subject).unwrap().stream();
        let mut config = jetstream::stream::Config {
            name: name.clone(),
            subjects: vec![stream_subject],
            max_messages: 2,
            discard: jetstream::stream::DiscardPolicy::New,
            ..Default::default()
        };
        js.create_stream(config.clone()).await.unwrap();

        let sink = NatsSink::connect(&cfg, subject).await.unwrap();
        let deliveries = [titled(&["a0", "a1", "a2"]), titled(&["b0"])];
        let contexts = [DeliveryContext::new(), DeliveryContext::new()];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();

        let outcomes = sink.send_batch(&items).await;
        assert!(outcomes[0].is_err(), "a2 was not confirmed");
        assert!(outcomes[1].is_err(), "b0 was not confirmed");

        config.max_messages = -1;
        js.update_stream(config).await.unwrap();
        for (result, ctx) in &items {
            sink.send_with_context(result, ctx).await.unwrap();
        }

        let mut stream = js.get_stream(&name).await.unwrap();
        assert_eq!(stream.info().await.unwrap().state.messages, 4);
        let mut titles = Vec::new();
        for sequence in 1..=4 {
            let message = stream.get_raw_message(sequence).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&message.payload).unwrap();
            titles.push(value["rule_title"].as_str().unwrap().to_string());
        }
        assert_eq!(
            titles,
            ["a0", "a1", "a2", "b0"],
            "confirmed messages are not published again"
        );
    }

    #[tokio::test]
    async fn a_batch_past_the_pending_ack_limit_is_published() {
        use testcontainers::ImageExt;
        use testcontainers::runners::AsyncRunner;
        use testcontainers_modules::nats::{Nats, NatsServerCmd};

        if !can_run_linux_containers() {
            eprintln!("Skipping: Docker with Linux container support is not available");
            return;
        }
        let cmd = NatsServerCmd::default().with_jetstream();
        let container = Nats::default().with_cmd(&cmd).start().await.unwrap();
        let port = container.get_host_port_ipv4(4222).await.unwrap();
        let cfg = NatsConnectConfig::new(format!("nats://127.0.0.1:{port}"));
        let subject = "rsigma.large";

        let sink = NatsSink::connect(&cfg, subject).await.unwrap();
        // More messages than the JetStream context lets wait for an ack.
        let titles: Vec<String> = (0..6_000).map(|i| format!("m{i}")).collect();
        let result = titled(&titles.iter().map(String::as_str).collect::<Vec<_>>());
        let ctx = DeliveryContext::new();
        let outcomes = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            sink.send_batch(&[(&result, &ctx)]),
        )
        .await
        .expect("the batch never finished publishing");
        assert!(outcomes[0].is_ok(), "{outcomes:?}");

        let js = jetstream::new(cfg.connect().await.unwrap());
        let (name, _) = SubjectTemplate::parse(subject).unwrap().stream();
        let mut stream = js.get_stream(&name).await.unwrap();
        assert_eq!(stream.info().await.unwrap().state.messages, 6_000);
    }

    #[test]
    fn a_per_tenant_subject_uses_one_wildcard_stream() {
        let template = SubjectTemplate::parse("tenants.{tenant}.detections").unwrap();
        let (name, subject) = template.stream();
        assert_eq!(subject, "tenants.*.detections");
        assert!(name.starts_with("rsigma-tenants"));
        let (static_name, _) = SubjectTemplate::parse("tenants.detections")
            .unwrap()
            .stream();
        assert_ne!(name, static_name);
    }
}
