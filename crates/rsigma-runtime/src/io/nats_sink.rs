use std::collections::HashSet;

use async_nats::jetstream;
use async_nats::subject::Subject;
use parking_lot::Mutex;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
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
        // Render every subject before publishing, so an untenanted result
        // fails the delivery without a partial publish.
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
        let mut published = 0_usize;
        for (index, m, subject) in targets {
            let json = serialize_result(
                m,
                self.format,
                false,
                ctx.map(|ctx| (ctx, index)),
                &self.ocsf,
            )?;
            self.ensure_stream(&self.subject).await?;
            self.publish_one(&subject, &json).await?;
            published += 1;
        }

        if published > 0 {
            tracing::debug!(messages = published, "NATS messages published");
        }
        Ok(())
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
