use std::io::Write;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::{DeliveryContext, SinkFormat, serialize_result};

/// Serializes ProcessResult to one line per result and writes it to stdout.
pub struct StdoutSink {
    pretty: bool,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
    tenant_filter: Option<TenantId>,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        StdoutSink {
            pretty,
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            tenant_filter: None,
        }
    }

    /// Only deliver results of `tenant`.
    #[must_use]
    pub fn with_tenant_filter(mut self, tenant: Option<TenantId>) -> Self {
        self.tenant_filter = tenant;
        self
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

    /// The wire format this sink serializes results into.
    pub fn format(&self) -> SinkFormat {
        self.format
    }

    pub fn ocsf_options(&self) -> &crate::ocsf::OcsfOptions {
        &self.ocsf
    }

    /// Serialize and write a ProcessResult to stdout.
    pub fn send(&self, result: &ProcessResult) -> Result<(), RuntimeError> {
        self.send_inner(result, None)
    }

    pub(crate) fn send_with_context(
        &self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.send_inner(result, Some(ctx))
    }

    fn send_inner(
        &self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
    ) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }

        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        for (index, m) in result.iter().enumerate() {
            if let Some(filter) = &self.tenant_filter
                && m.header.tenant_id.as_ref() != Some(filter)
            {
                continue;
            }
            let json = serialize_result(
                m,
                self.format,
                self.pretty,
                ctx.map(|ctx| (ctx, index)),
                &self.ocsf,
            )?;
            writeln!(out, "{json}")?;
        }

        Ok(())
    }

    /// Write a pre-serialized JSON string directly to stdout.
    pub fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{json}")?;
        Ok(())
    }

    /// Write a pre-serialized line when it belongs to `tenant`.
    pub fn send_raw_for_tenant(
        &self,
        json: &str,
        tenant: Option<&TenantId>,
    ) -> Result<(), RuntimeError> {
        if let Some(filter) = &self.tenant_filter
            && tenant != Some(filter)
        {
            return Ok(());
        }
        self.send_raw(json)
    }
}
