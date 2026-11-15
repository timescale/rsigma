use std::io::Write;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::io::{DeliveryContext, SinkFormat, serialize_result};

/// Serializes ProcessResult to one line per result and writes it to stdout.
pub struct StdoutSink {
    pretty: bool,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        StdoutSink {
            pretty,
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
        }
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

    pub fn ocsf_options(&self) -> crate::ocsf::OcsfOptions {
        self.ocsf
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
            let json = serialize_result(
                m,
                self.format,
                self.pretty,
                ctx.map(|ctx| (ctx, index)),
                self.ocsf,
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
}
