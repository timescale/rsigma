use parking_lot::Mutex;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::DeliveryContext;
use crate::io::SinkFormat;
use crate::io::lines::{LineEncoding, LineWriter};

/// Serializes ProcessResult to one line per result and writes it to stdout.
///
/// A delivery's lines, or a whole batch of deliveries, go out in one write.
/// When a delivery is retried after a failed write, lines that already
/// reached stdout are not written again, and a line cut off by the failure is
/// ended before anything else is written.
pub struct StdoutSink {
    pretty: bool,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
    tenant_filter: Option<TenantId>,
    out: Mutex<LineWriter<std::io::Stdout>>,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        StdoutSink {
            pretty,
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            tenant_filter: None,
            out: Mutex::new(LineWriter::new(std::io::stdout())),
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
        self.out.lock().write_result(result, None, self.encoding())
    }

    pub(crate) fn send_with_context(
        &self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.out
            .lock()
            .write_result(result, Some(ctx), self.encoding())
    }

    /// Write a batch of deliveries in one write, one outcome per delivery.
    pub(crate) fn send_batch(
        &self,
        items: &[(&ProcessResult, &DeliveryContext)],
    ) -> Vec<Result<(), RuntimeError>> {
        self.out.lock().write_results(items, self.encoding())
    }

    fn encoding(&self) -> LineEncoding<'_> {
        LineEncoding {
            format: self.format,
            pretty: self.pretty,
            ocsf: &self.ocsf,
            tenant_filter: self.tenant_filter.as_ref(),
        }
    }

    /// Write a pre-serialized JSON string directly to stdout.
    pub fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        self.out.lock().write_line(json)
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
