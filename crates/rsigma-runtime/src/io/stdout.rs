use std::sync::OnceLock;

use parking_lot::Mutex;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::DeliveryContext;
use crate::io::SinkFormat;
use crate::io::lines::{LineEncoding, LineWriter, WriterThread};

/// Serializes ProcessResult to one line per result and writes it to stdout.
///
/// A delivery's lines, or a whole batch of deliveries, go out in one write.
/// Batches the delivery worker drains while keeping up are written on one
/// `rsigma-stdout` thread shared by every stdout sink.
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
        self.with_writer(|out| out.write_result(result, None, self.encoding()))
    }

    pub(crate) fn send_with_context(
        &self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.with_writer(|out| out.write_result(result, Some(ctx), self.encoding()))
    }

    /// Write a batch of deliveries in one write, one outcome per delivery the
    /// write reached.
    ///
    /// Without a `backlog` the delivery worker is keeping up, and the batch
    /// is written on the stdout writer thread, so the runtime thread stays
    /// with the tasks that feed the worker. With one the worker is the
    /// bottleneck, and the batch is written in place through
    /// [`super::blocking_write`]: a full batch shares the cost of moving the
    /// runtime to another thread, and the write adds no round trip.
    pub(crate) async fn send_batch(
        &self,
        items: &[(&ProcessResult, &DeliveryContext)],
        backlog: bool,
    ) -> Vec<Result<(), RuntimeError>> {
        let writer = if backlog { None } else { stdout_writer() };
        let Some(writer) = writer else {
            return super::blocking_write(|| {
                self.with_writer(|out| out.write_results(items, self.encoding()))
            });
        };
        writer
            .write_results(&self.out, items, self.encoding())
            .await
    }

    /// Run `write` holding the process's stdout lock as well as this sink's
    /// writer, so a write that takes several `write` calls is not interleaved
    /// with another stdout writer's output.
    fn with_writer<R>(&self, write: impl FnOnce(&mut LineWriter<std::io::Stdout>) -> R) -> R {
        let _stdout = std::io::stdout().lock();
        write(&mut self.out.lock())
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
        self.with_writer(|out| out.write_line(json))
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

/// The process's stdout writer thread, started on first use. `None` when it
/// could not be started.
fn stdout_writer() -> Option<&'static WriterThread> {
    static WRITER: OnceLock<Option<WriterThread>> = OnceLock::new();
    WRITER
        .get_or_init(
            || match WriterThread::spawn("rsigma-stdout", || std::io::stdout().lock()) {
                Ok(writer) => Some(writer),
                Err(error) => {
                    tracing::warn!(%error, "Could not start the stdout writer thread");
                    None
                }
            },
        )
        .as_ref()
}
