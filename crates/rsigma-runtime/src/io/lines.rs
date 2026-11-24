//! Line bookkeeping shared by the NDJSON sinks that write to a byte stream
//! (stdout, file, and Unix socket): batches written in one go, and where a
//! retried delivery should resume.

use std::io::{self, Write};

use parking_lot::Mutex;
use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::{DeliveryContext, SinkFormat, serialize_result};

/// The NDJSON lines of one or more deliveries, serialized into a single
/// buffer so they go out in one write, with the end offset of each line and
/// the line count at the end of each delivery.
#[derive(Default)]
pub(crate) struct LineBatch {
    bytes: Vec<u8>,
    ends: Vec<usize>,
    items: Vec<usize>,
}

impl LineBatch {
    /// Append one line; the newline is added here.
    pub(crate) fn push(&mut self, json: &str) {
        self.bytes.extend_from_slice(json.as_bytes());
        self.bytes.push(b'\n');
        self.ends.push(self.bytes.len());
    }

    /// Close the current delivery: every line pushed since the previous call
    /// belongs to it. A delivery may have no lines.
    pub(crate) fn end_item(&mut self) {
        self.items.push(self.ends.len());
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many whole lines the first `written` bytes cover.
    pub(crate) fn complete_lines(&self, written: usize) -> usize {
        self.ends.partition_point(|&end| end <= written)
    }

    /// Byte offset where line `index` starts.
    pub(crate) fn line_start(&self, index: usize) -> usize {
        index.checked_sub(1).map_or(0, |i| self.ends[i])
    }

    /// Whether the first `written` bytes stop partway through a line.
    pub(crate) fn ends_mid_line(&self, written: usize) -> bool {
        written > self.line_start(self.complete_lines(written))
    }

    /// Where a write that stopped after `lines` whole lines left the
    /// deliveries: how many of them have every line written, and how many
    /// lines of the next one were written.
    pub(crate) fn item_progress(&self, lines: usize) -> (usize, usize) {
        let done = self.items.partition_point(|&end| end <= lines);
        let first_line = done.checked_sub(1).map_or(0, |i| self.items[i]);
        (done, lines - first_line)
    }
}

/// How a line sink serializes the results it delivers.
#[derive(Clone, Copy)]
pub(crate) struct LineEncoding<'a> {
    pub(crate) format: SinkFormat,
    pub(crate) pretty: bool,
    pub(crate) ocsf: &'a crate::ocsf::OcsfOptions,
    pub(crate) tenant_filter: Option<&'a TenantId>,
}

impl LineEncoding<'_> {
    /// The lines of `result` this sink writes, after the first `skip`.
    fn lines(
        &self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
        skip: usize,
    ) -> Result<Vec<String>, RuntimeError> {
        result
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                self.tenant_filter
                    .is_none_or(|t| m.header.tenant_id.as_ref() == Some(t))
            })
            .skip(skip)
            .map(|(index, m)| {
                serialize_result(
                    m,
                    self.format,
                    self.pretty,
                    ctx.map(|ctx| (ctx, index)),
                    self.ocsf,
                )
            })
            .collect()
    }
}

/// Serialize a batch of deliveries into one [`LineBatch`], skipping the
/// lines each one already wrote.
///
/// Returns the batch, each delivery's skipped line count, and each
/// delivery's outcome so far: a delivery that fails to serialize keeps its
/// error and contributes no lines.
pub(crate) fn encode_batch<'c, C>(
    items: &[(&ProcessResult, C)],
    resume: &ResumeMap<usize>,
    encoding: LineEncoding<'_>,
) -> (LineBatch, Vec<usize>, Vec<Result<(), RuntimeError>>)
where
    C: Copy + Into<Option<&'c DeliveryContext>>,
{
    let mut batch = LineBatch::default();
    let mut starts = Vec::with_capacity(items.len());
    let mut outcomes = Vec::with_capacity(items.len());
    for (result, ctx) in items {
        let ctx = (*ctx).into();
        let start = resume.start(ctx);
        match encoding.lines(result, ctx, start) {
            Ok(lines) => {
                for line in &lines {
                    batch.push(line);
                }
                outcomes.push(Ok(()));
            }
            Err(err) => outcomes.push(Err(err)),
        }
        batch.end_item();
        starts.push(start);
    }
    (batch, starts, outcomes)
}

/// Turn the outcome of writing an [`encode_batch`] batch into outcomes for the
/// deliveries it reached, recording how far the delivery cut off by a failure
/// got.
///
/// `failure` is the number of whole lines written and the error, when the
/// write stopped early. The deliveries after the cut-off one were not
/// attempted, so their outcomes are dropped and the worker delivers each on
/// its own once the cut-off one has settled.
pub(crate) fn settle_batch<'c, C>(
    items: &[(&ProcessResult, C)],
    batch: &LineBatch,
    starts: &[usize],
    outcomes: &mut Vec<Result<(), RuntimeError>>,
    resume: &mut ResumeMap<usize>,
    failure: Option<(usize, RuntimeError)>,
) where
    C: Copy + Into<Option<&'c DeliveryContext>>,
{
    let (done, torn, err) = match failure {
        Some((lines, err)) => {
            let (done, torn) = batch.item_progress(lines);
            (done, torn, Some(err))
        }
        None => (items.len(), 0, None),
    };
    for (index, ((_, ctx), outcome)) in items.iter().zip(outcomes.iter_mut()).enumerate() {
        let ctx = (*ctx).into();
        if outcome.is_err() {
            continue;
        }
        match &err {
            Some(err) if index == done => {
                resume.record(ctx, starts[index] + torn);
                *outcome = Err(err.duplicate());
            }
            Some(_) if index > done => {}
            _ => resume.clear(ctx),
        }
    }
    if err.is_some() {
        outcomes.truncate(done + 1);
    }
}

/// NDJSON writer over a byte stream that keeps lines whole across failures.
///
/// When a delivery is retried after a failed write, lines that already went
/// out are not written again, and a line cut off by the failure is ended
/// before anything else is written, so every later line starts at the
/// beginning of a line.
pub(crate) struct LineWriter<W> {
    pub(crate) inner: W,
    /// The last write stopped partway through a line.
    torn: bool,
    resume: ResumeMap<usize>,
}

impl<W: Write> LineWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        LineWriter {
            inner,
            torn: false,
            resume: ResumeMap::default(),
        }
    }

    /// Write one delivery's lines in one write.
    pub(crate) fn write_result(
        &mut self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
        encoding: LineEncoding<'_>,
    ) -> Result<(), RuntimeError> {
        self.write_results(&[(result, ctx)], encoding)
            .pop()
            .unwrap_or(Ok(()))
    }

    /// Write the lines of several deliveries in one write, returning one
    /// outcome per delivery the write reached.
    ///
    /// A failure partway through marks the deliveries whose lines all went
    /// out as delivered, remembers how many lines of the cut-off delivery
    /// went out, and fails it. The later deliveries get no outcome.
    pub(crate) fn write_results<'c, C>(
        &mut self,
        items: &[(&ProcessResult, C)],
        encoding: LineEncoding<'_>,
    ) -> Vec<Result<(), RuntimeError>>
    where
        C: Copy + Into<Option<&'c DeliveryContext>>,
    {
        let pending = self.begin_write(items, encoding);
        let written = (!pending.is_empty()).then(|| {
            write_lines(
                &mut self.inner,
                pending.end_torn_line,
                pending.batch.bytes(),
            )
        });
        self.finish_write(items, pending, written)
    }

    /// Encode a batch whose write runs somewhere else, such as on a
    /// [`WriterThread`], for [`Self::finish_write`] to settle. No other write
    /// on this writer may run between the two calls.
    pub(crate) fn begin_write<'c, C>(
        &mut self,
        items: &[(&ProcessResult, C)],
        encoding: LineEncoding<'_>,
    ) -> PendingWrite
    where
        C: Copy + Into<Option<&'c DeliveryContext>>,
    {
        self.resume
            .retain(items.iter().filter_map(|(_, ctx)| (*ctx).into()));
        let (batch, starts, outcomes) = encode_batch(items, &self.resume, encoding);
        PendingWrite {
            batch,
            starts,
            outcomes,
            end_torn_line: self.torn,
        }
    }

    /// Settle a batch from [`Self::begin_write`], returning one outcome per
    /// delivery the write reached. `written` is `None` when the batch had
    /// nothing to write.
    pub(crate) fn finish_write<'c, C>(
        &mut self,
        items: &[(&ProcessResult, C)],
        pending: PendingWrite,
        written: Option<Result<(), ShortWrite>>,
    ) -> Vec<Result<(), RuntimeError>>
    where
        C: Copy + Into<Option<&'c DeliveryContext>>,
    {
        let PendingWrite {
            batch,
            starts,
            mut outcomes,
            ..
        } = pending;
        let failure = written.and_then(|written| {
            let lines = self.record_write(&batch, &written);
            lines
                .zip(written.err())
                .map(|(lines, short)| (lines, short.error.into()))
        });
        settle_batch(
            items,
            &batch,
            &starts,
            &mut outcomes,
            &mut self.resume,
            failure,
        );
        outcomes
    }

    pub(crate) fn write_line(&mut self, json: &str) -> Result<(), RuntimeError> {
        let mut batch = LineBatch::default();
        batch.push(json);
        let written = write_lines(&mut self.inner, self.torn, batch.bytes());
        self.record_write(&batch, &written);
        written.map_err(|short| short.error.into())
    }

    /// Track whether a write of `batch` left a line cut off. On a failure,
    /// returns how many whole lines of `batch` went out.
    fn record_write(
        &mut self,
        batch: &LineBatch,
        written: &Result<(), ShortWrite>,
    ) -> Option<usize> {
        match written {
            Ok(()) => {
                self.torn = false;
                None
            }
            Err(ShortWrite { written: None, .. }) => Some(0),
            Err(ShortWrite {
                written: Some(bytes),
                ..
            }) => {
                self.torn = batch.ends_mid_line(*bytes);
                Some(batch.complete_lines(*bytes))
            }
        }
    }
}

/// A batch encoded by [`LineWriter::begin_write`], waiting for its write.
pub(crate) struct PendingWrite {
    batch: LineBatch,
    starts: Vec<usize>,
    outcomes: Vec<Result<(), RuntimeError>>,
    /// End the line an earlier failed write cut off before writing the batch.
    end_torn_line: bool,
}

impl PendingWrite {
    pub(crate) fn is_empty(&self) -> bool {
        self.batch.bytes().is_empty()
    }
}

/// A write that stopped before the whole batch went out.
#[derive(Debug)]
pub(crate) struct ShortWrite {
    /// Bytes of the batch written. `None` when none were: ending the torn
    /// line failed first, or the writer thread was gone.
    written: Option<usize>,
    error: io::Error,
}

/// Write `bytes` in full, first ending the line an earlier failed write cut
/// off when `end_torn_line` is set.
fn write_lines<W: Write>(out: &mut W, end_torn_line: bool, bytes: &[u8]) -> Result<(), ShortWrite> {
    if end_torn_line {
        write_counted(out, b"\n").map_err(|(_, error)| ShortWrite {
            written: None,
            error,
        })?;
    }
    write_counted(out, bytes)
        .and_then(|()| out.flush().map_err(|err| (bytes.len(), err)))
        .map_err(|(written, error)| ShortWrite {
            written: Some(written),
            error,
        })
}

/// A dedicated thread that runs a line sink's blocking writes, so a delivery
/// worker awaits each batch write instead of blocking a runtime thread or
/// moving the runtime to another thread for every batch.
pub(crate) struct WriterThread {
    jobs: std::sync::mpsc::Sender<WriteJob>,
}

struct WriteJob {
    bytes: Vec<u8>,
    end_torn_line: bool,
    done: tokio::sync::oneshot::Sender<Result<(), ShortWrite>>,
}

impl WriterThread {
    /// Start a thread named `name` that writes each batch to the writer
    /// `open` returns for it.
    pub(crate) fn spawn<W, F>(name: &str, mut open: F) -> io::Result<Self>
    where
        W: Write,
        F: FnMut() -> W + Send + 'static,
    {
        let (jobs, rx) = std::sync::mpsc::channel::<WriteJob>();
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                for job in rx {
                    let written = write_lines(&mut open(), job.end_torn_line, &job.bytes);
                    let _ = job.done.send(written);
                }
            })?;
        Ok(WriterThread { jobs })
    }

    /// Write the lines of several deliveries through `out` on the thread,
    /// returning one outcome per delivery the write reached, as
    /// [`LineWriter::write_results`] does. `out` is locked to encode and to
    /// settle the batch, but not while the thread writes it.
    pub(crate) async fn write_results<W: Write>(
        &self,
        out: &Mutex<LineWriter<W>>,
        items: &[(&ProcessResult, &DeliveryContext)],
        encoding: LineEncoding<'_>,
    ) -> Vec<Result<(), RuntimeError>> {
        let mut pending = out.lock().begin_write(items, encoding);
        let written = if pending.is_empty() {
            None
        } else {
            Some(self.write(&mut pending).await)
        };
        out.lock().finish_write(items, pending, written)
    }

    /// Write a batch from [`LineWriter::begin_write`] on the thread, in the
    /// order the writes were requested.
    pub(crate) async fn write(&self, pending: &mut PendingWrite) -> Result<(), ShortWrite> {
        let (done, outcome) = tokio::sync::oneshot::channel();
        let job = WriteJob {
            bytes: std::mem::take(&mut pending.batch.bytes),
            end_torn_line: pending.end_torn_line,
            done,
        };
        if self.jobs.send(job).is_err() {
            return Err(ShortWrite::stopped());
        }
        outcome.await.unwrap_or_else(|_| Err(ShortWrite::stopped()))
    }
}

impl ShortWrite {
    fn stopped() -> Self {
        ShortWrite {
            written: None,
            error: io::Error::other("the writer thread stopped"),
        }
    }
}

/// `write_all` that reports how many bytes were written when it fails.
fn write_counted<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), (usize, io::Error)> {
    let mut written = 0;
    while written < bytes.len() {
        match writer.write(&bytes[written..]) {
            Ok(0) => return Err((written, io::ErrorKind::WriteZero.into())),
            Ok(n) => written += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err((written, err)),
        }
    }
    Ok(())
}

/// Per-delivery progress a sink keeps across the worker's retries, so a retry
/// does not repeat what already went out.
///
/// The delivery context is shared by every sink a result fans out to, so
/// each sink keeps its own map, keyed by the context's sequence number. An
/// entry is removed when its delivery succeeds; [`Self::retain`] drops the
/// entries of deliveries the worker has finished with.
pub(crate) struct ResumeMap<T> {
    entries: Vec<(u64, T)>,
}

impl<T> Default for ResumeMap<T> {
    fn default() -> Self {
        ResumeMap {
            entries: Vec::new(),
        }
    }
}

impl<T> ResumeMap<T> {
    /// The progress recorded for this delivery. Always `None` without a
    /// context.
    pub(crate) fn get(&self, ctx: Option<&DeliveryContext>) -> Option<&T> {
        let seq = ctx?.seq();
        self.entries
            .iter()
            .find(|(entry, _)| *entry == seq)
            .map(|(_, progress)| progress)
    }

    /// Remember the progress of this delivery. A no-op without a context.
    pub(crate) fn record(&mut self, ctx: Option<&DeliveryContext>, progress: T) {
        let Some(ctx) = ctx else {
            return;
        };
        let seq = ctx.seq();
        match self.entries.iter_mut().find(|(entry, _)| *entry == seq) {
            Some((_, slot)) => *slot = progress,
            None => self.entries.push((seq, progress)),
        }
    }

    /// Forget this delivery.
    pub(crate) fn clear(&mut self, ctx: Option<&DeliveryContext>) {
        if let Some(ctx) = ctx {
            let seq = ctx.seq();
            self.entries.retain(|(entry, _)| *entry != seq);
        }
    }

    /// Keep only the deliveries in `ctxs`.
    pub(crate) fn retain<'a>(&mut self, ctxs: impl IntoIterator<Item = &'a DeliveryContext>) {
        if self.entries.is_empty() {
            return;
        }
        let keep: Vec<u64> = ctxs.into_iter().map(DeliveryContext::seq).collect();
        self.entries.retain(|(entry, _)| keep.contains(entry));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl ResumeMap<usize> {
    /// Lines to skip for this delivery: 0 without a context and for a
    /// delivery with nothing recorded.
    pub(crate) fn start(&self, ctx: Option<&DeliveryContext>) -> usize {
        self.get(ctx).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use rsigma_eval::EvaluationResult;
    use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};

    use super::*;

    /// Accepts up to `budget` bytes, then fails every write until refilled,
    /// counting `write` calls.
    struct FlakyWriter {
        out: Vec<u8>,
        budget: usize,
        writes: usize,
    }

    impl FlakyWriter {
        fn new(budget: usize) -> Self {
            FlakyWriter {
                out: Vec::new(),
                budget,
                writes: 0,
            }
        }
    }

    impl Write for FlakyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.budget == 0 {
                return Err(io::Error::other("disk full"));
            }
            let n = buf.len().min(self.budget);
            self.out.extend_from_slice(&buf[..n]);
            self.budget -= n;
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn detection(title: &str, tenant: Option<&str>) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: title.to_string(),
                rule_id: None,
                tenant_id: tenant.map(|t| TenantId::new(t).unwrap()),
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
        }
    }

    fn results(titles: &[&str]) -> ProcessResult {
        titles.iter().map(|title| detection(title, None)).collect()
    }

    fn line(m: &EvaluationResult) -> String {
        serialize_result(
            m,
            SinkFormat::default(),
            false,
            None,
            &crate::ocsf::OcsfOptions::default(),
        )
        .unwrap()
    }

    fn encoding(ocsf: &crate::ocsf::OcsfOptions) -> LineEncoding<'_> {
        LineEncoding {
            format: SinkFormat::default(),
            pretty: false,
            ocsf,
            tenant_filter: None,
        }
    }

    fn written(out: &LineWriter<FlakyWriter>) -> Vec<String> {
        String::from_utf8(out.inner.out.clone())
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn retry_resumes_after_a_partial_write() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let result = results(&["first", "second", "third"]);
        let lines: Vec<String> = result.iter().map(line).collect();
        // The first line, then half of the second.
        let mut out = LineWriter::new(FlakyWriter::new(lines[0].len() + 1 + lines[1].len() / 2));
        let ctx = DeliveryContext::new();

        assert!(
            out.write_result(&result, Some(&ctx), encoding(&ocsf))
                .is_err()
        );
        out.inner.budget = usize::MAX;
        out.write_result(&result, Some(&ctx), encoding(&ocsf))
            .unwrap();
        out.write_line("{\"next\":true}").unwrap();

        assert_eq!(
            written(&out),
            [
                lines[0].as_str(),
                &lines[1][..lines[1].len() / 2],
                lines[1].as_str(),
                lines[2].as_str(),
                "{\"next\":true}",
            ],
            "the first line is not repeated and the torn line is ended"
        );
    }

    #[test]
    fn a_new_delivery_starts_from_its_first_line() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let result = results(&["first", "second", "third"]);
        let mut out = LineWriter::new(FlakyWriter::new(1));
        let failed = DeliveryContext::new();
        assert!(
            out.write_result(&result, Some(&failed), encoding(&ocsf))
                .is_err()
        );
        out.inner.budget = usize::MAX;
        let next = DeliveryContext::new();
        out.write_result(&result, Some(&next), encoding(&ocsf))
            .unwrap();
        assert_eq!(written(&out).len(), 4, "{:?}", written(&out));
    }

    #[test]
    fn a_batch_goes_out_in_one_write() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let deliveries = [results(&["a"]), results(&["b", "c"]), results(&["d"])];
        let contexts = [
            DeliveryContext::new(),
            DeliveryContext::new(),
            DeliveryContext::new(),
        ];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();
        let mut out = LineWriter::new(FlakyWriter::new(usize::MAX));

        let outcomes = out.write_results(&items, encoding(&ocsf));

        assert!(outcomes.iter().all(Result::is_ok));
        assert_eq!(out.inner.writes, 1);
        assert_eq!(written(&out).len(), 4);
    }

    #[test]
    fn a_torn_batch_delivers_the_items_before_the_tear_and_resumes_the_torn_one() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let deliveries = [
            results(&["one"]),
            results(&["two-a", "two-b", "two-c"]),
            results(&["three"]),
        ];
        let contexts = [
            DeliveryContext::new(),
            DeliveryContext::new(),
            DeliveryContext::new(),
        ];
        let lines: Vec<String> = deliveries.iter().flatten().map(line).collect();
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();
        // All of item 1, the first line of item 2, and half of its second.
        let budget = lines[0].len() + 1 + lines[1].len() + 1 + lines[2].len() / 2;
        let mut out = LineWriter::new(FlakyWriter::new(budget));

        let outcomes = out.write_results(&items, encoding(&ocsf));
        assert_eq!(
            outcomes.len(),
            2,
            "the write never reached item 3, so it has no outcome"
        );
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());

        // The worker retries the torn item, then delivers the next one.
        out.inner.budget = usize::MAX;
        out.write_result(&deliveries[1], Some(&contexts[1]), encoding(&ocsf))
            .unwrap();
        out.write_result(&deliveries[2], Some(&contexts[2]), encoding(&ocsf))
            .unwrap();

        assert_eq!(
            written(&out),
            [
                lines[0].as_str(),
                lines[1].as_str(),
                &lines[2][..lines[2].len() / 2],
                lines[2].as_str(),
                lines[3].as_str(),
                lines[4].as_str(),
            ],
            "no line is written twice and the torn line is ended"
        );
    }

    /// One [`FlakyWriter`] stream shared by a writer thread and an inline
    /// writer.
    #[derive(Clone)]
    struct Shared(Arc<std::sync::Mutex<FlakyWriter>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().out.clone())
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    #[tokio::test]
    async fn a_batch_on_the_writer_thread_keeps_lines_whole_across_failures() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let deliveries = [
            results(&["one"]),
            results(&["two-a", "two-b", "two-c"]),
            results(&["three"]),
        ];
        let contexts = [
            DeliveryContext::new(),
            DeliveryContext::new(),
            DeliveryContext::new(),
        ];
        let lines: Vec<String> = deliveries.iter().flatten().map(line).collect();
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();
        // All of item 1, the first line of item 2, and half of its second.
        let budget = lines[0].len() + 1 + lines[1].len() + 1 + lines[2].len() / 2;
        let stream = Shared(Arc::new(std::sync::Mutex::new(FlakyWriter::new(budget))));
        let for_thread = stream.clone();
        let writer = WriterThread::spawn("test-writer", move || for_thread.clone()).unwrap();
        let out = Mutex::new(LineWriter::new(stream.clone()));

        let outcomes = writer.write_results(&out, &items, encoding(&ocsf)).await;
        assert_eq!(outcomes.len(), 2, "the write never reached item 3");
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());

        // The torn item's retry goes through the thread, the next item inline.
        stream.0.lock().unwrap().budget = usize::MAX;
        let retry = writer
            .write_results(&out, &items[1..2], encoding(&ocsf))
            .await;
        assert!(retry[0].is_ok());
        out.lock()
            .write_result(&deliveries[2], Some(&contexts[2]), encoding(&ocsf))
            .unwrap();

        assert_eq!(
            stream.lines(),
            [
                lines[0].as_str(),
                lines[1].as_str(),
                &lines[2][..lines[2].len() / 2],
                lines[2].as_str(),
                lines[3].as_str(),
                lines[4].as_str(),
            ],
            "no line is written twice and the torn line is ended"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_write_on_the_writer_thread_leaves_the_runtime_free() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let result = results(&["a"]);
        let ctx = DeliveryContext::new();
        let items = [(&result, &ctx)];
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let released_in_time = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = released_in_time.clone();
        // The write waits for a task on this single-threaded runtime, which
        // can only run while the write is in flight if the write does not
        // hold the runtime's thread.
        let writer = WriterThread::spawn("test-gated", move || {
            let in_time = gate.recv_timeout(std::time::Duration::from_secs(5)).is_ok();
            seen.store(in_time, std::sync::atomic::Ordering::SeqCst);
            Vec::new()
        })
        .unwrap();
        let out = Mutex::new(LineWriter::new(Vec::new()));

        let (outcomes, ()) =
            tokio::join!(writer.write_results(&out, &items, encoding(&ocsf)), async {
                tokio::task::yield_now().await;
                let _ = release.send(());
            });

        assert!(outcomes[0].is_ok());
        assert!(
            released_in_time.load(std::sync::atomic::Ordering::SeqCst),
            "the runtime ran another task while the write was in flight"
        );
    }

    #[tokio::test]
    async fn a_stopped_writer_thread_fails_the_batch_without_recording_progress() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let result = results(&["first", "second"]);
        let ctx = DeliveryContext::new();
        let items = [(&result, &ctx)];
        let writer = WriterThread::spawn("test-stopped", || -> Vec<u8> {
            panic!("the writer thread stops")
        })
        .unwrap();
        let stream = Shared(Arc::new(std::sync::Mutex::new(FlakyWriter::new(
            usize::MAX,
        ))));
        let out = Mutex::new(LineWriter::new(stream.clone()));

        for _ in 0..2 {
            let outcomes = writer.write_results(&out, &items, encoding(&ocsf)).await;
            assert!(outcomes[0].is_err(), "a lost write fails the delivery");
        }
        out.lock()
            .write_result(&result, Some(&ctx), encoding(&ocsf))
            .unwrap();
        assert_eq!(
            stream.lines(),
            [line(&result[0]), line(&result[1])],
            "the retry starts from the first line"
        );
    }

    #[test]
    fn a_batch_writes_only_the_filtered_tenant() {
        let ocsf = crate::ocsf::OcsfOptions::default();
        let tenant = TenantId::new("a").unwrap();
        let deliveries = [
            vec![detection("x", Some("a")), detection("y", Some("b"))],
            vec![detection("z", Some("b"))],
        ];
        let contexts = [DeliveryContext::new(), DeliveryContext::new()];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();
        let mut out = LineWriter::new(FlakyWriter::new(usize::MAX));

        let outcomes = out.write_results(
            &items,
            LineEncoding {
                tenant_filter: Some(&tenant),
                ..encoding(&ocsf)
            },
        );

        assert!(outcomes.iter().all(Result::is_ok));
        assert_eq!(written(&out), [line(&deliveries[0][0])]);
    }

    #[test]
    fn item_progress_splits_lines_by_delivery() {
        let mut batch = LineBatch::default();
        batch.push("a1");
        batch.end_item();
        batch.end_item();
        batch.push("c1");
        batch.push("c2");
        batch.push("c3");
        batch.end_item();
        batch.push("d1");
        batch.end_item();

        assert_eq!(batch.item_progress(0), (0, 0));
        assert_eq!(
            batch.item_progress(1),
            (2, 0),
            "an empty delivery after a written one is done"
        );
        assert_eq!(batch.item_progress(2), (2, 1));
        assert_eq!(batch.item_progress(3), (2, 2));
        assert_eq!(batch.item_progress(4), (3, 0));
        assert_eq!(batch.item_progress(5), (4, 0));
    }

    #[test]
    fn line_offsets() {
        let mut batch = LineBatch::default();
        batch.push("ab");
        batch.push("cde");
        assert_eq!(batch.bytes(), b"ab\ncde\n");
        assert_eq!(batch.complete_lines(0), 0);
        assert_eq!(batch.complete_lines(2), 0);
        assert_eq!(batch.complete_lines(3), 1);
        assert_eq!(batch.complete_lines(6), 1);
        assert_eq!(batch.complete_lines(7), 2);
        assert!(!batch.ends_mid_line(0));
        assert!(batch.ends_mid_line(1));
        assert!(!batch.ends_mid_line(3));
        assert!(batch.ends_mid_line(4));
        assert!(!batch.ends_mid_line(7));
        assert_eq!(batch.line_start(0), 0);
        assert_eq!(batch.line_start(1), 3);
        assert_eq!(batch.line_start(2), 7);
    }

    #[test]
    fn resume_map_tracks_each_delivery() {
        let first = DeliveryContext::new();
        let second = DeliveryContext::new();
        let third = DeliveryContext::new();
        let mut resume = ResumeMap::default();
        resume.record(Some(&first), 2);
        resume.record(Some(&second), 1);
        assert_eq!(resume.start(Some(&first)), 2);
        assert_eq!(resume.start(Some(&second)), 1);
        assert_eq!(resume.start(Some(&third)), 0);
        assert_eq!(resume.start(None), 0);

        resume.record(Some(&first), 3);
        assert_eq!(resume.start(Some(&first)), 3);
        assert_eq!(resume.len(), 2);

        resume.clear(Some(&first));
        assert_eq!(resume.start(Some(&first)), 0);
        assert_eq!(resume.start(Some(&second)), 1);

        resume.record(None, 5);
        assert_eq!(resume.len(), 1, "no context records nothing");
    }

    #[test]
    fn retain_drops_finished_deliveries() {
        let kept = DeliveryContext::new();
        let finished = DeliveryContext::new();
        let mut resume = ResumeMap::default();
        resume.record(Some(&kept), 1);
        resume.record(Some(&finished), 1);
        resume.retain([&kept]);
        assert_eq!(resume.start(Some(&kept)), 1);
        assert_eq!(resume.start(Some(&finished)), 0);
        assert_eq!(resume.len(), 1);
    }
}
