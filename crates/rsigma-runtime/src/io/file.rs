use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::io::lines::{LineBatch, ResumePoint};
use crate::io::{DeliveryContext, SinkFormat, serialize_result};

/// Appends ProcessResult to a file as one line per result.
///
/// Each result's lines go out in a single write. When a delivery is retried
/// after a failed write, lines that already reached the file are not written
/// again, and a line cut off by the failure is ended before anything else is
/// appended, so every later line starts at the beginning of a line.
pub struct FileSink {
    out: LineWriter<File>,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
}

impl FileSink {
    /// Open (or create) the file at `path` for appending.
    pub fn open(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileSink {
            out: LineWriter::new(file),
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
        })
    }

    /// Select the wire format this sink serializes results into.
    #[must_use]
    pub fn with_format(mut self, format: SinkFormat) -> Self {
        self.format = format;
        self
    }

    /// OCSF serializer options when [`Self::format`] is [`SinkFormat::Ocsf`].
    #[must_use]
    pub fn with_ocsf_options(mut self, ocsf: crate::ocsf::OcsfOptions) -> Self {
        self.ocsf = ocsf;
        self
    }

    /// The wire format this sink serializes results into.
    pub fn format(&self) -> SinkFormat {
        self.format
    }

    /// OCSF serializer options when [`Self::format`] is [`SinkFormat::Ocsf`].
    pub fn ocsf_options(&self) -> crate::ocsf::OcsfOptions {
        self.ocsf
    }

    /// Serialize and append a ProcessResult to the file.
    pub fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        self.out.write_result(result, self.format, None, self.ocsf)
    }

    pub(crate) fn send_with_context(
        &mut self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.out
            .write_result(result, self.format, Some(ctx), self.ocsf)
    }

    /// Write a pre-serialized JSON string directly to the file.
    pub fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        self.out.write_line(json)
    }
}

/// NDJSON writer over a byte stream that keeps lines whole across failures.
struct LineWriter<W> {
    inner: W,
    /// The last write stopped partway through a line.
    torn: bool,
    resume: ResumePoint,
}

impl<W: Write> LineWriter<W> {
    fn new(inner: W) -> Self {
        LineWriter {
            inner,
            torn: false,
            resume: ResumePoint::default(),
        }
    }

    fn write_result(
        &mut self,
        result: &ProcessResult,
        format: SinkFormat,
        ctx: Option<&DeliveryContext>,
        ocsf: crate::ocsf::OcsfOptions,
    ) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }
        let start = self.resume.start(ctx);
        let mut batch = LineBatch::default();
        for (index, m) in result.iter().enumerate().skip(start) {
            batch.push(&serialize_result(
                m,
                format,
                false,
                ctx.map(|ctx| (ctx, index)),
                ocsf,
            )?);
        }
        match self.write_batch(&batch) {
            Ok(()) => {
                self.resume.clear();
                Ok(())
            }
            Err((written, err)) => {
                self.resume
                    .record(ctx, start + batch.complete_lines(written));
                Err(err.into())
            }
        }
    }

    fn write_line(&mut self, json: &str) -> Result<(), RuntimeError> {
        let mut batch = LineBatch::default();
        batch.push(json);
        self.write_batch(&batch).map_err(|(_, err)| err.into())
    }

    /// Write `batch` in full. A failure reports how many of its bytes were
    /// written.
    fn write_batch(&mut self, batch: &LineBatch) -> Result<(), (usize, io::Error)> {
        if self.torn {
            write_counted(&mut self.inner, b"\n").map_err(|(_, err)| (0, err))?;
            self.torn = false;
        }
        let outcome = write_counted(&mut self.inner, batch.bytes())
            .and_then(|()| self.inner.flush().map_err(|err| (batch.bytes().len(), err)));
        if let Err((written, _)) = &outcome {
            self.torn = batch.ends_mid_line(*written);
        }
        outcome
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use rsigma_eval::EvaluationResult;
    use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};

    use super::*;

    /// Accepts up to `budget` bytes, then fails every write until refilled.
    struct FlakyWriter {
        out: Vec<u8>,
        budget: usize,
    }

    impl Write for FlakyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
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

    fn three_results() -> ProcessResult {
        ["first", "second", "third"]
            .into_iter()
            .map(|title| EvaluationResult {
                header: RuleHeader {
                    rule_title: title.to_string(),
                    rule_id: None,
                    level: None,
                    tags: vec![],
                    custom_attributes: Arc::new(HashMap::new()),
                    enrichments: None,
                },
                body: ResultBody::Detection(DetectionBody {
                    matched_selections: vec!["sel".to_string()],
                    matched_fields: vec![],
                    event: None,
                }),
            })
            .collect()
    }

    #[test]
    fn retry_resumes_after_a_partial_write() {
        let result = three_results();
        let lines: Vec<String> = result
            .iter()
            .map(|m| {
                serialize_result(
                    m,
                    SinkFormat::default(),
                    false,
                    None,
                    crate::ocsf::OcsfOptions::default(),
                )
                .unwrap()
            })
            .collect();
        let mut out = LineWriter::new(FlakyWriter {
            out: Vec::new(),
            // The first line, then half of the second.
            budget: lines[0].len() + 1 + lines[1].len() / 2,
        });
        let ctx = DeliveryContext::new();

        assert!(
            out.write_result(
                &result,
                SinkFormat::default(),
                Some(&ctx),
                crate::ocsf::OcsfOptions::default(),
            )
            .is_err()
        );
        out.inner.budget = usize::MAX;
        out.write_result(
            &result,
            SinkFormat::default(),
            Some(&ctx),
            crate::ocsf::OcsfOptions::default(),
        )
        .unwrap();
        out.write_line("{\"next\":true}").unwrap();

        let written = String::from_utf8(out.inner.out).unwrap();
        let written: Vec<&str> = written.lines().collect();
        assert_eq!(
            written,
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
        let result = three_results();
        let mut out = LineWriter::new(FlakyWriter {
            out: Vec::new(),
            budget: 1,
        });
        let failed = DeliveryContext::new();
        assert!(
            out.write_result(
                &result,
                SinkFormat::default(),
                Some(&failed),
                crate::ocsf::OcsfOptions::default(),
            )
            .is_err()
        );
        out.inner.budget = usize::MAX;
        let next = DeliveryContext::new();
        out.write_result(
            &result,
            SinkFormat::default(),
            Some(&next),
            crate::ocsf::OcsfOptions::default(),
        )
        .unwrap();
        let written = String::from_utf8(out.inner.out).unwrap();
        assert_eq!(written.lines().count(), 4, "{written}");
    }
}
