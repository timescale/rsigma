use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use rsigma_eval::{ProcessResult, TenantId};

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
    out: Option<LineWriter<File>>,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
    tenant_filter: Option<TenantId>,
    tenant_path: Option<TenantPath>,
    tenant_handles: HashMap<TenantId, TenantHandle>,
    /// Lines of a `{tenant}` delivery already written, across tenant files.
    tenant_resume: ResumePoint,
}

/// A `{tenant}` path template and the handle LRU bound.
struct TenantPath {
    before: String,
    after: String,
    max_open: usize,
    tick: u64,
}

struct TenantHandle {
    writer: LineWriter<File>,
    last_used: u64,
}

impl FileSink {
    /// Open (or create) the file at `path` for appending.
    pub fn open(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileSink {
            out: Some(LineWriter::new(file)),
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            tenant_filter: None,
            tenant_path: None,
            tenant_handles: HashMap::new(),
            tenant_resume: ResumePoint::default(),
        })
    }

    /// Build a sink whose file path carries `{tenant}` as a whole path
    /// component, opening one file per tenant lazily.
    pub fn open_template(
        before: String,
        after: String,
        max_open: usize,
    ) -> Result<Self, RuntimeError> {
        Ok(FileSink {
            out: None,
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            tenant_filter: None,
            tenant_path: Some(TenantPath {
                before,
                after,
                max_open: max_open.max(1),
                tick: 0,
            }),
            tenant_handles: HashMap::new(),
            tenant_resume: ResumePoint::default(),
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

    /// OCSF serializer options when [`Self::format`] is [`SinkFormat::Ocsf`].
    pub fn ocsf_options(&self) -> &crate::ocsf::OcsfOptions {
        &self.ocsf
    }

    /// Serialize and append a ProcessResult to the file.
    pub fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        self.send_inner(result, None)
    }

    pub(crate) fn send_with_context(
        &mut self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.send_inner(result, Some(ctx))
    }

    fn send_inner(
        &mut self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
    ) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }
        if self.tenant_path.is_some() {
            // Check every tenant before writing, so an untenanted result fails
            // the delivery without a partial write.
            let mut lines = Vec::new();
            for (index, m) in result.iter().enumerate() {
                if let Some(filter) = &self.tenant_filter
                    && m.header.tenant_id.as_ref() != Some(filter)
                {
                    continue;
                }
                let Some(tenant) = m.header.tenant_id.clone() else {
                    return Err(RuntimeError::Permanent(
                        "a {tenant} file sink received a result without a tenant".to_string(),
                    ));
                };
                lines.push((index, tenant, m));
            }
            let start = self.tenant_resume.start(ctx);
            for (done, (index, tenant, m)) in lines.iter().enumerate().skip(start) {
                let written = serialize_result(
                    m,
                    self.format,
                    false,
                    ctx.map(|ctx| (ctx, *index)),
                    &self.ocsf,
                )
                .and_then(|json| {
                    let path = self.render_path(tenant);
                    self.writer_for(tenant, &path)?.write_line(&json)
                });
                if let Err(err) = written {
                    self.tenant_resume.record(ctx, done);
                    return Err(err);
                }
            }
            self.tenant_resume.clear();
            return Ok(());
        }

        match self.out.as_mut() {
            Some(out) => out.write_result(
                result,
                self.format,
                ctx,
                &self.ocsf,
                self.tenant_filter.as_ref(),
            ),
            None => Ok(()),
        }
    }

    fn render_path(&self, tenant: &TenantId) -> std::path::PathBuf {
        let template = self.tenant_path.as_ref().expect("checked above");
        std::path::PathBuf::from(format!(
            "{}{}{}",
            template.before,
            tenant.as_str(),
            template.after
        ))
    }

    fn writer_for(
        &mut self,
        tenant: &TenantId,
        path: &Path,
    ) -> Result<&mut LineWriter<File>, RuntimeError> {
        let tick = {
            let template = self.tenant_path.as_mut().expect("checked above");
            template.tick += 1;
            template.tick
        };
        if !self.tenant_handles.contains_key(tenant) {
            let max_open = self.tenant_path.as_ref().expect("checked above").max_open;
            while self.tenant_handles.len() >= max_open {
                let victim = self
                    .tenant_handles
                    .iter()
                    .min_by_key(|(_, handle)| handle.last_used)
                    .map(|(tenant, _)| tenant.clone());
                match victim {
                    Some(victim) => {
                        if let Some(mut handle) = self.tenant_handles.remove(&victim) {
                            let _ = handle.writer.inner.flush();
                        }
                    }
                    None => break,
                }
            }
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            self.tenant_handles.insert(
                tenant.clone(),
                TenantHandle {
                    writer: LineWriter::new(file),
                    last_used: tick,
                },
            );
        }
        let handle = self.tenant_handles.get_mut(tenant).expect("inserted above");
        handle.last_used = tick;
        Ok(&mut handle.writer)
    }

    /// Write a pre-serialized JSON string directly to the file.
    pub fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        match self.out.as_mut() {
            Some(out) => out.write_line(json),
            None => Err(RuntimeError::Permanent(
                "a {tenant} file sink received a line without a tenant".to_string(),
            )),
        }
    }

    /// Write a pre-serialized line to the file for `tenant`. With a `{tenant}`
    /// path template this opens the tenant's file; otherwise it applies the
    /// configured tenant filter.
    pub fn send_raw_for_tenant(
        &mut self,
        json: &str,
        tenant: Option<&TenantId>,
    ) -> Result<(), RuntimeError> {
        if self.tenant_path.is_some() {
            let Some(tenant) = tenant else {
                return Err(RuntimeError::Permanent(
                    "a {tenant} file sink received a line without a tenant".to_string(),
                ));
            };
            let path = self.render_path(tenant);
            self.writer_for(tenant, &path)?.write_line(json)?;
            return Ok(());
        }
        if let Some(filter) = &self.tenant_filter
            && tenant != Some(filter)
        {
            return Ok(());
        }
        self.send_raw(json)
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
        ocsf: &crate::ocsf::OcsfOptions,
        tenant_filter: Option<&TenantId>,
    ) -> Result<(), RuntimeError> {
        let filtered: Vec<(usize, &rsigma_eval::EvaluationResult)> = result
            .iter()
            .enumerate()
            .filter(|(_, m)| tenant_filter.is_none_or(|t| m.header.tenant_id.as_ref() == Some(t)))
            .collect();
        if filtered.is_empty() {
            return Ok(());
        }
        let start = self.resume.start(ctx);
        let mut batch = LineBatch::default();
        for (original_index, m) in filtered.iter().skip(start) {
            batch.push(&serialize_result(
                m,
                format,
                false,
                ctx.map(|ctx| (ctx, *original_index)),
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
                    &crate::ocsf::OcsfOptions::default(),
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
                &crate::ocsf::OcsfOptions::default(),
                None,
            )
            .is_err()
        );
        out.inner.budget = usize::MAX;
        out.write_result(
            &result,
            SinkFormat::default(),
            Some(&ctx),
            &crate::ocsf::OcsfOptions::default(),
            None,
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
                &crate::ocsf::OcsfOptions::default(),
                None,
            )
            .is_err()
        );
        out.inner.budget = usize::MAX;
        let next = DeliveryContext::new();
        out.write_result(
            &result,
            SinkFormat::default(),
            Some(&next),
            &crate::ocsf::OcsfOptions::default(),
            None,
        )
        .unwrap();
        let written = String::from_utf8(out.inner.out).unwrap();
        assert_eq!(written.lines().count(), 4, "{written}");
    }

    fn tenanted(title: &str, tenant: &str) -> EvaluationResult {
        let mut r = three_results().remove(0);
        r.header.rule_title = title.to_string();
        r.header.tenant_id = Some(TenantId::new(tenant).unwrap());
        r
    }

    #[test]
    fn tenant_paths_open_lazily_and_bound_open_handles() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, ".ndjson".to_string(), 2).unwrap();

        for tenant in ["a", "b", "c"] {
            sink.send(&vec![tenanted(tenant, tenant)]).unwrap();
        }

        for tenant in ["a", "b", "c"] {
            assert!(
                dir.path().join(format!("{tenant}.ndjson")).is_file(),
                "{tenant} file exists"
            );
        }
        assert_eq!(sink.tenant_handles.len(), 2, "open-handle LRU is bounded");
        assert!(
            sink.tenant_handles
                .contains_key(&TenantId::new("c").unwrap())
        );
    }

    #[test]
    fn a_tenant_filter_skips_other_tenants() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.ndjson");
        let mut sink = FileSink::open(&path)
            .unwrap()
            .with_tenant_filter(Some(TenantId::new("a").unwrap()));
        let result = vec![tenanted("a", "a"), tenanted("b", "b")];
        sink.send(&result).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written.lines().count(), 1);
        assert!(written.contains("\"tenant_id\":\"a\""));
        assert!(!written.contains("\"tenant_id\":\"b\""));
    }

    #[test]
    fn a_tenant_directory_is_created_on_first_write() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, "/findings.ndjson".to_string(), 4).unwrap();
        sink.send(&vec![tenanted("a", "a")]).unwrap();
        assert!(dir.path().join("a/findings.ndjson").is_file());
    }

    #[test]
    fn a_retried_tenant_delivery_skips_lines_already_written() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, "/findings.ndjson".to_string(), 4).unwrap();
        let blocker = dir.path().join("b");
        std::fs::write(&blocker, "not a directory").unwrap();
        let result = vec![tenanted("a", "a"), tenanted("b", "b")];
        let ctx = DeliveryContext::new();

        assert!(sink.send_with_context(&result, &ctx).is_err());
        std::fs::remove_file(&blocker).unwrap();
        sink.send_with_context(&result, &ctx).unwrap();

        let a = std::fs::read_to_string(dir.path().join("a/findings.ndjson")).unwrap();
        let b = std::fs::read_to_string(dir.path().join("b/findings.ndjson")).unwrap();
        assert_eq!(a.lines().count(), 1, "tenant a's line is not repeated");
        assert_eq!(b.lines().count(), 1);
    }

    #[test]
    fn an_untenanted_result_fails_before_any_tenant_file_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, ".ndjson".to_string(), 4).unwrap();
        let result = vec![tenanted("a", "a"), three_results().remove(0)];
        assert!(matches!(
            sink.send(&result),
            Err(RuntimeError::Permanent(_))
        ));
        assert!(!dir.path().join("a.ndjson").exists());
    }

    #[test]
    fn a_raw_line_on_a_tenant_path_is_a_permanent_failure() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, ".ndjson".to_string(), 4).unwrap();
        assert!(matches!(
            sink.send_raw("{}"),
            Err(RuntimeError::Permanent(_))
        ));
    }
}
