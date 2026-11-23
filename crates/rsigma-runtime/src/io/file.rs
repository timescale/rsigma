use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::lines::{LineEncoding, LineWriter, ResumeMap};
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
    tenant_resume: ResumeMap<usize>,
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
            tenant_resume: ResumeMap::default(),
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
            tenant_resume: ResumeMap::default(),
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
            self.tenant_resume.clear(ctx);
            return Ok(());
        }

        let encoding = LineEncoding {
            format: self.format,
            pretty: false,
            ocsf: &self.ocsf,
            tenant_filter: self.tenant_filter.as_ref(),
        };
        match self.out.as_mut() {
            Some(out) => out.write_result(result, ctx, encoding),
            None => Ok(()),
        }
    }

    /// Append a batch of deliveries, one outcome per attempted delivery. A
    /// plain path gets the whole batch in one write; a `{tenant}` path writes
    /// each delivery on its own, since one batch can span many files, and
    /// stops at the first failure so later deliveries keep their order.
    pub(crate) fn send_batch(
        &mut self,
        items: &[(&ProcessResult, &DeliveryContext)],
    ) -> Vec<Result<(), RuntimeError>> {
        if self.tenant_path.is_some() {
            self.tenant_resume.retain(items.iter().map(|(_, ctx)| *ctx));
            let mut outcomes = Vec::with_capacity(items.len());
            for (result, ctx) in items {
                let outcome = self.send_inner(result, Some(ctx));
                let failed = outcome.is_err();
                outcomes.push(outcome);
                if failed {
                    break;
                }
            }
            return outcomes;
        }
        let encoding = LineEncoding {
            format: self.format,
            pretty: false,
            ocsf: &self.ocsf,
            tenant_filter: self.tenant_filter.as_ref(),
        };
        match self.out.as_mut() {
            Some(out) => out.write_results(items, encoding),
            None => items.iter().map(|_| Ok(())).collect(),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use rsigma_eval::EvaluationResult;
    use rsigma_eval::result::{DetectionBody, ResultBody, RuleHeader};

    use super::*;

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
    fn a_batch_appends_every_delivery_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.ndjson");
        let mut sink = FileSink::open(&path).unwrap();
        let deliveries = [
            vec![tenanted("one", "a")],
            vec![tenanted("two", "a"), tenanted("three", "a")],
        ];
        let contexts = [DeliveryContext::new(), DeliveryContext::new()];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();

        let outcomes = sink.send_batch(&items);

        assert!(outcomes.iter().all(Result::is_ok));
        let written = std::fs::read_to_string(&path).unwrap();
        let titles: Vec<String> = written
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["rule_title"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(titles, ["one", "two", "three"]);
    }

    #[test]
    fn a_tenant_path_batch_goes_per_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, "/findings.ndjson".to_string(), 4).unwrap();
        let blocker = dir.path().join("b");
        std::fs::write(&blocker, "not a directory").unwrap();
        let deliveries = [vec![tenanted("a", "a")], vec![tenanted("b", "b")]];
        let contexts = [DeliveryContext::new(), DeliveryContext::new()];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();

        let outcomes = sink.send_batch(&items);
        assert!(outcomes[0].is_ok(), "the other tenant's delivery succeeds");
        assert!(outcomes[1].is_err());

        std::fs::remove_file(&blocker).unwrap();
        sink.send_with_context(&deliveries[1], &contexts[1])
            .unwrap();
        let a = std::fs::read_to_string(dir.path().join("a/findings.ndjson")).unwrap();
        let b = std::fs::read_to_string(dir.path().join("b/findings.ndjson")).unwrap();
        assert_eq!(a.lines().count(), 1);
        assert_eq!(b.lines().count(), 1);
    }

    #[test]
    fn each_failed_tenant_path_delivery_keeps_its_own_progress() {
        let dir = tempfile::tempdir().unwrap();
        let before = format!("{}/", dir.path().display());
        let mut sink = FileSink::open_template(before, "/findings.ndjson".to_string(), 4).unwrap();
        let blocker = dir.path().join("b");
        std::fs::write(&blocker, "not a directory").unwrap();
        // Both deliveries write tenant a's line, then fail on tenant b.
        let deliveries = [
            vec![tenanted("first-a", "a"), tenanted("first-b", "b")],
            vec![tenanted("second-a", "a"), tenanted("second-b", "b")],
        ];
        let contexts = [DeliveryContext::new(), DeliveryContext::new()];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();

        let outcomes = sink.send_batch(&items);
        assert_eq!(
            outcomes.len(),
            1,
            "the batch stops at the first failure, so the second delivery waits"
        );
        assert!(outcomes[0].is_err());
        // The worker's attempt of the second delivery fails the same way.
        assert!(
            sink.send_with_context(&deliveries[1], &contexts[1])
                .is_err()
        );

        std::fs::remove_file(&blocker).unwrap();
        for (result, ctx) in &items {
            sink.send_with_context(result, ctx).unwrap();
        }
        let a = std::fs::read_to_string(dir.path().join("a/findings.ndjson")).unwrap();
        let b = std::fs::read_to_string(dir.path().join("b/findings.ndjson")).unwrap();
        assert_eq!(
            a.lines().count(),
            2,
            "no tenant a line is written twice: {a}"
        );
        assert_eq!(b.lines().count(), 2);
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
