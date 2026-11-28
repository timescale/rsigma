//! Asynchronous disposition-bundle spooling.
//!
//! One job is enqueued per original accepted disposition. Filesystem work runs
//! in `spawn_blocking` with same-parent staging, restrictive permissions, and
//! a disk-byte budget that counts every tenant's bundles.
//!
//! A bundle's identity comes from the captured evidence: a rule, fingerprint,
//! or incident id the disposition names only counts when the retained events
//! show it, so a disposition cannot open a new bundle by naming values that
//! never fired.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rsigma_runtime::{
    BUNDLE_FORMAT_VERSION, BundleKind, BundleManifest, BundleRule, CaptureRing, CaptureSnapshot,
    Disposition, DispositionScope, ProvenanceLine, Verdict, bundle_id, disposition_identity,
    event_digest,
};
use tokio::sync::mpsc;

use super::metrics::Metrics;

/// Outcome of trying to enqueue a spool job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolStatus {
    Queued,
    Exists,
    Miss,
    QueueFull,
}

impl SpoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Exists => "exists",
            Self::Miss => "miss",
            Self::QueueFull => "queue_full",
        }
    }
}

/// Disk budgets for completed bundles.
#[derive(Debug, Clone, Copy)]
pub struct SpoolBudget {
    /// Bytes of completed bundles across every tenant.
    pub max_spool_bytes: u64,
    /// Bytes of one tenant's completed bundles, when tenancy sets a quota.
    pub max_tenant_bytes: Option<u64>,
}

/// Shared spool handle used by disposition ingest.
#[derive(Clone)]
pub struct CaptureSpool {
    tx: mpsc::Sender<SpoolJob>,
    spool_dir: PathBuf,
    ring: Arc<Mutex<CaptureRing>>,
    metrics: Arc<Metrics>,
}

struct SpoolJob {
    dest: PathBuf,
    tenant: Option<String>,
    verdict: Verdict,
    snapshot: CaptureSnapshot,
    manifest: BundleManifest,
}

impl CaptureSpool {
    /// Prepare the spool directory, clean abandoned staging dirs, and start
    /// the background writer.
    pub fn start(
        spool_dir: PathBuf,
        budget: SpoolBudget,
        queue_capacity: usize,
        ring: Arc<Mutex<CaptureRing>>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        prepare_spool_dir(&spool_dir)?;
        metrics
            .capture_spool_bytes
            .set(spool_usage(&spool_dir)?.total as i64);
        let (tx, rx) = mpsc::channel(queue_capacity);
        let worker_dir = spool_dir.clone();
        let worker_metrics = metrics.clone();
        tokio::spawn(async move {
            run_worker(rx, worker_dir, budget, worker_metrics).await;
        });
        Ok(Self {
            tx,
            spool_dir,
            ring,
            metrics,
        })
    }

    /// Snapshot matching ring evidence and try to enqueue one job.
    pub fn enqueue(&self, original: &Disposition, accepted_rules: &[String]) -> SpoolStatus {
        let found = if accepted_rules.is_empty() {
            None
        } else {
            lookup_snapshot(&self.ring, original).and_then(|(snapshot, by_incident)| {
                Evidence::verify(snapshot, by_incident, original, accepted_rules)
            })
        };
        let Some(Evidence {
            snapshot,
            rules,
            incident_id,
            fingerprint,
        }) = found
        else {
            self.metrics
                .capture_spool_jobs_total
                .with_label_values(&["miss"])
                .inc();
            return SpoolStatus::Miss;
        };
        let identity = disposition_identity(
            original.tenant.as_ref(),
            scope_str(original.scope),
            original.verdict.as_str(),
            incident_id.as_deref(),
            fingerprint.as_deref(),
            original
                .rule_id
                .as_deref()
                .filter(|_| original.scope == DispositionScope::Detection),
        );
        let id = bundle_id(&identity);
        let dest = dest_dir(
            &self.spool_dir,
            original.tenant.as_ref(),
            original.verdict,
            &id,
        );
        if dest.join("manifest.json").is_file() {
            self.metrics
                .capture_spool_jobs_total
                .with_label_values(&["exists"])
                .inc();
            return SpoolStatus::Exists;
        }
        let created_at = chrono::Utc::now().to_rfc3339();
        let job = SpoolJob {
            dest,
            tenant: original.tenant.as_ref().map(|t| t.as_str().to_string()),
            verdict: original.verdict,
            manifest: BundleManifest {
                format_version: BUNDLE_FORMAT_VERSION,
                bundle_id: id,
                kind: BundleKind::DetectionGroupBy,
                verdict: original.verdict.as_str().to_string(),
                scope: scope_str(original.scope).to_string(),
                incident_id,
                fingerprint,
                rule_ids: rules.iter().map(|r| r.id.clone()).collect(),
                rules,
                analyst: original.analyst.clone(),
                note: original.note.clone(),
                first_seen: snapshot.first_seen,
                last_seen: snapshot.last_seen,
                event_count: snapshot.events.len() as u64,
                byte_count: snapshot.bytes as u64,
                coalesced_matches: snapshot
                    .events
                    .iter()
                    .filter(|event| event.matches.len() > 1)
                    .count() as u64,
                truncated: false,
                created_at,
            },
            snapshot,
        };
        match self.tx.try_send(job) {
            Ok(()) => {
                self.metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["queued"])
                    .inc();
                SpoolStatus::Queued
            }
            Err(_) => {
                self.metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["queue_full"])
                    .inc();
                SpoolStatus::QueueFull
            }
        }
    }
}

/// The ring evidence for a disposition, and whether it was found by the
/// disposition's incident id (rather than by its rule and fingerprint).
fn lookup_snapshot(
    ring: &Mutex<CaptureRing>,
    original: &Disposition,
) -> Option<(CaptureSnapshot, bool)> {
    let ring = ring.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(id) = original.incident_id.as_deref()
        && let Some(snap) = ring.snapshot_incident(original.tenant.as_ref(), id)
    {
        return Some((snap, true));
    }
    if let (Some(rule), Some(fp)) = (original.rule_id.as_deref(), original.fingerprint.as_deref()) {
        return ring
            .snapshot_fingerprint(original.tenant.as_ref(), rule, fp)
            .map(|snap| (snap, false));
    }
    None
}

/// The parts of a disposition the captured events confirm.
struct Evidence {
    snapshot: CaptureSnapshot,
    /// Accepted rules that matched a captured event, in first-match order.
    rules: Vec<BundleRule>,
    /// The disposition's incident id, when the evidence was found by it.
    incident_id: Option<String>,
    /// The disposition's fingerprint, when a contributing rule's match
    /// carries it.
    fingerprint: Option<String>,
}

impl Evidence {
    /// `None` when no accepted rule matched a captured event, or when a
    /// detection-scoped disposition names a rule the events do not show.
    fn verify(
        snapshot: CaptureSnapshot,
        by_incident: bool,
        original: &Disposition,
        accepted_rules: &[String],
    ) -> Option<Self> {
        let mut rules: Vec<BundleRule> = Vec::new();
        let mut fingerprint_seen = false;
        for matched in snapshot.events.iter().flat_map(|event| &event.matches) {
            if !accepted_rules.contains(&matched.rule_id) {
                continue;
            }
            fingerprint_seen |= original.fingerprint.is_some()
                && matched.fingerprint.as_deref() == original.fingerprint.as_deref();
            if !rules.iter().any(|r| r.id == matched.rule_id) {
                rules.push(BundleRule {
                    id: matched.rule_id.clone(),
                    title: matched.rule_title.clone(),
                });
            }
        }
        if rules.is_empty() {
            return None;
        }
        if original.scope == DispositionScope::Detection
            && let Some(rule) = original.rule_id.as_deref()
            && !rules.iter().any(|r| r.id == rule)
        {
            return None;
        }
        Some(Evidence {
            snapshot,
            rules,
            incident_id: original.incident_id.clone().filter(|_| by_incident),
            fingerprint: original.fingerprint.clone().filter(|_| fingerprint_seen),
        })
    }
}

fn dest_dir(
    spool_dir: &Path,
    tenant: Option<&rsigma_eval::TenantId>,
    verdict: Verdict,
    bundle_id: &str,
) -> PathBuf {
    let kind = match verdict {
        Verdict::FalsePositive => "fp",
        Verdict::TruePositive | Verdict::BenignTruePositive => "tp",
    };
    match tenant {
        Some(tenant) => spool_dir.join(tenant.as_str()).join(kind).join(bundle_id),
        None => spool_dir.join(kind).join(bundle_id),
    }
}

fn scope_str(scope: DispositionScope) -> &'static str {
    match scope {
        DispositionScope::Detection => "detection",
        DispositionScope::Incident => "incident",
    }
}

async fn run_worker(
    mut rx: mpsc::Receiver<SpoolJob>,
    spool_dir: PathBuf,
    budget: SpoolBudget,
    metrics: Arc<Metrics>,
) {
    while let Some(job) = rx.recv().await {
        let dir = spool_dir.clone();
        let gauge = metrics.capture_spool_bytes.clone();
        let result = tokio::task::spawn_blocking(move || {
            let written = write_job(&dir, budget, job);
            if let Ok(usage) = spool_usage(&dir) {
                gauge.set(usage.total as i64);
            }
            written
        })
        .await;
        match result {
            Ok(Ok(evicted)) => {
                metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["written"])
                    .inc();
                if evicted > 0 {
                    metrics
                        .capture_spool_evictions_total
                        .with_label_values(&["budget"])
                        .inc_by(evicted);
                }
            }
            Ok(Err(WriteOutcome::Exists)) => {
                metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["exists"])
                    .inc();
            }
            Ok(Err(WriteOutcome::Io(error))) => {
                tracing::warn!(error = %error, "capture spool write failed");
                metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["io_error"])
                    .inc();
            }
            Err(_) => {
                metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["io_error"])
                    .inc();
            }
        }
    }
}

#[derive(Debug)]
enum WriteOutcome {
    Exists,
    Io(io::Error),
}

fn write_job(spool_dir: &Path, budget: SpoolBudget, job: SpoolJob) -> Result<u64, WriteOutcome> {
    if job.dest.join("manifest.json").is_file() {
        return Err(WriteOutcome::Exists);
    }
    if is_symlink(&job.dest) || parent_is_symlink(&job.dest) {
        return Err(WriteOutcome::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to write a bundle through a symlink",
        )));
    }
    let payload = render_bundle(&job).map_err(WriteOutcome::Io)?;
    let needed = payload.total_bytes();
    if needed > budget.max_spool_bytes {
        return Err(WriteOutcome::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle exceeds daemon.capture.max_spool_bytes",
        )));
    }
    if job.tenant.is_some() && budget.max_tenant_bytes.is_some_and(|max| needed > max) {
        return Err(WriteOutcome::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle exceeds daemon.tenancy.quotas.capture_spool_bytes",
        )));
    }
    let evicted = evict_for_budget(spool_dir, budget, job.tenant.as_deref(), needed)
        .map_err(WriteOutcome::Io)?;
    let staging = spool_dir.join(".staging").join(&job.manifest.bundle_id);
    if staging.exists() {
        let _ = remove_dir_nofollow(&staging);
    }
    create_dir_secure(&staging).map_err(WriteOutcome::Io)?;
    payload
        .write_into(&staging)
        .map_err(WriteOutcome::Io)
        .inspect_err(|_| {
            let _ = remove_dir_nofollow(&staging);
        })?;
    if let Some(parent) = job.dest.parent() {
        create_dir_secure(parent).map_err(WriteOutcome::Io)?;
    }
    fs::rename(&staging, &job.dest).map_err(WriteOutcome::Io)?;
    set_dir_perms(&job.dest).map_err(WriteOutcome::Io)?;
    Ok(evicted)
}

struct RenderedBundle {
    corpus: String,
    provenance: String,
    manifest: String,
    expectations: Option<String>,
}

impl RenderedBundle {
    fn total_bytes(&self) -> u64 {
        let mut n = self.corpus.len() + self.provenance.len() + self.manifest.len();
        if let Some(exp) = &self.expectations {
            n += exp.len();
        }
        n as u64
    }

    fn write_into(&self, dest: &Path) -> io::Result<()> {
        let corpus_dir = dest.join("corpus");
        let provenance_dir = dest.join("provenance");
        create_dir_secure(&corpus_dir)?;
        create_dir_secure(&provenance_dir)?;
        write_file_secure(&corpus_dir.join("events.ndjson"), self.corpus.as_bytes())?;
        write_file_secure(
            &provenance_dir.join("events.ndjson"),
            self.provenance.as_bytes(),
        )?;
        write_file_secure(&dest.join("manifest.json"), self.manifest.as_bytes())?;
        if let Some(exp) = &self.expectations {
            write_file_secure(dest.join("expectations.yml").as_path(), exp.as_bytes())?;
        }
        Ok(())
    }
}

fn render_bundle(job: &SpoolJob) -> io::Result<RenderedBundle> {
    let mut corpus = String::new();
    let mut provenance = String::new();
    for event in &job.snapshot.events {
        let line = serde_json::to_string(&event.event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        corpus.push_str(&line);
        corpus.push('\n');
        let captured_at = chrono::DateTime::from_timestamp(event.captured_at, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch"))
            .to_rfc3339();
        let rec = ProvenanceLine {
            event_digest: if event.event_digest.is_empty() {
                event_digest(&event.event)
            } else {
                event.event_digest.clone()
            },
            captured_at,
            matches: event.matches.clone(),
            event: event.event.clone(),
        };
        let line = serde_json::to_string(&rec)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        provenance.push_str(&line);
        provenance.push('\n');
    }
    let manifest = serde_json::to_string_pretty(&job.manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let expectations = match job.verdict {
        Verdict::FalsePositive => None,
        Verdict::TruePositive | Verdict::BenignTruePositive => {
            Some(render_expectations(&job.manifest.rule_ids))
        }
    };
    Ok(RenderedBundle {
        corpus,
        provenance,
        manifest,
        expectations,
    })
}

fn render_expectations(rule_ids: &[String]) -> String {
    let mut out = String::from("expectations:\n");
    for id in rule_ids {
        out.push_str("  - rule: ");
        out.push_str(id);
        out.push_str("\n    at_least: 1\n    corpus: events.ndjson\n");
    }
    out
}

pub(crate) fn prepare_spool_dir(spool_dir: &Path) -> io::Result<()> {
    create_dir_secure(spool_dir)?;
    create_dir_secure(&spool_dir.join("tp"))?;
    create_dir_secure(&spool_dir.join("fp"))?;
    let staging = spool_dir.join(".staging");
    if staging.exists() {
        let _ = remove_dir_nofollow(&staging);
    }
    create_dir_secure(&staging)?;
    Ok(())
}

/// One completed bundle in the spool.
struct SpooledBundle {
    path: PathBuf,
    tenant: Option<String>,
    created: i64,
    size: u64,
}

/// The completed bundles in the spool, across every tenant.
struct SpoolUsage {
    bundles: Vec<SpooledBundle>,
    total: u64,
}

impl SpoolUsage {
    fn tenant_bytes(&self, tenant: &str) -> u64 {
        self.bundles
            .iter()
            .filter(|b| b.tenant.as_deref() == Some(tenant))
            .map(|b| b.size)
            .sum()
    }
}

/// Free room for a bundle of `needed` bytes owned by `tenant`, evicting the
/// oldest bundles first: the tenant's own while it is over its quota, then
/// any tenant's while the spool is over its budget. Returns the count evicted.
fn evict_for_budget(
    spool_dir: &Path,
    budget: SpoolBudget,
    tenant: Option<&str>,
    needed: u64,
) -> io::Result<u64> {
    let mut usage = spool_usage(spool_dir)?;
    usage.bundles.sort_by_key(|b| b.created);
    let mut evicted = 0;
    if let (Some(tenant), Some(max)) = (tenant, budget.max_tenant_bytes) {
        let mut held = usage.tenant_bytes(tenant);
        let mut i = 0;
        while held.saturating_add(needed) > max && i < usage.bundles.len() {
            if usage.bundles[i].tenant.as_deref() == Some(tenant) {
                let bundle = usage.bundles.remove(i);
                remove_bundle(&bundle.path)?;
                held = held.saturating_sub(bundle.size);
                usage.total = usage.total.saturating_sub(bundle.size);
                evicted += 1;
            } else {
                i += 1;
            }
        }
        if held.saturating_add(needed) > max {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "the tenant's capture spool quota is full and could not evict enough bundles",
            ));
        }
    }
    let mut oldest = usage.bundles.into_iter();
    while usage.total.saturating_add(needed) > budget.max_spool_bytes {
        let Some(bundle) = oldest.next() else {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "capture spool is over budget and could not evict enough bundles",
            ));
        };
        remove_bundle(&bundle.path)?;
        usage.total = usage.total.saturating_sub(bundle.size);
        evicted += 1;
    }
    Ok(evicted)
}

/// Remove a completed bundle. One already gone counts as removed.
fn remove_bundle(path: &Path) -> io::Result<()> {
    match remove_dir_nofollow(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Walk `<spool>/{tp,fp}/<bundle>` and `<spool>/<tenant>/{tp,fp}/<bundle>`.
fn spool_usage(spool_dir: &Path) -> io::Result<SpoolUsage> {
    let mut bundles = Vec::new();
    for kind in ["tp", "fp"] {
        collect_bundles(&spool_dir.join(kind), None, &mut bundles)?;
    }
    if let Ok(entries) = fs::read_dir(spool_dir) {
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if is_symlink(&path) || !path.is_dir() || rsigma_eval::TenantId::new(&name).is_err() {
                continue;
            }
            for kind in ["tp", "fp"] {
                collect_bundles(&path.join(kind), Some(&name), &mut bundles)?;
            }
        }
    }
    let total = bundles.iter().map(|b| b.size).sum();
    Ok(SpoolUsage { bundles, total })
}

fn collect_bundles(
    parent: &Path,
    tenant: Option<&str>,
    out: &mut Vec<SpooledBundle>,
) -> io::Result<()> {
    if is_symlink(parent) {
        return Ok(());
    }
    let Ok(entries) = fs::read_dir(parent) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let is_bundle_id = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()));
        if !is_bundle_id || is_symlink(&path) || !path.join("manifest.json").is_file() {
            continue;
        }
        let created = fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let size = dir_size_nofollow(&path)?;
        out.push(SpooledBundle {
            path,
            tenant: tenant.map(str::to_string),
            created,
            size,
        });
    }
    Ok(())
}

fn dir_size_nofollow(path: &Path) -> io::Result<u64> {
    if is_symlink(path) {
        return Ok(0);
    }
    if !path.is_dir() {
        return Ok(fs::metadata(path).map(|m| m.len()).unwrap_or(0));
    }
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries {
            let entry = entry?;
            let child = entry.path();
            if is_symlink(&child) {
                continue;
            }
            total += dir_size_nofollow(&child)?;
        }
    }
    Ok(total)
}

fn create_dir_secure(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_dir_perms(path)
}

fn write_file_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if is_symlink(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to write through a symlink",
        ));
    }
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    set_file_perms(path)
}

fn set_dir_perms(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        tracing::warn!("capture spool cannot apply 0700 directory permissions on this platform");
    }
    Ok(())
}

fn set_file_perms(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        tracing::warn!("capture spool cannot apply 0600 file permissions on this platform");
    }
    Ok(())
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn parent_is_symlink(path: &Path) -> bool {
    path.parent().is_some_and(is_symlink)
}

fn remove_dir_nofollow(path: &Path) -> io::Result<()> {
    if is_symlink(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to remove a symlink",
        ));
    }
    fs::remove_dir_all(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_runtime::{AdmittedMatch, CaptureConfig, CaptureRing, CapturedEvent, NoopMetrics};
    use serde_json::json;

    fn snapshot() -> CaptureSnapshot {
        CaptureSnapshot {
            incident_id: "inc".into(),
            first_seen: 1,
            last_seen: 2,
            bytes: 20,
            events: vec![CapturedEvent {
                event_digest: event_digest(&json!({"user":"a"})),
                captured_at: 1,
                matches: vec![AdmittedMatch {
                    rule_id: "r1".into(),
                    rule_title: "Rule".into(),
                    fingerprint: None,
                }],
                event: json!({"user":"a"}),
                event_bytes: 12,
            }],
        }
    }

    fn budget(max_spool_bytes: u64) -> SpoolBudget {
        SpoolBudget {
            max_spool_bytes,
            max_tenant_bytes: None,
        }
    }

    fn job(dir: &Path) -> SpoolJob {
        let id = bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}");
        SpoolJob {
            dest: dest_dir(dir, None, Verdict::TruePositive, &id),
            tenant: None,
            verdict: Verdict::TruePositive,
            snapshot: snapshot(),
            manifest: BundleManifest {
                format_version: BUNDLE_FORMAT_VERSION,
                bundle_id: id,
                kind: BundleKind::DetectionGroupBy,
                verdict: "true_positive".into(),
                scope: "incident".into(),
                incident_id: Some("inc".into()),
                fingerprint: None,
                rule_ids: vec!["r1".into()],
                rules: vec![BundleRule {
                    id: "r1".into(),
                    title: "Rule".into(),
                }],
                analyst: None,
                note: None,
                first_seen: 1,
                last_seen: 2,
                event_count: 1,
                byte_count: 20,
                coalesced_matches: 0,
                truncated: false,
                created_at: "2026-01-01T00:00:00Z".into(),
            },
        }
    }

    #[test]
    fn write_job_creates_backtest_bundle() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), budget(10_000), job(dir.path())).unwrap();
        let dest = dest_dir(
            dir.path(),
            None,
            Verdict::TruePositive,
            &bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}"),
        );
        let corpus = fs::read_to_string(dest.join("corpus/events.ndjson")).unwrap();
        assert!(corpus.contains("\"user\":\"a\""));
        let expectations = fs::read_to_string(dest.join("expectations.yml")).unwrap();
        assert!(expectations.contains("expectations:"));
        assert!(expectations.contains("corpus: events.ndjson"));
        let manifest =
            rsigma_runtime::parse_manifest(&fs::read(dest.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest.rule_ids, vec!["r1".to_string()]);
    }

    #[test]
    fn write_job_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), budget(10_000), job(dir.path())).unwrap();
        assert!(matches!(
            write_job(dir.path(), budget(10_000), job(dir.path())),
            Err(WriteOutcome::Exists)
        ));
    }

    #[test]
    fn write_job_rejects_oversized_bundle() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        let err = write_job(dir.path(), budget(8), job(dir.path())).unwrap_err();
        assert!(matches!(err, WriteOutcome::Io(_)));
    }

    #[test]
    fn write_job_evicts_completed_bundles_for_budget() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), budget(10_000), job(dir.path())).unwrap();
        let first = dest_dir(
            dir.path(),
            None,
            Verdict::TruePositive,
            &bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}"),
        );
        assert!(first.join("manifest.json").is_file());

        let mut second = job(dir.path());
        second.manifest.bundle_id = bundle_id("incident\u{1}true_positive\u{1}other\u{1}\u{1}");
        second.dest = dest_dir(
            dir.path(),
            None,
            Verdict::TruePositive,
            &second.manifest.bundle_id,
        );
        let first_size = dir_size_nofollow(&first).unwrap();
        write_job(dir.path(), budget(first_size + 80), second).unwrap();
        assert!(
            !first.join("manifest.json").is_file(),
            "older bundle should be evicted to free disk budget"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_job_uses_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), budget(10_000), job(dir.path())).unwrap();
        let dest = dest_dir(
            dir.path(),
            None,
            Verdict::TruePositive,
            &bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}"),
        );
        let dir_mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(dest.join("manifest.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn lookup_uses_ring_snapshot() {
        let mut ring = CaptureRing::new(CaptureConfig::default());
        ring.admit(
            rsigma_runtime::AdmittedEvent {
                incident_id: "inc".into(),
                incident_key: None,
                tenant: None,
                is_fresh_generation: true,
                event: json!({"user":"a"}),
                matches: vec![AdmittedMatch {
                    rule_id: "r1".into(),
                    rule_title: "Rule".into(),
                    fingerprint: Some("fp1".into()),
                }],
            },
            1,
            &NoopMetrics,
        );
        let ring = Mutex::new(ring);
        let disp = Disposition {
            rule_id: None,
            verdict: Verdict::TruePositive,
            scope: DispositionScope::Incident,
            fingerprint: None,
            incident_id: Some("inc".into()),
            timestamp: 1,
            analyst: None,
            note: None,
            tenant: None,
        };
        assert!(lookup_snapshot(&ring, &disp).is_some());
    }

    /// A bundle for `tenant` under a distinct incident id `n`.
    fn tenant_job(dir: &Path, tenant: &str, n: usize) -> SpoolJob {
        let mut job = job(dir);
        let tenant_id = rsigma_eval::TenantId::new(tenant).unwrap();
        job.manifest.bundle_id = bundle_id(&format!("{tenant}\u{1}{n}"));
        job.dest = dest_dir(
            dir,
            Some(&tenant_id),
            Verdict::TruePositive,
            &job.manifest.bundle_id,
        );
        job.tenant = Some(tenant.to_string());
        job
    }

    #[test]
    fn tenant_bundles_count_against_the_spool_budget() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), budget(1 << 20), tenant_job(dir.path(), "a", 0)).unwrap();
        let one = spool_usage(dir.path()).unwrap().total;
        let max = one * 3 + one / 2;
        for n in 1..20 {
            for tenant in ["a", "b", "tp"] {
                write_job(dir.path(), budget(max), tenant_job(dir.path(), tenant, n)).unwrap();
                let usage = spool_usage(dir.path()).unwrap();
                assert!(usage.total <= max, "{} > {max}", usage.total);
            }
        }
        assert_eq!(spool_usage(dir.path()).unwrap().bundles.len(), 3);
    }

    #[test]
    fn a_tenant_over_its_quota_evicts_only_its_own_bundles() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), budget(1 << 20), tenant_job(dir.path(), "b", 0)).unwrap();
        let one = spool_usage(dir.path()).unwrap().total;
        let quota = SpoolBudget {
            max_spool_bytes: 1 << 20,
            max_tenant_bytes: Some(one * 2),
        };
        for n in 0..10 {
            write_job(dir.path(), quota, tenant_job(dir.path(), "a", n)).unwrap();
        }
        let usage = spool_usage(dir.path()).unwrap();
        assert_eq!(usage.tenant_bytes("a"), one * 2);
        assert_eq!(
            usage.tenant_bytes("b"),
            one,
            "another tenant's bundle stays"
        );
    }

    fn ring_with(fingerprint: &str) -> Arc<Mutex<CaptureRing>> {
        let mut ring = CaptureRing::new(CaptureConfig::default());
        ring.admit(
            rsigma_runtime::AdmittedEvent {
                incident_id: "inc".into(),
                incident_key: None,
                tenant: None,
                is_fresh_generation: true,
                event: json!({"user":"a"}),
                matches: vec![AdmittedMatch {
                    rule_id: "r1".into(),
                    rule_title: "Rule".into(),
                    fingerprint: Some(fingerprint.into()),
                }],
            },
            1,
            &NoopMetrics,
        );
        Arc::new(Mutex::new(ring))
    }

    fn incident_disposition(fingerprint: Option<String>, rule_id: Option<&str>) -> Disposition {
        Disposition {
            rule_id: rule_id.map(str::to_string),
            verdict: Verdict::TruePositive,
            scope: DispositionScope::Incident,
            fingerprint,
            incident_id: Some("inc".into()),
            timestamp: 1,
            analyst: None,
            note: None,
            tenant: None,
        }
    }

    #[test]
    fn evidence_keeps_only_what_the_events_show() {
        let ring = ring_with("fp1");
        let verify = |disp: &Disposition, rules: &[&str]| {
            let (snapshot, by_incident) = lookup_snapshot(&ring, disp).unwrap();
            let rules: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
            Evidence::verify(snapshot, by_incident, disp, &rules)
        };
        let real = verify(&incident_disposition(Some("fp1".into()), None), &["r1"]).unwrap();
        assert_eq!(real.fingerprint.as_deref(), Some("fp1"));
        assert_eq!(real.incident_id.as_deref(), Some("inc"));

        let bogus = verify(&incident_disposition(Some("made-up".into()), None), &["r1"]).unwrap();
        assert_eq!(bogus.fingerprint, None, "an unseen fingerprint is ignored");

        assert!(
            verify(&incident_disposition(None, None), &["never-fired"]).is_none(),
            "no accepted rule matched a captured event"
        );
        let mut detection = incident_disposition(None, Some("made-up"));
        detection.scope = DispositionScope::Detection;
        assert!(verify(&detection, &["made-up"]).is_none());
    }

    #[tokio::test]
    async fn bogus_fingerprints_open_no_new_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let spool = CaptureSpool::start(
            dir.path().to_path_buf(),
            budget(1 << 20),
            1024,
            ring_with("fp1"),
            Arc::new(Metrics::new()),
        )
        .unwrap();
        for i in 0..50 {
            let disp = incident_disposition(Some(format!("bogus-{i}")), None);
            spool.enqueue(&disp, &["r1".to_string()]);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let written = spool
                .metrics
                .capture_spool_jobs_total
                .with_label_values(&["written"])
                .get()
                + spool
                    .metrics
                    .capture_spool_jobs_total
                    .with_label_values(&["exists"])
                    .get();
            if written == 50 || std::time::Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(spool_usage(dir.path()).unwrap().bundles.len(), 1);
    }
}
