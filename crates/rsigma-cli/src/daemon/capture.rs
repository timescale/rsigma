//! Asynchronous disposition-bundle spooling.
//!
//! One job is enqueued per original accepted disposition. Filesystem work runs
//! in `spawn_blocking` with same-parent staging, restrictive permissions, and
//! a disk-byte budget.

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
    verdict: Verdict,
    snapshot: CaptureSnapshot,
    manifest: BundleManifest,
}

impl CaptureSpool {
    /// Prepare the spool directory, clean abandoned staging dirs, and start
    /// the background writer.
    pub fn start(
        spool_dir: PathBuf,
        max_spool_bytes: u64,
        queue_capacity: usize,
        ring: Arc<Mutex<CaptureRing>>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        prepare_spool_dir(&spool_dir)?;
        let (tx, rx) = mpsc::channel(queue_capacity);
        let worker_dir = spool_dir.clone();
        let worker_metrics = metrics.clone();
        tokio::spawn(async move {
            run_worker(rx, worker_dir, max_spool_bytes, worker_metrics).await;
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
        if accepted_rules.is_empty() {
            return SpoolStatus::Miss;
        }
        let snapshot = lookup_snapshot(&self.ring, original);
        let Some(snapshot) = snapshot else {
            self.metrics
                .capture_spool_jobs_total
                .with_label_values(&["miss"])
                .inc();
            return SpoolStatus::Miss;
        };
        let identity = disposition_identity(
            scope_str(original.scope),
            original.verdict.as_str(),
            original.incident_id.as_deref(),
            original.fingerprint.as_deref(),
            original
                .rule_id
                .as_deref()
                .filter(|_| original.scope == DispositionScope::Detection),
        );
        let id = bundle_id(&identity);
        let dest = dest_dir(&self.spool_dir, original.verdict, &id);
        if dest.join("manifest.json").is_file() {
            self.metrics
                .capture_spool_jobs_total
                .with_label_values(&["exists"])
                .inc();
            return SpoolStatus::Exists;
        }
        let rules = rules_from_snapshot(&snapshot, accepted_rules);
        let created_at = chrono::Utc::now().to_rfc3339();
        let job = SpoolJob {
            dest,
            verdict: original.verdict,
            manifest: BundleManifest {
                format_version: BUNDLE_FORMAT_VERSION,
                bundle_id: id,
                kind: BundleKind::DetectionGroupBy,
                verdict: original.verdict.as_str().to_string(),
                scope: scope_str(original.scope).to_string(),
                incident_id: original.incident_id.clone(),
                fingerprint: original.fingerprint.clone(),
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

fn lookup_snapshot(ring: &Mutex<CaptureRing>, original: &Disposition) -> Option<CaptureSnapshot> {
    let ring = ring.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(id) = original.incident_id.as_deref()
        && let Some(snap) = ring.snapshot_incident(id)
    {
        return Some(snap);
    }
    if let (Some(rule), Some(fp)) = (original.rule_id.as_deref(), original.fingerprint.as_deref()) {
        return ring.snapshot_fingerprint(rule, fp);
    }
    None
}

fn rules_from_snapshot(snapshot: &CaptureSnapshot, accepted_rules: &[String]) -> Vec<BundleRule> {
    let mut rules = Vec::new();
    for event in &snapshot.events {
        for matched in &event.matches {
            if accepted_rules.contains(&matched.rule_id)
                && !rules.iter().any(|r: &BundleRule| r.id == matched.rule_id)
            {
                rules.push(BundleRule {
                    id: matched.rule_id.clone(),
                    title: matched.rule_title.clone(),
                });
            }
        }
    }
    if rules.is_empty() {
        for id in accepted_rules {
            rules.push(BundleRule {
                id: id.clone(),
                title: id.clone(),
            });
        }
    }
    rules
}

fn dest_dir(spool_dir: &Path, verdict: Verdict, bundle_id: &str) -> PathBuf {
    let kind = match verdict {
        Verdict::FalsePositive => "fp",
        Verdict::TruePositive | Verdict::BenignTruePositive => "tp",
    };
    spool_dir.join(kind).join(bundle_id)
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
    max_spool_bytes: u64,
    metrics: Arc<Metrics>,
) {
    while let Some(job) = rx.recv().await {
        let dir = spool_dir.clone();
        let metrics = metrics.clone();
        let result =
            tokio::task::spawn_blocking(move || write_job(&dir, max_spool_bytes, job)).await;
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

fn write_job(spool_dir: &Path, max_spool_bytes: u64, job: SpoolJob) -> Result<u64, WriteOutcome> {
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
    if needed > max_spool_bytes {
        return Err(WriteOutcome::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle exceeds daemon.capture.max_spool_bytes",
        )));
    }
    let evicted = evict_for_budget(spool_dir, max_spool_bytes, needed).map_err(WriteOutcome::Io)?;
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

fn evict_for_budget(spool_dir: &Path, max_bytes: u64, needed: u64) -> io::Result<u64> {
    let mut used =
        dir_size_nofollow(&spool_dir.join("tp"))? + dir_size_nofollow(&spool_dir.join("fp"))?;
    if used.saturating_add(needed) <= max_bytes {
        return Ok(0);
    }
    let mut bundles = completed_bundles(spool_dir)?;
    bundles.sort_by_key(|(_, created, _)| *created);
    let mut evicted = 0;
    for (path, _, size) in bundles {
        if used.saturating_add(needed) <= max_bytes {
            break;
        }
        remove_dir_nofollow(&path)?;
        used = used.saturating_sub(size);
        evicted += 1;
    }
    if used.saturating_add(needed) > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "capture spool is over budget and could not evict enough bundles",
        ));
    }
    Ok(evicted)
}

fn completed_bundles(spool_dir: &Path) -> io::Result<Vec<(PathBuf, i64, u64)>> {
    let mut out = Vec::new();
    for kind in ["tp", "fp"] {
        let parent = spool_dir.join(kind);
        let Ok(entries) = fs::read_dir(&parent) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if is_symlink(&path) || !path.is_dir() {
                continue;
            }
            if !path.join("manifest.json").is_file() {
                continue;
            }
            let created = fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let size = dir_size_nofollow(&path)?;
            out.push((path, created, size));
        }
    }
    Ok(out)
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

    fn job(dir: &Path) -> SpoolJob {
        let id = bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}");
        SpoolJob {
            dest: dest_dir(dir, Verdict::TruePositive, &id),
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
        write_job(dir.path(), 10_000, job(dir.path())).unwrap();
        let dest = dest_dir(
            dir.path(),
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
        write_job(dir.path(), 10_000, job(dir.path())).unwrap();
        assert!(matches!(
            write_job(dir.path(), 10_000, job(dir.path())),
            Err(WriteOutcome::Exists)
        ));
    }

    #[test]
    fn write_job_rejects_oversized_bundle() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        let err = write_job(dir.path(), 8, job(dir.path())).unwrap_err();
        assert!(matches!(err, WriteOutcome::Io(_)));
    }

    #[test]
    fn write_job_evicts_completed_bundles_for_budget() {
        let dir = tempfile::tempdir().unwrap();
        prepare_spool_dir(dir.path()).unwrap();
        write_job(dir.path(), 10_000, job(dir.path())).unwrap();
        let first = dest_dir(
            dir.path(),
            Verdict::TruePositive,
            &bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}"),
        );
        assert!(first.join("manifest.json").is_file());

        let mut second = job(dir.path());
        second.manifest.bundle_id = bundle_id("incident\u{1}true_positive\u{1}other\u{1}\u{1}");
        second.dest = dest_dir(
            dir.path(),
            Verdict::TruePositive,
            &second.manifest.bundle_id,
        );
        let first_size = dir_size_nofollow(&first).unwrap();
        write_job(dir.path(), first_size + 80, second).unwrap();
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
        write_job(dir.path(), 10_000, job(dir.path())).unwrap();
        let dest = dest_dir(
            dir.path(),
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
        };
        assert!(lookup_snapshot(&ring, &disp).is_some());
    }
}
