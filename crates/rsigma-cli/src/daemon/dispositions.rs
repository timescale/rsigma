//! Daemon wiring for the triage feedback loop (#70).
//!
//! Owns the rolling [`DispositionStore`] behind an `RwLock`, shared by the
//! `POST`/`GET /api/v1/dispositions` handlers (and, in later phases, the pull
//! source and the persistence hooks). Ingestion validates each record, resolves
//! an incident-scoped verdict to its contributing rules through the live
//! alert-pipeline incident map, updates the store, and refreshes the Prometheus
//! series. The store never sits in the eval or sink path, so it cannot affect
//! detection throughput.

use std::sync::{Arc, RwLock};

use rsigma_runtime::{
    AlertPipelineState, Disposition, DispositionConfig, DispositionScope, DispositionStore,
    IngestOutcome, MAX_DISPOSITIONS_PER_REQUEST, RawDisposition, parse_dispositions,
};
use serde::Serialize;
use serde_json::json;

use super::capture::CaptureSpool;
use super::metrics::Metrics;

/// How often the background pruner rolls the window forward for idle rules.
const PRUNE_INTERVAL_SECS: u64 = 60;

/// Whether a loaded rule carries a given rule identity.
pub type RuleCatalog = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Why a batch was refused as a whole.
#[derive(Debug)]
pub enum IngestError {
    /// The payload did not parse.
    Parse(String),
    /// The batch has more records than a request may carry.
    TooMany { records: usize },
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Parse(message) => f.write_str(message),
            IngestError::TooMany { records } => write!(
                f,
                "a disposition batch accepts at most {MAX_DISPOSITIONS_PER_REQUEST} records, got {records}"
            ),
        }
    }
}

/// Shared triage-feedback state. Cloneable; all clones share one store.
#[derive(Clone)]
pub struct DispositionState {
    store: Arc<RwLock<DispositionStore>>,
    metrics: Arc<Metrics>,
    alert_state: Arc<RwLock<AlertPipelineState>>,
    capture: Option<CaptureSpool>,
    rules: Option<RuleCatalog>,
}

/// The result of ingesting a batch of dispositions, returned by the endpoint
/// and logged for the pull source.
#[derive(Debug, Default, Serialize)]
pub struct IngestSummary {
    pub accepted: u64,
    pub duplicate: u64,
    pub rejected: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capture: Vec<String>,
}

impl DispositionState {
    /// Test-only constructor without a capture spool.
    #[cfg(test)]
    pub fn new(
        config: DispositionConfig,
        metrics: Arc<Metrics>,
        alert_state: Arc<RwLock<AlertPipelineState>>,
    ) -> Self {
        Self::with_capture(config, metrics, alert_state, None)
    }

    /// Create the shared state with the given store config and an optional
    /// capture spool, sharing the alert-pipeline state so `scope: incident`
    /// verdicts can resolve to their contributing rules.
    pub fn with_capture(
        config: DispositionConfig,
        metrics: Arc<Metrics>,
        alert_state: Arc<RwLock<AlertPipelineState>>,
        capture: Option<CaptureSpool>,
    ) -> Self {
        Self {
            store: Arc::new(RwLock::new(DispositionStore::new(config))),
            metrics,
            alert_state,
            capture,
            rules: None,
        }
    }

    /// Refuse dispositions for rule ids `catalog` does not know.
    pub fn set_rule_catalog(&mut self, catalog: RuleCatalog) {
        self.rules = Some(catalog);
    }

    /// Capture the store into a versioned snapshot for persistence, or `None`
    /// if the store lock is poisoned.
    pub fn snapshot(&self) -> Option<rsigma_runtime::DispositionSnapshot> {
        self.store.read().ok().map(|s| s.snapshot())
    }

    /// Restore a persisted snapshot at `now`, pruning entries past the window,
    /// then refresh the ratio gauges. Returns `false` on a version mismatch.
    pub fn restore(
        &self,
        snapshot: rsigma_runtime::DispositionSnapshot,
        now: i64,
        tenancy: bool,
    ) -> bool {
        let stats = self
            .store
            .write()
            .map(|mut s| s.restore_detailed(snapshot, now, tenancy))
            .unwrap_or(None);
        if let Some(stats) = &stats {
            if stats.discarded_untenanted > 0 || stats.discarded_tenanted > 0 {
                tracing::warn!(
                    untenanted = stats.discarded_untenanted,
                    tenanted = stats.discarded_tenanted,
                    "Discarded disposition buckets that do not match the tenancy mode"
                );
            }
            self.refresh_all_gauges();
            true
        } else {
            false
        }
    }

    /// Ingest a batch from `body` (a single object, a JSON array, or NDJSON),
    /// labeling metrics with `source` (`api`, `file`, `http`, or `nats`).
    /// Returns `Err` only when the whole payload fails to parse. A pull
    /// source may carry any number of records.
    pub fn ingest(&self, body: &str, source: &str) -> Result<IngestSummary, String> {
        let raws = self.parse(body).map_err(|e| e.to_string())?;
        Ok(self.ingest_raws(raws, source, None))
    }

    /// Parse a request body, refusing more than
    /// [`MAX_DISPOSITIONS_PER_REQUEST`] records.
    pub fn parse_request(&self, body: &str) -> Result<Vec<RawDisposition>, IngestError> {
        let raws = self.parse(body)?;
        if raws.len() > MAX_DISPOSITIONS_PER_REQUEST {
            self.metrics
                .disposition_ingest_errors_total
                .with_label_values(&["batch_size"])
                .inc();
            return Err(IngestError::TooMany {
                records: raws.len(),
            });
        }
        Ok(raws)
    }

    fn parse(&self, body: &str) -> Result<Vec<RawDisposition>, IngestError> {
        parse_dispositions(body).map_err(|e| {
            self.metrics
                .disposition_ingest_errors_total
                .with_label_values(&["parse"])
                .inc();
            IngestError::Parse(e.to_string())
        })
    }

    /// Ingest parsed records and bind every disposition to `tenant`,
    /// replacing any `tenant` in the records (`None` clears it).
    pub fn ingest_raws(
        &self,
        mut raws: Vec<RawDisposition>,
        source: &str,
        tenant: Option<rsigma_eval::TenantId>,
    ) -> IngestSummary {
        let now = chrono::Utc::now().timestamp();
        // A record's own `tenant` is never identity: only the API principal
        // binds one, and every other source ingests untenanted records.
        for raw in &mut raws {
            raw.tenant = tenant.as_ref().map(|t| t.as_str().to_string());
        }
        let mut summary = IngestSummary::default();
        for raw in raws {
            match Disposition::from_raw(raw, now) {
                Ok(disp) => self.apply(disp, now, source, &mut summary),
                Err(e) => self.reject(source, "validation", e.to_string(), &mut summary),
            }
        }
        self.set_tracked_gauge();
        summary
    }

    fn reject(&self, source: &str, reason: &str, error: String, summary: &mut IngestSummary) {
        self.metrics
            .disposition_ingest_errors_total
            .with_label_values(&[reason])
            .inc();
        self.count_ingest(source, "rejected");
        summary.rejected += 1;
        summary.errors.push(error);
    }

    fn set_tracked_gauge(&self) {
        if let Ok(store) = self.store.read() {
            self.metrics
                .disposition_tracked_rules
                .set(store.rule_count() as i64);
        }
    }

    /// Apply one validated disposition, expanding an unresolved incident-scoped
    /// record into one verdict per contributing rule.
    fn apply(&self, disp: Disposition, now: i64, source: &str, summary: &mut IngestSummary) {
        let original = disp.clone();
        let targets = if disp.scope == DispositionScope::Incident && disp.rule_id.is_none() {
            let rules = disp
                .incident_id
                .as_deref()
                .map(|id| self.resolve_incident_rules(disp.tenant.as_ref(), id))
                .unwrap_or_default();
            if rules.is_empty() {
                self.count_ingest(source, "rejected");
                summary.rejected += 1;
                summary.errors.push(format!(
                    "incident '{}' is not open; supply an explicit rule_id",
                    disp.incident_id.as_deref().unwrap_or("")
                ));
                return;
            }
            rules
                .into_iter()
                .map(|rid| {
                    let mut d = disp.clone();
                    d.rule_id = Some(rid);
                    d
                })
                .collect()
        } else {
            vec![disp]
        };

        let mut accepted_rules = Vec::new();
        let mut accepted = 0u64;
        let mut any_duplicate = false;
        for d in targets {
            if let (Some(rules), Some(rule_id)) = (&self.rules, d.rule_id.as_deref())
                && !rules(rule_id)
            {
                self.reject(
                    source,
                    "unknown_rule",
                    format!("rule_id '{rule_id}' is not a loaded rule"),
                    summary,
                );
                continue;
            }
            let outcome = self
                .store
                .write()
                .map(|mut s| s.apply(&d, now))
                .unwrap_or_else(|_| IngestOutcome::Rejected("store lock poisoned".to_string()));
            match outcome {
                IngestOutcome::Accepted => {
                    accepted += 1;
                    summary.accepted += 1;
                    self.count_ingest(source, "accepted");
                    if let Some(rid) = d.rule_id.clone() {
                        self.metrics
                            .dispositions_total
                            .with_label_values(&[&rid, d.verdict.as_str()])
                            .inc();
                        self.refresh_gauge(&rid);
                        accepted_rules.push(rid);
                    }
                }
                IngestOutcome::Duplicate => {
                    summary.duplicate += 1;
                    self.count_ingest(source, "duplicate");
                    any_duplicate = true;
                    if let Some(rid) = d.rule_id {
                        accepted_rules.push(rid);
                    }
                }
                IngestOutcome::Rejected(reason) => {
                    summary.rejected += 1;
                    self.count_ingest(source, "rejected");
                    summary.errors.push(reason);
                }
                IngestOutcome::RuleCapReached => {
                    let max = self
                        .store
                        .read()
                        .map(|s| s.config().max_rules)
                        .unwrap_or_default();
                    self.reject(
                        source,
                        "rule_cap",
                        format!(
                            "the disposition store already counts {max} (tenant, rule) pairs; raise daemon.dispositions.max_rules"
                        ),
                        summary,
                    );
                }
            }
        }

        if let Some(spool) = &self.capture
            && !accepted_rules.is_empty()
            && (accepted > 0 || any_duplicate)
        {
            let status = spool.enqueue(&original, &accepted_rules);
            summary.capture.push(status.as_str().to_string());
        }
    }

    fn count_ingest(&self, source: &str, result: &str) {
        self.metrics
            .disposition_ingest_total
            .with_label_values(&[source, result])
            .inc();
    }

    /// Recompute one rule's ratio gauge. The series is absent (removed) while
    /// the rule is below `min_sample`, so a sparse rule never publishes a
    /// misleading value.
    fn refresh_gauge(&self, rule_id: &str) {
        let ratio = self.store.read().ok().and_then(|s| s.ratio(rule_id));
        match ratio {
            Some(r) => self
                .metrics
                .rule_false_positive_ratio
                .with_label_values(&[rule_id])
                .set(r),
            None => {
                let _ = self
                    .metrics
                    .rule_false_positive_ratio
                    .remove_label_values(&[rule_id]);
            }
        }
    }

    /// Spawn the background pull-source consumer: run the given dynamic sources
    /// through a `RefreshScheduler` (reusing the shared file, HTTP, and NATS
    /// fetch and refresh machinery) and ingest each refreshed payload as
    /// dispositions, labeling ingest metrics by transport. Idempotency makes a
    /// re-read or redelivery safe (the same records never double count).
    pub fn spawn_source(&self, sources: Vec<rsigma_eval::pipeline::sources::DynamicSource>) {
        use rsigma_eval::pipeline::sources::SourceType;
        use rsigma_runtime::{DefaultSourceResolver, RefreshScheduler, RefreshTrigger};

        if sources.is_empty() {
            return;
        }
        let labels: std::collections::HashMap<String, &'static str> = sources
            .iter()
            .map(|s| {
                let label = match s.source_type {
                    SourceType::File { .. } => "file",
                    SourceType::Http { .. } => "http",
                    SourceType::Nats { .. } => "nats",
                    SourceType::Command { .. } => "command",
                    SourceType::Watchlist { .. } => "watchlist",
                    SourceType::Taxii { .. } => "taxii",
                };
                (s.id.clone(), label)
            })
            .collect();

        let scheduler = RefreshScheduler::new();
        let mut resolver = DefaultSourceResolver::new();
        if let Err(err) = resolver.prepare_taxii(&sources) {
            tracing::error!(error = %err, "Failed to prepare TAXII sources");
            return;
        }
        let sub = scheduler.subscribe(sources, Arc::new(resolver));
        let handle = sub.handle;
        let trigger = sub.trigger.clone();
        let mut results = sub.results;
        let this = self.clone();

        tokio::spawn(async move {
            // Hold the scheduler coordination task for our lifetime; it is never
            // awaited (the refresh loop runs in its own spawned tasks).
            let _scheduler_task = handle;
            // Resolve once on startup, then react to each scheduled refresh.
            let _ = trigger.send(RefreshTrigger::All).await;
            // Each notification carries every source's latest value; ingest only the ones that changed.
            let mut ingested = std::collections::HashMap::new();
            while results.changed().await.is_ok() {
                let Some(result) = results.borrow_and_update().clone() else {
                    continue;
                };
                for (id, value) in result.resolved {
                    if ingested.get(&id) == Some(&value) {
                        continue;
                    }
                    ingested.insert(id.clone(), value.clone());
                    let label = labels.get(&id).copied().unwrap_or("file");
                    let text = serde_json::to_string(&value).unwrap_or_default();
                    let state = this.clone();
                    let ingested =
                        tokio::task::spawn_blocking(move || state.ingest(&text, label)).await;
                    let Ok(ingested) = ingested else {
                        tracing::warn!(source_id = %id, "Disposition ingest task failed");
                        continue;
                    };
                    match ingested {
                        Ok(summary) => tracing::debug!(
                            source_id = %id,
                            accepted = summary.accepted,
                            duplicate = summary.duplicate,
                            rejected = summary.rejected,
                            "Ingested dispositions from source"
                        ),
                        Err(e) => tracing::warn!(
                            source_id = %id,
                            error = %e,
                            "Failed to ingest dispositions from source"
                        ),
                    }
                }
                let state = this.clone();
                let _ = tokio::task::spawn_blocking(move || state.refresh_all_gauges()).await;
            }
        });
    }

    /// Spawn the background pruner that rolls the rolling window forward on a
    /// timer, so a rule that stops receiving dispositions still ages its old
    /// buckets out (per-apply retention only fires when a rule is touched).
    pub fn spawn_pruner(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let state = this.clone();
                let now = chrono::Utc::now().timestamp();
                let _ = tokio::task::spawn_blocking(move || state.prune(now)).await;
            }
        });
    }

    /// Drop buckets and rules past the window at `now`, removing the ratio gauge
    /// for any rule that aged out entirely, then refresh the survivors' gauges.
    pub fn prune(&self, now: i64) {
        let gone = self
            .store
            .write()
            .map(|mut store| store.prune(now))
            .unwrap_or_default();
        for rule_id in gone {
            let _ = self
                .metrics
                .rule_false_positive_ratio
                .remove_label_values(&[rule_id.as_str()]);
        }
        self.refresh_all_gauges();
    }

    /// Recompute every rule's ratio gauge (after a bulk source ingest, a
    /// prune, or a state restore), in time linear in the rules tracked. The
    /// gauge is labeled by rule only, so each value sums the rule's
    /// dispositions across tenants.
    pub fn refresh_all_gauges(&self) {
        let Ok(store) = self.store.read() else {
            return;
        };
        for rule_id in store.rule_ids() {
            match store.ratio(&rule_id) {
                Some(r) => self
                    .metrics
                    .rule_false_positive_ratio
                    .with_label_values(&[rule_id.as_str()])
                    .set(r),
                None => {
                    let _ = self
                        .metrics
                        .rule_false_positive_ratio
                        .remove_label_values(&[rule_id.as_str()]);
                }
            }
        }
        self.metrics
            .disposition_tracked_rules
            .set(store.rule_count() as i64);
    }

    /// Resolve an incident id to its contributing rule identities through the
    /// live alert-pipeline incident map. Empty when the incident is unknown or
    /// belongs to another tenant.
    fn resolve_incident_rules(
        &self,
        tenant: Option<&rsigma_eval::TenantId>,
        incident_id: &str,
    ) -> Vec<String> {
        let Ok(state) = self.alert_state.read() else {
            return Vec::new();
        };
        state
            .incidents
            .incident_rule_keys(tenant, incident_id)
            .unwrap_or_default()
    }

    /// The per-rule ratio view served by `GET /api/v1/dispositions`.
    #[allow(dead_code)]
    pub fn view(&self) -> serde_json::Value {
        self.view_for_tenant(None)
    }

    /// The per-rule view scoped to `tenant`. `None` shows every tenant.
    pub fn view_for_tenant(&self, tenant: Option<&rsigma_eval::TenantId>) -> serde_json::Value {
        let Ok(store) = self.store.read() else {
            return json!({ "error": "store lock poisoned" });
        };
        let cfg = store.config();
        let rules: Vec<serde_json::Value> = store
            .summaries()
            .into_iter()
            .filter(|s| match tenant {
                None => true,
                Some(tenant) => s.tenant.as_ref() == Some(tenant),
            })
            .map(|s| {
                json!({
                    "rule_id": s.rule_id,
                    "tenant_id": s.tenant.as_ref().map(|t| t.as_str()),
                    "true_positives": s.true_positives,
                    "false_positives": s.false_positives,
                    "benign_true_positives": s.benign_true_positives,
                    "total": s.total,
                    "fp_ratio": s.fp_ratio,
                })
            })
            .collect();
        json!({
            "window_seconds": cfg.window.as_secs(),
            "numerator": cfg.numerator.as_str(),
            "min_sample": cfg.min_sample,
            "rules": rules,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(min_sample: u64) -> DispositionState {
        let metrics = Arc::new(Metrics::new());
        let alert_state = Arc::new(RwLock::new(AlertPipelineState::default()));
        let config = DispositionConfig {
            min_sample,
            ..Default::default()
        };
        DispositionState::new(config, metrics, alert_state)
    }

    #[test]
    fn post_applies_and_moves_the_gauge() {
        let state = state(1);
        let summary = state
            .ingest(r#"{"rule_id": "r1", "verdict": "false_positive"}"#, "api")
            .unwrap();
        assert_eq!(summary.accepted, 1);
        assert_eq!(summary.rejected, 0);

        assert_eq!(
            state
                .metrics
                .dispositions_total
                .with_label_values(&["r1", "false_positive"])
                .get(),
            1
        );
        assert_eq!(
            state
                .metrics
                .rule_false_positive_ratio
                .with_label_values(&["r1"])
                .get(),
            1.0
        );
        assert_eq!(
            state
                .metrics
                .disposition_ingest_total
                .with_label_values(&["api", "accepted"])
                .get(),
            1
        );
    }

    #[test]
    fn get_view_reflects_ingest() {
        let state = state(1);
        // Distinct fingerprints so both land in-window with distinct dedup keys.
        state
            .ingest(
                r#"[{"rule_id":"r1","verdict":"false_positive","fingerprint":"a"},{"rule_id":"r1","verdict":"true_positive","fingerprint":"b"}]"#,
                "api",
            )
            .unwrap();
        let view = state.view();
        assert_eq!(view["numerator"], "fp_only");
        assert_eq!(view["min_sample"], 1);
        let rules = view["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["rule_id"], "r1");
        assert_eq!(rules[0]["total"], 2);
        assert_eq!(rules[0]["false_positives"], 1);
        assert_eq!(rules[0]["fp_ratio"], 0.5);
    }

    #[test]
    fn unknown_incident_is_rejected_with_a_pointed_error() {
        let state = state(1);
        let summary = state
            .ingest(
                r#"{"verdict": "true_positive", "scope": "incident", "incident_id": "missing"}"#,
                "api",
            )
            .unwrap();
        assert_eq!(summary.accepted, 0);
        assert_eq!(summary.rejected, 1);
        assert!(summary.errors[0].contains("not open"));
    }

    #[test]
    fn redelivery_is_idempotent() {
        let state = state(1);
        let body = r#"{"rule_id": "r1", "verdict": "false_positive", "fingerprint": "fp1"}"#;
        assert_eq!(state.ingest(body, "api").unwrap().accepted, 1);
        let again = state.ingest(body, "api").unwrap();
        assert_eq!(again.accepted, 0);
        assert_eq!(again.duplicate, 1);
    }

    #[test]
    fn malformed_payload_errors() {
        let state = state(1);
        assert!(state.ingest("[not json", "api").is_err());
        assert_eq!(
            state
                .metrics
                .disposition_ingest_errors_total
                .with_label_values(&["parse"])
                .get(),
            1
        );
    }

    #[test]
    fn invalid_record_is_rejected_not_errored() {
        let state = state(1);
        // Missing verdict: the batch parses, but the record fails validation.
        let summary = state.ingest(r#"{"rule_id": "r1"}"#, "api").unwrap();
        assert_eq!(summary.rejected, 1);
        assert!(summary.errors[0].contains("verdict"));
        assert_eq!(
            state
                .metrics
                .disposition_ingest_errors_total
                .with_label_values(&["validation"])
                .get(),
            1
        );
    }

    #[test]
    fn snapshot_restores_and_refreshes_gauges() {
        let original = state(1);
        original
            .ingest(
                r#"[{"rule_id":"r1","verdict":"false_positive","fingerprint":"a"},{"rule_id":"r1","verdict":"true_positive","fingerprint":"b"}]"#,
                "api",
            )
            .unwrap();
        let snap = original.snapshot().expect("snapshot");

        let restored = state(1);
        let now = chrono::Utc::now().timestamp();
        assert!(restored.restore(snap, now, false));

        // The restored view matches and the gauge was refreshed on restore.
        assert_eq!(restored.view()["rules"][0]["total"], 2);
        assert_eq!(
            restored
                .metrics
                .rule_false_positive_ratio
                .with_label_values(&["r1"])
                .get(),
            0.5
        );
    }

    #[test]
    fn the_ratio_gauge_sums_a_rule_across_tenants() {
        let state = state(1);
        let tenant = |id: &str| Some(rsigma_eval::TenantId::new(id).unwrap());
        for (body, id) in [
            (
                r#"{"rule_id":"r1","verdict":"true_positive","fingerprint":"x"}"#,
                "a",
            ),
            (
                r#"{"rule_id":"r1","verdict":"false_positive","fingerprint":"y"}"#,
                "b",
            ),
        ] {
            let raws = state.parse_request(body).unwrap();
            state.ingest_raws(raws, "api", tenant(id));
        }
        state.refresh_all_gauges();
        assert_eq!(
            state
                .metrics
                .rule_false_positive_ratio
                .with_label_values(&["r1"])
                .get(),
            0.5
        );
    }

    fn known_rules(state: &mut DispositionState, ids: &'static [&'static str]) {
        state.set_rule_catalog(Arc::new(move |id: &str| ids.contains(&id)));
    }

    #[test]
    fn unknown_rule_ids_are_refused_and_create_no_entries() {
        let mut state = state(1);
        known_rules(&mut state, &["r1"]);
        let body: String = (0..100_000)
            .map(|i| format!("{{\"rule_id\":\"bogus-{i}\",\"verdict\":\"false_positive\"}}\n"))
            .collect();
        let summary = state.ingest(&body, "file").unwrap();
        assert_eq!(summary.accepted, 0);
        assert_eq!(summary.rejected, 100_000);
        assert!(state.view()["rules"].as_array().unwrap().is_empty());
        assert_eq!(state.metrics.disposition_tracked_rules.get(), 0);
        assert_eq!(
            state
                .metrics
                .disposition_ingest_errors_total
                .with_label_values(&["unknown_rule"])
                .get(),
            100_000
        );
        let summary = state
            .ingest(r#"{"rule_id":"r1","verdict":"false_positive"}"#, "api")
            .unwrap();
        assert_eq!(summary.accepted, 1);
    }

    #[test]
    fn known_rules_past_max_rules_are_refused() {
        let metrics = Arc::new(Metrics::new());
        let alert_state = Arc::new(RwLock::new(AlertPipelineState::default()));
        let config = DispositionConfig {
            min_sample: 1,
            max_rules: 2,
            ..Default::default()
        };
        let state = DispositionState::new(config, metrics, alert_state);
        let body = r#"[{"rule_id":"a","verdict":"true_positive"},{"rule_id":"b","verdict":"true_positive"},{"rule_id":"c","verdict":"true_positive"}]"#;
        let summary = state.ingest(body, "api").unwrap();
        assert_eq!((summary.accepted, summary.rejected), (2, 1));
        assert!(
            summary.errors[0].contains("max_rules"),
            "{:?}",
            summary.errors
        );
        assert_eq!(state.metrics.disposition_tracked_rules.get(), 2);
    }

    #[test]
    fn a_request_past_the_batch_limit_is_refused_whole() {
        let state = state(1);
        let one = r#"{"rule_id":"r1","verdict":"true_positive"}"#;
        let body = vec![one; MAX_DISPOSITIONS_PER_REQUEST + 1].join("\n");
        assert!(matches!(
            state.parse_request(&body),
            Err(IngestError::TooMany { records }) if records == MAX_DISPOSITIONS_PER_REQUEST + 1
        ));
        let body = vec![one; MAX_DISPOSITIONS_PER_REQUEST].join("\n");
        assert_eq!(
            state.parse_request(&body).unwrap().len(),
            MAX_DISPOSITIONS_PER_REQUEST
        );
    }

    #[test]
    fn a_future_timestamp_is_refused() {
        let state = state(1);
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let summary = state
            .ingest(
                &format!(r#"{{"rule_id":"r1","verdict":"true_positive","timestamp":"{future}"}}"#),
                "api",
            )
            .unwrap();
        assert_eq!(summary.rejected, 1);
        assert!(summary.errors[0].contains("future"), "{:?}", summary.errors);
    }

    fn open_incidents(count: usize) -> Arc<RwLock<AlertPipelineState>> {
        use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
        let pipeline = rsigma_runtime::parse_alert_pipeline_config(
            "group:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n",
        )
        .unwrap();
        let results = (0..count)
            .map(|i| EvaluationResult {
                header: RuleHeader {
                    rule_title: "r1".into(),
                    rule_id: Some("r1".into()),
                    tenant_id: None,
                    level: None,
                    tags: vec![],
                    custom_attributes: Arc::new(std::collections::HashMap::new()),
                    enrichments: None,
                    ruleset: None,
                },
                body: ResultBody::Detection(DetectionBody {
                    matched_selections: vec![],
                    matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(i))],
                    event: None,
                }),
            })
            .collect();
        let mut st = AlertPipelineState::default();
        pipeline.process(results, &mut st, 0, &rsigma_runtime::NoopMetrics);
        assert_eq!(st.incidents.len(), count);
        Arc::new(RwLock::new(st))
    }

    #[test]
    fn incident_scoped_batches_cost_the_same_however_many_incidents_are_open() {
        let body: String = (0..1000)
            .map(|i| {
                format!(
                    "{{\"verdict\":\"false_positive\",\"scope\":\"incident\",\"incident_id\":\"missing-{i}\"}}\n"
                )
            })
            .collect();
        let best_of_three = |incidents: usize| {
            let state = DispositionState::new(
                DispositionConfig::default(),
                Arc::new(Metrics::new()),
                open_incidents(incidents),
            );
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    let summary = state.ingest(&body, "api").unwrap();
                    assert_eq!(summary.rejected, 1000);
                    started.elapsed()
                })
                .min()
                .unwrap()
        };
        let few = best_of_three(10);
        let many = best_of_three(10_000);
        // A scan of every open incident per record makes the second run about
        // a thousand times slower; a keyed lookup keeps the two close.
        assert!(
            many < few * 20 + std::time::Duration::from_millis(50),
            "10 incidents: {few:?}, 10000 incidents: {many:?}"
        );
    }

    #[test]
    fn prune_ages_out_idle_rules() {
        let state = state(1);
        state
            .ingest(
                r#"{"rule_id":"r1","verdict":"false_positive","fingerprint":"x"}"#,
                "api",
            )
            .unwrap();
        assert_eq!(state.view()["rules"].as_array().unwrap().len(), 1);

        // Prune as if far in the future: the rule's only bucket is now well
        // outside the window, so the idle rule ages out without new input.
        let future = chrono::Utc::now().timestamp() + 40 * 24 * 60 * 60;
        state.prune(future);
        assert!(state.view()["rules"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pull_source_ingests_from_a_file() {
        use rsigma_eval::pipeline::sources::{
            DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dispositions.json");
        std::fs::write(
            &path,
            r#"[{"rule_id":"r1","verdict":"false_positive","fingerprint":"x"}]"#,
        )
        .unwrap();

        let source = DynamicSource {
            id: "disp".to_string(),
            source_type: SourceType::File {
                path,
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::OnDemand,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        };

        let state = state(1);
        state.spawn_source(vec![source]);

        for _ in 0..100 {
            let view = state.view();
            if view["rules"].as_array().is_some_and(|a| !a.is_empty()) {
                assert_eq!(view["rules"][0]["rule_id"], "r1");
                assert_eq!(view["rules"][0]["false_positives"], 1);
                assert_eq!(
                    state
                        .metrics
                        .disposition_ingest_total
                        .with_label_values(&["file", "accepted"])
                        .get(),
                    1
                );
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("disposition source ingestion did not appear in the view");
    }
}
