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
    IncludeMode, IngestOutcome, parse_dispositions,
};
use serde::Serialize;
use serde_json::json;

use super::metrics::Metrics;

/// How often the background pruner rolls the window forward for idle rules.
const PRUNE_INTERVAL_SECS: u64 = 60;

/// Shared triage-feedback state. Cloneable; all clones share one store.
#[derive(Clone)]
pub struct DispositionState {
    store: Arc<RwLock<DispositionStore>>,
    metrics: Arc<Metrics>,
    alert_state: Arc<RwLock<AlertPipelineState>>,
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
}

impl DispositionState {
    /// Create the shared state with the given store config, sharing the
    /// alert-pipeline state so `scope: incident` verdicts can resolve to their
    /// contributing rules.
    pub fn new(
        config: DispositionConfig,
        metrics: Arc<Metrics>,
        alert_state: Arc<RwLock<AlertPipelineState>>,
    ) -> Self {
        Self {
            store: Arc::new(RwLock::new(DispositionStore::new(config))),
            metrics,
            alert_state,
        }
    }

    /// Capture the store into a versioned snapshot for persistence, or `None`
    /// if the store lock is poisoned.
    pub fn snapshot(&self) -> Option<rsigma_runtime::DispositionSnapshot> {
        self.store.read().ok().map(|s| s.snapshot())
    }

    /// Restore a persisted snapshot at `now`, pruning entries past the window,
    /// then refresh the ratio gauges. Returns `false` on a version mismatch.
    pub fn restore(&self, snapshot: rsigma_runtime::DispositionSnapshot, now: i64) -> bool {
        let restored = self
            .store
            .write()
            .map(|mut s| s.restore(snapshot, now))
            .unwrap_or(false);
        if restored {
            self.refresh_all_gauges();
        }
        restored
    }

    /// Ingest a batch from `body` (a single object, a JSON array, or NDJSON),
    /// labeling metrics with `source` (`api`, `file`, `http`, or `nats`).
    /// Returns `Err` only when the whole payload fails to parse.
    pub fn ingest(&self, body: &str, source: &str) -> Result<IngestSummary, String> {
        let now = chrono::Utc::now().timestamp();
        let raws = match parse_dispositions(body) {
            Ok(r) => r,
            Err(e) => {
                self.metrics
                    .disposition_ingest_errors_total
                    .with_label_values(&["parse"])
                    .inc();
                return Err(e.to_string());
            }
        };
        let mut summary = IngestSummary::default();
        for raw in raws {
            match Disposition::from_raw(raw, now) {
                Ok(disp) => self.apply(disp, now, source, &mut summary),
                Err(e) => {
                    self.metrics
                        .disposition_ingest_errors_total
                        .with_label_values(&["validation"])
                        .inc();
                    self.count_ingest(source, "rejected");
                    summary.rejected += 1;
                    summary.errors.push(e.to_string());
                }
            }
        }
        Ok(summary)
    }

    /// Apply one validated disposition, expanding an unresolved incident-scoped
    /// record into one verdict per contributing rule.
    fn apply(&self, disp: Disposition, now: i64, source: &str, summary: &mut IngestSummary) {
        let targets = if disp.scope == DispositionScope::Incident && disp.rule_id.is_none() {
            let rules = disp
                .incident_id
                .as_deref()
                .map(|id| self.resolve_incident_rules(id))
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

        for d in targets {
            let outcome = self
                .store
                .write()
                .map(|mut s| s.apply(&d, now))
                .unwrap_or_else(|_| IngestOutcome::Rejected("store lock poisoned".to_string()));
            match outcome {
                IngestOutcome::Accepted => {
                    summary.accepted += 1;
                    self.count_ingest(source, "accepted");
                    if let Some(rid) = d.rule_id.as_deref() {
                        self.metrics
                            .dispositions_total
                            .with_label_values(&[rid, d.verdict.as_str()])
                            .inc();
                        self.refresh_gauge(rid);
                    }
                }
                IngestOutcome::Duplicate => {
                    summary.duplicate += 1;
                    self.count_ingest(source, "duplicate");
                }
                IngestOutcome::Rejected(reason) => {
                    summary.rejected += 1;
                    self.count_ingest(source, "rejected");
                    summary.errors.push(reason);
                }
            }
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
    /// through a [`RefreshScheduler`] (reusing the shared file, HTTP, and NATS
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
                };
                (s.id.clone(), label)
            })
            .collect();

        let scheduler = RefreshScheduler::new();
        let sub = scheduler.subscribe(sources, Arc::new(DefaultSourceResolver::new()));
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
            while results.changed().await.is_ok() {
                let Some(result) = results.borrow_and_update().clone() else {
                    continue;
                };
                for (id, value) in result.resolved {
                    let label = labels.get(&id).copied().unwrap_or("file");
                    let text = serde_json::to_string(&value).unwrap_or_default();
                    match this.ingest(&text, label) {
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
                this.refresh_all_gauges();
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
                this.prune(chrono::Utc::now().timestamp());
            }
        });
    }

    /// Drop buckets and rules past the window at `now`, removing the ratio gauge
    /// for any rule that aged out entirely, then refresh the survivors' gauges.
    pub fn prune(&self, now: i64) {
        let rules_before: std::collections::HashSet<String> = self
            .store
            .read()
            .ok()
            .map(|s| s.summaries().into_iter().map(|x| x.rule_id).collect())
            .unwrap_or_default();
        if let Ok(mut store) = self.store.write() {
            store.prune(now);
        }
        let rules_after: std::collections::HashSet<String> = self
            .store
            .read()
            .ok()
            .map(|s| s.summaries().into_iter().map(|x| x.rule_id).collect())
            .unwrap_or_default();
        for rule_id in rules_before.difference(&rules_after) {
            let _ = self
                .metrics
                .rule_false_positive_ratio
                .remove_label_values(&[rule_id.as_str()]);
        }
        self.refresh_all_gauges();
    }

    /// Recompute every rule's ratio gauge (after a bulk source ingest or a
    /// state restore).
    pub fn refresh_all_gauges(&self) {
        if let Ok(store) = self.store.read() {
            for summary in store.summaries() {
                match summary.fp_ratio {
                    Some(r) => self
                        .metrics
                        .rule_false_positive_ratio
                        .with_label_values(&[&summary.rule_id])
                        .set(r),
                    None => {
                        let _ = self
                            .metrics
                            .rule_false_positive_ratio
                            .remove_label_values(&[&summary.rule_id]);
                    }
                }
            }
        }
    }

    /// Resolve an incident id to its contributing rule identities through the
    /// live alert-pipeline incident map. Empty when the incident is unknown.
    fn resolve_incident_rules(&self, incident_id: &str) -> Vec<String> {
        let Ok(state) = self.alert_state.read() else {
            return Vec::new();
        };
        for inc in state.incidents.snapshot(IncludeMode::Refs) {
            if inc.incident_id == incident_id {
                return inc.rule_counts.into_keys().collect();
            }
        }
        Vec::new()
    }

    /// The per-rule ratio view served by `GET /api/v1/dispositions`.
    pub fn view(&self) -> serde_json::Value {
        let Ok(store) = self.store.read() else {
            return json!({ "error": "store lock poisoned" });
        };
        let cfg = store.config();
        let rules: Vec<serde_json::Value> = store
            .summaries()
            .into_iter()
            .map(|s| {
                json!({
                    "rule_id": s.rule_id,
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
        assert!(restored.restore(snap, now));

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
