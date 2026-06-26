//! Post-engine alert-processing layer.
//!
//! An optional stage in the daemon sink path, between post-evaluation
//! enrichment and the sinks, modeled on the Alertmanager processing pipeline.
//! This module currently implements fingerprint deduplication with an
//! `active -> resolved` lifecycle; it is the home for the grouping, silencing,
//! and inhibition stages as they land.
//!
//! The layer is strictly post-engine: it consumes [`EvaluationResult`]s and
//! emits [`EvaluationResult`]s, so the evaluation hot path is untouched. The
//! immutable, validated config ([`AlertPipeline`]) is built from a YAML file
//! and swapped atomically on hot-reload; the mutable [`DedupStore`] is owned
//! single-threaded by the sink task.

mod config;
mod dedup;
mod selector;

pub use config::{
    AlertPipelineConfigError, AlertPipelineFile, DedupFile, ScopeConfig, build_alert_pipeline,
    load_alert_pipeline_file, parse_alert_pipeline_config,
};
pub use dedup::DedupStore;
pub use selector::{Selector, SelectorParseError};

use rsigma_eval::{EvaluationResult, ProcessResult};

use crate::{MetricsHook, Scope};

use dedup::DedupConfig;

/// A validated, runnable alert-processing pipeline.
///
/// Immutable after construction and cheap to clone behind an `Arc`, so it can
/// be swapped atomically on hot-reload while the sink task keeps a live
/// snapshot for the duration of a batch.
#[derive(Debug)]
pub struct AlertPipeline {
    scope: Scope,
    strip_event: bool,
    dedup: Option<DedupConfig>,
}

impl AlertPipeline {
    /// Construct from validated parts. Prefer [`build_alert_pipeline`].
    pub(crate) fn new(scope: Scope, strip_event: bool, dedup: Option<DedupConfig>) -> Self {
        AlertPipeline {
            scope,
            strip_event,
            dedup,
        }
    }

    /// True when the pipeline does nothing (no dedup and no event stripping),
    /// so the sink task can skip it entirely.
    pub fn is_noop(&self) -> bool {
        self.dedup.is_none() && !self.strip_event
    }

    /// Process the results produced from one input event, folding duplicates
    /// into `store` and returning the results that should continue to the
    /// sinks. Out-of-scope results pass through untouched.
    pub fn process(
        &self,
        results: ProcessResult,
        store: &mut DedupStore,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> ProcessResult {
        if self.is_noop() {
            return results;
        }
        let start = std::time::Instant::now();
        let mut kept = Vec::with_capacity(results.len());

        for mut result in results {
            if !self.scope.matches(&result) {
                kept.push(result);
                continue;
            }

            let Some(cfg) = self.dedup.as_ref() else {
                // No dedup, but in scope: apply strip_event and pass through.
                if self.strip_event {
                    strip_event_payloads(&mut result);
                }
                kept.push(result);
                continue;
            };

            let fingerprint = dedup::fingerprint(&cfg.fingerprint, &result);
            if store.contains(&fingerprint) {
                store.fold(&fingerprint, now);
                metrics.on_alert_pipeline_result("folded");
            } else {
                let fields = dedup::resolve_fields(&cfg.fingerprint, &result);
                let sample = dedup::sample_of(&result);
                store.insert(fingerprint, now, sample, fields);
                metrics.on_alert_pipeline_result("emitted");
                if self.strip_event {
                    strip_event_payloads(&mut result);
                }
                kept.push(result);
            }
        }

        metrics.set_alert_pipeline_store_entries(store.len() as i64);
        metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        kept
    }

    /// Advance time: emit any `repeat` re-emits and `resolved` summaries due
    /// from the active-alert store. Returns the records to dispatch (with no
    /// ack tokens, since they are synthetic).
    pub fn tick(
        &self,
        store: &mut DedupStore,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> ProcessResult {
        let Some(cfg) = self.dedup.as_ref() else {
            return Vec::new();
        };
        let start = std::time::Instant::now();
        let records = store.tick(cfg, now);
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            metrics.on_alert_pipeline_result(record.state);
            metrics.on_alert_pipeline_summary_emitted();
            if record.state == "resolved" {
                metrics.on_alert_pipeline_eviction();
            }
            out.push(record.result);
        }
        if !out.is_empty() {
            metrics.set_alert_pipeline_store_entries(store.len() as i64);
            metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        }
        out
    }
}

/// Remove raw event payloads from a result. Used for the long-lived dedup
/// sample and, when `strip_event` is set, for pass-through results, so the
/// layer can fingerprint on `event.*` without emitting full events.
pub(crate) fn strip_event_payloads(result: &mut EvaluationResult) {
    if let Some(detection) = result.as_detection_mut() {
        detection.event = None;
    }
    if let Some(correlation) = result.as_correlation_mut() {
        correlation.events = None;
        correlation.event_refs = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopMetrics;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn pipeline(yaml: &str) -> AlertPipeline {
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        build_alert_pipeline(file).unwrap()
    }

    fn detection(ip: &str, level: Level) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Brute force".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: Some(serde_json::json!({"raw": "event"})),
            }),
        }
    }

    #[test]
    fn dedup_emits_first_fire_and_folds_duplicates() {
        let p = pipeline("dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\n");
        let mut store = DedupStore::default();
        let m = NoopMetrics;

        let first = p.process(vec![detection("10.0.0.1", Level::High)], &mut store, 0, &m);
        assert_eq!(first.len(), 1, "first fire passes through");

        let dup = p.process(vec![detection("10.0.0.1", Level::High)], &mut store, 5, &m);
        assert!(dup.is_empty(), "duplicate folded and dropped");

        let other = p.process(vec![detection("10.0.0.2", Level::High)], &mut store, 6, &m);
        assert_eq!(other.len(), 1, "a different fingerprint is its own alert");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn out_of_scope_results_bypass_dedup() {
        let p = pipeline("scope:\n  levels: [critical]\ndedup:\n  fingerprint: [match.SourceIp]\n");
        let mut store = DedupStore::default();
        let m = NoopMetrics;

        // High is out of scope -> always passes through, even twice.
        let a = p.process(vec![detection("10.0.0.1", Level::High)], &mut store, 0, &m);
        let b = p.process(vec![detection("10.0.0.1", Level::High)], &mut store, 1, &m);
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(
            store.is_empty(),
            "out-of-scope results never enter the store"
        );
    }

    #[test]
    fn strip_event_drops_payload_on_pass_through() {
        let p = pipeline("strip_event: true\ndedup:\n  fingerprint: [event.raw]\n");
        let mut store = DedupStore::default();
        let m = NoopMetrics;
        let kept = p.process(vec![detection("10.0.0.1", Level::High)], &mut store, 0, &m);
        assert_eq!(kept.len(), 1);
        assert!(
            kept[0].as_detection().unwrap().event.is_none(),
            "strip_event removes the raw event before delivery"
        );
    }

    #[test]
    fn tick_resolves_idle_alert() {
        let p = pipeline("dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 30s\n");
        let mut store = DedupStore::default();
        let m = NoopMetrics;
        let _ = p.process(vec![detection("10.0.0.1", Level::High)], &mut store, 0, &m);
        assert!(p.tick(&mut store, 10, &m).is_empty(), "not yet idle");
        let resolved = p.tick(&mut store, 40, &m);
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].header.enrichments.as_ref().unwrap()["dedup_state"],
            serde_json::json!("resolved")
        );
        assert!(store.is_empty());
    }
}
