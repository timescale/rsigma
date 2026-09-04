//! Post-engine alert-processing layer.
//!
//! An optional stage in the daemon sink path, between post-evaluation
//! enrichment and the sinks, modeled on the Alertmanager processing pipeline.
//! It currently runs two stages: fingerprint deduplication (`active ->
//! resolved` lifecycle) and incident grouping (`group_by` equality or an
//! opt-in `entity_graph` union-find). It is the home for the silencing and
//! inhibition stages as they land.
//!
//! The layer is strictly post-engine: it consumes [`EvaluationResult`]s and
//! emits [`EvaluationResult`]s plus [`IncidentResult`]s, so the evaluation hot
//! path is untouched. The immutable, validated config ([`AlertPipeline`]) is
//! built from a YAML file and swapped atomically on hot-reload; the mutable
//! [`DedupStore`] and [`IncidentStore`] are owned by the sink task (the
//! incident store behind an `RwLock` so the admin API can read open incidents).
//!
//! An optional [`CaptureSink`](crate::capture::CaptureSink) can observe
//! detections after inhibition/silencing and before dedup. When the sink is
//! absent, process output is unchanged.

mod config;
mod dedup;
mod grouping;
mod inhibit;
mod matcher;
mod silence;
mod snapshot;
mod state;

pub use crate::selector::{Selector, SelectorParseError};
pub use config::{
    AlertPipelineConfigError, AlertPipelineFile, CapsFile, DEFAULT_MAX_DYNAMIC_SILENCES, DedupFile,
    GroupFile, GroupModeLabel, IncludeLabel, ScopeConfig, build_alert_pipeline,
    load_alert_pipeline_file, parse_alert_pipeline_config,
};
pub use dedup::DedupStore;
pub use grouping::{
    Caps, GroupMode, IncidentRef, IncidentResult, IncidentStore, IncludeMode, SampleMode,
    group_fingerprint,
};
pub use matcher::{MatchOp, Matcher, MatcherError, MatcherSet, MatcherSpec};
pub use silence::{
    Silence, SilenceError, SilenceOrigin, SilenceSpec, SilenceState, SilenceStore, SilenceView,
};
pub use snapshot::{AlertPipelineSnapshot, SNAPSHOT_VERSION};
pub use state::AlertPipelineState;

use rsigma_eval::{EvaluationResult, ProcessResult};
use serde_json::Value;

use crate::{MetricsHook, Scope};

use dedup::DedupConfig;
use grouping::{GroupConfig, OvermergeGuard};
use inhibit::InhibitConfig;
use silence::Silence as StaticSilence;

/// Output of [`AlertPipeline::tick`]: dedup summary records (re-emit /
/// resolved) and incident emissions.
#[derive(Debug, Default)]
pub struct TickOutput {
    /// Dedup `repeat` / `resolved` summary lines (serialized results with
    /// `dedup_*` keys), dispatched as raw NDJSON.
    pub dedup_lines: Vec<Value>,
    /// Incident emissions, dispatched via the incident path.
    pub incidents: Vec<IncidentResult>,
}

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
    group: Option<GroupConfig>,
    static_silences: Vec<StaticSilence>,
    inhibit: Option<InhibitConfig>,
    max_silences: usize,
}

impl AlertPipeline {
    /// Construct from validated parts. Prefer [`build_alert_pipeline`].
    pub(crate) fn new(
        scope: Scope,
        strip_event: bool,
        dedup: Option<DedupConfig>,
        group: Option<GroupConfig>,
        static_silences: Vec<StaticSilence>,
        inhibit: Option<InhibitConfig>,
        max_silences: usize,
    ) -> Self {
        AlertPipeline {
            scope,
            strip_event,
            dedup,
            group,
            static_silences,
            inhibit,
            max_silences,
        }
    }

    /// The static silences declared in the config, for (re-)seeding the store.
    pub fn static_silences(&self) -> &[StaticSilence] {
        &self.static_silences
    }

    /// Ceiling on concurrently-tracked dynamic (API) silences. The silence API
    /// rejects creation past this many.
    pub fn max_dynamic_silences(&self) -> usize {
        self.max_silences
    }

    /// The configured incident include mode, if grouping is enabled.
    pub fn incident_include(&self) -> Option<IncludeMode> {
        self.group.as_ref().map(|g| g.include)
    }

    /// The configured incident NATS subject override, if any.
    pub fn incident_nats_subject(&self) -> Option<&str> {
        self.group.as_ref().and_then(|g| g.nats_subject.as_deref())
    }

    /// The configured grouping mode, if grouping is enabled.
    pub fn group_mode(&self) -> Option<GroupMode> {
        self.group.as_ref().map(|g| g.mode)
    }

    /// The `group.by` selectors when grouping is `group_by`.
    pub fn group_by_selectors(&self) -> Option<&[Selector]> {
        self.group
            .as_ref()
            .and_then(|g| (g.mode == GroupMode::GroupBy).then_some(g.by.as_slice()))
    }

    /// The dedup fingerprint selectors, if dedup is enabled.
    pub fn dedup_selectors(&self) -> Option<&[Selector]> {
        self.dedup.as_ref().map(|d| d.fingerprint.as_slice())
    }

    /// Ceiling on concurrently-open incidents, if grouping is enabled.
    pub fn max_open_incidents(&self) -> Option<usize> {
        self.group.as_ref().map(|g| g.caps.max_open_incidents)
    }

    /// Why this pipeline cannot host capture, or `None` when it can.
    ///
    /// Capture requires `group.mode: group_by`. When dedup is also configured,
    /// every `group.by` selector must appear in `dedup.fingerprint` so a folded
    /// alert cannot span incident identities.
    pub fn capture_incompatibility(&self) -> Option<crate::capture::CaptureIncompatibility> {
        use crate::capture::CaptureIncompatibility;
        match &self.group {
            None => Some(CaptureIncompatibility::MissingGroupBy),
            Some(g) if g.mode == GroupMode::EntityGraph => {
                Some(CaptureIncompatibility::EntityGraph)
            }
            Some(g) => {
                if let Some(d) = &self.dedup {
                    let missing: Vec<String> =
                        g.by.iter()
                            .filter(|sel| !d.fingerprint.contains(*sel))
                            .map(Selector::as_str)
                            .collect();
                    if !missing.is_empty() {
                        return Some(CaptureIncompatibility::DedupSelectorsMissing(missing));
                    }
                }
                None
            }
        }
    }

    /// Process the results produced from one input event: dedup folds
    /// duplicates into `dedup_store`, grouping assigns survivors to incidents
    /// in `incident_store` and annotates them with `incident_id`. Out-of-scope
    /// results pass through untouched.
    pub fn process(
        &self,
        results: ProcessResult,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> ProcessResult {
        self.process_with_capture(results, state, now, metrics, None)
    }

    /// [`Self::process`] plus an optional capture sink that observes detections
    /// after inhibition/silencing and before dedup. Process output is unchanged
    /// relative to [`Self::process`] regardless of whether a sink is attached.
    pub fn process_with_capture(
        &self,
        results: ProcessResult,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
        mut capture: Option<&mut dyn crate::capture::CaptureSink>,
    ) -> ProcessResult {
        let start = std::time::Instant::now();
        let mut kept = Vec::with_capacity(results.len());
        let mut pending = Vec::new();
        let capturing = capture.is_some();
        let capture_ok = capturing && self.capture_incompatibility().is_none();

        for mut result in results {
            if !self.scope.matches(&result) {
                kept.push(result);
                continue;
            }

            // Inhibition: an inhibited target is dropped before it can become a
            // source. `evaluate` also records non-inhibited results (including
            // ones about to be silenced) as active sources, so a silenced
            // source still inhibits its targets.
            if let Some(icfg) = self.inhibit.as_ref()
                && let Some(rule) = state.inhibit.evaluate(icfg, &result, now)
            {
                metrics.on_alert_pipeline_inhibited(&rule);
                continue;
            }

            // Silencing: an active silence mutes the result before dedup, so a
            // silenced result neither emits nor opens an incident.
            if state.silences.active_match(&result, now).is_some() {
                metrics.on_alert_pipeline_silenced();
                continue;
            }

            if capturing {
                self.offer_capture(&result, &state.incidents, capture_ok, &mut pending);
            }

            // Dedup: fold duplicates into the active alert. When the store is at
            // its cap, a first-fire for a new fingerprint passes through
            // un-deduped rather than opening another alert, bounding memory; the
            // store-entries gauge plateauing at the cap signals saturation.
            if let Some(cfg) = self.dedup.as_ref() {
                let fingerprint = dedup::fingerprint(&cfg.fingerprint, &result);
                if state.dedup.contains(&fingerprint) {
                    state.dedup.fold(&fingerprint, now);
                    metrics.on_alert_pipeline_result("folded");
                    continue;
                }
                if state.dedup.len() < cfg.max_active_alerts {
                    let fields = dedup::resolve_fields(&cfg.fingerprint, &result);
                    let sample = dedup::sample_of(&result);
                    state.dedup.insert(fingerprint, now, sample, fields);
                }
                metrics.on_alert_pipeline_result("emitted");
            }

            // Grouping: assign the survivor to an incident, reading entity /
            // group-by selectors off the result while the event is still
            // present, then annotate it with the incident id.
            if let Some(gcfg) = self.group.as_ref()
                && let Some(id) = state.incidents.assign(gcfg, &result, now, |guard| {
                    metrics.on_alert_pipeline_overmerge(guard_label(guard));
                })
            {
                if self.strip_event {
                    strip_event_payloads(&mut result);
                }
                annotate_incident(&mut result, id);
                kept.push(result);
                continue;
            }

            if self.strip_event {
                strip_event_payloads(&mut result);
            }
            kept.push(result);
        }

        if let Some(sink) = capture.as_mut() {
            crate::capture::flush_pending(pending, *sink, now);
        }

        if self.dedup.is_some() {
            metrics.set_alert_pipeline_store_entries(state.dedup.len() as i64);
        }
        if self.group.is_some() {
            metrics.set_incidents_open(state.incidents.len() as i64);
        }
        metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        kept
    }

    fn offer_capture(
        &self,
        result: &EvaluationResult,
        incidents: &IncidentStore,
        capture_ok: bool,
        pending: &mut Vec<crate::capture::PendingCapture>,
    ) {
        use crate::capture::{AdmittedMatch, CaptureReject, PendingAdmit, PendingCapture};

        if !result.is_detection() {
            pending.push(PendingCapture::Reject(CaptureReject::UnsupportedResultKind));
            return;
        }
        if !capture_ok {
            return;
        }
        let Some(event) = result.as_detection().and_then(|d| d.event.clone()) else {
            pending.push(PendingCapture::Reject(CaptureReject::MissingEvent));
            return;
        };
        let Some(gcfg) = self.group.as_ref() else {
            return;
        };
        let (incident_id, _) = grouping::group_fingerprint(&gcfg.by, result);
        if !incidents.can_assign(&incident_id, gcfg.caps.max_open_incidents) {
            pending.push(PendingCapture::Reject(CaptureReject::NotAssignable));
            return;
        }
        let fingerprint = self
            .dedup
            .as_ref()
            .map(|cfg| dedup::fingerprint(&cfg.fingerprint, result));
        let rule_id = result
            .header
            .rule_id
            .clone()
            .unwrap_or_else(|| result.header.rule_title.clone());
        pending.push(PendingCapture::Admit(PendingAdmit {
            is_fresh_generation: !incidents.contains(&incident_id),
            incident_id,
            event,
            match_: AdmittedMatch {
                rule_id,
                rule_title: result.header.rule_title.clone(),
                fingerprint,
            },
        }));
    }

    /// Advance time: emit due dedup `repeat` / `resolved` records and incident
    /// emissions (`group_wait` / `group_interval` / `repeat` / `resolved`).
    pub fn tick(
        &self,
        state: &mut AlertPipelineState,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> TickOutput {
        let start = std::time::Instant::now();
        let mut out = TickOutput::default();

        if let Some(cfg) = self.dedup.as_ref() {
            for record in state.dedup.tick(cfg, now) {
                metrics.on_alert_pipeline_result(record.state);
                metrics.on_alert_pipeline_summary_emitted();
                if record.state == "resolved" {
                    metrics.on_alert_pipeline_eviction();
                }
                out.dedup_lines.push(record.json);
            }
            metrics.set_alert_pipeline_store_entries(state.dedup.len() as i64);
        }

        if let Some(gcfg) = self.group.as_ref() {
            for emission in state.incidents.tick(gcfg, now) {
                metrics.on_incident_emitted(emission.trigger);
                out.incidents.push(emission.result);
            }
            metrics.set_incidents_open(state.incidents.len() as i64);
        }

        // Garbage-collect expired silences and refresh the active gauge.
        state.silences.gc(now);
        metrics.set_silences_active(state.silences.active_count(now) as i64);

        // Garbage-collect stale inhibition sources and refresh the gauge.
        if let Some(icfg) = self.inhibit.as_ref() {
            state.inhibit.gc(icfg, now);
            metrics.set_inhibit_sources_active(state.inhibit.active_count(icfg, now) as i64);
        }

        if !out.dedup_lines.is_empty() || !out.incidents.is_empty() {
            metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        }
        out
    }

    /// Capture the mutable state into a versioned persistence snapshot.
    pub fn snapshot(&self, state: &AlertPipelineState) -> AlertPipelineSnapshot {
        AlertPipelineSnapshot {
            version: SNAPSHOT_VERSION,
            dedup: state.dedup.snapshot(),
            incidents: state.incidents.export(),
            silences: state.silences.api_snapshot(),
            inhibit_sources: state.inhibit.snapshot(),
        }
    }

    /// Restore a snapshot into `state`, pruning entries past their window at
    /// `now`. Returns `false` on a version mismatch (caller starts fresh).
    pub fn restore(
        &self,
        state: &mut AlertPipelineState,
        snap: AlertPipelineSnapshot,
        now: i64,
    ) -> bool {
        if snap.version != SNAPSHOT_VERSION {
            return false;
        }
        // Silences are independent of the configured stages.
        state.silences.restore_api(snap.silences, now);
        if let Some(cfg) = self.dedup.as_ref() {
            state
                .dedup
                .restore(snap.dedup, now, cfg.resolve_timeout.as_secs() as i64);
        }
        if let Some(g) = self.group.as_ref() {
            state
                .incidents
                .restore(snap.incidents, now, g.resolve_timeout.as_secs() as i64);
        }
        if let Some(icfg) = self.inhibit.as_ref() {
            state.inhibit.restore(snap.inhibit_sources, icfg, now);
        }
        true
    }
}

/// Inject the reserved `incident_id` key into a result's enrichments. The layer
/// wins on a collision with a user enricher.
fn annotate_incident(result: &mut EvaluationResult, id: String) {
    let map = result
        .header
        .enrichments
        .get_or_insert_with(serde_json::Map::new);
    if map.contains_key("incident_id") {
        // Debug, not warn: an upstream enricher setting `incident_id` on every
        // result would otherwise emit one log line per result.
        tracing::debug!("alert pipeline: overwriting a user-set `incident_id` enrichment key");
    }
    map.insert("incident_id".to_string(), Value::String(id));
}

/// Metric label for an entity-graph guard hit.
fn guard_label(guard: OvermergeGuard) -> &'static str {
    match guard {
        OvermergeGuard::StopValue => "stop_value",
        OvermergeGuard::CardinalityCeiling => "cardinality_ceiling",
    }
}

/// Remove raw event payloads from a result. Used for the long-lived dedup
/// sample and, when `strip_event` is set, for pass-through results, so the
/// layer can fingerprint and group on `event.*` without emitting full events.
pub fn strip_event_payloads(result: &mut EvaluationResult) {
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

    fn run(
        p: &AlertPipeline,
        ip: &str,
        level: Level,
        state: &mut AlertPipelineState,
        now: i64,
    ) -> ProcessResult {
        p.process(vec![detection(ip, level)], state, now, &NoopMetrics)
    }

    #[test]
    fn dedup_emits_first_fire_and_folds_duplicates() {
        let p = pipeline("dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\n");
        let mut st = AlertPipelineState::default();

        let first = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(first.len(), 1);
        let dup = run(&p, "10.0.0.1", Level::High, &mut st, 5);
        assert!(dup.is_empty());
    }

    #[test]
    fn out_of_scope_results_bypass_the_layer() {
        let p = pipeline("scope:\n  levels: [critical]\ndedup:\n  fingerprint: [match.SourceIp]\n");
        let mut st = AlertPipelineState::default();
        let a = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        let b = run(&p, "10.0.0.1", Level::High, &mut st, 1);
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(st.dedup.is_empty());
    }

    #[test]
    fn grouping_annotates_incident_id_and_opens_on_group_wait() {
        let p =
            pipeline("group:\n  by: [match.SourceIp]\n  group_wait: 30s\n  resolve_timeout: 1h\n");
        let mut st = AlertPipelineState::default();
        let kept = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(kept.len(), 1);
        let id = kept[0].header.enrichments.as_ref().unwrap()["incident_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!id.is_empty());

        // No incident emission before group_wait; one open emission after.
        assert!(p.tick(&mut st, 10, &NoopMetrics).incidents.is_empty());
        let out = p.tick(&mut st, 40, &NoopMetrics);
        assert_eq!(out.incidents.len(), 1);
        assert_eq!(out.incidents[0].incident_id, id);
        assert_eq!(out.incidents[0].trigger, "group_wait");
    }

    #[test]
    fn dedup_then_group_compose() {
        let p = pipeline(
            "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 0s\n",
        );
        let mut st = AlertPipelineState::default();
        // First fire: deduped (passes) and grouped.
        let a = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(a.len(), 1);
        assert!(
            a[0].header
                .enrichments
                .as_ref()
                .unwrap()
                .contains_key("incident_id")
        );
        // Duplicate: folded by dedup, never reaches grouping.
        let b = run(&p, "10.0.0.1", Level::High, &mut st, 1);
        assert!(b.is_empty());
        assert_eq!(
            st.incidents.len(),
            1,
            "the duplicate did not open a second incident"
        );
    }

    #[test]
    fn strip_event_drops_payload_after_grouping() {
        let p = pipeline("strip_event: true\ngroup:\n  by: [event.raw]\n  group_wait: 0s\n");
        let mut st = AlertPipelineState::default();
        let kept = run(&p, "10.0.0.1", Level::High, &mut st, 0);
        assert_eq!(kept.len(), 1);
        // Event stripped from the delivered result, but grouping still keyed
        // on event.raw (one incident opened).
        assert!(kept[0].as_detection().unwrap().event.is_none());
        assert_eq!(st.incidents.len(), 1);
    }

    #[test]
    fn inhibition_mutes_target_while_source_active() {
        let p = pipeline(
            "inhibit_rules:\n  - name: crit\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    equal: [match.SourceIp]\n    duration: 5m\n",
        );
        let mut st = AlertPipelineState::default();
        // Critical source on 10.0.0.1 passes and registers as a source.
        assert_eq!(run(&p, "10.0.0.1", Level::Critical, &mut st, 0).len(), 1);
        // High target on the same IP is inhibited (dropped).
        assert!(run(&p, "10.0.0.1", Level::High, &mut st, 1).is_empty());
        // High target on a different IP passes.
        assert_eq!(run(&p, "10.0.0.2", Level::High, &mut st, 2).len(), 1);
    }

    #[test]
    fn snapshot_round_trips_and_prunes() {
        let p = pipeline(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 1h\n  resolve_timeout: 1h\n",
        );
        let mut st = AlertPipelineState::default();
        let _ = run(&p, "10.0.0.1", Level::High, &mut st, 100);
        st.silences.add(
            Silence::build(
                SilenceSpec {
                    matchers: vec![MatcherSpec {
                        selector: "rule".to_string(),
                        op: MatchOp::Eq,
                        value: "other".to_string(),
                    }],
                    ..Default::default()
                },
                SilenceOrigin::Api,
            )
            .unwrap(),
        );
        assert_eq!(st.dedup.len(), 1);
        assert_eq!(st.incidents.len(), 1);

        // Round-trip the snapshot through JSON.
        let json = serde_json::to_string(&p.snapshot(&st)).unwrap();
        let snap: AlertPipelineSnapshot = serde_json::from_str(&json).unwrap();

        // Restore within the window: state comes back.
        let mut fresh = AlertPipelineState::default();
        assert!(p.restore(&mut fresh, snap, 200));
        assert_eq!(fresh.dedup.len(), 1, "dedup alert restored");
        assert_eq!(fresh.incidents.len(), 1, "incident restored");
        assert_eq!(
            fresh.silences.api_snapshot().len(),
            1,
            "api silence restored"
        );
        // The restored dedup alert folds a duplicate.
        assert!(run(&p, "10.0.0.1", Level::High, &mut fresh, 250).is_empty());

        // Restore far past the windows: dedup + incident are pruned.
        let snap2: AlertPipelineSnapshot =
            serde_json::from_str(&serde_json::to_string(&p.snapshot(&st)).unwrap()).unwrap();
        let mut aged = AlertPipelineState::default();
        assert!(p.restore(&mut aged, snap2, 100 + 3600 + 5));
        assert!(aged.dedup.is_empty(), "stale dedup alert pruned on restore");
        assert!(
            aged.incidents.is_empty(),
            "stale incident pruned on restore"
        );
    }

    #[test]
    fn static_silence_mutes_matching_results() {
        let p = pipeline(
            "silences:\n  - matchers:\n      - selector: match.SourceIp\n        op: \"=\"\n        value: 10.0.0.1\ndedup:\n  fingerprint: [match.SourceIp]\n",
        );
        let mut st = AlertPipelineState::default();
        st.silences.set_static(p.static_silences().to_vec());

        // 10.0.0.1 is silenced (dropped); 10.0.0.2 passes through.
        assert!(run(&p, "10.0.0.1", Level::High, &mut st, 0).is_empty());
        assert_eq!(run(&p, "10.0.0.2", Level::High, &mut st, 0).len(), 1);
        // The silenced result never entered the dedup store.
        assert_eq!(st.dedup.len(), 1);
    }

    #[derive(Default)]
    struct RecordingSink {
        admits: Vec<crate::AdmittedEvent>,
        rejects: Vec<crate::CaptureReject>,
    }

    impl crate::CaptureSink for RecordingSink {
        fn admit(&mut self, event: crate::AdmittedEvent, _now: i64) {
            self.admits.push(event);
        }
        fn reject(&mut self, reason: crate::CaptureReject) {
            self.rejects.push(reason);
        }
    }

    fn capture_pipeline() -> AlertPipeline {
        pipeline(
            "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 0s\n",
        )
    }

    #[test]
    fn capture_absent_matches_process_output() {
        let p = capture_pipeline();
        let mut with_hook = AlertPipelineState::default();
        let mut without = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        let a = p.process(
            vec![detection("10.0.0.1", Level::High)],
            &mut without,
            0,
            &NoopMetrics,
        );
        let b = p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut with_hook,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::to_value(&b).unwrap()
        );
        assert_eq!(sink.admits.len(), 1);
    }

    #[test]
    fn capture_skips_silenced_and_inhibited() {
        let p = pipeline(
            "silences:\n  - matchers:\n      - selector: match.SourceIp\n        op: \"=\"\n        value: 10.0.0.1\ninhibit_rules:\n  - name: crit\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    equal: [match.SourceIp]\n    duration: 5m\ngroup:\n  by: [match.SourceIp]\n",
        );
        let mut st = AlertPipelineState::default();
        st.silences.set_static(p.static_silences().to_vec());
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert!(
            sink.admits.is_empty(),
            "silenced result must not be captured"
        );

        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.2", Level::Critical)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 1);
        p.process_with_capture(
            vec![detection("10.0.0.2", Level::High)],
            &mut st,
            2,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(
            sink.admits.len(),
            1,
            "inhibited result must not be captured"
        );
    }

    #[test]
    fn capture_sees_repeats_before_dedup() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 2, "folded repeats are still captured");
        assert!(!sink.admits[1].is_fresh_generation);
    }

    #[test]
    fn capture_coalesces_matches_in_one_call() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        let mut second = detection("10.0.0.1", Level::High);
        second.header.rule_id = Some("rule-2".to_string());
        second.header.rule_title = "Other".to_string();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High), second],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 1);
        assert_eq!(sink.admits[0].matches.len(), 2);
        assert!(sink.admits[0].matches.iter().any(|m| m.rule_id == "rule-1"));
        assert!(sink.admits[0].matches.iter().any(|m| m.rule_id == "rule-2"));
    }

    #[test]
    fn capture_rejects_correlation_results() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        let correlation = EvaluationResult {
            header: RuleHeader {
                rule_title: "Corr".to_string(),
                rule_id: Some("corr-1".to_string()),
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Correlation(rsigma_eval::CorrelationBody {
                correlation_type: rsigma_parser::CorrelationType::EventCount,
                group_key: vec![],
                aggregated_value: 1.0,
                timespan_secs: 60,
                events: None,
                event_refs: None,
            }),
        };
        p.process_with_capture(vec![correlation], &mut st, 0, &NoopMetrics, Some(&mut sink));
        assert_eq!(
            sink.rejects,
            vec![crate::CaptureReject::UnsupportedResultKind]
        );
        assert!(sink.admits.is_empty());
    }

    #[test]
    fn capture_incompatibility_requires_group_by_and_dedup_coverage() {
        let no_group = pipeline("dedup:\n  fingerprint: [rule]\n");
        assert_eq!(
            no_group.capture_incompatibility(),
            Some(crate::CaptureIncompatibility::MissingGroupBy)
        );

        let entity = pipeline("group:\n  mode: entity_graph\n  entities: [match.SourceIp]\n");
        assert_eq!(
            entity.capture_incompatibility(),
            Some(crate::CaptureIncompatibility::EntityGraph)
        );

        let mismatch = pipeline("dedup:\n  fingerprint: [rule]\ngroup:\n  by: [match.SourceIp]\n");
        match mismatch.capture_incompatibility() {
            Some(crate::CaptureIncompatibility::DedupSelectorsMissing(missing)) => {
                assert_eq!(missing, vec!["match.SourceIp".to_string()]);
            }
            other => panic!("expected missing selectors, got {other:?}"),
        }

        assert!(capture_pipeline().capture_incompatibility().is_none());
    }

    #[test]
    fn capture_refuses_when_incident_store_is_full() {
        let p = pipeline("group:\n  by: [match.SourceIp]\n  caps:\n    max_open_incidents: 1\n");
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        p.process_with_capture(
            vec![detection("10.0.0.2", Level::High)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert_eq!(sink.admits.len(), 1);
        assert_eq!(sink.rejects, vec![crate::CaptureReject::NotAssignable]);
    }

    #[test]
    fn capture_fresh_generation_when_incident_is_not_open() {
        let p = capture_pipeline();
        let mut st = AlertPipelineState::default();
        let mut sink = RecordingSink::default();
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            0,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert!(sink.admits[0].is_fresh_generation);
        p.process_with_capture(
            vec![detection("10.0.0.1", Level::High)],
            &mut st,
            1,
            &NoopMetrics,
            Some(&mut sink),
        );
        assert!(!sink.admits[1].is_fresh_generation);
    }
}
