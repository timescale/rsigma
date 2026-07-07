use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Instant;

use arc_swap::ArcSwap;
use rsigma_eval::{
    Event, FieldObserver, JsonEvent, ProcessResult, ProcessResultExt, RuleFieldSet, SchemaObserver,
};

use crate::engine::RuntimeEngine;
use crate::input::{EventInputDecoded, InputFormat, parse_line};
use crate::metrics::MetricsHook;
use crate::tap::{TapPayload, TapRegistry, TapStage};

/// Closure that extracts multiple payloads from a single JSON value.
///
/// Used by the daemon's event filter (e.g. jq/jsonpath) to explode a JSON
/// object into sub-events (e.g. `.records[]`). Only applies to JSON input.
pub type EventFilter = dyn Fn(&serde_json::Value) -> Vec<serde_json::Value>;

/// Thread-safe handle to the engine, swappable atomically for hot-reload.
///
/// Uses `ArcSwap<Mutex<RuntimeEngine>>` so that:
/// - Detection + correlation processing can acquire `&mut RuntimeEngine` via
///   the inner `Mutex`.
/// - Hot-reload swaps the entire engine atomically without blocking in-flight
///   batches (they hold an `Arc` to the old engine until their batch completes).
pub struct LogProcessor {
    engine: Arc<ArcSwap<Mutex<RuntimeEngine>>>,
    metrics: Arc<dyn MetricsHook>,
    /// Optional opt-in field observer. When `Some`, every parsed event
    /// flowing through `process_batch_with_format` has its field keys
    /// recorded. When `None`, the batch path skips iteration entirely
    /// so the hot path stays untouched.
    field_observer: ArcSwap<Option<Arc<FieldObserver>>>,
    /// Optional opt-in schema observer. When `Some`, every parsed event
    /// flowing through `process_batch_with_format` is classified and tallied
    /// per schema. When `None`, the batch path skips classification entirely
    /// so the hot path stays untouched.
    schema_observer: ArcSwap<Option<Arc<SchemaObserver>>>,
    /// Optional live event tap. When `Some`, `process_batch_with_format`
    /// offers raw lines and/or decoded events to any active capture
    /// sessions with a non-blocking `try_send`. When `None` (or when no
    /// session is active), the hot path performs one `ArcSwap` load and
    /// skips capture entirely.
    event_tap: ArcSwap<Option<Arc<TapRegistry>>>,
}

impl LogProcessor {
    /// Create a new processor wrapping the given engine and metrics hook.
    pub fn new(engine: RuntimeEngine, metrics: Arc<dyn MetricsHook>) -> Self {
        LogProcessor {
            engine: Arc::new(ArcSwap::from_pointee(Mutex::new(engine))),
            metrics,
            field_observer: ArcSwap::new(Arc::new(None)),
            schema_observer: ArcSwap::new(Arc::new(None)),
            event_tap: ArcSwap::new(Arc::new(None)),
        }
    }

    /// Attach (or detach) the opt-in field observer.
    ///
    /// When set, [`process_batch_with_format`](Self::process_batch_with_format)
    /// records each parsed event's field keys before evaluation. Pass
    /// `None` to disable observation; the hot path then performs zero
    /// extra work. Safe to call at runtime: the swap is wait-free, and
    /// in-flight batches finish against whichever observer they read.
    pub fn set_field_observer(&self, observer: Option<Arc<FieldObserver>>) {
        self.field_observer.store(Arc::new(observer));
    }

    /// Return the currently-attached field observer, if any.
    pub fn field_observer(&self) -> Option<Arc<FieldObserver>> {
        self.field_observer.load_full().as_ref().clone()
    }

    /// Attach (or detach) the opt-in schema observer.
    ///
    /// When set, [`process_batch_with_format`](Self::process_batch_with_format)
    /// classifies each parsed event before evaluation. Pass `None` to disable
    /// classification; the hot path then performs zero extra work. Safe to
    /// call at runtime: the swap is wait-free, and in-flight batches finish
    /// against whichever observer they read.
    pub fn set_schema_observer(&self, observer: Option<Arc<SchemaObserver>>) {
        self.schema_observer.store(Arc::new(observer));
    }

    /// Return the currently-attached schema observer, if any.
    pub fn schema_observer(&self) -> Option<Arc<SchemaObserver>> {
        self.schema_observer.load_full().as_ref().clone()
    }

    /// Attach (or detach) the live event tap.
    ///
    /// When set, [`process_batch_with_format`](Self::process_batch_with_format)
    /// offers raw lines and decoded events to the registry's active capture
    /// sessions. Pass `None` to disable the tap; the hot path then performs a
    /// single `ArcSwap` load and skips capture. Safe to call at runtime: the
    /// swap is wait-free, and in-flight batches finish against whichever
    /// registry they read.
    pub fn set_event_tap(&self, tap: Option<Arc<TapRegistry>>) {
        self.event_tap.store(Arc::new(tap));
    }

    /// Return the currently-attached event tap registry, if any.
    pub fn event_tap(&self) -> Option<Arc<TapRegistry>> {
        self.event_tap.load_full().as_ref().clone()
    }

    /// Atomically replace the engine with a new one.
    ///
    /// In-flight batches continue against the old engine (they hold an `Arc`
    /// snapshot). New batches see the replacement on their next call to
    /// `process_batch_lines`.
    pub fn swap_engine(&self, new_engine: RuntimeEngine) {
        self.engine.store(Arc::new(Mutex::new(new_engine)));
    }

    /// Load a snapshot of the current engine for use during reload.
    ///
    /// The caller can lock the returned guard to export state, build a new
    /// engine, import state, and then call `swap_engine`.
    pub fn engine_snapshot(&self) -> arc_swap::Guard<Arc<Mutex<RuntimeEngine>>> {
        self.engine.load()
    }

    /// Process a batch of raw input lines through the engine.
    ///
    /// 1. Parses each line as JSON; on error, increments parse error metrics.
    /// 2. Applies the `event_filter` closure to extract payloads.
    /// 3. Evaluates all payloads via `RuntimeEngine::process_batch`.
    /// 4. Merges per-payload results back into per-line results.
    /// 5. Updates metrics (events processed, latency, match counts).
    ///
    /// Returns one `ProcessResult` per input line.
    pub fn process_batch_lines(
        &self,
        batch: &[String],
        event_filter: &EventFilter,
    ) -> Vec<ProcessResult> {
        let engine_guard = self.engine.load();
        let mut engine = engine_guard.lock();

        // Phase 1: Parse JSON and apply event filters, tracking line origin.
        let mut parsed: Vec<(usize, Vec<serde_json::Value>)> = Vec::with_capacity(batch.len());
        for (line_idx, line) in batch.iter().enumerate() {
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => {
                    let payloads = event_filter(&value);
                    if !payloads.is_empty() {
                        parsed.push((line_idx, payloads));
                    }
                }
                Err(e) => {
                    self.metrics.on_parse_error();
                    tracing::debug!(error = %e, "Invalid JSON on input");
                }
            }
        }

        // Flatten: (line_idx, &Value) for each payload across all lines
        let mut flat: Vec<(usize, &serde_json::Value)> = Vec::new();
        for (line_idx, payloads) in &parsed {
            for payload in payloads {
                flat.push((*line_idx, payload));
            }
        }

        if flat.is_empty() {
            return empty_results(batch.len());
        }

        // Phase 2: Batch evaluation — parallel detection + sequential correlation
        let events: Vec<JsonEvent> = flat.iter().map(|(_, v)| JsonEvent::borrow(v)).collect();
        let event_refs: Vec<&JsonEvent> = events.iter().collect();

        let start = Instant::now();
        let batch_results = engine.process_batch(&event_refs);
        let elapsed = start.elapsed().as_secs_f64();
        let per_event_latency = elapsed / event_refs.len() as f64;

        // Update correlation state metrics while we still hold the lock
        let stats = engine.stats();
        self.metrics
            .set_correlation_state_entries(stats.state_entries as u64);

        // Phase 3: Merge results per input line and update metrics
        let mut line_results = empty_results(batch.len());

        for ((line_idx, _), result) in flat.iter().zip(batch_results) {
            self.metrics.on_events_processed(1);
            self.metrics.observe_processing_latency(per_event_latency);
            self.metrics
                .on_detection_matches(result.detection_count() as u64);
            self.metrics
                .on_correlation_matches(result.correlation_count() as u64);

            for r in &result {
                let level_str = r.header.level.as_ref().map_or("unknown", |l| l.as_str());
                let title = &r.header.rule_title;
                match &r.body {
                    rsigma_eval::ResultBody::Detection(_) => {
                        self.metrics.on_detection_match_detail(title, level_str);
                    }
                    rsigma_eval::ResultBody::Correlation(body) => {
                        self.metrics.on_correlation_match_detail(
                            title,
                            level_str,
                            body.correlation_type.as_str(),
                        );
                    }
                }
            }

            line_results[*line_idx].extend(result);
        }

        line_results
    }

    /// Process a batch of raw input lines using the specified input format.
    ///
    /// Unlike [`process_batch_lines`](Self::process_batch_lines), this method
    /// supports all input formats (JSON, syslog, plain, logfmt, CEF). The
    /// `event_filter` only applies to JSON-decoded events (it extracts multiple
    /// payloads from one JSON object, e.g. a `records[]` array). Non-JSON
    /// formats produce exactly one event per line.
    ///
    /// Returns one `ProcessResult` per input line.
    pub fn process_batch_with_format(
        &self,
        batch: &[String],
        format: &InputFormat,
        event_filter: Option<&EventFilter>,
    ) -> Vec<ProcessResult> {
        let engine_guard = self.engine.load();
        let mut engine = engine_guard.lock();

        // Live event tap: load the active-session snapshot once for the whole
        // batch. Cheap when disabled (one `ArcSwap` load plus an `Option`
        // check); the guard is held through the line and event loops below.
        let tap_guard = self.event_tap.load();
        let tap_sessions = tap_guard
            .as_ref()
            .as_ref()
            .map(|reg| reg.sessions_snapshot());
        let tap_has_raw = tap_sessions
            .as_ref()
            .is_some_and(|s| s.iter().any(|x| x.stage == TapStage::Raw));
        let tap_has_decoded = tap_sessions
            .as_ref()
            .is_some_and(|s| s.iter().any(|x| x.stage == TapStage::Decoded));

        // Phase 1: Parse each line into decoded events, tracking line origin.
        // For JSON with an event_filter, one line can produce multiple events.
        let mut decoded_events: Vec<(usize, EventInputDecoded)> = Vec::with_capacity(batch.len());

        for (line_idx, line) in batch.iter().enumerate() {
            // Raw-stage tap runs before parsing so a non-redacting raw capture
            // records every non-empty line, including ones that fail to parse.
            if tap_has_raw
                && !line.trim().is_empty()
                && let Some(sessions) = tap_sessions.as_ref()
            {
                for s in sessions.iter().filter(|s| s.stage == TapStage::Raw) {
                    s.offer(TapPayload::Raw(line.clone()));
                }
            }

            let Some(decoded) = parse_line(line, format) else {
                if !line.trim().is_empty() {
                    self.metrics.on_parse_error();
                    tracing::debug!("Failed to parse input line");
                }
                continue;
            };

            // For JSON events with an event filter, apply the filter which
            // may produce multiple payloads (e.g. `.records[]`).
            if let Some(filter) = event_filter
                && let EventInputDecoded::Json(ref json_event) = decoded
            {
                let json_value = json_event.to_json();
                let payloads = filter(&json_value);
                for payload in payloads {
                    decoded_events
                        .push((line_idx, EventInputDecoded::Json(JsonEvent::owned(payload))));
                }
                continue;
            }

            decoded_events.push((line_idx, decoded));
        }

        if decoded_events.is_empty() {
            return empty_results(batch.len());
        }

        // Optional opt-in field observation. Cheap when disabled: one
        // hazard-pointer `Guard` (no Arc clone) plus an `Option` check.
        // When enabled, walks each decoded event's field keys before
        // evaluation. The Guard's lifetime extends through the loop so
        // the observer cannot be dropped mid-batch even if the daemon
        // detaches it concurrently.
        let observer_guard = self.field_observer.load();
        if let Some(observer) = observer_guard.as_ref() {
            for (_, decoded) in &decoded_events {
                observer.observe(decoded);
            }
        }
        drop(observer_guard);

        // Optional opt-in schema observation, with the same cheap-when-disabled
        // discipline as the field observer above.
        let schema_guard = self.schema_observer.load();
        if let Some(observer) = schema_guard.as_ref() {
            for (_, decoded) in &decoded_events {
                observer.observe(decoded);
            }
        }
        drop(schema_guard);

        // Decoded-stage tap: offer each decoded event (post-parse,
        // post-event-filter) to active decoded-stage sessions. The event is
        // serialized to JSON only when at least one decoded session is active.
        if tap_has_decoded && let Some(sessions) = tap_sessions.as_ref() {
            for (_, decoded) in &decoded_events {
                let value = decoded.to_json();
                for s in sessions.iter().filter(|s| s.stage == TapStage::Decoded) {
                    s.offer(TapPayload::Decoded(Box::new(value.clone())));
                }
            }
        }

        // Phase 2: Batch evaluation — parallel detection + sequential correlation
        let event_refs: Vec<&EventInputDecoded> = decoded_events.iter().map(|(_, e)| e).collect();

        let start = Instant::now();
        let batch_results = engine.process_batch(&event_refs);
        let elapsed = start.elapsed().as_secs_f64();
        let per_event_latency = elapsed / event_refs.len() as f64;

        let stats = engine.stats();
        self.metrics
            .set_correlation_state_entries(stats.state_entries as u64);

        // Phase 3: Merge results per input line and update metrics
        let mut line_results = empty_results(batch.len());

        for ((line_idx, _), result) in decoded_events.iter().zip(batch_results) {
            self.metrics.on_events_processed(1);
            self.metrics.observe_processing_latency(per_event_latency);
            self.metrics
                .on_detection_matches(result.detection_count() as u64);
            self.metrics
                .on_correlation_matches(result.correlation_count() as u64);

            for r in &result {
                let level_str = r.header.level.as_ref().map_or("unknown", |l| l.as_str());
                let title = &r.header.rule_title;
                match &r.body {
                    rsigma_eval::ResultBody::Detection(_) => {
                        self.metrics.on_detection_match_detail(title, level_str);
                    }
                    rsigma_eval::ResultBody::Correlation(body) => {
                        self.metrics.on_correlation_match_detail(
                            title,
                            level_str,
                            body.correlation_type.as_str(),
                        );
                    }
                }
            }

            line_results[*line_idx].extend(result);
        }

        line_results
    }

    /// Reload rules (and pipelines) without blocking in-flight event processing.
    ///
    /// Builds a fresh `RuntimeEngine` with the same configuration as the
    /// current one, re-reads pipeline files from disk (if paths are set),
    /// loads rules into it, imports the old engine's correlation state, and
    /// atomically swaps. In-flight batches that already hold an `Arc` to
    /// the old engine finish undisturbed.
    ///
    /// If pipeline or rule loading fails, the old engine remains active.
    pub fn reload_rules(&self) -> Result<crate::engine::EngineStats, String> {
        // Snapshot the old engine's configuration AND tuning so the
        // replacement reaches `load_rules()` with the same flags. Daemon
        // startup typically sets `set_bloom_prefilter`/`set_bloom_max_bytes`
        // (and `set_cross_rule_ac` behind `daachorse-index`) before the
        // first load; carrying those across the swap keeps hot-reload from
        // silently undoing them.
        let snapshot = self.engine.load();
        let old = snapshot.lock();
        let old_state = old.export_state();
        let rules_path = old.rules_path().to_path_buf();
        let pipelines = old.pipelines().to_vec();
        let pipeline_paths = old.pipeline_paths().to_vec();
        let corr_config = old.corr_config().clone();
        let include_event = old.include_event();
        let resolver = old.source_resolver().cloned();
        let external_sources = old.external_sources().to_vec();
        let allow_remote_include = old.allow_remote_include();
        let bloom_prefilter = old.bloom_prefilter();
        let bloom_max_bytes = old.bloom_max_bytes();
        let match_detail = old.match_detail();
        let routing = old.routing();
        let logsource_extractor = old.logsource_extractor();
        #[cfg(feature = "daachorse-index")]
        let cross_rule_ac = old.cross_rule_ac();
        drop(old);
        drop(snapshot);

        let mut new_engine = RuntimeEngine::new(rules_path, pipelines, corr_config, include_event);
        new_engine.set_pipeline_paths(pipeline_paths);
        new_engine.set_allow_remote_include(allow_remote_include);
        new_engine.set_match_detail(match_detail);
        new_engine.set_bloom_prefilter(bloom_prefilter);
        if let Some(budget) = bloom_max_bytes {
            new_engine.set_bloom_max_bytes(budget);
        }
        #[cfg(feature = "daachorse-index")]
        new_engine.set_cross_rule_ac(cross_rule_ac);
        if let Some(resolver) = resolver {
            new_engine.set_source_resolver(resolver);
        }
        new_engine.set_external_sources(external_sources);
        // Carry the schema-routing spec so hot-reload rebuilds the router
        // instead of silently dropping back to a single engine.
        new_engine.set_routing(routing);
        // Carry the logsource extractor so pruning survives hot-reload.
        new_engine.set_logsource_extractor(logsource_extractor);
        let stats = new_engine.load_rules()?;

        if let Some(state) = old_state
            && !new_engine.import_state(&state)
        {
            tracing::warn!(
                "Incompatible correlation snapshot version during reload, starting fresh"
            );
        }

        self.swap_engine(new_engine);
        Ok(stats)
    }

    /// Return the rules path from the current engine.
    pub fn rules_path(&self) -> std::path::PathBuf {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.rules_path().to_path_buf()
    }

    /// Return a reference to the metrics hook.
    pub fn metrics(&self) -> &dyn MetricsHook {
        &*self.metrics
    }

    /// Export correlation state from the current engine.
    pub fn export_state(&self) -> Option<rsigma_eval::CorrelationSnapshot> {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.export_state()
    }

    /// Import correlation state into the current engine.
    pub fn import_state(&self, snapshot: &rsigma_eval::CorrelationSnapshot) -> bool {
        let guard = self.engine.load();
        let mut engine = guard.lock();
        engine.import_state(snapshot)
    }

    /// Return summary statistics about the current engine.
    pub fn stats(&self) -> crate::engine::EngineStats {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.stats()
    }

    /// Read-only snapshot of the correlation window state, filtered by
    /// correlation id and/or group-key substring. Holds the engine lock only
    /// for the projection. `None` for a detection-only engine.
    pub fn introspect_correlations(
        &self,
        id: Option<&str>,
        group: Option<&str>,
    ) -> Option<rsigma_eval::CorrelationStateSnapshot> {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.introspect_correlations(id, group)
    }

    /// Total rule candidates pruned by logsource on the current engine.
    pub fn logsource_pruned_total(&self) -> u64 {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.logsource_pruned_total()
    }

    /// Total evaluate calls with no extractable event logsource (fail-open).
    pub fn logsource_absent_total(&self) -> u64 {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.logsource_absent_total()
    }

    /// Static per-schema logsource pruning summary on the current engine.
    /// Empty unless schema routing and logsource routing are both enabled.
    pub fn schema_pruning_summary(&self) -> Vec<rsigma_eval::SchemaPruning> {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.schema_pruning_summary()
    }

    /// Return an immutable snapshot of the current rule field set
    /// (post-pipeline). The lock is held only long enough to clone the
    /// `Arc`; the returned value remains valid across reloads.
    pub fn rule_field_set(&self) -> Arc<RuleFieldSet> {
        let snapshot = self.engine.load();
        let engine = snapshot.lock();
        engine.rule_field_set()
    }
}

/// Produce a vec of empty `ProcessResult`, one per input line.
fn empty_results(count: usize) -> Vec<ProcessResult> {
    (0..count).map(|_| ProcessResult::new()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::NoopMetrics;
    use rsigma_eval::CorrelationConfig;

    fn identity_filter(v: &serde_json::Value) -> Vec<serde_json::Value> {
        vec![v.clone()]
    }

    fn make_processor(rules_yaml: &str) -> LogProcessor {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(&rule_path, rules_yaml).unwrap();

        let mut engine = RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
        engine.load_rules().unwrap();
        // Leak the tempdir so the path stays valid
        std::mem::forget(dir);
        LogProcessor::new(engine, Arc::new(NoopMetrics))
    }

    #[test]
    fn process_batch_lines_valid_json() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec![
            r#"{"EventID": 1}"#.to_string(),
            r#"{"EventID": 2}"#.to_string(),
        ];
        let results = proc.process_batch_lines(&batch, &identity_filter);
        assert_eq!(results.len(), 2);
        assert!(results[0].detection_count() > 0, "EventID=1 should match");
        assert!(
            results[1].detection_count() == 0,
            "EventID=2 should not match"
        );
    }

    #[test]
    fn process_batch_lines_invalid_json() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec!["not json".to_string(), r#"{"EventID": 1}"#.to_string()];
        let results = proc.process_batch_lines(&batch, &identity_filter);
        assert_eq!(results.len(), 2);
        assert!(
            results[0].detection_count() == 0,
            "invalid JSON produces empty result"
        );
        assert!(results[1].detection_count() > 0, "valid line still matches");
    }

    #[test]
    fn swap_engine_replaces_rules() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        )
        .unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            vec![],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

        let batch = vec![r#"{"EventID": 1}"#.to_string()];
        assert!(proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() > 0);

        // Swap to a rule that matches EventID: 99
        std::fs::write(
            &rule_path,
            r#"
title: Rule B
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 99
    condition: selection
"#,
        )
        .unwrap();

        let mut new_engine =
            RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
        new_engine.load_rules().unwrap();
        proc.swap_engine(new_engine);

        assert!(proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() == 0);

        let batch2 = vec![r#"{"EventID": 99}"#.to_string()];
        assert!(proc.process_batch_lines(&batch2, &identity_filter)[0].detection_count() > 0);

        std::mem::forget(dir);
    }

    #[test]
    fn reload_rules_preserves_bloom_tuning() {
        // Daemon startup typically calls `set_bloom_prefilter(true)` and
        // friends on the initial RuntimeEngine. Previously, `reload_rules`
        // rebuilt a fresh RuntimeEngine via `RuntimeEngine::new`, which
        // resets those flags to defaults; the daemon then silently lost
        // bloom pre-filtering on the first hot-reload. This test pins the
        // fix by checking the underlying engine's setters after reload.
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        )
        .unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            vec![],
            CorrelationConfig::default(),
            false,
        );
        engine.set_bloom_prefilter(true);
        engine.set_bloom_max_bytes(2 * 1024 * 1024);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(true);
        engine.load_rules().unwrap();

        let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));
        proc.reload_rules().unwrap();

        let snapshot = proc.engine_snapshot();
        let reloaded = snapshot.lock();
        assert!(
            reloaded.bloom_prefilter(),
            "bloom_prefilter must survive reload_rules"
        );
        assert_eq!(
            reloaded.bloom_max_bytes(),
            Some(2 * 1024 * 1024),
            "bloom_max_bytes must survive reload_rules"
        );
        #[cfg(feature = "daachorse-index")]
        assert!(
            reloaded.cross_rule_ac(),
            "cross_rule_ac must survive reload_rules"
        );

        std::mem::forget(dir);
    }

    #[test]
    fn reload_rules_preserves_engine() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        )
        .unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            vec![],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

        let batch = vec![r#"{"EventID": 1}"#.to_string()];
        assert!(proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() > 0);

        // Update the rule file and reload
        std::fs::write(
            &rule_path,
            r#"
title: Rule B
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 42
    condition: selection
"#,
        )
        .unwrap();

        let stats = proc.reload_rules().unwrap();
        assert_eq!(stats.detection_rules, 1);

        // Old rule should no longer match
        assert!(proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() == 0);
        // New rule should match
        let batch2 = vec![r#"{"EventID": 42}"#.to_string()];
        assert!(proc.process_batch_lines(&batch2, &identity_filter)[0].detection_count() > 0);

        std::mem::forget(dir);
    }

    #[test]
    fn reload_re_reads_pipelines_from_disk() {
        let dir = tempfile::tempdir().unwrap();

        // Rule uses the generic Sigma field name "SourceIP".
        // The pipeline maps it to what the events actually contain.
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        SourceIP: "10.0.0.1"
    condition: selection
"#,
        )
        .unwrap();

        // Pipeline maps the rule's SourceIP field to "src_ip" (event field)
        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(
            &pipeline_path,
            r#"
name: Initial Pipeline
priority: 10
transformations:
  - id: rename_field
    type: field_name_mapping
    mapping:
      SourceIP: src_ip
"#,
        )
        .unwrap();

        let pipelines = vec![rsigma_eval::parse_pipeline_file(&pipeline_path).unwrap()];
        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            pipelines,
            CorrelationConfig::default(),
            false,
        );
        engine.set_pipeline_paths(vec![pipeline_path.clone()]);
        engine.load_rules().unwrap();
        let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

        // Event uses "src_ip" which the pipeline mapped from SourceIP
        let batch = vec![r#"{"src_ip": "10.0.0.1"}"#.to_string()];
        assert!(
            proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() > 0,
            "src_ip should match because pipeline mapped SourceIP -> src_ip"
        );

        // Update pipeline to map SourceIP to a different event field name
        std::fs::write(
            &pipeline_path,
            r#"
name: Updated Pipeline
priority: 10
transformations:
  - id: rename_field
    type: field_name_mapping
    mapping:
      SourceIP: source.ip
"#,
        )
        .unwrap();

        proc.reload_rules().unwrap();

        // src_ip no longer the target, should not match
        assert!(
            proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() == 0,
            "after pipeline reload, src_ip should no longer match"
        );

        // source.ip is now the mapped name, should match
        let batch2 = vec![r#"{"source.ip": "10.0.0.1"}"#.to_string()];
        assert!(
            proc.process_batch_lines(&batch2, &identity_filter)[0].detection_count() > 0,
            "after pipeline reload, source.ip should match"
        );

        std::mem::forget(dir);
    }

    #[test]
    fn reload_with_broken_pipeline_keeps_old_engine() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        SourceIP: "10.0.0.1"
    condition: selection
"#,
        )
        .unwrap();

        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(
            &pipeline_path,
            r#"
name: Working Pipeline
priority: 10
transformations:
  - id: rename_field
    type: field_name_mapping
    mapping:
      SourceIP: src_ip
"#,
        )
        .unwrap();

        let pipelines = vec![rsigma_eval::parse_pipeline_file(&pipeline_path).unwrap()];
        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            pipelines,
            CorrelationConfig::default(),
            false,
        );
        engine.set_pipeline_paths(vec![pipeline_path.clone()]);
        engine.load_rules().unwrap();
        let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

        // Verify initial state works (SourceIP mapped to src_ip)
        let batch = vec![r#"{"src_ip": "10.0.0.1"}"#.to_string()];
        assert!(proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() > 0);

        // Write broken YAML to the pipeline file
        std::fs::write(&pipeline_path, "{{{{ invalid yaml !!!!").unwrap();

        // Reload should fail
        let result = proc.reload_rules();
        assert!(result.is_err(), "reload with broken pipeline should fail");

        // Old engine should still be active and working
        assert!(
            proc.process_batch_lines(&batch, &identity_filter)[0].detection_count() > 0,
            "old engine should still work after failed reload"
        );

        std::mem::forget(dir);
    }

    #[test]
    fn custom_event_filter() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        // Filter that extracts a nested "records" array
        let filter = |v: &serde_json::Value| -> Vec<serde_json::Value> {
            if let Some(records) = v.get("records").and_then(|r| r.as_array()) {
                records.clone()
            } else {
                vec![v.clone()]
            }
        };

        let batch = vec![r#"{"records": [{"EventID": 1}, {"EventID": 2}]}"#.to_string()];
        let results = proc.process_batch_lines(&batch, &filter);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].detection_count(),
            1,
            "only EventID=1 from records array should match"
        );
    }

    #[test]
    fn empty_batch_returns_empty() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch: Vec<String> = vec![];
        let results = proc.process_batch_lines(&batch, &identity_filter);
        assert!(results.is_empty());
    }

    /// Verify MetricsHook is called correctly during processing.
    #[test]
    fn metrics_hook_invocations() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CountingMetrics {
            parse_errors: AtomicU64,
            events_processed: AtomicU64,
            detection_matches: AtomicU64,
        }

        impl MetricsHook for CountingMetrics {
            fn on_parse_error(&self) {
                self.parse_errors.fetch_add(1, Ordering::Relaxed);
            }
            fn on_events_processed(&self, count: u64) {
                self.events_processed.fetch_add(count, Ordering::Relaxed);
            }
            fn on_detection_matches(&self, count: u64) {
                self.detection_matches.fetch_add(count, Ordering::Relaxed);
            }
            fn on_correlation_matches(&self, _: u64) {}
            fn observe_processing_latency(&self, _: f64) {}
            fn on_input_queue_depth_change(&self, _: i64) {}
            fn on_back_pressure(&self) {}
            fn observe_batch_size(&self, _: u64) {}
            fn on_output_queue_depth_change(&self, _: i64) {}
            fn observe_pipeline_latency(&self, _: f64) {}
            fn set_correlation_state_entries(&self, _: u64) {}
        }

        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        )
        .unwrap();

        let mut engine = RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
        engine.load_rules().unwrap();

        let metrics = Arc::new(CountingMetrics {
            parse_errors: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
            detection_matches: AtomicU64::new(0),
        });
        let proc = LogProcessor::new(engine, metrics.clone());

        let batch = vec![
            "not json".to_string(),
            r#"{"EventID": 1}"#.to_string(),
            r#"{"EventID": 2}"#.to_string(),
        ];
        proc.process_batch_lines(&batch, &identity_filter);

        assert_eq!(metrics.parse_errors.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.events_processed.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.detection_matches.load(Ordering::Relaxed), 1);

        std::mem::forget(dir);
    }

    /// Verify concurrent processing and swap don't panic (basic thread safety).
    #[test]
    fn concurrent_swap_and_process() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("test.yml");
        std::fs::write(
            &rule_path,
            r#"
title: Rule A
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        )
        .unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path.clone(),
            vec![],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        let proc = Arc::new(LogProcessor::new(engine, Arc::new(NoopMetrics)));

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let proc = proc.clone();
                let rule_path = rule_path.clone();
                std::thread::spawn(move || {
                    let batch = vec![r#"{"EventID": 1}"#.to_string()];
                    for _ in 0..100 {
                        let _ = proc.process_batch_lines(&batch, &identity_filter);
                    }
                    // Thread 0 does a swap mid-flight
                    if i == 0 {
                        let mut new_engine = RuntimeEngine::new(
                            rule_path,
                            vec![],
                            CorrelationConfig::default(),
                            false,
                        );
                        new_engine.load_rules().unwrap();
                        proc.swap_engine(new_engine);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        std::mem::forget(dir);
    }

    // --- Tests for process_batch_with_format ---

    #[test]
    fn format_json_matches() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec![r#"{"EventID": 1}"#.to_string()];
        let results = proc.process_batch_with_format(&batch, &InputFormat::Json, None);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].detection_count() > 0,
            "JSON EventID=1 should match"
        );
    }

    #[test]
    fn format_syslog_extracts_fields() {
        let proc = make_processor(
            r#"
title: Syslog Test
status: test
logsource:
    category: test
detection:
    selection:
        hostname: mymachine
    condition: selection
"#,
        );

        let batch = vec!["<34>Oct 11 22:14:15 mymachine su: test message".to_string()];
        let results = proc.process_batch_with_format(
            &batch,
            &InputFormat::Syslog(crate::input::SyslogConfig::default()),
            None,
        );
        assert_eq!(results.len(), 1);
        assert!(
            results[0].detection_count() > 0,
            "syslog hostname=mymachine should match"
        );
    }

    #[test]
    fn format_plain_keyword_match() {
        let proc = make_processor(
            r#"
title: Keyword Test
status: test
logsource:
    category: test
detection:
    keywords:
        - "disk full"
    condition: keywords
"#,
        );

        let batch = vec!["ERROR: disk full on /dev/sda1".to_string()];
        let results = proc.process_batch_with_format(&batch, &InputFormat::Plain, None);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].detection_count() > 0,
            "plain keyword 'disk full' should match"
        );
    }

    #[test]
    fn format_auto_detects_json() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec![r#"{"EventID": 1}"#.to_string()];
        let results = proc.process_batch_with_format(&batch, &InputFormat::default(), None);
        assert_eq!(results.len(), 1);
        assert!(results[0].detection_count() > 0);
    }

    #[test]
    fn format_json_with_event_filter() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let filter = |v: &serde_json::Value| -> Vec<serde_json::Value> {
            if let Some(records) = v.get("records").and_then(|r| r.as_array()) {
                records.clone()
            } else {
                vec![v.clone()]
            }
        };

        let batch = vec![r#"{"records": [{"EventID": 1}, {"EventID": 2}]}"#.to_string()];
        let results = proc.process_batch_with_format(&batch, &InputFormat::Json, Some(&filter));
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].detection_count(),
            1,
            "only EventID=1 from records array should match"
        );
    }

    #[test]
    fn format_empty_lines_skipped() {
        let proc = make_processor(
            r#"
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );

        let batch = vec![
            "".to_string(),
            "   ".to_string(),
            r#"{"EventID": 1}"#.to_string(),
        ];
        let results = proc.process_batch_with_format(&batch, &InputFormat::Json, None);
        assert_eq!(results.len(), 3);
        assert!(results[0].detection_count() == 0);
        assert!(results[1].detection_count() == 0);
        assert!(results[2].detection_count() > 0);
    }

    #[cfg(feature = "logfmt")]
    #[test]
    fn format_logfmt_matches() {
        let proc = make_processor(
            r#"
title: Logfmt Test
status: test
logsource:
    category: test
detection:
    selection:
        level: error
    condition: selection
"#,
        );

        let batch = vec!["level=error msg=something host=web01".to_string()];
        let results = proc.process_batch_with_format(&batch, &InputFormat::Logfmt, None);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].detection_count() > 0,
            "logfmt level=error should match"
        );
    }

    #[cfg(feature = "cef")]
    #[test]
    fn format_cef_matches() {
        let proc = make_processor(
            r#"
title: CEF Test
status: test
logsource:
    category: test
detection:
    selection:
        deviceVendor: Security
    condition: selection
"#,
        );

        let batch = vec!["CEF:0|Security|IDS|1.0|100|Attack|9|src=10.0.0.1".to_string()];
        let results = proc.process_batch_with_format(&batch, &InputFormat::Cef, None);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].detection_count() > 0,
            "CEF deviceVendor=Security should match"
        );
    }
}
