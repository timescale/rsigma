//! Stateful correlation engine with time-windowed aggregation.
//!
//! `CorrelationEngine` wraps the stateless `Engine` and adds support for
//! Sigma correlation rules: `event_count`, `value_count`, `temporal`,
//! `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`,
//! and `value_median`.
//!
//! # Architecture
//!
//! 1. Events are first evaluated against detection rules (stateless)
//! 2. Detection matches update correlation window state (stateful)
//! 3. When a correlation condition is met, a `CorrelationResult` is emitted
//! 4. Correlation results can chain into higher-level correlations

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;

use rsigma_parser::{CorrelationRule, CorrelationType, Level, SigmaCollection, SigmaRule};

use crate::correlation::{CompiledCorrelation, GroupKey, WindowState, compile_correlation};
use crate::engine::Engine;
use crate::error::Result;
use crate::event::Event;
use crate::result::MatchResult;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the correlation engine.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Field names to try for timestamp extraction, in order of priority.
    ///
    /// The engine will try each field until one yields a parseable timestamp.
    /// If none succeed, falls back to `Utc::now()`.
    pub timestamp_fields: Vec<String>,

    /// Maximum number of state entries (across all correlations and groups)
    /// before aggressive eviction is triggered. Prevents unbounded memory growth.
    ///
    /// Default: 100_000.
    pub max_state_entries: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        CorrelationConfig {
            timestamp_fields: vec![
                "@timestamp".to_string(),
                "timestamp".to_string(),
                "EventTime".to_string(),
                "TimeCreated".to_string(),
                "eventTime".to_string(),
            ],
            max_state_entries: 100_000,
        }
    }
}

// =============================================================================
// Result types
// =============================================================================

/// Combined result from processing a single event.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessResult {
    /// Detection rule matches (stateless, immediate).
    pub detections: Vec<MatchResult>,
    /// Correlation rule matches (stateful, accumulated).
    pub correlations: Vec<CorrelationResult>,
}

/// The result of a correlation rule firing.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationResult {
    /// Title of the correlation rule.
    pub rule_title: String,
    /// ID of the correlation rule (if present).
    pub rule_id: Option<String>,
    /// Severity level.
    pub level: Option<Level>,
    /// Tags from the correlation rule.
    pub tags: Vec<String>,
    /// Type of correlation.
    pub correlation_type: CorrelationType,
    /// Group-by field names and their values for this match.
    pub group_key: Vec<(String, String)>,
    /// The aggregated value that triggered the condition (count, sum, avg, etc.).
    pub aggregated_value: f64,
    /// The time window in seconds.
    pub timespan_secs: u64,
}

// =============================================================================
// Correlation Engine
// =============================================================================

/// Stateful correlation engine.
///
/// Wraps the stateless `Engine` for detection rules and adds time-windowed
/// correlation on top. Supports all 7 Sigma correlation types and chaining.
pub struct CorrelationEngine {
    /// Inner stateless detection engine.
    engine: Engine,
    /// Compiled correlation rules.
    correlations: Vec<CompiledCorrelation>,
    /// Maps rule ID/name -> indices into `correlations` that reference it.
    /// This allows quick lookup: "which correlations care about rule X?"
    rule_index: HashMap<String, Vec<usize>>,
    /// Maps detection rule index -> (rule_id, rule_name) for reverse lookup.
    /// Used to find which correlations a detection match triggers.
    rule_ids: Vec<(Option<String>, Option<String>)>,
    /// Per-(correlation_index, group_key) window state.
    state: HashMap<(usize, GroupKey), WindowState>,
    /// Configuration.
    config: CorrelationConfig,
}

impl CorrelationEngine {
    /// Create a new correlation engine with the given configuration.
    pub fn new(config: CorrelationConfig) -> Self {
        CorrelationEngine {
            engine: Engine::new(),
            correlations: Vec::new(),
            rule_index: HashMap::new(),
            rule_ids: Vec::new(),
            state: HashMap::new(),
            config,
        }
    }

    /// Add a single detection rule.
    pub fn add_rule(&mut self, rule: &SigmaRule) -> Result<()> {
        self.rule_ids.push((rule.id.clone(), rule.name.clone()));
        self.engine.add_rule(rule)?;
        Ok(())
    }

    /// Add a single correlation rule.
    pub fn add_correlation(&mut self, corr: &CorrelationRule) -> Result<()> {
        let compiled = compile_correlation(corr)?;
        let idx = self.correlations.len();

        // Index by each referenced rule ID/name
        for rule_ref in &compiled.rule_refs {
            self.rule_index
                .entry(rule_ref.clone())
                .or_default()
                .push(idx);
        }

        self.correlations.push(compiled);
        Ok(())
    }

    /// Add all rules and correlations from a parsed collection.
    ///
    /// Detection rules are added first (so they're available for correlation
    /// references), then correlation rules.
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        for rule in &collection.rules {
            self.add_rule(rule)?;
        }
        // Apply filter rules to the inner engine's detection rules
        for filter in &collection.filters {
            self.engine.apply_filter(filter)?;
        }
        for corr in &collection.correlations {
            self.add_correlation(corr)?;
        }
        Ok(())
    }

    /// Process an event, extracting the timestamp from configured event fields.
    ///
    /// Falls back to `Utc::now()` if no timestamp field is found or parseable.
    pub fn process_event(&mut self, event: &Event) -> ProcessResult {
        let ts = self.extract_timestamp(event);
        self.process_event_at(event, ts)
    }

    /// Process an event with an explicit Unix epoch timestamp (seconds).
    pub fn process_event_at(&mut self, event: &Event, timestamp_secs: i64) -> ProcessResult {
        // Step 1: Run stateless detection
        let detections = self.engine.evaluate(event);

        // Step 2: Feed detection matches into correlations
        let mut correlations = Vec::new();
        self.feed_detections(event, &detections, timestamp_secs, &mut correlations);

        // Step 3: Chain — correlation results may trigger higher-level correlations
        self.chain_correlations(&correlations, timestamp_secs);

        // Step 4: Memory management — evict if over limit
        if self.state.len() > self.config.max_state_entries {
            self.evict_all(timestamp_secs);
        }

        ProcessResult {
            detections,
            correlations,
        }
    }

    /// Feed detection matches into correlation window states.
    fn feed_detections(
        &mut self,
        event: &Event,
        detections: &[MatchResult],
        ts: i64,
        out: &mut Vec<CorrelationResult>,
    ) {
        // Collect all (corr_idx, rule_id, rule_name) tuples upfront to avoid
        // borrow conflicts between self.rule_ids and self.update_correlation.
        let mut work: Vec<(usize, Option<String>, Option<String>)> = Vec::new();

        for det in detections {
            // Use the MatchResult's rule_id to find the original rule's ID/name.
            // We also look up by rule_id in our rule_ids table for the name.
            let (rule_id, rule_name) = self.find_rule_identity(det);

            // Collect correlation indices that reference this rule
            let mut corr_indices = Vec::new();
            if let Some(ref id) = rule_id
                && let Some(indices) = self.rule_index.get(id)
            {
                corr_indices.extend(indices);
            }
            if let Some(ref name) = rule_name
                && let Some(indices) = self.rule_index.get(name)
            {
                corr_indices.extend(indices);
            }

            corr_indices.sort_unstable();
            corr_indices.dedup();

            for &corr_idx in &corr_indices {
                work.push((corr_idx, rule_id.clone(), rule_name.clone()));
            }
        }

        for (corr_idx, rule_id, rule_name) in work {
            self.update_correlation(corr_idx, event, ts, &rule_id, &rule_name, out);
        }
    }

    /// Find the (id, name) for a detection match by searching our rule_ids table.
    fn find_rule_identity(&self, det: &MatchResult) -> (Option<String>, Option<String>) {
        // First, try to find by matching rule_id in our table
        if let Some(ref match_id) = det.rule_id {
            for (id, name) in &self.rule_ids {
                if id.as_deref() == Some(match_id.as_str()) {
                    return (id.clone(), name.clone());
                }
            }
        }
        // Fall back to using just the MatchResult's rule_id
        (det.rule_id.clone(), None)
    }

    /// Update a single correlation's state and check its condition.
    fn update_correlation(
        &mut self,
        corr_idx: usize,
        event: &Event,
        ts: i64,
        rule_id: &Option<String>,
        rule_name: &Option<String>,
        out: &mut Vec<CorrelationResult>,
    ) {
        // Read all needed data from the correlation upfront to release the
        // immutable borrow on self.correlations before mutating self.state.
        let corr_type = self.correlations[corr_idx].correlation_type;
        let timespan = self.correlations[corr_idx].timespan_secs;
        let group_by = self.correlations[corr_idx].group_by.clone();
        let condition = self.correlations[corr_idx].condition.clone();
        let extended_expr = self.correlations[corr_idx].extended_expr.clone();
        let rule_refs = self.correlations[corr_idx].rule_refs.clone();
        let title = self.correlations[corr_idx].title.clone();
        let corr_id = self.correlations[corr_idx].id.clone();
        let level = self.correlations[corr_idx].level;
        let tags = self.correlations[corr_idx].tags.clone();
        let cond_field = condition.field.clone();

        // Determine the rule_ref strings for alias resolution and temporal tracking.
        // We collect both ID and name so that alias mappings can use either.
        let mut ref_strs: Vec<&str> = Vec::new();
        if let Some(id) = rule_id.as_deref() {
            ref_strs.push(id);
        }
        if let Some(name) = rule_name.as_deref() {
            ref_strs.push(name);
        }
        let rule_ref = rule_id.as_deref().or(rule_name.as_deref()).unwrap_or("");

        // Extract group key
        let group_key = GroupKey::extract(event, &group_by, &ref_strs);

        // Get or create window state
        let state_key = (corr_idx, group_key.clone());
        let state = self
            .state
            .entry(state_key)
            .or_insert_with(|| WindowState::new_for(corr_type));

        // Evict expired entries
        let cutoff = ts - timespan as i64;
        state.evict(cutoff);

        // Push the new event into the state
        match corr_type {
            CorrelationType::EventCount => {
                state.push_event_count(ts);
            }
            CorrelationType::ValueCount => {
                if let Some(ref field_name) = cond_field
                    && let Some(val) = event.get_field(field_name)
                    && let Some(s) = value_to_string_for_count(val)
                {
                    state.push_value_count(ts, s);
                }
            }
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                state.push_temporal(ts, rule_ref);
            }
            CorrelationType::ValueSum
            | CorrelationType::ValueAvg
            | CorrelationType::ValuePercentile
            | CorrelationType::ValueMedian => {
                if let Some(ref field_name) = cond_field
                    && let Some(val) = event.get_field(field_name)
                    && let Some(n) = value_to_f64(val)
                {
                    state.push_numeric(ts, n);
                }
            }
        }

        // Check condition
        if let Some(agg_value) =
            state.check_condition(&condition, corr_type, &rule_refs, extended_expr.as_ref())
        {
            let result = CorrelationResult {
                rule_title: title,
                rule_id: corr_id,
                level,
                tags,
                correlation_type: corr_type,
                group_key: group_key.to_pairs(&group_by),
                aggregated_value: agg_value,
                timespan_secs: timespan,
            };
            out.push(result);
        }
    }

    /// Propagate correlation results to higher-level correlations (chaining).
    ///
    /// When a correlation fires, any correlation that references it (by ID or name)
    /// is updated. Limits chain depth to 10 to prevent infinite loops.
    fn chain_correlations(&mut self, fired: &[CorrelationResult], ts: i64) {
        const MAX_CHAIN_DEPTH: usize = 10;
        let mut pending: Vec<CorrelationResult> = fired.to_vec();
        let mut depth = 0;

        while !pending.is_empty() && depth < MAX_CHAIN_DEPTH {
            depth += 1;

            // Collect work items: (corr_idx, group_key_pairs, fired_ref)
            #[allow(clippy::type_complexity)]
            let mut work: Vec<(usize, Vec<(String, String)>, String)> = Vec::new();
            for result in &pending {
                if let Some(ref id) = result.rule_id
                    && let Some(indices) = self.rule_index.get(id)
                {
                    let fired_ref = result
                        .rule_id
                        .as_deref()
                        .unwrap_or(&result.rule_title)
                        .to_string();
                    for &corr_idx in indices {
                        work.push((corr_idx, result.group_key.clone(), fired_ref.clone()));
                    }
                }
            }

            let mut next_pending = Vec::new();
            for (corr_idx, group_key_pairs, fired_ref) in work {
                // Read correlation metadata (immutable borrow released before mutable)
                let corr_type = self.correlations[corr_idx].correlation_type;
                let timespan = self.correlations[corr_idx].timespan_secs;
                let group_by = self.correlations[corr_idx].group_by.clone();
                let condition = self.correlations[corr_idx].condition.clone();
                let extended_expr = self.correlations[corr_idx].extended_expr.clone();
                let rule_refs = self.correlations[corr_idx].rule_refs.clone();
                let title = self.correlations[corr_idx].title.clone();
                let id = self.correlations[corr_idx].id.clone();
                let level = self.correlations[corr_idx].level;
                let tags = self.correlations[corr_idx].tags.clone();

                let group_key = GroupKey::from_pairs(&group_key_pairs, &group_by);
                let state_key = (corr_idx, group_key.clone());
                let state = self
                    .state
                    .entry(state_key)
                    .or_insert_with(|| WindowState::new_for(corr_type));

                let cutoff = ts - timespan as i64;
                state.evict(cutoff);

                match corr_type {
                    CorrelationType::EventCount => {
                        state.push_event_count(ts);
                    }
                    CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                        state.push_temporal(ts, &fired_ref);
                    }
                    _ => {
                        state.push_event_count(ts);
                    }
                }

                if let Some(agg_value) =
                    state.check_condition(&condition, corr_type, &rule_refs, extended_expr.as_ref())
                {
                    next_pending.push(CorrelationResult {
                        rule_title: title,
                        rule_id: id,
                        level,
                        tags,
                        correlation_type: corr_type,
                        group_key: group_key.to_pairs(&group_by),
                        aggregated_value: agg_value,
                        timespan_secs: timespan,
                    });
                }
            }

            pending = next_pending;
        }
    }

    // =========================================================================
    // Timestamp extraction
    // =========================================================================

    /// Extract a Unix epoch timestamp (seconds) from an event.
    ///
    /// Tries each configured timestamp field in order. Supports:
    /// - Numeric values (epoch seconds, or epoch millis if > 1e12)
    /// - ISO 8601 strings (e.g., "2024-07-10T12:30:00Z")
    ///
    /// Falls back to `Utc::now()` if no field yields a valid timestamp.
    fn extract_timestamp(&self, event: &Event) -> i64 {
        for field_name in &self.config.timestamp_fields {
            if let Some(val) = event.get_field(field_name)
                && let Some(ts) = parse_timestamp_value(val)
            {
                return ts;
            }
        }
        Utc::now().timestamp()
    }

    // =========================================================================
    // State management
    // =========================================================================

    /// Manually evict all expired state entries.
    pub fn evict_expired(&mut self, now_secs: i64) {
        self.evict_all(now_secs);
    }

    /// Evict expired entries and remove empty states.
    fn evict_all(&mut self, now_secs: i64) {
        // For each state entry, evict based on its correlation's timespan
        let timespans: Vec<u64> = self.correlations.iter().map(|c| c.timespan_secs).collect();

        self.state.retain(|&(corr_idx, _), state| {
            if corr_idx < timespans.len() {
                let cutoff = now_secs - timespans[corr_idx] as i64;
                state.evict(cutoff);
            }
            !state.is_empty()
        });
    }

    /// Number of active state entries (for monitoring).
    pub fn state_count(&self) -> usize {
        self.state.len()
    }

    /// Number of detection rules loaded.
    pub fn detection_rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Number of correlation rules loaded.
    pub fn correlation_rule_count(&self) -> usize {
        self.correlations.len()
    }

    /// Access the inner stateless engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

// =============================================================================
// Timestamp parsing helpers
// =============================================================================

/// Parse a JSON value as a Unix epoch timestamp in seconds.
fn parse_timestamp_value(val: &serde_json::Value) -> Option<i64> {
    match val {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(normalize_epoch(i))
            } else {
                n.as_f64().map(|f| normalize_epoch(f as i64))
            }
        }
        serde_json::Value::String(s) => parse_timestamp_string(s),
        _ => None,
    }
}

/// Normalize an epoch value: if it looks like milliseconds (> year 33658),
/// convert to seconds.
fn normalize_epoch(v: i64) -> i64 {
    if v > 1_000_000_000_000 { v / 1000 } else { v }
}

/// Parse a timestamp string. Tries ISO 8601 with timezone, then without.
fn parse_timestamp_string(s: &str) -> Option<i64> {
    // Try RFC 3339 / ISO 8601 with timezone
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }

    // Try ISO 8601 without timezone (assume UTC)
    // Common formats: "2024-07-10T12:30:00", "2024-07-10 12:30:00"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }

    // Try with fractional seconds
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }

    None
}

/// Convert a JSON value to a string for value_count purposes.
fn value_to_string_for_count(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

/// Convert a JSON value to f64 for numeric aggregation.
fn value_to_f64(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    // =========================================================================
    // Timestamp parsing
    // =========================================================================

    #[test]
    fn test_parse_timestamp_epoch_secs() {
        let val = json!(1720612200);
        assert_eq!(parse_timestamp_value(&val), Some(1720612200));
    }

    #[test]
    fn test_parse_timestamp_epoch_millis() {
        let val = json!(1720612200000i64);
        assert_eq!(parse_timestamp_value(&val), Some(1720612200));
    }

    #[test]
    fn test_parse_timestamp_rfc3339() {
        let val = json!("2024-07-10T12:30:00Z");
        let ts = parse_timestamp_value(&val).unwrap();
        assert_eq!(ts, 1720614600);
    }

    #[test]
    fn test_parse_timestamp_naive() {
        let val = json!("2024-07-10T12:30:00");
        let ts = parse_timestamp_value(&val).unwrap();
        assert_eq!(ts, 1720614600);
    }

    #[test]
    fn test_parse_timestamp_with_space() {
        let val = json!("2024-07-10 12:30:00");
        let ts = parse_timestamp_value(&val).unwrap();
        assert_eq!(ts, 1720614600);
    }

    #[test]
    fn test_parse_timestamp_fractional() {
        let val = json!("2024-07-10T12:30:00.123Z");
        let ts = parse_timestamp_value(&val).unwrap();
        assert_eq!(ts, 1720614600);
    }

    #[test]
    fn test_extract_timestamp_from_event() {
        let config = CorrelationConfig {
            timestamp_fields: vec!["@timestamp".to_string()],
            max_state_entries: 100_000,
        };
        let engine = CorrelationEngine::new(config);

        let v = json!({"@timestamp": "2024-07-10T12:30:00Z", "data": "test"});
        let event = Event::from_value(&v);
        let ts = engine.extract_timestamp(&event);
        assert_eq!(ts, 1720614600);
    }

    #[test]
    fn test_extract_timestamp_fallback_fields() {
        let config = CorrelationConfig {
            timestamp_fields: vec![
                "@timestamp".to_string(),
                "timestamp".to_string(),
                "EventTime".to_string(),
            ],
            max_state_entries: 100_000,
        };
        let engine = CorrelationEngine::new(config);

        // First field missing, second field present
        let v = json!({"timestamp": 1720613400, "data": "test"});
        let event = Event::from_value(&v);
        let ts = engine.extract_timestamp(&event);
        assert_eq!(ts, 1720613400);
    }

    // =========================================================================
    // Event count correlation
    // =========================================================================

    #[test]
    fn test_event_count_basic() {
        let yaml = r#"
title: Base Rule
id: base-rule-001
name: base_rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: low
---
title: Multiple Whoami
id: corr-001
correlation:
    type: event_count
    rules:
        - base-rule-001
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        assert_eq!(engine.detection_rule_count(), 1);
        assert_eq!(engine.correlation_rule_count(), 1);

        // Send 3 events from same user within the window
        let base_ts = 1000i64;
        for i in 0..3 {
            let v = json!({"CommandLine": "whoami", "User": "admin"});
            let event = Event::from_value(&v);
            let result = engine.process_event_at(&event, base_ts + i * 10);

            // Each event should match the detection rule
            assert_eq!(result.detections.len(), 1);

            if i < 2 {
                // Not enough events yet
                assert!(result.correlations.is_empty());
            } else {
                // 3rd event triggers the correlation
                assert_eq!(result.correlations.len(), 1);
                assert_eq!(result.correlations[0].rule_title, "Multiple Whoami");
                assert_eq!(result.correlations[0].aggregated_value, 3.0);
            }
        }
    }

    #[test]
    fn test_event_count_different_groups() {
        let yaml = r#"
title: Login
id: login-001
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
level: low
---
title: Many Logins
id: corr-login
correlation:
    type: event_count
    rules:
        - login-001
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        // User "alice" sends 2 events, "bob" sends 3
        let ts = 1000i64;
        for i in 0..2 {
            let v = json!({"EventType": "login", "User": "alice"});
            let event = Event::from_value(&v);
            let r = engine.process_event_at(&event, ts + i);
            assert!(r.correlations.is_empty());
        }
        for i in 0..3 {
            let v = json!({"EventType": "login", "User": "bob"});
            let event = Event::from_value(&v);
            let r = engine.process_event_at(&event, ts + i);
            if i == 2 {
                assert_eq!(r.correlations.len(), 1);
                assert_eq!(
                    r.correlations[0].group_key,
                    vec![("User".to_string(), "bob".to_string())]
                );
            }
        }
    }

    #[test]
    fn test_event_count_window_expiry() {
        let yaml = r#"
title: Base
id: base-002
logsource:
    category: test
detection:
    selection:
        action: click
    condition: selection
---
title: Rapid Clicks
id: corr-002
correlation:
    type: event_count
    rules:
        - base-002
    group-by:
        - User
    timespan: 10s
    condition:
        gte: 3
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        // Send 2 events at t=0,1 then 1 event at t=15 (outside window)
        let v = json!({"action": "click", "User": "admin"});
        let event = Event::from_value(&v);
        engine.process_event_at(&event, 0);
        engine.process_event_at(&event, 1);
        let r = engine.process_event_at(&event, 15);
        // Only 1 event in window [5, 15], not enough
        assert!(r.correlations.is_empty());
    }

    // =========================================================================
    // Value count correlation
    // =========================================================================

    #[test]
    fn test_value_count() {
        let yaml = r#"
title: Failed Login
id: failed-login-001
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
level: low
---
title: Failed Logins From Many Users
id: corr-vc-001
correlation:
    type: value_count
    rules:
        - failed-login-001
    group-by:
        - Host
    timespan: 60s
    condition:
        field: User
        gte: 3
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // 3 different users failing login on same host
        for (i, user) in ["alice", "bob", "charlie"].iter().enumerate() {
            let v = json!({"EventType": "failed_login", "Host": "srv01", "User": user});
            let event = Event::from_value(&v);
            let r = engine.process_event_at(&event, ts + i as i64);
            if i == 2 {
                assert_eq!(r.correlations.len(), 1);
                assert_eq!(r.correlations[0].aggregated_value, 3.0);
            }
        }
    }

    // =========================================================================
    // Temporal correlation
    // =========================================================================

    #[test]
    fn test_temporal() {
        let yaml = r#"
title: Recon A
id: recon-a
name: recon_a
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Recon B
id: recon-b
name: recon_b
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
---
title: Recon Combo
id: corr-temporal
correlation:
    type: temporal
    rules:
        - recon-a
        - recon-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // Only recon A fires
        let v1 = json!({"CommandLine": "whoami", "User": "admin"});
        let ev1 = Event::from_value(&v1);
        let r1 = engine.process_event_at(&ev1, ts);
        assert!(r1.correlations.is_empty());

        // Now recon B fires — both rules have fired within window
        let v2 = json!({"CommandLine": "ipconfig /all", "User": "admin"});
        let ev2 = Event::from_value(&v2);
        let r2 = engine.process_event_at(&ev2, ts + 10);
        assert_eq!(r2.correlations.len(), 1);
        assert_eq!(r2.correlations[0].rule_title, "Recon Combo");
    }

    // =========================================================================
    // Temporal ordered correlation
    // =========================================================================

    #[test]
    fn test_temporal_ordered() {
        let yaml = r#"
title: Failed Login
id: failed-001
name: failed_login
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Success Login
id: success-001
name: successful_login
logsource:
    category: auth
detection:
    selection:
        EventType: success_login
    condition: selection
---
title: Brute Force Then Login
id: corr-bf
correlation:
    type: temporal_ordered
    rules:
        - failed-001
        - success-001
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: critical
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // Failed login first
        let v1 = json!({"EventType": "failed_login", "User": "admin"});
        let ev1 = Event::from_value(&v1);
        let r1 = engine.process_event_at(&ev1, ts);
        assert!(r1.correlations.is_empty());

        // Then successful login — correct order!
        let v2 = json!({"EventType": "success_login", "User": "admin"});
        let ev2 = Event::from_value(&v2);
        let r2 = engine.process_event_at(&ev2, ts + 10);
        assert_eq!(r2.correlations.len(), 1);
    }

    #[test]
    fn test_temporal_ordered_wrong_order() {
        let yaml = r#"
title: Rule A
id: rule-a
logsource:
    category: test
detection:
    selection:
        type: a
    condition: selection
---
title: Rule B
id: rule-b
logsource:
    category: test
detection:
    selection:
        type: b
    condition: selection
---
title: A then B
id: corr-ab
correlation:
    type: temporal_ordered
    rules:
        - rule-a
        - rule-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // B fires first, then A — wrong order
        let v1 = json!({"type": "b", "User": "admin"});
        let ev1 = Event::from_value(&v1);
        engine.process_event_at(&ev1, ts);

        let v2 = json!({"type": "a", "User": "admin"});
        let ev2 = Event::from_value(&v2);
        let r2 = engine.process_event_at(&ev2, ts + 10);
        assert!(r2.correlations.is_empty());
    }

    // =========================================================================
    // Numeric aggregation (value_sum, value_avg)
    // =========================================================================

    #[test]
    fn test_value_sum() {
        let yaml = r#"
title: Web Access
id: web-001
logsource:
    category: web
detection:
    selection:
        action: upload
    condition: selection
---
title: Large Upload
id: corr-sum
correlation:
    type: value_sum
    rules:
        - web-001
    group-by:
        - User
    timespan: 60s
    condition:
        field: bytes_sent
        gt: 1000
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        let v1 = json!({"action": "upload", "User": "alice", "bytes_sent": 600});
        let ev1 = Event::from_value(&v1);
        let r1 = engine.process_event_at(&ev1, ts);
        assert!(r1.correlations.is_empty());

        let v2 = json!({"action": "upload", "User": "alice", "bytes_sent": 500});
        let ev2 = Event::from_value(&v2);
        let r2 = engine.process_event_at(&ev2, ts + 5);
        assert_eq!(r2.correlations.len(), 1);
        assert!((r2.correlations[0].aggregated_value - 1100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_value_avg() {
        let yaml = r#"
title: Request
id: req-001
logsource:
    category: web
detection:
    selection:
        type: request
    condition: selection
---
title: High Avg Latency
id: corr-avg
correlation:
    type: value_avg
    rules:
        - req-001
    group-by:
        - Service
    timespan: 60s
    condition:
        field: latency_ms
        gt: 500
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // Avg of 400, 600, 800 = 600 > 500
        for (i, latency) in [400, 600, 800].iter().enumerate() {
            let v = json!({"type": "request", "Service": "api", "latency_ms": latency});
            let event = Event::from_value(&v);
            let r = engine.process_event_at(&event, ts + i as i64);
            if i == 2 {
                assert_eq!(r.correlations.len(), 1);
                assert!((r.correlations[0].aggregated_value - 600.0).abs() < f64::EPSILON);
            }
        }
    }

    // =========================================================================
    // State management
    // =========================================================================

    #[test]
    fn test_state_count() {
        let yaml = r#"
title: Base
id: base-sc
logsource:
    category: test
detection:
    selection:
        action: test
    condition: selection
---
title: Count
id: corr-sc
correlation:
    type: event_count
    rules:
        - base-sc
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 100
level: low
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let v = json!({"action": "test", "User": "alice"});
        let event = Event::from_value(&v);
        engine.process_event_at(&event, 1000);
        assert_eq!(engine.state_count(), 1);

        let v2 = json!({"action": "test", "User": "bob"});
        let event2 = Event::from_value(&v2);
        engine.process_event_at(&event2, 1001);
        assert_eq!(engine.state_count(), 2);

        // Evict everything
        engine.evict_expired(2000);
        assert_eq!(engine.state_count(), 0);
    }

    // =========================================================================
    // Generate flag
    // =========================================================================

    #[test]
    fn test_generate_flag_default_false() {
        let yaml = r#"
title: Base
id: gen-base
logsource:
    category: test
detection:
    selection:
        action: test
    condition: selection
---
title: Correlation
id: gen-corr
correlation:
    type: event_count
    rules:
        - gen-base
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 1
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        // generate defaults to false — detection matches are still returned
        // (filtering by generate flag is a backend concern, not eval)
        let v = json!({"action": "test", "User": "alice"});
        let event = Event::from_value(&v);
        let r = engine.process_event_at(&event, 1000);
        assert_eq!(r.detections.len(), 1);
        assert_eq!(r.correlations.len(), 1);
    }

    // =========================================================================
    // Real-world example: AWS bucket enumeration
    // =========================================================================

    #[test]
    fn test_aws_bucket_enumeration() {
        let yaml = r#"
title: Potential Bucket Enumeration on AWS
id: f305fd62-beca-47da-ad95-7690a0620084
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
        eventName: "ListBuckets"
    condition: selection
level: low
---
title: Multiple AWS bucket enumerations
id: be246094-01d3-4bba-88de-69e582eba0cc
status: experimental
correlation:
    type: event_count
    rules:
        - f305fd62-beca-47da-ad95-7690a0620084
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        gte: 5
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let base_ts = 1_700_000_000i64;
        for i in 0..5 {
            let v = json!({
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListBuckets",
                "userIdentity.arn": "arn:aws:iam::123456789:user/attacker"
            });
            let event = Event::from_value(&v);
            let r = engine.process_event_at(&event, base_ts + i * 60);
            if i == 4 {
                assert_eq!(r.correlations.len(), 1);
                assert_eq!(
                    r.correlations[0].rule_title,
                    "Multiple AWS bucket enumerations"
                );
                assert_eq!(r.correlations[0].aggregated_value, 5.0);
            }
        }
    }

    // =========================================================================
    // Chaining: event_count -> temporal_ordered
    // =========================================================================

    #[test]
    fn test_chaining_event_count_to_temporal() {
        // Reproduces the spec's "failed logins followed by successful login" example.
        // Chain: failed_login (detection) -> many_failed (event_count) -> brute_then_login (temporal_ordered)
        let yaml = r#"
title: Single failed login
id: failed-login-chain
name: failed_login
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Successful login
id: success-login-chain
name: successful_login
logsource:
    category: auth
detection:
    selection:
        EventType: success_login
    condition: selection
---
title: Multiple failed logins
id: many-failed-chain
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed-login-chain
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: medium
---
title: Brute Force Followed by Login
id: brute-force-chain
correlation:
    type: temporal_ordered
    rules:
        - many-failed-chain
        - success-login-chain
    group-by:
        - User
    timespan: 120s
    condition:
        gte: 2
level: critical
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        assert_eq!(engine.detection_rule_count(), 2);
        assert_eq!(engine.correlation_rule_count(), 2);

        let ts = 1000i64;

        // Send 3 failed logins → triggers "many_failed_chain"
        for i in 0..3 {
            let v = json!({"EventType": "failed_login", "User": "victim"});
            let event = Event::from_value(&v);
            let r = engine.process_event_at(&event, ts + i);
            if i == 2 {
                // The event_count correlation should fire
                assert!(
                    r.correlations
                        .iter()
                        .any(|c| c.rule_title == "Multiple failed logins"),
                    "Expected event_count correlation to fire"
                );
            }
        }

        // Now send a successful login → should trigger the chained temporal_ordered
        // Note: chaining happens in chain_correlations when many-failed-chain fires
        // and then success-login-chain matches the detection.
        // The temporal_ordered correlation needs BOTH many-failed-chain AND success-login-chain
        // to have fired. success-login-chain is a detection rule, not a correlation,
        // so it gets matched via the regular detection path.
        let v = json!({"EventType": "success_login", "User": "victim"});
        let event = Event::from_value(&v);
        let r = engine.process_event_at(&event, ts + 30);

        // The detection should match
        assert_eq!(r.detections.len(), 1);
        assert_eq!(r.detections[0].rule_title, "Successful login");
    }

    // =========================================================================
    // Field aliases
    // =========================================================================

    #[test]
    fn test_field_aliases() {
        let yaml = r#"
title: Internal Error
id: internal-error-001
name: internal_error
logsource:
    category: web
detection:
    selection:
        http.response.status_code: 500
    condition: selection
---
title: New Connection
id: new-conn-001
name: new_network_connection
logsource:
    category: network
detection:
    selection:
        event.type: connection
    condition: selection
---
title: Error Then Connection
id: corr-alias
correlation:
    type: temporal
    rules:
        - internal-error-001
        - new-conn-001
    group-by:
        - internal_ip
    timespan: 60s
    condition:
        gte: 2
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;

        // Internal error with destination.ip = 10.0.0.5
        let v1 = json!({
            "http.response.status_code": 500,
            "destination.ip": "10.0.0.5"
        });
        let ev1 = Event::from_value(&v1);
        let r1 = engine.process_event_at(&ev1, ts);
        assert_eq!(r1.detections.len(), 1);
        assert!(r1.correlations.is_empty());

        // New connection with source.ip = 10.0.0.5 (same IP, aliased)
        let v2 = json!({
            "event.type": "connection",
            "source.ip": "10.0.0.5"
        });
        let ev2 = Event::from_value(&v2);
        let r2 = engine.process_event_at(&ev2, ts + 5);
        assert_eq!(r2.detections.len(), 1);
        // Both rules fired for the same internal_ip group → temporal should fire
        assert_eq!(r2.correlations.len(), 1);
        assert_eq!(r2.correlations[0].rule_title, "Error Then Connection");
        // Check group key contains the aliased field
        assert!(
            r2.correlations[0]
                .group_key
                .iter()
                .any(|(k, v)| k == "internal_ip" && v == "10.0.0.5")
        );
    }

    // =========================================================================
    // Value percentile (basic smoke test)
    // =========================================================================

    #[test]
    fn test_value_percentile() {
        let yaml = r#"
title: Process Creation
id: proc-001
logsource:
    category: process
detection:
    selection:
        type: process_creation
    condition: selection
---
title: Rare Process
id: corr-percentile
correlation:
    type: value_percentile
    rules:
        - proc-001
    group-by:
        - ComputerName
    timespan: 60s
    condition:
        field: image
        lte: 50
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // Push some numeric-ish values for the image field
        for (i, val) in [10.0, 20.0, 30.0, 40.0, 50.0].iter().enumerate() {
            let v = json!({"type": "process_creation", "ComputerName": "srv01", "image": val});
            let event = Event::from_value(&v);
            let _ = engine.process_event_at(&event, ts + i as i64);
        }
        // The median (30.0) should be <= 50, so condition fires
        // Note: percentile implementation is simplified for in-memory eval
    }

    // =========================================================================
    // Extended temporal conditions (end-to-end)
    // =========================================================================

    #[test]
    fn test_extended_temporal_and_condition() {
        // Temporal correlation with "rule_a and rule_b" extended condition
        let yaml = r#"
title: Login Attempt
id: login-attempt
logsource:
    category: auth
detection:
    selection:
        EventType: login_failure
    condition: selection
---
title: Password Change
id: password-change
logsource:
    category: auth
detection:
    selection:
        EventType: password_change
    condition: selection
---
title: Credential Attack
correlation:
    type: temporal
    rules:
        - login-attempt
        - password-change
    group-by:
        - User
    timespan: 300s
    condition: login-attempt and password-change
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;

        // Login failure by alice
        let ev1 = json!({"EventType": "login_failure", "User": "alice"});
        let r1 = engine.process_event_at(&Event::from_value(&ev1), ts);
        assert!(r1.correlations.is_empty(), "only one rule fired so far");

        // Password change by alice — both rules have now fired
        let ev2 = json!({"EventType": "password_change", "User": "alice"});
        let r2 = engine.process_event_at(&Event::from_value(&ev2), ts + 10);
        assert_eq!(
            r2.correlations.len(),
            1,
            "temporal correlation should fire: both rules matched"
        );
        assert_eq!(r2.correlations[0].rule_title, "Credential Attack");
    }

    #[test]
    fn test_extended_temporal_or_condition() {
        // Temporal with "rule_a or rule_b" — should fire when either fires
        let yaml = r#"
title: SSH Login
id: ssh-login
logsource:
    category: auth
detection:
    selection:
        EventType: ssh_login
    condition: selection
---
title: VPN Login
id: vpn-login
logsource:
    category: auth
detection:
    selection:
        EventType: vpn_login
    condition: selection
---
title: Any Remote Access
correlation:
    type: temporal
    rules:
        - ssh-login
        - vpn-login
    group-by:
        - User
    timespan: 60s
    condition: ssh-login or vpn-login
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        // Only SSH login by bob — "or" means this suffices
        let ev = json!({"EventType": "ssh_login", "User": "bob"});
        let r = engine.process_event_at(&Event::from_value(&ev), 1000);
        assert_eq!(r.correlations.len(), 1);
        assert_eq!(r.correlations[0].rule_title, "Any Remote Access");
    }

    #[test]
    fn test_extended_temporal_partial_and_no_fire() {
        // Temporal "and" with only one rule firing should not trigger
        let yaml = r#"
title: Recon Step 1
id: recon-1
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Recon Step 2
id: recon-2
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
---
title: Full Recon
correlation:
    type: temporal
    rules:
        - recon-1
        - recon-2
    group-by:
        - Host
    timespan: 120s
    condition: recon-1 and recon-2
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        // Only whoami (recon-1) — should not fire
        let ev = json!({"CommandLine": "whoami", "Host": "srv01"});
        let r = engine.process_event_at(&Event::from_value(&ev), 1000);
        assert!(r.correlations.is_empty(), "only one of two AND rules fired");

        // Now ipconfig (recon-2) — should fire
        let ev2 = json!({"CommandLine": "ipconfig /all", "Host": "srv01"});
        let r2 = engine.process_event_at(&Event::from_value(&ev2), 1010);
        assert_eq!(r2.correlations.len(), 1);
        assert_eq!(r2.correlations[0].rule_title, "Full Recon");
    }

    // =========================================================================
    // Filter rules with correlation engine
    // =========================================================================

    #[test]
    fn test_filter_with_correlation() {
        // Detection rule + filter + event_count correlation
        let yaml = r#"
title: Failed Auth
id: failed-auth
logsource:
    category: auth
detection:
    selection:
        EventType: auth_failure
    condition: selection
---
title: Exclude Service Accounts
filter:
    rules:
        - failed-auth
detection:
    svc:
        User|startswith: 'svc_'
    condition: svc
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed-auth
    group-by:
        - User
    timespan: 300s
    condition:
        gte: 3
level: critical
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;

        // Service account failures should be filtered — don't count
        for i in 0..5 {
            let ev = json!({"EventType": "auth_failure", "User": "svc_backup"});
            let r = engine.process_event_at(&Event::from_value(&ev), ts + i);
            assert!(
                r.correlations.is_empty(),
                "service account should be filtered, no correlation"
            );
        }

        // Normal user failures should count
        for i in 0..2 {
            let ev = json!({"EventType": "auth_failure", "User": "alice"});
            let r = engine.process_event_at(&Event::from_value(&ev), ts + 10 + i);
            assert!(r.correlations.is_empty(), "not yet 3 events");
        }

        // Third failure triggers correlation
        let ev = json!({"EventType": "auth_failure", "User": "alice"});
        let r = engine.process_event_at(&Event::from_value(&ev), ts + 12);
        assert_eq!(r.correlations.len(), 1);
        assert_eq!(r.correlations[0].rule_title, "Brute Force");
    }

    // =========================================================================
    // action: repeat with correlation engine
    // =========================================================================

    #[test]
    fn test_repeat_rules_in_correlation() {
        // Two detection rules via repeat, both feed into event_count
        let yaml = r#"
title: File Access A
id: file-a
logsource:
    category: file_access
detection:
    selection:
        FileName|endswith: '.docx'
    condition: selection
---
action: repeat
title: File Access B
id: file-b
detection:
    selection:
        FileName|endswith: '.xlsx'
    condition: selection
---
title: Mass File Access
correlation:
    type: event_count
    rules:
        - file-a
        - file-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 2);
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();
        assert_eq!(engine.detection_rule_count(), 2);

        let ts = 1000i64;
        // Mix of docx and xlsx accesses by same user
        let ev1 = json!({"FileName": "report.docx", "User": "bob"});
        engine.process_event_at(&Event::from_value(&ev1), ts);
        let ev2 = json!({"FileName": "data.xlsx", "User": "bob"});
        engine.process_event_at(&Event::from_value(&ev2), ts + 1);
        let ev3 = json!({"FileName": "notes.docx", "User": "bob"});
        let r = engine.process_event_at(&Event::from_value(&ev3), ts + 2);

        assert_eq!(r.correlations.len(), 1);
        assert_eq!(r.correlations[0].rule_title, "Mass File Access");
    }

    // =========================================================================
    // Expand modifier with correlation engine
    // =========================================================================

    #[test]
    fn test_expand_modifier_with_correlation() {
        let yaml = r#"
title: User Temp File
id: user-temp
logsource:
    category: file_access
detection:
    selection:
        FilePath|expand: 'C:\Users\%User%\Temp'
    condition: selection
---
title: Excessive Temp Access
correlation:
    type: event_count
    rules:
        - user-temp
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: medium
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // Event where User field matches the placeholder
        let ev1 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "alice"});
        let r1 = engine.process_event_at(&Event::from_value(&ev1), ts);
        assert!(r1.correlations.is_empty());

        let ev2 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "alice"});
        let r2 = engine.process_event_at(&Event::from_value(&ev2), ts + 1);
        assert_eq!(r2.correlations.len(), 1);
        assert_eq!(r2.correlations[0].rule_title, "Excessive Temp Access");

        // Different user — should NOT match (path says alice, user is bob)
        let ev3 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "bob"});
        let r3 = engine.process_event_at(&Event::from_value(&ev3), ts + 2);
        // Detection doesn't fire for this event since expand resolves to C:\Users\bob\Temp
        assert_eq!(r3.detections.len(), 0);
    }

    // =========================================================================
    // Timestamp modifier with correlation engine
    // =========================================================================

    #[test]
    fn test_timestamp_modifier_with_correlation() {
        let yaml = r#"
title: Night Login
id: night-login
logsource:
    category: auth
detection:
    login:
        EventType: login
    night:
        Timestamp|hour: 3
    condition: login and night
---
title: Frequent Night Logins
correlation:
    type: event_count
    rules:
        - night-login
    group-by:
        - User
    timespan: 3600s
    condition:
        gte: 2
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let ts = 1000i64;
        // Login at 3AM
        let ev1 =
            json!({"EventType": "login", "User": "alice", "Timestamp": "2024-01-15T03:10:00Z"});
        let r1 = engine.process_event_at(&Event::from_value(&ev1), ts);
        assert_eq!(r1.detections.len(), 1);
        assert!(r1.correlations.is_empty());

        let ev2 =
            json!({"EventType": "login", "User": "alice", "Timestamp": "2024-01-15T03:45:00Z"});
        let r2 = engine.process_event_at(&Event::from_value(&ev2), ts + 1);
        assert_eq!(r2.correlations.len(), 1);
        assert_eq!(r2.correlations[0].rule_title, "Frequent Night Logins");

        // Login at noon — should NOT count
        let ev3 = json!({"EventType": "login", "User": "bob", "Timestamp": "2024-01-15T12:00:00Z"});
        let r3 = engine.process_event_at(&Event::from_value(&ev3), ts + 2);
        assert!(
            r3.detections.is_empty(),
            "noon login should not match night rule"
        );
    }
}
