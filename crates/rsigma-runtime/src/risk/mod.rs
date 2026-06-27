//! Post-engine risk-based alerting layer.
//!
//! An optional stage in the daemon sink path, between post-evaluation
//! enrichment and the alert pipeline, modeled on Splunk RBA and Entity Risk
//! Scoring. It runs in two stages:
//!
//! - **Stage one (risk annotation):** each firing detection is assigned a risk
//!   score and one or more risk objects (entities such as `user`, `host`,
//!   `src_ip`). The score and objects are injected into `header.enrichments`
//!   under the reserved `risk.score` / `risk.objects` keys, and, when
//!   `emit_risk_events` is set, a compact risk event is emitted per
//!   `(detection, risk object)` pair.
//!
//! The layer is strictly post-engine: it consumes [`EvaluationResult`]s and
//! emits annotated [`EvaluationResult`]s plus additive risk events, so the
//! evaluation hot path is untouched. The immutable, validated config
//! ([`RiskLayer`]) is built from a YAML file and swapped atomically on
//! hot-reload.

mod config;
mod object;
mod score;

pub use config::{
    ObjectFile, ReducerLabel, RiskConfigError, RiskFile, ScopeConfig, ScoreFile, build_risk_layer,
    load_risk_file, parse_risk_config,
};
pub use object::RiskObject;
pub use score::DEFAULT_SCORE_ATTRIBUTE;

use rsigma_eval::{EvaluationResult, ProcessResult};
use serde_json::Value;

use crate::{MetricsHook, Scope};

use object::ObjectSelector;
use score::ScoreConfig;

/// Reserved enrichment key carrying the resolved risk score.
const RISK_SCORE_KEY: &str = "risk.score";
/// Reserved enrichment key carrying the extracted risk objects.
const RISK_OBJECTS_KEY: &str = "risk.objects";

/// Output of [`RiskLayer::process`]: the annotated pass-through results and the
/// additive risk events (opt-in).
#[derive(Debug, Default)]
pub struct RiskOutput {
    /// Annotated detections, flowing on to the alert pipeline and the sinks.
    pub kept: ProcessResult,
    /// Compact risk events, one per `(detection, risk object)` pair, dispatched
    /// as additive NDJSON (optionally to a dedicated subject). Empty unless
    /// `emit_risk_events` is set.
    pub risk_events: Vec<Value>,
}

/// A validated, runnable risk layer.
///
/// Immutable after construction and cheap to hold behind an `Arc`, so it can be
/// swapped atomically on hot-reload while the sink task keeps a live snapshot
/// for the duration of a batch.
#[derive(Debug)]
pub struct RiskLayer {
    scope: Scope,
    strip_event: bool,
    score: ScoreConfig,
    objects: Vec<ObjectSelector>,
    emit_risk_events: bool,
    nats_subject: Option<String>,
}

impl RiskLayer {
    /// Construct from validated parts. Prefer [`build_risk_layer`].
    pub(crate) fn new(
        scope: Scope,
        strip_event: bool,
        score: ScoreConfig,
        objects: Vec<ObjectSelector>,
        emit_risk_events: bool,
        nats_subject: Option<String>,
    ) -> Self {
        RiskLayer {
            scope,
            strip_event,
            score,
            objects,
            emit_risk_events,
            nats_subject,
        }
    }

    /// The optional NATS subject override for emitted risk events.
    pub fn risk_event_nats_subject(&self) -> Option<&str> {
        self.nats_subject.as_deref()
    }

    /// Annotate each in-scope detection with its risk score and risk objects,
    /// and (opt-in) emit a compact risk event per `(detection, risk object)`
    /// pair. Out-of-scope results pass through untouched.
    pub fn process(
        &self,
        results: ProcessResult,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> RiskOutput {
        let start = std::time::Instant::now();
        let mut out = RiskOutput {
            kept: Vec::with_capacity(results.len()),
            risk_events: Vec::new(),
        };

        for mut result in results {
            if !self.scope.matches(&result) {
                metrics.on_risk_annotation("skipped");
                out.kept.push(result);
                continue;
            }

            let score = self.score.resolve(&result);
            let objects = object::extract(&result, &self.objects);
            metrics.observe_risk_annotation_score(score as f64);
            if objects.is_empty() {
                metrics.on_risk_annotation("no_entity");
            } else {
                metrics.on_risk_annotation("scored");
                metrics.on_risk_objects(objects.len() as u64);
            }

            annotate(&mut result, score, &objects);

            if self.emit_risk_events {
                for object in &objects {
                    out.risk_events
                        .push(risk_event(&result, score, object, now));
                }
            }

            if self.strip_event {
                strip_event_payloads(&mut result);
            }
            out.kept.push(result);
        }

        metrics.observe_risk_layer_duration(start.elapsed().as_secs_f64());
        out
    }
}

/// Inject the reserved `risk.score` / `risk.objects` keys into a result's
/// enrichments. The layer wins on a collision with a user enricher.
fn annotate(result: &mut EvaluationResult, score: i64, objects: &[RiskObject]) {
    let map = result
        .header
        .enrichments
        .get_or_insert_with(serde_json::Map::new);
    if map.contains_key(RISK_SCORE_KEY) || map.contains_key(RISK_OBJECTS_KEY) {
        // Debug, not warn: an upstream enricher setting these on every result
        // would otherwise emit one log line per result.
        tracing::debug!("risk layer: overwriting a user-set `risk.*` enrichment key");
    }
    map.insert(RISK_SCORE_KEY.to_string(), Value::from(score));
    if !objects.is_empty() {
        let value = serde_json::to_value(objects).unwrap_or(Value::Null);
        map.insert(RISK_OBJECTS_KEY.to_string(), value);
    }
}

/// Remove raw event payloads from a result, so the layer can extract on
/// `event.*` without emitting full events when `strip_event` is set.
fn strip_event_payloads(result: &mut EvaluationResult) {
    if let Some(detection) = result.as_detection_mut() {
        detection.event = None;
    }
    if let Some(correlation) = result.as_correlation_mut() {
        correlation.events = None;
        correlation.event_refs = None;
    }
}

/// Build one compact risk event for a `(detection, risk object)` pair. The
/// `risk_event` marker key disambiguates it on the wire.
fn risk_event(result: &EvaluationResult, score: i64, object: &RiskObject, now: i64) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("risk_event".to_string(), Value::Bool(true));
    map.insert("timestamp".to_string(), Value::from(now));
    map.insert(
        "rule".to_string(),
        Value::String(
            result
                .header
                .rule_id
                .clone()
                .unwrap_or_else(|| result.header.rule_title.clone()),
        ),
    );
    map.insert(
        "rule_title".to_string(),
        Value::String(result.header.rule_title.clone()),
    );
    if let Some(level) = result.header.level {
        map.insert(
            "level".to_string(),
            Value::String(level.as_str().to_string()),
        );
    }
    map.insert("risk_score".to_string(), Value::from(score));
    map.insert(
        "risk_object".to_string(),
        serde_json::to_value(object).unwrap_or(Value::Null),
    );
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopMetrics;
    use rsigma_eval::{DetectionBody, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn layer(yaml: &str) -> RiskLayer {
        parse_risk_config(yaml).unwrap()
    }

    fn detection(ip: &str, level: Level, tags: Vec<&str>) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Suspicious activity".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(level),
                tags: tags.into_iter().map(str::to_string).collect(),
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
    fn annotates_score_and_objects() {
        let p = layer(
            "score:\n  level_scores:\n    high: 40\nobjects:\n  - type: src_ip\n    selector: match.SourceIp\n",
        );
        let out = p.process(
            vec![detection("10.0.0.1", Level::High, vec![])],
            0,
            &NoopMetrics,
        );
        assert_eq!(out.kept.len(), 1);
        let enr = out.kept[0].header.enrichments.as_ref().unwrap();
        assert_eq!(enr["risk.score"], serde_json::json!(40));
        assert_eq!(
            enr["risk.objects"],
            serde_json::json!([{"type": "src_ip", "value": "10.0.0.1"}])
        );
    }

    #[test]
    fn out_of_scope_passes_through_unannotated() {
        let p = layer(
            "scope:\n  levels: [critical]\nobjects:\n  - type: src_ip\n    selector: match.SourceIp\n",
        );
        let out = p.process(
            vec![detection("10.0.0.1", Level::High, vec![])],
            0,
            &NoopMetrics,
        );
        assert_eq!(out.kept.len(), 1);
        assert!(out.kept[0].header.enrichments.is_none());
    }

    #[test]
    fn no_entity_still_annotates_score_only() {
        let p = layer(
            "score:\n  default_score: 7\nobjects:\n  - type: user\n    selector: enrichment.user\n",
        );
        let out = p.process(
            vec![detection("10.0.0.1", Level::High, vec![])],
            0,
            &NoopMetrics,
        );
        let enr = out.kept[0].header.enrichments.as_ref().unwrap();
        assert_eq!(enr["risk.score"], serde_json::json!(7));
        assert!(!enr.contains_key("risk.objects"));
    }

    #[test]
    fn emits_risk_event_per_object_when_opted_in() {
        let p = layer(
            "emit_risk_events: true\nscore:\n  default_score: 5\nobjects:\n  - type: src_ip\n    selector: match.SourceIp\n",
        );
        let out = p.process(
            vec![detection("10.0.0.1", Level::High, vec![])],
            1234,
            &NoopMetrics,
        );
        assert_eq!(out.risk_events.len(), 1);
        let ev = &out.risk_events[0];
        assert_eq!(ev["risk_event"], serde_json::json!(true));
        assert_eq!(ev["risk_score"], serde_json::json!(5));
        assert_eq!(ev["timestamp"], serde_json::json!(1234));
        assert_eq!(ev["risk_object"]["value"], serde_json::json!("10.0.0.1"));
    }

    #[test]
    fn strip_event_drops_payload_after_extraction() {
        let p = layer("strip_event: true\nobjects:\n  - type: host\n    selector: event.raw\n");
        let out = p.process(
            vec![detection("10.0.0.1", Level::High, vec![])],
            0,
            &NoopMetrics,
        );
        // Event was used for extraction then stripped from the delivered result.
        assert!(out.kept[0].as_detection().unwrap().event.is_none());
        assert_eq!(
            out.kept[0].header.enrichments.as_ref().unwrap()["risk.objects"],
            serde_json::json!([{"type": "host", "value": "event"}])
        );
    }
}
