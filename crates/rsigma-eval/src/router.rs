//! Multi-engine schema router: classify each event, route it to the detection
//! engine built for its schema's pipeline-set, and feed every detection into
//! one shared correlation store.
//!
//! # Design
//!
//! - One [`Engine`] per deduplicated pipeline-set (index-aligned with
//!   [`RoutingPlan::pipeline_sets`]). The schema's pipeline is applied to the
//!   detection rules in its engine, exactly as a single-pipeline run would.
//! - One shared [`CorrelationEngine`] (present only when the rule set has
//!   correlation rules), built Sigma-native (no pipeline). Detections from any
//!   per-schema engine feed into it via
//!   [`CorrelationEngine::correlate_detections`].
//! - Cross-schema correlation grouping works because the group-by extraction is
//!   schema-aware: each set carries a `Sigma -> event field` map (derived from
//!   its pipelines' field-name mappings), and the event is wrapped in a
//!   [`MappedEvent`] before correlation so the Sigma-native group-by names
//!   resolve to the schema's field names. The window store stays shared, keyed
//!   by the logical correlation plus the extracted group values.
//!
//! This subsumes the single-schema case (one pipeline-set is the degenerate
//! configuration), so there is no separate code path for "routing off".

use std::collections::HashMap;

use rsigma_parser::SigmaCollection;

use crate::correlation_engine::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, ProcessResult,
};
use crate::engine::Engine;
use crate::error::Result;
use crate::event::{Event, MappedEvent};
use crate::logsource::LogSourceExtractor;
use crate::pipeline::Pipeline;
use crate::pipeline::transformations::Transformation;
use crate::result::EvaluationResult;
use crate::result::MatchDetailLevel;
use crate::schema::{OnUnknown, RouteDecision, RoutingPlan, SchemaClassifier};

/// What the router did with an event, for reporting and `on_unknown` handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    /// Evaluated against a bound or known schema's set.
    Evaluated,
    /// Evaluated against the default set because the schema was unrecognized
    /// (`on_unknown: warn` or `passthrough`).
    EvaluatedUnknown,
    /// Dropped without evaluating (`on_unknown: drop`).
    Dropped,
    /// Dropped and flagged as an error (`on_unknown: error`).
    Errored,
}

/// The result of routing one event.
pub struct RouteResult {
    /// Evaluation results (empty when dropped or errored).
    pub results: ProcessResult,
    /// The classified schema name, or `None` when unrecognized.
    pub schema: Option<String>,
    /// What the router did.
    pub outcome: RouteOutcome,
}

/// Collect a combined `Sigma -> [event field]` map from a pipeline-set's
/// field-name mappings, used for schema-aware correlation group-by extraction.
fn collect_field_map(pipelines: &[Pipeline]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for pipeline in pipelines {
        for item in &pipeline.transformations {
            if let Transformation::FieldNameMapping { mapping } = &item.transformation {
                for (from, to) in mapping {
                    map.entry(from.clone())
                        .or_default()
                        .extend(to.iter().cloned());
                }
            }
        }
    }
    map
}

/// Outcome of the stateless phase for one event in [`SchemaRouter::process_batch`].
enum Routed1 {
    /// Dropped or errored (`on_unknown`): no results.
    Skip,
    /// Evaluate detections against the shared correlation store under set `set`.
    Eval {
        set: usize,
        detections: Vec<EvaluationResult>,
    },
}

/// Stateless detection for one event: classify, decide, evaluate. Borrows only
/// shared state so it can run in parallel across a batch.
fn detect_one<E: Event>(
    classifier: &SchemaClassifier,
    plan: &RoutingPlan,
    engines: &[Engine],
    event: &E,
) -> Routed1 {
    let schema = classifier.classify(event).map(|m| m.name);
    match plan.decide(schema.as_deref()) {
        RouteDecision::Drop | RouteDecision::Error => Routed1::Skip,
        RouteDecision::Evaluate { set, .. } => Routed1::Eval {
            set,
            detections: engines[set].evaluate(event),
        },
    }
}

/// A multi-engine router over a classifier, a [`RoutingPlan`], one detection
/// engine per pipeline-set, and one shared correlation store.
pub struct SchemaRouter {
    classifier: SchemaClassifier,
    plan: RoutingPlan,
    /// One detection engine per pipeline-set (index = set index).
    engines: Vec<Engine>,
    /// `Sigma -> event field` map per pipeline-set, for correlation group-by.
    field_maps: Vec<HashMap<String, Vec<String>>>,
    /// Shared correlation store; `None` when there are no correlation rules.
    correlation: Option<CorrelationEngine>,
}

impl SchemaRouter {
    /// Build a router. `pipeline_sets` must be index-aligned with
    /// `plan.pipeline_sets()` (one resolved pipeline list per set).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        collection: &SigmaCollection,
        classifier: SchemaClassifier,
        plan: RoutingPlan,
        pipeline_sets: Vec<Vec<Pipeline>>,
        corr_config: CorrelationConfig,
        include_event: bool,
        match_detail: MatchDetailLevel,
        logsource_extractor: Option<LogSourceExtractor>,
    ) -> Result<Self> {
        let mut engines = Vec::with_capacity(pipeline_sets.len());
        let mut field_maps = Vec::with_capacity(pipeline_sets.len());
        for set in &pipeline_sets {
            let mut engine = Engine::new();
            engine.set_include_event(include_event);
            engine.set_match_detail(match_detail);
            engine.set_logsource_extractor(logsource_extractor.clone());
            for p in set {
                engine.add_pipeline(p.clone());
            }
            engine.add_collection(collection)?;
            engines.push(engine);
            field_maps.push(collect_field_map(set));
        }

        // The shared correlation store is Sigma-native (no pipeline): group-by
        // names stay logical and are mapped per schema at feed time. Its inner
        // detection engine is unused (routed detection runs in `engines`).
        let correlation = if collection.correlations.is_empty() {
            None
        } else {
            let mut ce = CorrelationEngine::new(corr_config);
            ce.set_include_event(include_event);
            ce.set_match_detail(match_detail);
            ce.add_collection(collection)?;
            Some(ce)
        };

        Ok(SchemaRouter {
            classifier,
            plan,
            engines,
            field_maps,
            correlation,
        })
    }

    /// The unknown-handling policy this router enforces.
    pub fn on_unknown(&self) -> OnUnknown {
        self.plan.on_unknown()
    }

    /// Whether this router has a correlation store.
    pub fn has_correlations(&self) -> bool {
        self.correlation.is_some()
    }

    /// Number of detection rules (same across every per-schema engine).
    pub fn detection_rule_count(&self) -> usize {
        self.engines.first().map(|e| e.rule_count()).unwrap_or(0)
    }

    /// Total rule candidates pruned by logsource across every per-schema
    /// engine (each event routes to exactly one engine).
    pub fn logsource_pruned_total(&self) -> u64 {
        self.engines
            .iter()
            .map(Engine::logsource_pruned_total)
            .sum()
    }

    /// Total evaluate calls with no extractable event logsource (fail-open)
    /// across every per-schema engine.
    pub fn logsource_absent_total(&self) -> u64 {
        self.engines
            .iter()
            .map(Engine::logsource_absent_total)
            .sum()
    }

    /// Number of correlation rules in the shared store (0 when none).
    pub fn correlation_rule_count(&self) -> usize {
        self.correlation
            .as_ref()
            .map(|c| c.correlation_rule_count())
            .unwrap_or(0)
    }

    /// Number of live correlation window-state entries (0 when none).
    pub fn state_count(&self) -> usize {
        self.correlation
            .as_ref()
            .map(|c| c.state_count())
            .unwrap_or(0)
    }

    /// Export the shared correlation state, if any, for hot-reload carry-over.
    pub fn export_state(&self) -> Option<CorrelationSnapshot> {
        self.correlation.as_ref().map(|c| c.export_state())
    }

    /// Import previously exported correlation state into the shared store.
    /// No-op (returns `true`) when there is no correlation store.
    pub fn import_state(&mut self, snapshot: CorrelationSnapshot) -> bool {
        match &mut self.correlation {
            Some(c) => c.import_state(snapshot),
            None => true,
        }
    }

    /// Route a batch of events: parallel classify + detection, then sequential
    /// correlation into the shared store. Mirrors
    /// `CorrelationEngine::process_batch`: the stateless phase runs concurrently
    /// (under the `parallel` feature) and the stateful correlation phase runs
    /// in order. Drop/error outcomes yield empty results for that event.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult> {
        // Stateless phase: classify + route + detect. Borrows only `&self`
        // fields, so it parallelizes; correlation state is untouched here.
        let classifier = &self.classifier;
        let plan = &self.plan;
        let engines = &self.engines;
        let phase1: Vec<Routed1> = {
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                events
                    .par_iter()
                    .map(|e| detect_one(classifier, plan, engines, *e))
                    .collect()
            }
            #[cfg(not(feature = "parallel"))]
            {
                events
                    .iter()
                    .map(|e| detect_one(classifier, plan, engines, *e))
                    .collect()
            }
        };

        // Stateful phase: feed detections into the shared correlation store in
        // event order. Disjoint field borrows let the field maps and the
        // correlation store be held at once.
        let field_maps = &self.field_maps;
        let correlation = &mut self.correlation;
        phase1
            .into_iter()
            .zip(events)
            .map(|(routed, event)| match routed {
                Routed1::Skip => Vec::new(),
                Routed1::Eval { set, detections } => match correlation {
                    Some(ce) => {
                        let mapped = MappedEvent::new(*event, &field_maps[set]);
                        ce.correlate_detections(&mapped, detections)
                    }
                    None => detections,
                },
            })
            .collect()
    }

    /// Classify and route one event.
    pub fn route(&mut self, event: &impl Event) -> RouteResult {
        let schema = self.classifier.classify(event).map(|m| m.name);
        match self.plan.decide(schema.as_deref()) {
            RouteDecision::Drop => RouteResult {
                results: Vec::new(),
                schema,
                outcome: RouteOutcome::Dropped,
            },
            RouteDecision::Error => RouteResult {
                results: Vec::new(),
                schema,
                outcome: RouteOutcome::Errored,
            },
            RouteDecision::Evaluate { set, unknown } => {
                let detections = self.engines[set].evaluate(event);
                let results = match &mut self.correlation {
                    Some(ce) => {
                        let mapped = MappedEvent::new(event, &self.field_maps[set]);
                        ce.correlate_detections(&mapped, detections)
                    }
                    None => detections,
                };
                RouteResult {
                    results,
                    schema,
                    outcome: if unknown {
                        RouteOutcome::EvaluatedUnknown
                    } else {
                        RouteOutcome::Evaluated
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JsonEvent;
    use crate::pipeline::parse_pipeline;
    use crate::schema::RoutingConfig;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    const RULES: &str = r#"
title: Whoami
id: rule-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;

    const ECS_PIPELINE: &str = r#"
name: ecs_test
priority: 20
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      User: user.name
"#;

    fn plan(bindings: &[(&str, &[&str])]) -> RoutingPlan {
        let config = RoutingConfig {
            on_unknown: OnUnknown::Warn,
            default_pipelines: vec![],
            bindings: bindings
                .iter()
                .map(|(s, ps)| crate::schema::SchemaBinding {
                    schema: (*s).to_string(),
                    pipelines: ps.iter().map(|p| (*p).to_string()).collect(),
                })
                .collect(),
        };
        RoutingPlan::from_config(&config)
    }

    #[test]
    fn routes_ecs_event_to_ecs_engine() {
        let collection = parse_sigma_yaml(RULES).unwrap();
        // set 0 = default (no pipeline, Sigma-native fields), set 1 = ECS.
        let ecs = parse_pipeline(ECS_PIPELINE).unwrap();
        let plan = plan(&[("ecs", &["ecs_test"])]);
        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            vec![vec![], vec![ecs]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
        )
        .unwrap();

        // ECS event: fields are renamed; only the ECS engine matches it.
        let ecs_event = json!({"ecs.version": "8.0.0", "process.command_line": "cmd /c whoami"});
        let r = router.route(&JsonEvent::borrow(&ecs_event));
        assert_eq!(r.schema.as_deref(), Some("ecs"));
        assert_eq!(r.outcome, RouteOutcome::Evaluated);
        assert_eq!(r.results.len(), 1, "ECS event matches via the ECS engine");

        // A Sigma-native event with the same command is unrecognized here
        // (no ecs.version, no sysmon markers) -> generic_json -> default set,
        // which has no pipeline, so the rule's CommandLine matches it.
        let native = json!({"CommandLine": "cmd /c whoami"});
        let r = router.route(&JsonEvent::borrow(&native));
        assert_eq!(r.schema.as_deref(), Some("generic_json"));
        assert_eq!(r.results.len(), 1);
    }

    #[test]
    fn cross_schema_correlation_groups_the_same_entity() {
        // A detection rule plus an event_count correlation grouped by User.
        // The same user appears once as an ECS event (user.name) and once as a
        // Sigma-native event (User); they must land in the same window and fire.
        let rules = r#"
title: Whoami
id: rule-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Repeated whoami by user
correlation:
    type: event_count
    rules:
        - rule-whoami
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 2
level: high
"#;
        let collection = parse_sigma_yaml(rules).unwrap();
        let ecs = parse_pipeline(ECS_PIPELINE).unwrap();
        // set 0 = default (Sigma-native), set 1 = ECS. ecs schema -> set 1;
        // everything else (incl. the generic event) -> default set 0.
        let plan = plan(&[("ecs", &["ecs_test"])]);

        let config = CorrelationConfig {
            timestamp_fallback: crate::correlation_engine::TimestampFallback::WallClock,
            ..Default::default()
        };

        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            vec![vec![], vec![ecs]],
            config,
            false,
            MatchDetailLevel::Off,
            None,
        )
        .unwrap();

        // First occurrence: ECS event for user alice.
        let ecs_event = json!({
            "ecs.version": "8.0.0",
            "process.command_line": "cmd /c whoami",
            "user.name": "alice"
        });
        let r1 = router.route(&JsonEvent::borrow(&ecs_event));
        assert_eq!(r1.schema.as_deref(), Some("ecs"));
        assert!(
            !r1.results.iter().any(|r| r.is_correlation()),
            "first event must not fire the count>=2 correlation yet"
        );

        // Second occurrence: Sigma-native event for the SAME user alice.
        let native_event = json!({"CommandLine": "cmd /c whoami", "User": "alice"});
        let r2 = router.route(&JsonEvent::borrow(&native_event));
        assert!(
            r2.results.iter().any(|r| r.is_correlation()),
            "the two events share group User=alice across schemas and must correlate"
        );
    }

    #[test]
    fn drop_policy_skips_unknown_events() {
        let collection = parse_sigma_yaml(RULES).unwrap();
        let config = RoutingConfig {
            on_unknown: OnUnknown::Drop,
            default_pipelines: vec![],
            // Bind generic_json away so a plain event is truly unknown.
            bindings: vec![],
        };
        let plan = RoutingPlan::from_config(&config);
        let mut router = SchemaRouter::build(
            &collection,
            // Classifier with no generic_json: only ECS recognized, everything
            // else is unknown.
            SchemaClassifier::new(vec![]),
            plan,
            vec![vec![]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
        )
        .unwrap();

        let native = json!({"CommandLine": "cmd /c whoami"});
        let r = router.route(&JsonEvent::borrow(&native));
        assert_eq!(r.schema, None);
        assert_eq!(r.outcome, RouteOutcome::Dropped);
        assert!(r.results.is_empty());
    }
}
