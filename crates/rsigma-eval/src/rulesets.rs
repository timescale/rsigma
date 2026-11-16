//! Several named rulesets evaluated side by side.
//!
//! Each [`RulesetUnit`] owns its own compiled engine, pipelines, and
//! correlation state. Units never share a router or a correlation store:
//! routing answers "which one pipeline set does this event belong to", while a
//! ruleset fan-out sends an event to several independent rule sets, and a
//! shared correlation store would double-count a rule that appears in more than
//! one ruleset.
//!
//! [`RulesetEngines`] fans an event out to the units that accept it, stamps the
//! ruleset name on every result, and keeps per-unit skip and route counters.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::SchemaClassifier;
use crate::correlation_engine::CorrelationEngine;
use crate::event::Event;
use crate::fields::RuleFieldSet;
use crate::result::EvaluationResult;
use crate::router::{RouteOutcome, SchemaRouter};
use crate::rule_metadata::RuleMetadataLookup;
use crate::{CorrelationSnapshot, CorrelationStateSnapshot, Engine, ProcessResult};

/// The compiled engine behind one ruleset unit.
pub enum UnitEngine {
    /// A stateless detection engine.
    Detection(Box<Engine>),
    /// A stateful detection and correlation engine.
    Correlation(Box<CorrelationEngine>),
    /// A schema router over one pipeline set.
    Routed(Box<SchemaRouter>),
}

/// One named ruleset unit: its name, schema bindings, engine, and the field
/// set its rules reference after pipelines.
pub struct RulesetUnit {
    /// Ruleset name, stamped on every result the unit produces.
    pub name: Arc<str>,
    /// Schema names that admit an event to this unit. Empty means every event.
    pub when_schemas: Vec<String>,
    /// The compiled engine for this unit.
    pub engine: UnitEngine,
    /// Post-pipeline field set for this unit's collection.
    pub field_set: RuleFieldSet,
}

/// One ruleset's loaded rule counts and schema bindings, for status and stats.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RulesetStats {
    /// Ruleset name.
    pub name: Arc<str>,
    /// Loaded detection rules.
    pub detection_rules: usize,
    /// Loaded correlation rules.
    pub correlation_rules: usize,
    /// Schema names that admit an event to this ruleset.
    pub when_schemas: Vec<String>,
}

/// Routing outcomes counted across a single routed unit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteCounts {
    /// Events with an unrecognized schema that were evaluated against the
    /// default set.
    pub unknown: u64,
    /// Events dropped without evaluation.
    pub dropped: u64,
    /// Events dropped and flagged as an error.
    pub errored: u64,
}

/// Introspection of one ruleset's correlation state.
pub type CorrelationIntrospection = CorrelationStateSnapshot;

/// Construction errors for [`RulesetEngines`].
#[derive(Debug, Error)]
pub enum RulesetEnginesError {
    /// No rulesets were supplied.
    #[error("at least one ruleset is required")]
    Empty,
    /// Two rulesets share a name.
    #[error("duplicate ruleset name '{0}'")]
    DuplicateName(String),
    /// A routed unit was supplied alongside another unit.
    #[error("schema routing supports exactly one ruleset, found {0}")]
    RoutedWithOthers(usize),
    /// A routed unit carries a `when` binding.
    #[error("ruleset '{0}' cannot use `when` with schema routing")]
    RoutedWithWhen(String),
    /// A unit carries `when` but no classifier is configured.
    #[error("ruleset '{0}' has `when` but no schema classifier is configured")]
    WhenWithoutClassifier(String),
    /// A `when` schema is not known to the classifier.
    #[error(
        "ruleset '{name}' references unknown schema '{schema}'; known schemas: {}",
        known.join(", ")
    )]
    UnknownSchema {
        /// Ruleset name.
        name: String,
        /// Unknown schema name.
        schema: String,
        /// Known schema names.
        known: Vec<String>,
    },
}

/// A fan-out over independent named rulesets.
pub struct RulesetEngines {
    units: Vec<RulesetUnit>,
    classifier: Option<Arc<SchemaClassifier>>,
    skipped: Vec<AtomicU64>,
    route_counts: RouteCounts,
}

impl RulesetEngines {
    /// Build a fan-out from units and an optional schema classifier.
    ///
    /// Validation fails on an empty list, duplicate names, a routed unit with
    /// other units or with `when`, `when` without a classifier, and `when`
    /// schemas the classifier does not know.
    pub fn new(
        units: Vec<RulesetUnit>,
        classifier: Option<Arc<SchemaClassifier>>,
    ) -> Result<Self, RulesetEnginesError> {
        if units.is_empty() {
            return Err(RulesetEnginesError::Empty);
        }

        let mut names = std::collections::HashSet::new();
        for unit in &units {
            if !names.insert(unit.name.clone()) {
                return Err(RulesetEnginesError::DuplicateName(unit.name.to_string()));
            }
        }

        if let Some(unit) = units
            .iter()
            .find(|unit| matches!(unit.engine, UnitEngine::Routed(_)))
        {
            if units.len() != 1 {
                return Err(RulesetEnginesError::RoutedWithOthers(units.len()));
            }
            if !unit.when_schemas.is_empty() {
                return Err(RulesetEnginesError::RoutedWithWhen(unit.name.to_string()));
            }
        }

        if units.iter().any(|unit| !unit.when_schemas.is_empty()) {
            let Some(classifier) = &classifier else {
                let name = units
                    .iter()
                    .find(|unit| !unit.when_schemas.is_empty())
                    .map(|unit| unit.name.to_string())
                    .unwrap_or_default();
                return Err(RulesetEnginesError::WhenWithoutClassifier(name));
            };
            let known: Vec<String> = classifier
                .schema_names()
                .into_iter()
                .map(str::to_string)
                .collect();
            for unit in &units {
                for schema in &unit.when_schemas {
                    if !known.iter().any(|known| known == schema) {
                        return Err(RulesetEnginesError::UnknownSchema {
                            name: unit.name.to_string(),
                            schema: schema.clone(),
                            known: known.clone(),
                        });
                    }
                }
            }
        }

        let skipped = units.iter().map(|_| AtomicU64::new(0)).collect::<Vec<_>>();

        Ok(Self {
            units,
            classifier,
            skipped,
            route_counts: RouteCounts::default(),
        })
    }

    /// The configured units, in declaration order.
    pub fn units(&self) -> &[RulesetUnit] {
        &self.units
    }

    /// Loaded rule counts and schema bindings for every unit.
    pub fn ruleset_stats(&self) -> Vec<RulesetStats> {
        self.units
            .iter()
            .map(|unit| RulesetStats {
                name: unit.name.clone(),
                detection_rules: unit_detection_rule_count(unit),
                correlation_rules: unit_correlation_rule_count(unit),
                when_schemas: unit.when_schemas.clone(),
            })
            .collect()
    }

    /// Cumulative events refused by each unit's `when` binding.
    pub fn skipped_totals(&self) -> Vec<(Arc<str>, u64)> {
        self.units
            .iter()
            .zip(&self.skipped)
            .map(|(unit, skipped)| (unit.name.clone(), skipped.load(Ordering::Relaxed)))
            .collect()
    }

    /// Routing outcomes counted by `process_event` for a routed unit.
    pub fn route_counts(&self) -> RouteCounts {
        self.route_counts
    }

    /// Summed detection rule count across units.
    pub fn detection_rule_count(&self) -> usize {
        self.units.iter().map(unit_detection_rule_count).sum()
    }

    /// Summed correlation rule count across units.
    pub fn correlation_rule_count(&self) -> usize {
        self.units.iter().map(unit_correlation_rule_count).sum()
    }

    /// Whether any unit carries correlation state.
    pub fn has_correlations(&self) -> bool {
        self.units.iter().any(|unit| match &unit.engine {
            UnitEngine::Detection(_) => false,
            UnitEngine::Correlation(_) => true,
            UnitEngine::Routed(router) => router.has_correlations(),
        })
    }

    /// Union of every unit's post-pipeline rule field set.
    pub fn rule_field_set(&self) -> RuleFieldSet {
        let mut set = RuleFieldSet::default();
        for unit in &self.units {
            set.extend(unit.field_set.clone());
        }
        set
    }

    /// Resolve a rule key across every unit. Differently overlaid copies of the
    /// same rule report [`RuleMetadataLookup::Ambiguous`].
    pub fn rule_metadata(&self, key: &str) -> RuleMetadataLookup {
        let mut variants = Vec::new();
        for unit in &self.units {
            match &unit.engine {
                UnitEngine::Detection(engine) => engine.collect_rule_metadata(key, &mut variants),
                UnitEngine::Correlation(engine) => engine.collect_rule_metadata(key, &mut variants),
                UnitEngine::Routed(router) => {
                    variants.extend(router.rule_metadata(key).variants().iter().cloned())
                }
            }
        }
        RuleMetadataLookup::from_variants(variants)
    }

    /// Process one event through every unit that accepts it.
    pub fn process_event<E: Event>(&mut self, event: &E) -> ProcessResult {
        let accepted = self.acceptance(event);
        let mut results = Vec::new();
        let units = &mut self.units;
        for (index, unit) in units.iter_mut().enumerate() {
            if !accepted[index] {
                self.skipped[index].fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut batch = match &mut unit.engine {
                UnitEngine::Detection(engine) => engine.evaluate(event),
                UnitEngine::Correlation(engine) => engine.process_event(event),
                UnitEngine::Routed(router) => {
                    let routed = router.route(event);
                    match routed.outcome {
                        RouteOutcome::Evaluated => {}
                        RouteOutcome::EvaluatedUnknown => self.route_counts.unknown += 1,
                        RouteOutcome::Dropped => self.route_counts.dropped += 1,
                        RouteOutcome::Errored => self.route_counts.errored += 1,
                    }
                    routed.results
                }
            };
            stamp_results(&unit.name, &mut batch);
            results.extend(batch);
        }
        results
    }

    /// Process a batch through every unit that accepts each event.
    ///
    /// Results are scattered back to their event positions in unit declaration
    /// order.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult> {
        let mut accepted = Vec::with_capacity(self.units.len());
        for (index, unit) in self.units.iter().enumerate() {
            let mut per_event = Vec::with_capacity(events.len());
            for event in events {
                let accepts = self.accepts(unit, event);
                if !accepts {
                    self.skipped[index].fetch_add(1, Ordering::Relaxed);
                }
                per_event.push(accepts);
            }
            accepted.push(per_event);
        }

        let mut output: Vec<ProcessResult> = vec![Vec::new(); events.len()];
        let units = &mut self.units;
        for (unit_index, unit) in units.iter_mut().enumerate() {
            let indices: Vec<usize> = accepted[unit_index]
                .iter()
                .enumerate()
                .filter_map(|(event_index, accepted)| accepted.then_some(event_index))
                .collect();
            if indices.is_empty() {
                continue;
            }
            let sub_events: Vec<&E> = indices.iter().map(|index| events[*index]).collect();
            let results = match &mut unit.engine {
                UnitEngine::Detection(engine) => engine.evaluate_batch(&sub_events),
                UnitEngine::Correlation(engine) => engine.process_batch(&sub_events),
                UnitEngine::Routed(router) => router.process_batch(&sub_events),
            };
            for (sub_index, mut batch) in results.into_iter().enumerate() {
                stamp_results(&unit.name, &mut batch);
                output[indices[sub_index]].extend(batch);
            }
        }
        output
    }

    /// Stateless detection for every unit, when every unit is detection-only.
    ///
    /// Returns `None` when any unit carries correlation state or a router.
    pub fn detect_batch<E: Event + Sync>(&self, events: &[&E]) -> Option<Vec<ProcessResult>> {
        if self
            .units
            .iter()
            .any(|unit| !matches!(unit.engine, UnitEngine::Detection(_)))
        {
            return None;
        }

        let mut accepted = Vec::with_capacity(self.units.len());
        for (index, unit) in self.units.iter().enumerate() {
            let mut per_event = Vec::with_capacity(events.len());
            for event in events {
                let accepts = self.accepts(unit, event);
                if !accepts {
                    self.skipped[index].fetch_add(1, Ordering::Relaxed);
                }
                per_event.push(accepts);
            }
            accepted.push(per_event);
        }

        let mut output: Vec<ProcessResult> = vec![Vec::new(); events.len()];
        for (unit_index, unit) in self.units.iter().enumerate() {
            let UnitEngine::Detection(engine) = &unit.engine else {
                continue;
            };
            let indices: Vec<usize> = accepted[unit_index]
                .iter()
                .enumerate()
                .filter_map(|(event_index, accepted)| accepted.then_some(event_index))
                .collect();
            if indices.is_empty() {
                continue;
            }
            let sub_events: Vec<&E> = indices.iter().map(|index| events[*index]).collect();
            let results = engine.evaluate_batch(&sub_events);
            for (sub_index, mut batch) in results.into_iter().enumerate() {
                stamp_results(&unit.name, &mut batch);
                output[indices[sub_index]].extend(batch);
            }
        }
        Some(output)
    }

    /// Export per-ruleset correlation state in one snapshot.
    pub fn export_state(&self) -> CorrelationSnapshot {
        let mut rulesets = BTreeMap::new();
        for unit in &self.units {
            let snapshot = match &unit.engine {
                UnitEngine::Detection(_) => None,
                UnitEngine::Correlation(engine) => Some(engine.export_state()),
                UnitEngine::Routed(router) => router.export_state(),
            };
            if let Some(snapshot) = snapshot {
                rulesets.insert(unit.name.to_string(), snapshot);
            }
        }
        CorrelationSnapshot {
            version: 1,
            windows: HashMap::new(),
            last_alert: HashMap::new(),
            event_buffers: HashMap::new(),
            event_ref_buffers: HashMap::new(),
            rulesets,
        }
    }

    /// Import per-ruleset correlation state by name. Names that no longer exist
    /// are dropped.
    pub fn import_state(&mut self, snapshot: &CorrelationSnapshot) -> bool {
        if snapshot.version != 1 {
            return false;
        }
        let mut units: HashMap<String, &mut RulesetUnit> = self
            .units
            .iter_mut()
            .map(|unit| (unit.name.to_string(), unit))
            .collect();
        for (name, state) in &snapshot.rulesets {
            let Some(unit) = units.get_mut(name.as_str()) else {
                continue;
            };
            match &mut unit.engine {
                UnitEngine::Detection(_) => {}
                UnitEngine::Correlation(engine) => {
                    engine.import_state(state.clone());
                }
                UnitEngine::Routed(router) => {
                    router.import_state(state.clone());
                }
            }
        }
        true
    }

    /// Introspect correlation state for every unit that has it.
    pub fn introspect(&self) -> BTreeMap<String, CorrelationIntrospection> {
        self.introspect_filtered(None, None)
    }

    /// Introspect correlation state with optional id and group filters.
    pub fn introspect_filtered(
        &self,
        id: Option<&str>,
        group: Option<&str>,
    ) -> BTreeMap<String, CorrelationIntrospection> {
        let mut out = BTreeMap::new();
        for unit in &self.units {
            let snapshot = match &unit.engine {
                UnitEngine::Detection(_) => None,
                UnitEngine::Correlation(engine) => Some(engine.introspect_filtered(id, group)),
                UnitEngine::Routed(router) => router.correlation_introspect(id, group),
            };
            if let Some(snapshot) = snapshot {
                out.insert(unit.name.to_string(), snapshot);
            }
        }
        out
    }

    fn accepts<E: Event>(&self, unit: &RulesetUnit, event: &E) -> bool {
        if unit.when_schemas.is_empty() {
            return true;
        }
        let Some(classifier) = &self.classifier else {
            return false;
        };
        let Some(matched) = classifier.classify(event) else {
            return false;
        };
        unit.when_schemas
            .iter()
            .any(|schema| schema == &matched.name)
    }

    fn acceptance<E: Event>(&self, event: &E) -> Vec<bool> {
        let any_when = self.units.iter().any(|unit| !unit.when_schemas.is_empty());
        if !any_when {
            return vec![true; self.units.len()];
        }
        let schema = self
            .classifier
            .as_ref()
            .and_then(|classifier| classifier.classify(event))
            .map(|matched| matched.name);
        self.units
            .iter()
            .map(|unit| {
                if unit.when_schemas.is_empty() {
                    true
                } else {
                    schema
                        .as_ref()
                        .is_some_and(|schema| unit.when_schemas.iter().any(|name| name == schema))
                }
            })
            .collect()
    }
}

fn stamp_results(name: &Arc<str>, results: &mut [EvaluationResult]) {
    for result in results {
        result.header.ruleset = Some(name.clone());
    }
}

fn unit_detection_rule_count(unit: &RulesetUnit) -> usize {
    match &unit.engine {
        UnitEngine::Detection(engine) => engine.rule_count(),
        UnitEngine::Correlation(engine) => engine.detection_rule_count(),
        UnitEngine::Routed(router) => router.detection_rule_count(),
    }
}

fn unit_correlation_rule_count(unit: &RulesetUnit) -> usize {
    match &unit.engine {
        UnitEngine::Detection(_) => 0,
        UnitEngine::Correlation(engine) => engine.correlation_rule_count(),
        UnitEngine::Routed(router) => router.correlation_rule_count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CorrelationConfig, JsonEvent, MatchDetailLevel, OnUnknown, Pipeline, RoutingConfig,
        RoutingPlan, SchemaPredicate, SchemaSignature, parse_pipeline,
    };
    use rsigma_parser::parse_sigma_yaml;

    const DETECTION: &str = r#"
title: Whoami
id: whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: whoami
    condition: selection
"#;

    const CORRELATION: &str = r#"
title: Whoami
id: whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: whoami
    condition: selection
---
title: Burst
id: burst
correlation:
    type: event_count
    rules: [whoami]
    group-by: [Image]
    timespan: 5m
    condition:
        gte: 2
"#;

    fn pipeline(mapping: &str) -> Pipeline {
        parse_pipeline(&format!(
            "name: p\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: {mapping}\n"
        ))
        .unwrap()
    }

    fn detection_unit(name: &str, pipelines: Vec<Pipeline>) -> RulesetUnit {
        let collection = parse_sigma_yaml(DETECTION).unwrap();
        let mut engine = Engine::new();
        engine.set_match_detail(MatchDetailLevel::Off);
        for pipeline in pipelines {
            engine.add_pipeline(pipeline);
        }
        engine.add_collection(&collection).unwrap();
        RulesetUnit {
            name: Arc::from(name),
            when_schemas: Vec::new(),
            engine: UnitEngine::Detection(Box::new(engine)),
            field_set: RuleFieldSet::collect(&collection, &[], true),
        }
    }

    fn correlation_unit(name: &str) -> RulesetUnit {
        let collection = parse_sigma_yaml(CORRELATION).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();
        RulesetUnit {
            name: Arc::from(name),
            when_schemas: Vec::new(),
            engine: UnitEngine::Correlation(Box::new(engine)),
            field_set: RuleFieldSet::collect(&collection, &[], true),
        }
    }

    fn bound_unit(name: &str, schemas: &[&str]) -> RulesetUnit {
        let mut unit = detection_unit(name, Vec::new());
        unit.when_schemas = schemas.iter().map(|schema| (*schema).to_string()).collect();
        unit
    }

    fn classifier_with(schemas: &[&str]) -> Arc<SchemaClassifier> {
        Arc::new(SchemaClassifier::new(
            schemas
                .iter()
                .map(|name| SchemaSignature {
                    name: (*name).to_string(),
                    predicates: vec![SchemaPredicate::FieldPresent("schema_marker".to_string())],
                    specificity: 10,
                })
                .collect(),
        ))
    }

    fn routed_engine(on_unknown: OnUnknown) -> RulesetEngines {
        let collection = parse_sigma_yaml(DETECTION).unwrap();
        let mut config = RoutingConfig::default();
        config.on_unknown = on_unknown;
        let plan = RoutingPlan::from_config(&config);
        let router = SchemaRouter::build(
            &collection,
            SchemaClassifier::new(Vec::new()),
            plan,
            vec![Vec::new()],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();
        RulesetEngines::new(
            vec![RulesetUnit {
                name: Arc::from("routed"),
                when_schemas: Vec::new(),
                engine: UnitEngine::Routed(Box::new(router)),
                field_set: RuleFieldSet::collect(&collection, &[], true),
            }],
            None,
        )
        .unwrap()
    }

    #[test]
    fn two_units_with_different_pipelines_both_fire_in_order() {
        let mut engines = RulesetEngines::new(
            vec![
                detection_unit("first", vec![pipeline("process.executable")]),
                detection_unit("second", vec![pipeline("process.path")]),
            ],
            None,
        )
        .unwrap();
        let value = serde_json::json!({
            "process.executable": "whoami",
            "process.path": "whoami",
        });
        let event = JsonEvent::borrow(&value);
        let results = engines.process_event(&event);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].header.ruleset.as_deref(), Some("first"));
        assert_eq!(results[1].header.ruleset.as_deref(), Some("second"));
    }

    #[test]
    fn when_routes_only_to_the_bound_unit() {
        let classifier = classifier_with(&["aws_cloudtrail"]);
        let mut engines = RulesetEngines::new(
            vec![
                detection_unit("unbound", Vec::new()),
                bound_unit("cloud", &["aws_cloudtrail"]),
            ],
            Some(classifier),
        )
        .unwrap();
        let cloud_value = serde_json::json!({
            "schema_marker": true,
            "Image": "whoami",
        });
        let cloud = JsonEvent::borrow(&cloud_value);
        let plain_value = serde_json::json!({"Image": "whoami"});
        let plain = JsonEvent::borrow(&plain_value);

        let cloud_results = engines.process_event(&cloud);
        assert_eq!(cloud_results.len(), 2);
        assert_eq!(cloud_results[0].header.ruleset.as_deref(), Some("unbound"));
        assert_eq!(cloud_results[1].header.ruleset.as_deref(), Some("cloud"));

        let plain_results = engines.process_event(&plain);
        assert_eq!(plain_results.len(), 1);
        assert_eq!(plain_results[0].header.ruleset.as_deref(), Some("unbound"));

        let skipped = engines.skipped_totals();
        assert_eq!(skipped[0].1, 0);
        assert_eq!(skipped[1].1, 1);
    }

    #[test]
    fn classifier_is_not_called_without_when() {
        let mut engines = RulesetEngines::new(
            vec![detection_unit("one", Vec::new())],
            Some(Arc::new(SchemaClassifier::new(Vec::new()))),
        )
        .unwrap();
        let value = serde_json::json!({"Image": "whoami"});
        let event = JsonEvent::borrow(&value);
        let results = engines.process_event(&event);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn correlation_state_is_isolated_per_unit() {
        let mut engines =
            RulesetEngines::new(vec![correlation_unit("a"), correlation_unit("b")], None).unwrap();
        let value = serde_json::json!({
            "Image": "whoami",
            "timestamp": "2026-01-01T00:00:00Z",
        });
        let event = JsonEvent::borrow(&value);
        let results = engines.process_event(&event);
        assert!(
            results.is_empty(),
            "a shared store would count the event twice and fire the correlation"
        );
    }

    #[test]
    fn export_and_import_round_trip_by_name() {
        let mut engines =
            RulesetEngines::new(vec![correlation_unit("a"), correlation_unit("b")], None).unwrap();
        for offset in [0, 1] {
            let value = serde_json::json!({
                "Image": "whoami",
                "timestamp": format!("2026-01-01T00:00:0{offset}Z"),
            });
            let event = JsonEvent::borrow(&value);
            engines.process_event(&event);
        }
        let snapshot = engines.export_state();
        assert_eq!(snapshot.rulesets.len(), 2);

        let mut restored = RulesetEngines::new(vec![correlation_unit("a")], None).unwrap();
        assert!(restored.import_state(&snapshot));
        let introspected = restored.introspect();
        assert!(introspected.contains_key("a"));
        assert!(!introspected.contains_key("b"));
    }

    #[test]
    fn detect_batch_rejects_correlation_units() {
        let engines = RulesetEngines::new(
            vec![detection_unit("one", Vec::new()), correlation_unit("two")],
            None,
        )
        .unwrap();
        let value = serde_json::json!({"Image": "whoami"});
        let event = JsonEvent::borrow(&value);
        assert!(engines.detect_batch(&[&event]).is_none());
    }

    #[test]
    fn routed_unit_counts_route_outcomes() {
        let value = serde_json::json!({"foo": "bar"});
        let event = JsonEvent::borrow(&value);

        let mut unknown = routed_engine(OnUnknown::Warn);
        unknown.process_event(&event);
        assert_eq!(unknown.route_counts().unknown, 1);

        let mut dropped = routed_engine(OnUnknown::Drop);
        dropped.process_event(&event);
        assert_eq!(dropped.route_counts().dropped, 1);

        let mut errored = routed_engine(OnUnknown::Error);
        errored.process_event(&event);
        assert_eq!(errored.route_counts().errored, 1);
    }

    #[test]
    fn construction_errors_are_reported() {
        assert!(matches!(
            RulesetEngines::new(Vec::new(), None),
            Err(RulesetEnginesError::Empty)
        ));
        assert!(matches!(
            RulesetEngines::new(
                vec![
                    detection_unit("a", Vec::new()),
                    detection_unit("a", Vec::new())
                ],
                None
            ),
            Err(RulesetEnginesError::DuplicateName(_))
        ));
        assert!(matches!(
            RulesetEngines::new(
                vec![detection_unit("a", Vec::new()), {
                    let mut routed = routed_engine(OnUnknown::Warn);
                    routed.units.remove(0)
                }],
                None
            ),
            Err(RulesetEnginesError::RoutedWithOthers(2))
        ));
        assert!(matches!(
            RulesetEngines::new(
                vec![{
                    let mut routed = routed_engine(OnUnknown::Warn);
                    routed.units.remove(0)
                }],
                None
            ),
            Ok(_)
        ));
        assert!(matches!(
            RulesetEngines::new(
                vec![{
                    let mut routed = routed_engine(OnUnknown::Warn);
                    let mut unit = routed.units.remove(0);
                    unit.when_schemas = vec!["x".to_string()];
                    unit
                }],
                None
            ),
            Err(RulesetEnginesError::RoutedWithWhen(_))
        ));
        assert!(matches!(
            RulesetEngines::new(vec![bound_unit("a", &["x"])], None),
            Err(RulesetEnginesError::WhenWithoutClassifier(_))
        ));
        assert!(matches!(
            RulesetEngines::new(
                vec![bound_unit("a", &["nope"])],
                Some(classifier_with(&["known"]))
            ),
            Err(RulesetEnginesError::UnknownSchema { .. })
        ));
    }

    #[test]
    fn process_event_and_process_batch_agree() {
        let mut single = RulesetEngines::new(
            vec![
                detection_unit("a", Vec::new()),
                detection_unit("b", Vec::new()),
            ],
            None,
        )
        .unwrap();
        let mut batch = RulesetEngines::new(
            vec![
                detection_unit("a", Vec::new()),
                detection_unit("b", Vec::new()),
            ],
            None,
        )
        .unwrap();
        let values = [
            serde_json::json!({"Image": "whoami"}),
            serde_json::json!({"Image": "hostname"}),
        ];
        let events: Vec<JsonEvent> = values.iter().map(JsonEvent::borrow).collect();
        let refs: Vec<&JsonEvent> = events.iter().collect();
        let batched = batch.process_batch(&refs);
        let mut singles = Vec::new();
        for event in &refs {
            singles.push(single.process_event(*event));
        }
        for (single, batch) in singles.iter().zip(&batched) {
            assert_eq!(
                serde_json::to_string(single).unwrap(),
                serde_json::to_string(batch).unwrap()
            );
        }
    }
}
