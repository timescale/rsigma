//! Rule-field extraction shared between `rsigma rule fields` and the daemon's
//! field-observability endpoints.
//!
//! [`RuleFieldSet::collect`] walks a [`SigmaCollection`] (after optional
//! pipeline transformations are applied) and records every field name
//! referenced by detection items, correlation `group-by` / threshold / alias
//! fields, filter detections, and rule-level `fields:` metadata. The result
//! tracks per-field provenance (rule titles + source kinds) so callers can
//! decide whether to surface a finding as a gap signal, a broken-coverage
//! signal, or a coverage summary.
//!
//! The CLI command `rsigma rule fields` and the daemon's
//! `GET /api/v1/fields/*` endpoints share this implementation so the
//! field set the operator inspects offline matches exactly what the engine
//! references at runtime.

use std::collections::{BTreeMap, BTreeSet};

use rsigma_parser::{
    CorrelationCondition, CorrelationRule, Detection, DetectionItem, Detections, FilterRule,
    SigmaCollection, SigmaRule,
};
use serde::Serialize;

use crate::pipeline::{Pipeline, apply_pipelines};

/// Where in a rule a field reference came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldSource {
    /// Field used in a detection condition (`selection`, etc.).
    Detection,
    /// Field used by a correlation rule (group-by, threshold field, alias mapping).
    Correlation,
    /// Field used in a filter rule's detection block.
    Filter,
    /// Field listed in rule-level `fields:` metadata.
    Metadata,
}

impl FieldSource {
    /// Stable string identifier used in JSON serialization and human output.
    pub fn as_str(self) -> &'static str {
        match self {
            FieldSource::Detection => "detection",
            FieldSource::Correlation => "correlation",
            FieldSource::Filter => "filter",
            FieldSource::Metadata => "metadata",
        }
    }
}

/// Provenance for a single field name across the loaded rule set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldOrigin {
    /// Rule titles that reference this field.
    pub rule_titles: BTreeSet<String>,
    /// Source kinds (detection, correlation, filter, metadata) where this
    /// field was seen.
    pub sources: BTreeSet<FieldSource>,
}

/// Set of field names referenced by a loaded `SigmaCollection`, optionally
/// after applying processing pipelines.
///
/// Built via [`RuleFieldSet::collect`] and queried via [`contains`](Self::contains),
/// [`iter`](Self::iter), and [`len`](Self::len). Cheap to clone for sharing
/// across threads behind an `Arc`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFieldSet {
    fields: BTreeMap<String, FieldOrigin>,
}

impl RuleFieldSet {
    /// Walk a rule collection (and any pipelines) and return the resulting
    /// field set. When `pipelines` is non-empty, each rule is cloned and
    /// transformed before its fields are collected so the recorded names
    /// match what the engine evaluates against. Rules whose pipeline
    /// application fails fall back to the untransformed names so the set
    /// stays observable even when a pipeline misfires on one rule.
    ///
    /// `include_filters` controls whether filter-rule detection blocks
    /// contribute to the set; mirrors the existing `--no-filters` flag on
    /// `rsigma rule fields`.
    pub fn collect(
        collection: &SigmaCollection,
        pipelines: &[Pipeline],
        include_filters: bool,
    ) -> Self {
        let mut collector = Collector::default();

        if pipelines.is_empty() {
            for rule in &collection.rules {
                collector.collect_rule(rule);
            }
        } else {
            for rule in &collection.rules {
                let mut transformed = rule.clone();
                if apply_pipelines(pipelines, &mut transformed).is_err() {
                    collector.collect_rule(rule);
                    continue;
                }
                collector.collect_rule(&transformed);
            }
        }

        for corr in &collection.correlations {
            collector.collect_correlation(corr);
        }

        if include_filters {
            for filter in &collection.filters {
                collector.collect_filter(filter);
            }
        }

        Self {
            fields: collector.fields,
        }
    }

    /// True if any rule references this field name.
    pub fn contains(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Look up provenance for a single field name.
    pub fn origin(&self, field: &str) -> Option<&FieldOrigin> {
        self.fields.get(field)
    }

    /// Iterate field names and their provenance in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &FieldOrigin)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Iterate just the field names in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    /// Number of distinct fields in the set.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// True when no fields were collected.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[derive(Default)]
struct Collector {
    fields: BTreeMap<String, FieldOrigin>,
}

impl Collector {
    fn add(&mut self, field: &str, rule_title: &str, source: FieldSource) {
        let entry = self.fields.entry(field.to_string()).or_default();
        entry.rule_titles.insert(rule_title.to_string());
        entry.sources.insert(source);
    }

    fn collect_detection_items(
        &mut self,
        detection: &Detection,
        rule_title: &str,
        source: FieldSource,
    ) {
        match detection {
            Detection::AllOf(items) => {
                for item in items {
                    self.collect_item(item, rule_title, source);
                }
            }
            Detection::AnyOf(subs) => {
                for sub in subs {
                    self.collect_detection_items(sub, rule_title, source);
                }
            }
            Detection::Keywords(_) => {}
        }
    }

    fn collect_item(&mut self, item: &DetectionItem, rule_title: &str, source: FieldSource) {
        if let Some(ref name) = item.field.name {
            self.add(name, rule_title, source);
        }
    }

    fn collect_detections(
        &mut self,
        detections: &Detections,
        rule_title: &str,
        source: FieldSource,
    ) {
        for det in detections.named.values() {
            self.collect_detection_items(det, rule_title, source);
        }
    }

    fn collect_rule(&mut self, rule: &SigmaRule) {
        self.collect_detections(&rule.detection, &rule.title, FieldSource::Detection);
        for f in &rule.fields {
            self.add(f, &rule.title, FieldSource::Metadata);
        }
    }

    fn collect_correlation(&mut self, corr: &CorrelationRule) {
        for f in &corr.group_by {
            self.add(f, &corr.title, FieldSource::Correlation);
        }
        if let CorrelationCondition::Threshold {
            field: Some(ref fields),
            ..
        } = corr.condition
        {
            for f in fields {
                self.add(f, &corr.title, FieldSource::Correlation);
            }
        }
        for alias in &corr.aliases {
            for mapped_field in alias.mapping.values() {
                self.add(mapped_field, &corr.title, FieldSource::Correlation);
            }
        }
        for f in &corr.fields {
            self.add(f, &corr.title, FieldSource::Metadata);
        }
    }

    fn collect_filter(&mut self, filter: &FilterRule) {
        self.collect_detections(&filter.detection, &filter.title, FieldSource::Filter);
        for f in &filter.fields {
            self.add(f, &filter.title, FieldSource::Metadata);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn build(yaml: &str) -> SigmaCollection {
        parse_sigma_yaml(yaml).expect("parse")
    }

    #[test]
    fn collects_detection_fields() {
        let collection = build(
            r#"
title: Test
status: test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
        EventID: 1
    condition: selection
"#,
        );
        let set = RuleFieldSet::collect(&collection, &[], true);
        assert!(set.contains("CommandLine"));
        assert!(set.contains("EventID"));
        assert!(
            set.origin("CommandLine")
                .unwrap()
                .sources
                .contains(&FieldSource::Detection)
        );
    }

    #[test]
    fn collects_correlation_group_by() {
        let collection = build(
            r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
"#,
        );
        let set = RuleFieldSet::collect(&collection, &[], true);
        assert!(set.contains("EventType"));
        assert!(set.contains("User"));
        let user_origin = set.origin("User").unwrap();
        assert!(user_origin.sources.contains(&FieldSource::Correlation));
    }

    #[test]
    fn include_filters_toggle() {
        let collection = build(
            r#"
title: Detection
status: test
logsource:
    category: test
detection:
    selection:
        DetField: x
    condition: selection
---
title: Filter
filter:
    rules:
        - non-existent
    selection:
        FilterField: y
    condition: selection
"#,
        );
        let with_filters = RuleFieldSet::collect(&collection, &[], true);
        let without_filters = RuleFieldSet::collect(&collection, &[], false);
        assert!(with_filters.contains("FilterField"));
        assert!(!without_filters.contains("FilterField"));
        assert!(with_filters.contains("DetField"));
        assert!(without_filters.contains("DetField"));
    }

    #[test]
    fn empty_collection_is_empty_set() {
        let collection = SigmaCollection::default();
        let set = RuleFieldSet::collect(&collection, &[], true);
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }
}
