//! Rule documentation recovered from a rule key.
//!
//! Downstream aggregation (incident grouping, risk accumulation) keeps only a
//! rule *key* per contributing result: the rule id, or the title when the rule
//! has no id. That is enough to count firings but not enough to explain them.
//! [`RuleBundleMetadata`] closes the gap by carrying every field an
//! [ADS](rsigma_parser::ads) document is built from, and the lookup methods on
//! [`Engine`](crate::Engine), [`CorrelationEngine`](crate::CorrelationEngine),
//! and [`SchemaRouter`](crate::SchemaRouter) resolve a key back to it.
//!
//! Two rules can share a key, and a routed rule set compiles the same rule once
//! per pipeline-set, so a lookup answers with [`RuleMetadataLookup`] rather than
//! a bare `Option`: variants that are byte-identical collapse to
//! [`Unique`](RuleMetadataLookup::Unique), and genuinely differing ones stay
//! visible as [`Ambiguous`](RuleMetadataLookup::Ambiguous) instead of silently
//! resolving to whichever was compiled first.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_parser::Level;
use rsigma_parser::ads::{AdsCarriers, AdsContent};
use serde::Serialize;

use crate::compiler::CompiledRule;
use crate::correlation::CompiledCorrelation;

/// Which kind of rule a metadata entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// A stateless detection rule.
    Detection,
    /// A stateful correlation rule.
    Correlation,
}

/// A rule's identity: its kind plus the id and title it is known by.
///
/// Kept structured rather than flattened to a single string so a detection rule
/// and a correlation rule that happen to share a key stay distinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleIdentity {
    /// Whether this is a detection or a correlation rule.
    pub kind: RuleKind,
    /// The rule's `id`, when it declares one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The rule's `title`.
    pub title: String,
}

impl RuleIdentity {
    /// The key downstream aggregation groups this rule under: the id, falling
    /// back to the title. Mirrors how a result header is reduced to a rule key.
    pub fn key(&self) -> &str {
        self.id.as_deref().unwrap_or(&self.title)
    }
}

/// Everything needed to document one rule away from the engine that compiled
/// it: its identity, its severity and tags, and the three standard fields plus
/// `rsigma.ads.*` attributes an ADS document is assembled from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleBundleMetadata {
    /// The rule's kind, id, and title.
    pub identity: RuleIdentity,
    /// The rule's `level`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    /// The rule's `tags` (the ADS categorization carrier).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The rule's `description` (the ADS goal carrier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The rule's `falsepositives` (the ADS false-positives carrier).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub falsepositives: Vec<String>,
    /// The rule's custom attributes, post-pipeline. Carries the six
    /// `rsigma.ads.*` sections that have no standard Sigma field.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

impl AdsCarriers for RuleBundleMetadata {
    fn ads_description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn ads_tags(&self) -> &[String] {
        &self.tags
    }

    fn ads_falsepositives(&self) -> &[String] {
        &self.falsepositives
    }

    fn ads_custom_attribute(&self, key: &str) -> Option<AdsContent> {
        self.custom_attributes
            .get(key)
            .and_then(AdsContent::from_json)
    }

    fn ads_match_exemplar_count(&self) -> usize {
        rsigma_parser::match_exemplar_count_json(&self.custom_attributes)
    }
}

/// The outcome of resolving a rule key to metadata.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleMetadataLookup {
    /// No loaded rule carries the key. Expected when an incident outlives the
    /// rule that opened it across a reload.
    Missing,
    /// Exactly one distinct metadata document carries the key.
    Unique(Box<RuleBundleMetadata>),
    /// Several rules carry the key with differing metadata, in the order the
    /// engines were built. Callers must decide how to present the conflict
    /// rather than being handed an arbitrary one.
    Ambiguous(Vec<RuleBundleMetadata>),
}

impl RuleMetadataLookup {
    /// Collapse candidate variants into a lookup outcome, treating identical
    /// documents as one. Routed rule sets compile the same rule once per
    /// pipeline-set, so most keys yield several byte-identical candidates.
    pub fn from_variants(variants: Vec<RuleBundleMetadata>) -> Self {
        let mut distinct: Vec<RuleBundleMetadata> = Vec::new();
        for variant in variants {
            if !distinct.contains(&variant) {
                distinct.push(variant);
            }
        }
        match distinct.len() {
            0 => RuleMetadataLookup::Missing,
            1 => RuleMetadataLookup::Unique(Box::new(distinct.remove(0))),
            _ => RuleMetadataLookup::Ambiguous(distinct),
        }
    }

    /// Every candidate document, empty when the key is unknown.
    pub fn variants(&self) -> &[RuleBundleMetadata] {
        match self {
            RuleMetadataLookup::Missing => &[],
            RuleMetadataLookup::Unique(one) => std::slice::from_ref(one),
            RuleMetadataLookup::Ambiguous(many) => many,
        }
    }
}

impl CompiledRule {
    /// This rule's identity as a detection rule.
    pub fn identity(&self) -> RuleIdentity {
        RuleIdentity {
            kind: RuleKind::Detection,
            id: self.id.clone(),
            title: self.title.clone(),
        }
    }

    /// The documentation fields a downstream consumer needs to explain a match.
    pub fn bundle_metadata(&self) -> RuleBundleMetadata {
        RuleBundleMetadata {
            identity: self.identity(),
            level: self.level,
            tags: self.tags.clone(),
            description: self.description.clone(),
            falsepositives: self.falsepositives.clone(),
            custom_attributes: Arc::clone(&self.custom_attributes),
        }
    }
}

impl CompiledCorrelation {
    /// This correlation's identity.
    pub fn identity(&self) -> RuleIdentity {
        RuleIdentity {
            kind: RuleKind::Correlation,
            id: self.id.clone(),
            title: self.title.clone(),
        }
    }

    /// The documentation fields a downstream consumer needs to explain a
    /// firing.
    pub fn bundle_metadata(&self) -> RuleBundleMetadata {
        RuleBundleMetadata {
            identity: self.identity(),
            level: self.level,
            tags: self.tags.clone(),
            description: self.description.clone(),
            falsepositives: self.falsepositives.clone(),
            custom_attributes: Arc::clone(&self.custom_attributes),
        }
    }
}

/// Candidate metadata from the rules in `rules` whose own key matches `key`.
///
/// Matching on each rule's *own* derived key (rather than testing id and title
/// separately) is what keeps a rule whose title equals another rule's id out of
/// the answer.
pub(crate) fn matching_detections<'a>(
    rules: impl IntoIterator<Item = &'a CompiledRule>,
    key: &str,
    out: &mut Vec<RuleBundleMetadata>,
) {
    for rule in rules {
        if rule.id.as_deref().unwrap_or(&rule.title) == key {
            out.push(rule.bundle_metadata());
        }
    }
}

/// Candidate metadata from the correlations whose own key matches `key`.
pub(crate) fn matching_correlations<'a>(
    correlations: impl IntoIterator<Item = &'a CompiledCorrelation>,
    key: &str,
    out: &mut Vec<RuleBundleMetadata>,
) {
    for corr in correlations {
        if corr.id.as_deref().unwrap_or(&corr.title) == key {
            out.push(corr.bundle_metadata());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation_engine::{CorrelationConfig, CorrelationEngine};
    use crate::engine::Engine;
    use crate::pipeline::parse_pipeline;
    use crate::router::SchemaRouter;
    use crate::schema::{OnUnknown, RoutingConfig, RoutingPlan, SchemaBinding, SchemaClassifier};
    use rsigma_parser::ads::AdsDocument;
    use rsigma_parser::parse_sigma_yaml;

    const DOCUMENTED: &str = r#"
title: Whoami execution
id: rule-whoami
description: Detects whoami execution, a common discovery step.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
falsepositives:
    - Administrators enumerating their own privileges
tags:
    - attack.discovery
    - attack.t1033
custom_attributes:
    rsigma.ads.strategy: Watch process creation for the whoami binary.
    rsigma.ads.technical_context: Requires process_creation telemetry.
    rsigma.ads.blind_spots:
        - A renamed binary evades the command-line match.
    rsigma.ads.validation: Run whoami in a lab and confirm the rule fires.
    rsigma.ads.priority: High because discovery precedes lateral movement.
    rsigma.ads.response:
        - Confirm the user and host.
"#;

    fn engine(yaml: &str) -> Engine {
        let mut engine = Engine::new();
        engine
            .add_collection(&parse_sigma_yaml(yaml).unwrap())
            .unwrap();
        engine
    }

    #[test]
    fn a_detection_rule_resolves_by_its_id() {
        let engine = engine(DOCUMENTED);
        let RuleMetadataLookup::Unique(meta) = engine.rule_metadata("rule-whoami") else {
            panic!("expected a unique match");
        };
        assert_eq!(meta.identity.kind, RuleKind::Detection);
        assert_eq!(meta.identity.title, "Whoami execution");
        assert_eq!(meta.identity.key(), "rule-whoami");
    }

    #[test]
    fn every_ads_section_survives_compilation() {
        let engine = engine(DOCUMENTED);
        let RuleMetadataLookup::Unique(meta) = engine.rule_metadata("rule-whoami") else {
            panic!("expected a unique match");
        };
        let doc = AdsDocument::from_carriers(meta.as_ref());
        assert!(
            doc.missing_required().is_empty(),
            "missing: {:?}",
            doc.missing_required()
        );
    }

    #[test]
    fn a_rule_without_an_id_resolves_by_its_title() {
        let engine = engine(
            r#"
title: Untitled discovery
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: whoami
    condition: selection
"#,
        );
        assert!(matches!(
            engine.rule_metadata("Untitled discovery"),
            RuleMetadataLookup::Unique(_)
        ));
    }

    #[test]
    fn a_title_matching_another_rules_id_does_not_cross_match() {
        // The second rule's title is the first rule's id. Only the rule whose
        // own derived key is `rule-whoami` may answer, and the second rule has
        // an id of its own so its title is never its key.
        let engine = engine(&format!(
            "{DOCUMENTED}---
title: rule-whoami
id: rule-decoy
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: decoy
    condition: selection
"
        ));
        let RuleMetadataLookup::Unique(meta) = engine.rule_metadata("rule-whoami") else {
            panic!("expected a unique match");
        };
        assert_eq!(meta.identity.title, "Whoami execution");
    }

    #[test]
    fn an_unknown_key_is_missing() {
        let engine = engine(DOCUMENTED);
        assert_eq!(
            engine.rule_metadata("rule-absent"),
            RuleMetadataLookup::Missing
        );
    }

    #[test]
    fn a_correlation_resolves_alongside_the_detections_it_references() {
        let yaml = format!(
            "{DOCUMENTED}---
title: Repeated whoami
id: corr-whoami
description: Fires when whoami runs repeatedly for one user.
correlation:
    type: event_count
    rules:
        - rule-whoami
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: critical
"
        );
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine
            .add_collection(&parse_sigma_yaml(&yaml).unwrap())
            .unwrap();

        let RuleMetadataLookup::Unique(corr) = engine.rule_metadata("corr-whoami") else {
            panic!("expected a unique correlation match");
        };
        assert_eq!(corr.identity.kind, RuleKind::Correlation);
        assert_eq!(
            corr.description.as_deref(),
            Some("Fires when whoami runs repeatedly for one user.")
        );

        let RuleMetadataLookup::Unique(detection) = engine.rule_metadata("rule-whoami") else {
            panic!("expected a unique detection match");
        };
        assert_eq!(detection.identity.kind, RuleKind::Detection);
    }

    fn router(pipelines: Vec<Vec<crate::pipeline::Pipeline>>, names: &[&str]) -> SchemaRouter {
        let plan = RoutingPlan::from_config(&RoutingConfig {
            on_unknown: OnUnknown::Warn,
            default_pipelines: vec![],
            aliases: std::collections::HashMap::new(),
            bindings: names
                .iter()
                .map(|n| SchemaBinding {
                    schema: (*n).to_string(),
                    pipelines: vec![(*n).to_string()],
                    logsource: None,
                })
                .collect(),
        });
        SchemaRouter::build(
            &parse_sigma_yaml(DOCUMENTED).unwrap(),
            SchemaClassifier::builtin(),
            plan,
            pipelines,
            CorrelationConfig::default(),
            false,
            crate::result::MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap()
    }

    #[test]
    fn identical_per_schema_variants_collapse_to_one_answer() {
        // A field-mapping pipeline rewrites detection fields but leaves the
        // documentation alone, so every per-schema copy documents identically.
        let ecs = parse_pipeline(
            r#"
name: ecs
priority: 20
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#,
        )
        .unwrap();
        let router = router(vec![vec![], vec![ecs]], &["ecs"]);
        assert!(matches!(
            router.rule_metadata("rule-whoami"),
            RuleMetadataLookup::Unique(_)
        ));
    }

    #[test]
    fn per_schema_documentation_differences_stay_visible() {
        // This pipeline rewrites the response section for its schema only, so
        // the two copies genuinely disagree and neither may be picked blindly.
        let ecs = parse_pipeline(
            r#"
name: ecs
priority: 20
transformations:
  - id: response
    type: set_custom_attribute
    attribute: rsigma.ads.response
    value: Escalate to the cloud on-call rotation.
"#,
        )
        .unwrap();
        let router = router(vec![vec![], vec![ecs]], &["ecs"]);
        let RuleMetadataLookup::Ambiguous(variants) = router.rule_metadata("rule-whoami") else {
            panic!("expected the per-schema documents to differ");
        };
        assert_eq!(variants.len(), 2);
    }
}
