//! Incident bundle assembly.
//!
//! An open incident on its own is a fingerprint, some counters, and a list of
//! rule keys. That is enough to page someone and not much else. A bundle is the
//! same incident joined to the two things an analyst reaches for next: the
//! [ADS](rsigma_parser::ads) documentation of every rule that contributed, and
//! the risk entities the incident overlaps.
//!
//! Assembly is pure. [`build`] takes snapshots of each component and a
//! generation timestamp, so a bundle is fully determined by its inputs and the
//! HTTP layer decides how (and how consistently) those snapshots are taken.

use std::collections::{BTreeMap, HashSet};

use rsigma_eval::{RuleIdentity, RuleMetadataLookup};
use rsigma_parser::Level;
use rsigma_parser::ads::{AdsContent, AdsDocument};
use rsigma_runtime::alert_pipeline::IncidentResult;
use rsigma_runtime::risk::RiskEntityView;
use serde::Serialize;
use serde_json::Value;

/// The bundle wire-format version. Bumped when a field is removed or changes
/// meaning; additive fields do not bump it.
pub(super) const SCHEMA_VERSION: u32 = 1;

/// Requested rendering of a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BundleFormat {
    /// The full structured document.
    Json,
    /// A human-readable report rendered from the same document.
    Markdown,
}

impl BundleFormat {
    /// Parse the `format` query parameter.
    pub(super) fn parse(value: &str) -> Option<BundleFormat> {
        match value {
            "json" => Some(BundleFormat::Json),
            "markdown" | "md" => Some(BundleFormat::Markdown),
            _ => None,
        }
    }

    /// The `Content-Type` a rendered bundle is served with.
    pub(super) fn content_type(self) -> &'static str {
        match self {
            BundleFormat::Json => "application/json",
            BundleFormat::Markdown => "text/markdown; charset=utf-8",
        }
    }
}

/// A self-contained incident report.
#[derive(Debug, Clone, Serialize)]
pub(super) struct IncidentBundle {
    /// The bundle wire-format version.
    pub schema_version: u32,
    /// When the bundle was assembled (RFC 3339). Injected by the caller so a
    /// bundle is reproducible from its inputs.
    pub generated_at: String,
    /// Which components the bundle could consult. A component that is not
    /// configured is reported here rather than being silently empty.
    pub sources: BundleSources,
    /// The incident snapshot the bundle documents.
    pub incident: IncidentResult,
    /// One entry per contributing rule key, in the incident's own key order.
    pub rules: Vec<BundleRule>,
    /// Risk entities the incident overlaps. Absent when no risk accumulator is
    /// configured, which is not the same as an incident with no risk overlap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<Vec<BundleRiskEntity>>,
}

/// Which components contributed to a bundle.
#[derive(Debug, Clone, Copy, Serialize)]
pub(super) struct BundleSources {
    /// Whether rule documentation was resolved against the loaded rule set.
    pub rules: bool,
    /// Whether a risk accumulator was configured and consulted.
    pub risk: bool,
}

/// How a rule key resolved against the loaded rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RuleResolution {
    /// Exactly one rule carries the key.
    Unique,
    /// Several loaded rules carry the key with differing documentation.
    Ambiguous,
    /// No loaded rule carries the key, usually because the rule set changed
    /// while the incident was open.
    Missing,
}

/// One contributing rule key, with whatever documentation it resolved to.
#[derive(Debug, Clone, Serialize)]
pub(super) struct BundleRule {
    /// The key the incident recorded: a rule id, or a title for a rule without
    /// one.
    pub key: String,
    /// How many contributing results this key accounts for.
    pub count: u64,
    /// How the key resolved.
    pub resolution: RuleResolution,
    /// The resolved documentation: empty when missing, one entry when unique,
    /// and one per differing rule when ambiguous.
    pub documents: Vec<BundleRuleDocument>,
}

/// One rule's documentation.
#[derive(Debug, Clone, Serialize)]
pub(super) struct BundleRuleDocument {
    /// The rule's kind, id, and title.
    pub identity: RuleIdentity,
    /// The rule's severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    /// The rule's tags.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The nine-section ADS document assembled from the rule's carriers.
    pub ads: AdsDocument,
}

/// How a risk entity was tied to the incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RiskMatch {
    /// A retained result named the entity in its `risk.objects` enrichment, so
    /// the type and the value both come from the risk layer.
    RiskObject,
    /// The incident's own grouping key names the entity. Used when the
    /// incident retained only references, which carry no enrichments.
    GroupKey,
}

/// A risk entity the incident overlaps.
#[derive(Debug, Clone, Serialize)]
pub(super) struct BundleRiskEntity {
    /// How the entity was tied to the incident.
    pub matched_on: RiskMatch,
    /// The open-entity view from the risk accumulator.
    #[serde(flatten)]
    pub entity: RiskEntityView,
}

/// Assemble a bundle from component snapshots.
///
/// `metadata` is expected to answer for every key in the incident's
/// `rule_counts`; a key it does not answer for resolves as
/// [`RuleResolution::Missing`]. `risk` is `None` when no risk accumulator is
/// configured.
pub(super) fn build(
    incident: IncidentResult,
    metadata: &BTreeMap<String, RuleMetadataLookup>,
    risk: Option<&[RiskEntityView]>,
    generated_at: String,
) -> IncidentBundle {
    let rules = incident
        .rule_counts
        .iter()
        .map(|(key, count)| build_rule(key, *count, metadata.get(key)))
        .collect();

    let matched_risk = risk.map(|entities| match_risk(&incident, entities));

    IncidentBundle {
        schema_version: SCHEMA_VERSION,
        generated_at,
        sources: BundleSources {
            rules: true,
            risk: risk.is_some(),
        },
        incident,
        rules,
        risk: matched_risk,
    }
}

fn build_rule(key: &str, count: u64, lookup: Option<&RuleMetadataLookup>) -> BundleRule {
    let lookup = lookup.unwrap_or(&RuleMetadataLookup::Missing);
    let resolution = match lookup {
        RuleMetadataLookup::Missing => RuleResolution::Missing,
        RuleMetadataLookup::Unique(_) => RuleResolution::Unique,
        RuleMetadataLookup::Ambiguous(_) => RuleResolution::Ambiguous,
    };
    let documents = lookup
        .variants()
        .iter()
        .map(|meta| BundleRuleDocument {
            identity: meta.identity.clone(),
            level: meta.level,
            tags: meta.tags.clone(),
            ads: AdsDocument::from_carriers(meta),
        })
        .collect();
    BundleRule {
        key: key.to_string(),
        count,
        resolution,
        documents,
    }
}

/// Select the risk entities the incident overlaps.
///
/// Preference order matters. A retained result's `risk.objects` enrichment
/// names both the entity type and its value, so it is an exact join. An
/// incident holding only references has no enrichments to read, and the only
/// evidence left is its own grouping key, which names a field rather than a
/// risk-object type. Matching a bare value against every entity would tie the
/// user `alice` to the host `alice`, so the fallback requires the field's last
/// path segment to name the entity type as well.
fn match_risk(incident: &IncidentResult, entities: &[RiskEntityView]) -> Vec<BundleRiskEntity> {
    // Sets, not vectors: the accumulator can hold `max_open_entities` (100k by
    // default) and an incident can retain `max_results_per_incident` samples,
    // so a linear membership test would make this quadratic in two operator
    // caps at once.
    let exact = risk_objects(incident);
    let from_grouping = group_key_names(incident);
    let mut out = Vec::new();
    for entity in entities {
        let pair = (entity.entity_type.as_str(), entity.entity_value.as_str());
        let matched = if exact.contains(&pair) {
            Some(RiskMatch::RiskObject)
        } else if from_grouping.contains(&(entity.entity_type.to_lowercase(), pair.1.to_string())) {
            Some(RiskMatch::GroupKey)
        } else {
            None
        };
        if let Some(matched_on) = matched {
            out.push(BundleRiskEntity {
                matched_on,
                entity: entity.clone(),
            });
        }
    }
    out
}

/// The `(type, value)` pairs named by the retained results' `risk.objects`
/// enrichments.
///
/// Borrowed from the incident, which outlives the match.
fn risk_objects(incident: &IncidentResult) -> HashSet<(&str, &str)> {
    let mut out = HashSet::new();
    let Some(results) = &incident.results else {
        return out;
    };
    for result in results {
        let Some(objects) = result
            .get("enrichments")
            .and_then(|e| e.get("risk.objects"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for object in objects {
            let (Some(object_type), Some(value)) = (
                object.get("type").and_then(Value::as_str),
                object.get("value").and_then(Value::as_str),
            ) else {
                continue;
            };
            out.insert((object_type, value));
        }
    }
    out
}

/// The `(type, value)` pairs the incident's own grouping names, reading each
/// selector's last path segment as a candidate risk-object type.
///
/// The segment is lowercased because it is a field name (`event.User`) being
/// compared against an operator-declared risk-object type (`user`), and the two
/// are not written in the same case.
fn group_key_names(incident: &IncidentResult) -> HashSet<(String, String)> {
    let mut out = HashSet::new();
    let mut push = |selector: &str, value: &Value| {
        let Some(value) = value.as_str() else {
            return;
        };
        let Some(segment) = selector.rsplit('.').next() else {
            return;
        };
        out.insert((segment.to_lowercase(), value.to_string()));
    };
    for (selector, value) in &incident.group_by {
        push(selector, value);
    }
    for (selector, values) in &incident.entities {
        for value in values.as_array().into_iter().flatten() {
            push(selector, value);
        }
    }
    out
}

// =============================================================================
// Markdown rendering
// =============================================================================

/// Render a bundle as a human-readable report.
///
/// Every fact in the report comes from the JSON document, so the two renderings
/// never disagree about what the incident contains.
pub(super) fn render_markdown(bundle: &IncidentBundle) -> String {
    let mut out = String::new();
    let incident = &bundle.incident;

    out.push_str(&format!("# Incident {}\n\n", incident.incident_id));
    out.push_str(&format!("- Generated: {}\n", bundle.generated_at));
    out.push_str(&format!("- State: {}\n", incident.state));
    if let Some(level) = &incident.max_level {
        out.push_str(&format!("- Highest severity: {level}\n"));
    }
    out.push_str(&format!(
        "- Window: {} to {}\n",
        timestamp(incident.first_seen),
        timestamp(incident.last_seen)
    ));
    out.push_str(&format!(
        "- Contributing results: {}\n",
        incident.result_count
    ));
    if let Some(mode) = incident.sample_mode {
        out.push_str(&format!(
            "- Retained samples: {}\n",
            serde_json::to_value(mode)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        ));
    }
    if incident.bundle_ready == Some(false) {
        out.push_str("- Note: still inside `group_wait`, so the incident has not been reported yet and may still change.\n");
    }
    out.push('\n');

    if !incident.group_by.is_empty() {
        out.push_str("## Grouping\n\n");
        for (selector, value) in &incident.group_by {
            out.push_str(&format!("- `{selector}`: {}\n", scalar(value)));
        }
        out.push('\n');
    }

    if !incident.entities.is_empty() {
        out.push_str("## Entities\n\n");
        for (selector, values) in &incident.entities {
            let joined: Vec<String> = values
                .as_array()
                .into_iter()
                .flatten()
                .map(scalar)
                .collect();
            out.push_str(&format!("- `{selector}`: {}\n", joined.join(", ")));
        }
        out.push('\n');
    }

    out.push_str("## Contributing rules\n\n");
    for rule in &bundle.rules {
        render_rule(&mut out, rule);
    }

    match &bundle.risk {
        None => {
            out.push_str("## Risk\n\nNo risk accumulator is configured.\n\n");
        }
        Some(entities) if entities.is_empty() => {
            out.push_str("## Risk\n\nNo tracked risk entity overlaps this incident.\n\n");
        }
        Some(entities) => {
            out.push_str("## Risk\n\n");
            for entry in entities {
                let entity = &entry.entity;
                out.push_str(&format!(
                    "### {}: {}\n\n",
                    entity.entity_type, entity.entity_value
                ));
                out.push_str(&format!("- Score: {}\n", entity.score));
                out.push_str(&format!("- Distinct tactics: {}\n", entity.tactic_count));
                out.push_str(&format!(
                    "- Contributing sources: {}\n",
                    entity.source_count
                ));
                out.push_str(&format!(
                    "- Window: {} to {}\n",
                    timestamp(entity.window_start),
                    timestamp(entity.window_end)
                ));
                out.push_str(&format!(
                    "- Matched on: {}\n\n",
                    match entry.matched_on {
                        RiskMatch::RiskObject => "a contributing result's risk objects",
                        RiskMatch::GroupKey => "the incident grouping key",
                    }
                ));
            }
        }
    }

    out
}

fn render_rule(out: &mut String, rule: &BundleRule) {
    out.push_str(&format!(
        "### `{}` ({} result{})\n\n",
        rule.key,
        rule.count,
        if rule.count == 1 { "" } else { "s" }
    ));

    match rule.resolution {
        RuleResolution::Missing => {
            out.push_str(
                "No loaded rule carries this key. The rule set most likely changed while the \
                 incident was open.\n\n",
            );
            return;
        }
        RuleResolution::Ambiguous => {
            out.push_str(&format!(
                "{} loaded rules carry this key with differing documentation. All are shown.\n\n",
                rule.documents.len()
            ));
        }
        RuleResolution::Unique => {}
    }

    for document in &rule.documents {
        out.push_str(&format!("**{}**\n\n", document.identity.title));
        if let Some(level) = document.level {
            out.push_str(&format!("- Level: {}\n", level.as_str()));
        }
        if !document.tags.is_empty() {
            out.push_str(&format!("- Tags: {}\n", document.tags.join(", ")));
        }
        out.push('\n');

        if document.ads.is_empty() {
            out.push_str("This rule carries no ADS documentation.\n\n");
            continue;
        }
        for section in &document.ads.sections {
            let Some(content) = &section.content else {
                continue;
            };
            out.push_str(&format!("*{}*\n\n", heading(section.id)));
            match content {
                AdsContent::Text(text) => out.push_str(&format!("{text}\n\n")),
                AdsContent::List(items) => {
                    for item in items {
                        out.push_str(&format!("- {item}\n"));
                    }
                    out.push('\n');
                }
            }
        }
    }
}

/// A section id rendered as a heading (`blind_spots` becomes `Blind spots`).
fn heading(id: &str) -> String {
    let spaced = id.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => spaced,
    }
}

/// A JSON value rendered for prose: strings unquoted, everything else as JSON.
fn scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A Unix timestamp rendered for a reader.
///
/// The JSON bundle keeps epoch seconds, matching every other timestamp the API
/// serves, but nobody reads a window off two ten-digit integers. Falls back to
/// the raw number if the value is not a representable time.
fn timestamp(seconds: i64) -> String {
    match chrono::DateTime::from_timestamp(seconds, 0) {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => seconds.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{RuleBundleMetadata, RuleKind};
    use rsigma_runtime::alert_pipeline::{IncidentRef, SampleMode};
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// A fixed generation time, so a golden is the same bytes on every run.
    const GENERATED_AT: &str = "2026-07-26T12:00:00Z";

    fn documented(id: &str, title: &str) -> RuleMetadataLookup {
        RuleMetadataLookup::Unique(Box::new(RuleBundleMetadata {
            identity: RuleIdentity {
                kind: RuleKind::Detection,
                id: Some(id.to_string()),
                title: title.to_string(),
            },
            level: Some(Level::High),
            tags: vec!["attack.discovery".to_string(), "attack.t1033".to_string()],
            description: Some("Detects whoami execution, a common discovery step.".to_string()),
            falsepositives: vec!["Administrators enumerating their own privileges".to_string()],
            custom_attributes: Arc::new(
                [
                    (
                        "rsigma.ads.strategy".to_string(),
                        json!("Watch process creation for the whoami binary."),
                    ),
                    (
                        "rsigma.ads.technical_context".to_string(),
                        json!("Requires process_creation telemetry with CommandLine."),
                    ),
                    (
                        "rsigma.ads.blind_spots".to_string(),
                        json!(["A renamed binary evades the command-line match."]),
                    ),
                    (
                        "rsigma.ads.validation".to_string(),
                        json!("Run whoami in a lab and confirm the rule fires."),
                    ),
                    (
                        "rsigma.ads.priority".to_string(),
                        json!("High because discovery precedes lateral movement."),
                    ),
                    (
                        "rsigma.ads.response".to_string(),
                        json!([
                            "Confirm the user and host.",
                            "Correlate with other discovery."
                        ]),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        }))
    }

    fn retained_result(rule: &str, objects: Value) -> Value {
        json!({
            "rule_title": rule,
            "rule_id": rule,
            "level": "high",
            "enrichments": { "risk.score": 60, "risk.objects": objects },
            "matched_fields": [{ "field": "User", "value": "alice" }],
        })
    }

    fn incident() -> IncidentResult {
        IncidentResult {
            incident_id: "f8bcd62a829b1126".to_string(),
            state: "open",
            trigger: "snapshot",
            first_seen: 1_767_225_000,
            last_seen: 1_767_225_600,
            max_level: Some("high".to_string()),
            result_count: 3,
            rule_counts: BTreeMap::from([
                ("rule-whoami".to_string(), 2),
                ("rule-retired".to_string(), 1),
            ]),
            group_by: serde_json::Map::from_iter([("match.User".to_string(), json!("alice"))]),
            entities: serde_json::Map::new(),
            refs: None,
            results: Some(vec![retained_result(
                "rule-whoami",
                json!([{ "type": "user", "value": "alice" }]),
            )]),
            sample_mode: Some(SampleMode::Results),
            bundle_ready: Some(true),
        }
    }

    fn metadata() -> BTreeMap<String, RuleMetadataLookup> {
        BTreeMap::from([
            (
                "rule-whoami".to_string(),
                documented("rule-whoami", "Whoami execution"),
            ),
            ("rule-retired".to_string(), RuleMetadataLookup::Missing),
        ])
    }

    fn entity(entity_type: &str, entity_value: &str, score: i64) -> RiskEntityView {
        RiskEntityView {
            entity_type: entity_type.to_string(),
            entity_value: entity_value.to_string(),
            score,
            tactic_count: 2,
            source_count: 2,
            result_count: 3,
            window_start: 1_767_225_000,
            window_end: 1_767_225_600,
            last_fired: None,
        }
    }

    fn sample_bundle() -> IncidentBundle {
        build(
            incident(),
            &metadata(),
            Some(&[
                entity("user", "alice", 120),
                entity("host", "alice", 200),
                entity("user", "bob", 40),
            ]),
            GENERATED_AT.to_string(),
        )
    }

    // -- assembly -----------------------------------------------------------

    #[test]
    fn every_contributing_rule_key_gets_an_entry() {
        let bundle = sample_bundle();
        let keys: Vec<&str> = bundle.rules.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["rule-retired", "rule-whoami"]);
        assert_eq!(bundle.rules[0].resolution, RuleResolution::Missing);
        assert!(bundle.rules[0].documents.is_empty());
        assert_eq!(bundle.rules[1].resolution, RuleResolution::Unique);
        assert_eq!(bundle.rules[1].count, 2);
    }

    #[test]
    fn a_documented_rule_carries_its_full_ads_document() {
        let bundle = sample_bundle();
        let ads = &bundle.rules[1].documents[0].ads;
        assert!(
            ads.missing_required().is_empty(),
            "{:?}",
            ads.missing_required()
        );
    }

    #[test]
    fn a_risk_entity_must_match_on_type_as_well_as_value() {
        let bundle = sample_bundle();
        let matched: Vec<(&str, &str)> = bundle
            .risk
            .as_ref()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e.entity.entity_type.as_str(),
                    e.entity.entity_value.as_str(),
                )
            })
            .collect();
        // The host named `alice` shares the incident's value but not its type,
        // and `bob` shares neither.
        assert_eq!(matched, [("user", "alice")]);
        assert_eq!(
            bundle.risk.as_ref().unwrap()[0].matched_on,
            RiskMatch::RiskObject
        );
    }

    #[test]
    fn a_refs_only_incident_falls_back_to_its_grouping_key() {
        let mut incident = incident();
        incident.results = None;
        incident.refs = Some(vec![IncidentRef {
            rule: "rule-whoami".to_string(),
            level: Some("high".to_string()),
        }]);
        incident.sample_mode = Some(SampleMode::Refs);

        let bundle = build(
            incident,
            &metadata(),
            Some(&[entity("user", "alice", 120), entity("host", "alice", 200)]),
            GENERATED_AT.to_string(),
        );
        let risk = bundle.risk.unwrap();
        assert_eq!(risk.len(), 1);
        assert_eq!(risk[0].entity.entity_type, "user");
        assert_eq!(risk[0].matched_on, RiskMatch::GroupKey);
    }

    #[test]
    fn the_grouping_fallback_ignores_the_case_of_the_entity_type() {
        // The selector names a field (`match.User`) and the risk layer names a
        // type the operator declared. Nothing forces the two to agree on case,
        // so a `User` entity must still join a `match.User` grouping key.
        let mut incident = incident();
        incident.results = None;
        incident.sample_mode = Some(SampleMode::Refs);

        let bundle = build(
            incident,
            &metadata(),
            Some(&[entity("User", "alice", 120)]),
            GENERATED_AT.to_string(),
        );
        let risk = bundle.risk.unwrap();
        assert_eq!(risk.len(), 1, "a differently-cased type must still join");
        assert_eq!(risk[0].matched_on, RiskMatch::GroupKey);
    }

    #[test]
    fn an_unconfigured_risk_layer_is_reported_rather_than_shown_as_empty() {
        let bundle = build(incident(), &metadata(), None, GENERATED_AT.to_string());
        assert!(bundle.risk.is_none());
        assert!(!bundle.sources.risk);
        assert!(render_markdown(&bundle).contains("No risk accumulator is configured."));
    }

    #[test]
    fn ambiguous_documentation_is_shown_in_full() {
        let mut variants = Vec::new();
        for response in ["Page the host on-call.", "Page the cloud on-call."] {
            let RuleMetadataLookup::Unique(mut meta) =
                documented("rule-whoami", "Whoami execution")
            else {
                unreachable!()
            };
            let mut attributes = (*meta.custom_attributes).clone();
            attributes.insert("rsigma.ads.response".to_string(), json!(response));
            meta.custom_attributes = Arc::new(attributes);
            variants.push(*meta);
        }
        let metadata = BTreeMap::from([(
            "rule-whoami".to_string(),
            RuleMetadataLookup::from_variants(variants),
        )]);

        let mut incident = incident();
        incident.rule_counts = BTreeMap::from([("rule-whoami".to_string(), 2)]);
        let bundle = build(incident, &metadata, None, GENERATED_AT.to_string());

        assert_eq!(bundle.rules[0].resolution, RuleResolution::Ambiguous);
        assert_eq!(bundle.rules[0].documents.len(), 2);
        let markdown = render_markdown(&bundle);
        assert!(markdown.contains("Page the host on-call."));
        assert!(markdown.contains("Page the cloud on-call."));
    }

    #[test]
    fn a_batching_incident_is_flagged_in_the_report() {
        let mut incident = incident();
        incident.bundle_ready = Some(false);
        let bundle = build(incident, &metadata(), None, GENERATED_AT.to_string());
        assert!(render_markdown(&bundle).contains("group_wait"));
    }

    // -- goldens ------------------------------------------------------------

    fn golden_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(name)
    }

    /// Rebuild every object with its keys sorted, so a golden stays valid under
    /// both `serde_json` map orderings (`preserve_order` is feature-unified on
    /// in some workspace builds and off in others).
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|key| (key.clone(), canonical(&map[key])))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }

    /// Compare rendered output to its committed golden.
    ///
    /// Set `RSIGMA_UPDATE_GOLDEN=1` to rewrite the goldens after an
    /// intentional change.
    fn check_golden(name: &str, actual: &str) {
        let path = golden_path(name);
        if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(actual, expected, "bundle golden drifted for '{name}'");
    }

    #[test]
    fn json_bundle_matches_golden() {
        let value = serde_json::to_value(sample_bundle()).unwrap();
        let actual = format!(
            "{}\n",
            serde_json::to_string_pretty(&canonical(&value)).unwrap()
        );
        check_golden("incident_bundle.json", &actual);
    }

    #[test]
    fn markdown_bundle_matches_golden() {
        check_golden("incident_bundle.md", &render_markdown(&sample_bundle()));
    }
}
