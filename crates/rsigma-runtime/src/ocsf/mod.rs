//! OCSF Detection Finding (class 2004) serialization.
//!
//! Renders the three finding shapes rsigma emits, [`EvaluationResult`]
//! (detections and correlations), [`IncidentResult`], and
//! [`RiskIncidentResult`], as OCSF Detection Finding JSON objects so findings
//! land natively in the tools that standardized on OCSF. Selected per sink
//! with `?format=ocsf` on a line-oriented sink spec; the native NDJSON shapes
//! are unchanged and remain the default.
//!
//! The mapping is deliberately conservative. Everything with a faithful OCSF
//! home moves there; everything else rides under `unmapped` with its native
//! key, so a consumer reading OCSF loses nothing relative to the native line.
//! The serializer is output-only: nothing here deserializes OCSF, and rsigma
//! still ingests and evaluates events in whatever schema they arrive in.
//!
//! ```
//! use rsigma_runtime::ocsf;
//! # use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
//! # use std::{collections::HashMap, sync::Arc};
//! # let result = EvaluationResult {
//! #     header: RuleHeader {
//! #         rule_title: "Suspicious PowerShell".to_string(),
//! #         rule_id: Some("rule-1".to_string()),
//! #         level: Some(rsigma_parser::Level::High),
//! #         tags: vec!["attack.t1059.001".to_string()],
//! #         custom_attributes: Arc::new(HashMap::new()),
//! #         enrichments: None,
//! #     },
//! #     body: ResultBody::Detection(DetectionBody {
//! #         matched_selections: vec!["selection".to_string()],
//! #         matched_fields: vec![FieldMatch::new("CommandLine", "powershell -enc".into())],
//! #         event: None,
//! #     }),
//! # };
//! let finding = ocsf::detection_finding(&result);
//! assert_eq!(finding["class_uid"], 2004);
//! assert_eq!(finding["type_uid"], 200401);
//! assert_eq!(finding["severity"], "High");
//! assert_eq!(finding["finding_info"]["title"], "Suspicious PowerShell");
//! ```

mod attack;

use serde_json::{Map, Value, json};

use rsigma_eval::{EvaluationResult, ResultBody};
use rsigma_parser::Level;

use crate::alert_pipeline::IncidentResult;
use crate::risk::{RISK_OBJECTS_KEY, RISK_SCORE_KEY, RiskIncidentResult};

/// OCSF class: Detection Finding.
const CLASS_UID: i64 = 2004;
/// OCSF category: Findings.
const CATEGORY_UID: i64 = 2;
/// The OCSF schema version this serializer targets, recorded on every finding.
///
/// One pinned version, bumped deliberately: a change here is visible in the
/// goldens and the committed conformance schema.
pub const OCSF_VERSION: &str = "1.1.0";

/// Time and identity source for a finding.
///
/// Findings carry a `metadata.uid` and, for the per-result shapes, a
/// serialization timestamp. Both are injected so golden tests can pin them;
/// production uses [`SystemSource`].
pub trait FindingSource {
    /// Wall-clock time in unix milliseconds.
    fn now_ms(&self) -> i64;
    /// A fresh unique id for one finding.
    fn uid(&self) -> String;
}

/// The production [`FindingSource`]: the system clock and UUIDv4.
pub struct SystemSource;

impl FindingSource for SystemSource {
    fn now_ms(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    fn uid(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

/// What the finding reports about the lifecycle of the underlying detection.
#[derive(Clone, Copy)]
enum Activity {
    /// First emission.
    Create = 1,
    /// A re-emission of something already reported.
    Update = 2,
    /// The underlying incident closed.
    Close = 3,
}

impl Activity {
    fn name(self) -> &'static str {
        match self {
            Activity::Create => "Create",
            Activity::Update => "Update",
            Activity::Close => "Close",
        }
    }
}

/// OCSF finding status. rsigma only ever reports the two ends it knows about;
/// triage states (In Progress, Suppressed, Archived) belong to the consumer.
#[derive(Clone, Copy)]
enum Status {
    New = 1,
    Resolved = 4,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::New => "New",
            Status::Resolved => "Resolved",
        }
    }
}

/// Serialize a detection or correlation result as a Detection Finding.
pub fn detection_finding(result: &EvaluationResult) -> Value {
    detection_finding_with(result, &SystemSource)
}

/// Serialize an alert-pipeline incident as a Detection Finding.
pub fn incident_finding(incident: &IncidentResult) -> Value {
    incident_finding_with(incident, &SystemSource)
}

/// Serialize a risk incident as a Detection Finding.
pub fn risk_incident_finding(incident: &RiskIncidentResult) -> Value {
    risk_incident_finding_with(incident, &SystemSource)
}

/// [`detection_finding`] against an injected time and identity source.
pub fn detection_finding_with(result: &EvaluationResult, src: &dyn FindingSource) -> Value {
    let header = &result.header;
    let title = header.rule_title.as_str();

    let mut analytic = Map::new();
    analytic.insert("type_id".to_string(), json!(1));
    analytic.insert("type".to_string(), json!("Rule"));
    analytic.insert("name".to_string(), json!(title));
    if let Some(uid) = &header.rule_id {
        analytic.insert("uid".to_string(), json!(uid));
    }

    let mut finding_info = Map::new();
    finding_info.insert("title".to_string(), json!(title));
    // A minted uid, not the rule id: `finding_info.uid` identifies the finding,
    // and one rule produces many. Rule identity lives in `analytic.uid`.
    finding_info.insert("uid".to_string(), json!(src.uid()));
    finding_info.insert("analytic".to_string(), Value::Object(analytic));
    if let Some(attacks) = attack::attacks_from_tags(&header.tags) {
        finding_info.insert("attacks".to_string(), attacks);
    }

    // The risk layer's reserved enrichments have real OCSF homes; the rest of
    // the enrichment map rides under `unmapped`.
    let lifted = LiftedRisk::from_enrichments(header.enrichments.as_ref());

    let mut unmapped = Map::new();
    insert_if(
        &mut unmapped,
        "tags",
        (!header.tags.is_empty()).then(|| json!(header.tags)),
    );
    insert_if(
        &mut unmapped,
        "custom_attributes",
        (!header.custom_attributes.is_empty())
            .then(|| serde_json::to_value(&*header.custom_attributes).unwrap_or(Value::Null)),
    );
    insert_if(&mut unmapped, "enrichments", lifted.remaining.clone());

    let evidences = match &result.body {
        ResultBody::Detection(body) => {
            unmapped.insert(
                "matched_selections".to_string(),
                json!(body.matched_selections),
            );
            // Also under `unmapped` in full fidelity: `evidences[]` flattens
            // matched fields to field/value pairs, which drops the detail keys
            // (`selection`, `matcher`, `pattern`) a `match_detail` run adds.
            unmapped.insert(
                "matched_fields".to_string(),
                serde_json::to_value(&body.matched_fields).unwrap_or(Value::Null),
            );
            detection_evidences(body)
        }
        ResultBody::Correlation(body) => {
            unmapped.insert("correlation_type".to_string(), json!(body.correlation_type));
            unmapped.insert("group_key".to_string(), json!(body.group_key));
            unmapped.insert("aggregated_value".to_string(), json!(body.aggregated_value));
            unmapped.insert("timespan_secs".to_string(), json!(body.timespan_secs));
            correlation_evidences(body)
        }
    };

    let mut finding = base_finding(
        src,
        Activity::Create,
        Status::New,
        severity_from_level(header.level.as_ref()),
        // `EvaluationResult` carries no event timestamp, so the honest value
        // is the serialization clock. Consumers needing event time enable
        // `rsigma.include_event` and read it from `evidences[].data`.
        src.now_ms(),
        title,
    );
    finding.insert("finding_info".to_string(), Value::Object(finding_info));
    insert_if(&mut finding, "evidences", evidences);
    insert_if(&mut finding, "risk_score", lifted.score.clone());
    insert_if(&mut finding, "resources", lifted.resources.clone());
    insert_if(&mut finding, "actor", lifted.actor.clone());
    finding.insert("unmapped".to_string(), Value::Object(unmapped));
    Value::Object(finding)
}

/// [`incident_finding`] against an injected time and identity source.
pub fn incident_finding_with(incident: &IncidentResult, src: &dyn FindingSource) -> Value {
    let title = incident_title(incident);
    let resolved = incident.state == "resolved";

    let mut analytic = Map::new();
    analytic.insert("type_id".to_string(), json!(1));
    analytic.insert("type".to_string(), json!("Rule"));
    analytic.insert("name".to_string(), json!("alert pipeline"));

    let mut finding_info = Map::new();
    finding_info.insert("title".to_string(), json!(title));
    // The incident id is already a stable per-incident identity, so it is the
    // finding uid: re-emissions of one incident share it by design.
    finding_info.insert("uid".to_string(), json!(incident.incident_id));
    finding_info.insert("analytic".to_string(), Value::Object(analytic));
    let related: Vec<Value> = incident
        .rule_counts
        .keys()
        .map(|rule| json!({ "type_id": 1, "type": "Rule", "name": rule }))
        .collect();
    if !related.is_empty() {
        finding_info.insert("related_analytics".to_string(), json!(related));
    }

    let mut resources: Vec<Value> = Vec::new();
    for (key, value) in incident.group_by.iter().chain(incident.entities.iter()) {
        resources.push(json!({ "type": key, "name": scalar_name(value) }));
    }

    let mut unmapped = Map::new();
    unmapped.insert("state".to_string(), json!(incident.state));
    unmapped.insert("trigger".to_string(), json!(incident.trigger));
    unmapped.insert("rule_counts".to_string(), json!(incident.rule_counts));
    insert_if(
        &mut unmapped,
        "refs",
        incident
            .refs
            .as_ref()
            .map(|refs| serde_json::to_value(refs).unwrap_or(Value::Null)),
    );
    insert_if(
        &mut unmapped,
        "results",
        incident.results.clone().map(Value::from),
    );

    let mut finding = base_finding(
        src,
        incident_activity(incident.trigger),
        if resolved {
            Status::Resolved
        } else {
            Status::New
        },
        severity_from_name(incident.max_level.as_deref()),
        // `last_seen` is the last contributing result, not the time this
        // Create/Update/Close finding was emitted. Keep the observed window in
        // start_time/end_time and timestamp the lifecycle event itself here.
        src.now_ms(),
        &title,
    );
    finding.insert("finding_info".to_string(), Value::Object(finding_info));
    finding.insert("start_time".to_string(), json!(incident.first_seen * 1000));
    finding.insert("end_time".to_string(), json!(incident.last_seen * 1000));
    finding.insert("count".to_string(), json!(incident.result_count));
    insert_if(
        &mut finding,
        "resources",
        (!resources.is_empty()).then(|| Value::Array(resources)),
    );
    finding.insert("unmapped".to_string(), Value::Object(unmapped));
    Value::Object(finding)
}

/// [`risk_incident_finding`] against an injected time and identity source.
pub fn risk_incident_finding_with(incident: &RiskIncidentResult, src: &dyn FindingSource) -> Value {
    let title = risk_incident_title(incident);

    let mut analytic = Map::new();
    analytic.insert("type_id".to_string(), json!(1));
    analytic.insert("type".to_string(), json!("Rule"));
    analytic.insert("name".to_string(), json!("risk accumulator"));

    let mut finding_info = Map::new();
    finding_info.insert("title".to_string(), json!(title));
    finding_info.insert("uid".to_string(), json!(incident.risk_incident_id));
    finding_info.insert("analytic".to_string(), Value::Object(analytic));
    let related: Vec<Value> = incident
        .sources
        .iter()
        .map(|source| json!({ "type_id": 1, "type": "Rule", "name": source }))
        .collect();
    if !related.is_empty() {
        finding_info.insert("related_analytics".to_string(), json!(related));
    }
    if let Some(attacks) = attack::attacks_from_tactics(&incident.tactics) {
        finding_info.insert("attacks".to_string(), attacks);
    }

    let mut unmapped = Map::new();
    unmapped.insert("trigger".to_string(), json!(incident.trigger));
    unmapped.insert("tactic_count".to_string(), json!(incident.tactic_count));
    insert_if(
        &mut unmapped,
        "tactic_count_threshold",
        incident.tactic_count_threshold.map(Value::from),
    );
    insert_if(
        &mut unmapped,
        "score_threshold",
        incident.score_threshold.map(Value::from),
    );
    unmapped.insert("source_count".to_string(), json!(incident.source_count));
    insert_if(
        &mut unmapped,
        "refs",
        incident
            .refs
            .as_ref()
            .map(|refs| serde_json::to_value(refs).unwrap_or(Value::Null)),
    );
    insert_if(
        &mut unmapped,
        "results",
        incident.results.clone().map(Value::from),
    );

    // A risk incident has no rule level: its severity is the accumulated score
    // crossing a configured threshold, which OCSF carries as `risk_score`.
    let mut finding = base_finding(
        src,
        Activity::Create,
        Status::New,
        0,
        incident.window_end * 1000,
        &title,
    );
    finding.insert("finding_info".to_string(), Value::Object(finding_info));
    finding.insert(
        "start_time".to_string(),
        json!(incident.window_start * 1000),
    );
    finding.insert("end_time".to_string(), json!(incident.window_end * 1000));
    finding.insert("count".to_string(), json!(incident.result_count));
    finding.insert("risk_score".to_string(), json!(incident.score));
    finding.insert(
        "resources".to_string(),
        json!([{ "type": incident.entity_type, "name": incident.entity_value }]),
    );
    if incident.entity_type == "user" {
        finding.insert(
            "actor".to_string(),
            json!({ "user": { "name": incident.entity_value } }),
        );
    }
    finding.insert("unmapped".to_string(), Value::Object(unmapped));
    Value::Object(finding)
}

/// The fields every Detection Finding carries, whatever it was built from.
fn base_finding(
    src: &dyn FindingSource,
    activity: Activity,
    status: Status,
    severity_id: i64,
    time_ms: i64,
    title: &str,
) -> Map<String, Value> {
    let activity_id = activity as i64;
    let mut finding = Map::new();
    // rsigma reports detections but does not itself take a control action.
    // Detection Finding requires action_id, so report that honestly as
    // Unknown rather than omitting the required attribute.
    finding.insert("action_id".to_string(), json!(0));
    finding.insert("action".to_string(), json!("Unknown"));
    finding.insert("activity_id".to_string(), json!(activity_id));
    finding.insert("activity_name".to_string(), json!(activity.name()));
    finding.insert("category_uid".to_string(), json!(CATEGORY_UID));
    finding.insert("category_name".to_string(), json!("Findings"));
    finding.insert("class_uid".to_string(), json!(CLASS_UID));
    finding.insert("class_name".to_string(), json!("Detection Finding"));
    finding.insert("type_uid".to_string(), json!(CLASS_UID * 100 + activity_id));
    finding.insert(
        "type_name".to_string(),
        json!(format!("Detection Finding: {}", activity.name())),
    );
    finding.insert("severity_id".to_string(), json!(severity_id));
    finding.insert("severity".to_string(), json!(severity_name(severity_id)));
    finding.insert("status_id".to_string(), json!(status as i64));
    finding.insert("status".to_string(), json!(status.name()));
    finding.insert("time".to_string(), json!(time_ms));
    // Every timestamp rsigma stamps is UTC millis.
    finding.insert("timezone_offset".to_string(), json!(0));
    // A consumer that renders only `message` still gets a readable line.
    finding.insert("message".to_string(), json!(title));
    finding.insert(
        "metadata".to_string(),
        json!({
            "product": {
                "name": "rsigma",
                "vendor_name": "rsigma",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "version": OCSF_VERSION,
            "uid": src.uid(),
        }),
    );
    finding
}

/// The risk layer's reserved enrichments, lifted out of the enrichment map.
///
/// A malformed value (a user-set `risk.score` that is not an integer, a
/// `risk.objects` that is not an array of objects) is left where it was, so
/// nothing is silently dropped or coerced.
#[derive(Default)]
struct LiftedRisk {
    score: Option<Value>,
    resources: Option<Value>,
    actor: Option<Value>,
    remaining: Option<Value>,
}

impl LiftedRisk {
    fn from_enrichments(enrichments: Option<&Map<String, Value>>) -> Self {
        let Some(enrichments) = enrichments else {
            return LiftedRisk::default();
        };
        let mut remaining = enrichments.clone();
        let mut lifted = LiftedRisk::default();

        if let Some(score) = remaining.get(RISK_SCORE_KEY).and_then(Value::as_i64) {
            lifted.score = Some(json!(score));
            remaining.remove(RISK_SCORE_KEY);
        }

        if let Some(objects) = remaining.get(RISK_OBJECTS_KEY).and_then(Value::as_array) {
            let resources: Vec<Value> = objects
                .iter()
                .filter_map(|object| {
                    let object_type = object.get("type")?.as_str()?;
                    let value = object.get("value")?.as_str()?;
                    Some(json!({ "type": object_type, "name": value }))
                })
                .collect();
            if resources.len() == objects.len() && !resources.is_empty() {
                // `user` is the one risk-object type OCSF gives a structured
                // home; the rest stay resources.
                lifted.actor = objects
                    .iter()
                    .find(|object| object.get("type").and_then(Value::as_str) == Some("user"))
                    .and_then(|object| object.get("value").and_then(Value::as_str))
                    .map(|name| json!({ "user": { "name": name } }));
                lifted.resources = Some(Value::Array(resources));
                remaining.remove(RISK_OBJECTS_KEY);
            }
        }

        lifted.remaining = (!remaining.is_empty()).then(|| Value::Object(remaining));
        lifted
    }
}

/// One evidence entry holding whatever the detection retained: the event
/// (kept only when the rule sets `rsigma.include_event`) and the matched
/// field/value pairs.
fn detection_evidences(body: &rsigma_eval::DetectionBody) -> Option<Value> {
    let mut data = Map::new();
    if let Some(event) = &body.event {
        data.insert("event".to_string(), event.clone());
    }
    if !body.matched_fields.is_empty() {
        let fields: Map<String, Value> = body
            .matched_fields
            .iter()
            .map(|m| (m.field.clone(), m.value.clone()))
            .collect();
        data.insert("matched_fields".to_string(), Value::Object(fields));
    }
    (!data.is_empty()).then(|| json!([{ "data": Value::Object(data) }]))
}

/// One evidence entry for the events a correlation retained, if its event mode
/// retained any.
fn correlation_evidences(body: &rsigma_eval::CorrelationBody) -> Option<Value> {
    let mut data = Map::new();
    if let Some(events) = &body.events {
        data.insert("events".to_string(), json!(events));
    }
    if let Some(refs) = &body.event_refs {
        data.insert("event_refs".to_string(), json!(refs));
    }
    (!data.is_empty()).then(|| json!([{ "data": Value::Object(data) }]))
}

/// Alert-pipeline trigger to OCSF activity: the first emission creates, a
/// later one updates, and the resolution closes.
fn incident_activity(trigger: &str) -> Activity {
    match trigger {
        "group_wait" => Activity::Create,
        "resolved" => Activity::Close,
        _ => Activity::Update,
    }
}

/// OCSF severity id from a Sigma level.
fn severity_from_level(level: Option<&Level>) -> i64 {
    severity_from_name(level.map(Level::as_str))
}

/// OCSF severity id from an already-lowercased level name, as the incident
/// shapes carry it. An unrecognized or absent level is `Unknown`, never a
/// guess.
fn severity_from_name(level: Option<&str>) -> i64 {
    match level {
        Some("informational") => 1,
        Some("low") => 2,
        Some("medium") => 3,
        Some("high") => 4,
        Some("critical") => 5,
        _ => 0,
    }
}

fn severity_name(severity_id: i64) -> &'static str {
    match severity_id {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        _ => "Unknown",
    }
}

/// A title for an incident, which carries contributing rules but no rule name.
///
/// Prefers the busiest contributing rule (ties broken by name, so the title is
/// stable across emissions), then the group key, then the bare id.
fn incident_title(incident: &IncidentResult) -> String {
    if let Some((rule, _)) =
        incident
            .rule_counts
            .iter()
            .max_by(|(a_rule, a_count), (b_rule, b_count)| {
                a_count.cmp(b_count).then_with(|| b_rule.cmp(a_rule))
            })
    {
        let others = incident.rule_counts.len() - 1;
        return match others {
            0 => rule.clone(),
            1 => format!("{rule} and 1 other rule"),
            n => format!("{rule} and {n} other rules"),
        };
    }

    let key: Vec<String> = incident
        .group_by
        .iter()
        .chain(incident.entities.iter())
        .map(|(field, value)| format!("{field}={}", scalar_name(value)))
        .collect();
    if key.is_empty() {
        format!("incident {}", incident.incident_id)
    } else {
        format!("incident for {}", key.join(", "))
    }
}

/// A title for a risk incident, whose identity is its entity and what crossed.
fn risk_incident_title(incident: &RiskIncidentResult) -> String {
    let crossed = match incident.trigger {
        "tactic_count" => "tactic-count threshold crossed",
        _ => "risk threshold crossed",
    };
    format!(
        "{crossed} for {} {}",
        incident.entity_type, incident.entity_value
    )
}

/// Render a group-key or entity value as a resource name. Strings keep their
/// bare form; anything else keeps its JSON spelling.
fn scalar_name(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Insert `value` under `key` when it is present, so absent data is an absent
/// key rather than a null.
fn insert_if(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        map.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    struct FixedSource;

    impl FindingSource for FixedSource {
        fn now_ms(&self) -> i64 {
            99_000
        }

        fn uid(&self) -> String {
            "fixed".to_string()
        }
    }

    fn incident(
        rule_counts: BTreeMap<String, u64>,
        group_by: Map<String, Value>,
    ) -> IncidentResult {
        IncidentResult {
            incident_id: "i-1".to_string(),
            state: "open",
            trigger: "group_wait",
            first_seen: 10,
            last_seen: 20,
            max_level: Some("medium".to_string()),
            result_count: 1,
            rule_counts,
            group_by,
            entities: Map::new(),
            refs: None,
            results: None,
            sample_mode: None,
            bundle_ready: None,
        }
    }

    fn enrichments(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect()
    }

    #[test]
    fn severity_maps_both_entry_points_to_the_same_ids() {
        assert_eq!(severity_from_level(Some(&Level::Informational)), 1);
        assert_eq!(severity_from_level(Some(&Level::Low)), 2);
        assert_eq!(severity_from_level(Some(&Level::Medium)), 3);
        assert_eq!(severity_from_level(Some(&Level::High)), 4);
        assert_eq!(severity_from_level(Some(&Level::Critical)), 5);
        assert_eq!(severity_from_level(None), 0);

        assert_eq!(severity_from_name(Some("critical")), 5);
        assert_eq!(
            severity_from_name(Some("HIGH")),
            0,
            "levels arrive lowercased"
        );
        assert_eq!(severity_from_name(Some("catastrophic")), 0);
        assert_eq!(severity_from_name(None), 0);

        assert_eq!(severity_name(0), "Unknown");
        assert_eq!(severity_name(5), "Critical");
    }

    #[test]
    fn incident_triggers_map_to_the_finding_lifecycle() {
        assert_eq!(incident_activity("group_wait") as i64, 1);
        assert_eq!(incident_activity("group_interval") as i64, 2);
        assert_eq!(incident_activity("repeat") as i64, 2);
        assert_eq!(incident_activity("resolved") as i64, 3);
    }

    #[test]
    fn a_resolved_incident_closes_the_finding() {
        let mut resolved = incident(BTreeMap::from([("rule-1".to_string(), 1)]), Map::new());
        resolved.state = "resolved";
        resolved.trigger = "resolved";
        let finding = incident_finding_with(&resolved, &FixedSource);
        assert_eq!(finding["activity_id"], 3);
        assert_eq!(finding["activity_name"], "Close");
        assert_eq!(finding["type_uid"], 200403);
        assert_eq!(finding["status_id"], 4);
        assert_eq!(finding["status"], "Resolved");
        assert_eq!(finding["time"], 99_000);
        assert_eq!(finding["end_time"], 20_000);
    }

    #[test]
    fn incident_titles_prefer_the_busiest_rule_then_the_group_key() {
        let busiest = incident(
            BTreeMap::from([("rule-a".to_string(), 1), ("rule-b".to_string(), 9)]),
            Map::new(),
        );
        assert_eq!(incident_title(&busiest), "rule-b and 1 other rule");

        let three = incident(
            BTreeMap::from([
                ("rule-a".to_string(), 9),
                ("rule-b".to_string(), 1),
                ("rule-c".to_string(), 1),
            ]),
            Map::new(),
        );
        assert_eq!(incident_title(&three), "rule-a and 2 other rules");

        let single = incident(BTreeMap::from([("rule-a".to_string(), 1)]), Map::new());
        assert_eq!(incident_title(&single), "rule-a");

        // A tie is broken by name so the title does not flip between emissions.
        let tied = incident(
            BTreeMap::from([("rule-b".to_string(), 4), ("rule-a".to_string(), 4)]),
            Map::new(),
        );
        assert_eq!(incident_title(&tied), "rule-a and 1 other rule");

        let keyed = incident(
            BTreeMap::new(),
            Map::from_iter([("match.User".to_string(), json!("alice"))]),
        );
        assert_eq!(incident_title(&keyed), "incident for match.User=alice");

        let bare = incident(BTreeMap::new(), Map::new());
        assert_eq!(incident_title(&bare), "incident i-1");
    }

    #[test]
    fn risk_incident_titles_name_what_crossed() {
        let mut incident = RiskIncidentResult {
            risk_incident_id: "r-1".to_string(),
            entity_type: "user".to_string(),
            entity_value: "alice".to_string(),
            trigger: "score",
            score: 120,
            score_threshold: Some(100),
            tactic_count: 3,
            tactic_count_threshold: Some(3),
            tactics: vec![],
            sources: vec![],
            source_count: 0,
            window_start: 0,
            window_end: 60,
            result_count: 2,
            refs: None,
            results: None,
        };
        assert_eq!(
            risk_incident_title(&incident),
            "risk threshold crossed for user alice"
        );

        incident.trigger = "tactic_count";
        assert_eq!(
            risk_incident_title(&incident),
            "tactic-count threshold crossed for user alice"
        );
    }

    #[test]
    fn risk_enrichments_lift_out_of_the_unmapped_map() {
        let lifted = LiftedRisk::from_enrichments(Some(&enrichments(&[
            ("risk.score", json!(75)),
            (
                "risk.objects",
                json!([{"type": "host", "value": "ws-01"}, {"type": "user", "value": "alice"}]),
            ),
            ("incident_id", json!("i-1")),
        ])));

        assert_eq!(lifted.score, Some(json!(75)));
        assert_eq!(
            lifted.resources,
            Some(json!([
                {"type": "host", "name": "ws-01"},
                {"type": "user", "name": "alice"},
            ]))
        );
        assert_eq!(lifted.actor, Some(json!({"user": {"name": "alice"}})));
        // Only the lifted keys leave; the alert pipeline's `incident_id` stays.
        assert_eq!(lifted.remaining, Some(json!({"incident_id": "i-1"})));
    }

    #[test]
    fn absent_enrichments_lift_nothing() {
        let lifted = LiftedRisk::from_enrichments(None);
        assert!(lifted.score.is_none());
        assert!(lifted.resources.is_none());
        assert!(lifted.actor.is_none());
        assert!(lifted.remaining.is_none());
    }

    #[test]
    fn malformed_risk_enrichments_stay_untouched() {
        let lifted = LiftedRisk::from_enrichments(Some(&enrichments(&[
            ("risk.score", json!("seventy-five")),
            ("risk.objects", json!({"user": "alice"})),
        ])));
        assert!(lifted.score.is_none());
        assert!(lifted.resources.is_none());
        assert_eq!(
            lifted.remaining,
            Some(json!({"risk.score": "seventy-five", "risk.objects": {"user": "alice"}})),
            "a value the risk layer did not write is carried through, not coerced",
        );

        // A single unusable entry keeps the whole array where it was, rather
        // than emitting a partial resource list.
        let partial = LiftedRisk::from_enrichments(Some(&enrichments(&[(
            "risk.objects",
            json!([{"type": "user", "value": "alice"}, {"type": "host"}]),
        )])));
        assert!(partial.resources.is_none());
        assert!(partial.remaining.is_some());
    }

    #[test]
    fn an_empty_risk_objects_array_is_not_a_resource_list() {
        let lifted =
            LiftedRisk::from_enrichments(Some(&enrichments(&[("risk.objects", json!([]))])));
        assert!(lifted.resources.is_none());
        assert!(lifted.actor.is_none());
    }
}
