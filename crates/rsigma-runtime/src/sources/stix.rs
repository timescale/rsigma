//! Turn a STIX bundle into a dynamic-source value.
//!
//! Lifecycle is evaluated at each resolve against the caller's clock. An
//! indicator whose `valid_until` has passed stays in the value until the next
//! refresh, so the source refresh interval is the expiry granularity.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rsigma_eval::pipeline::sources::StixOptions;
use rstix::core::StixTimestamp;
use rstix::model::sdo::SdoObject;
use rstix::{Bundle, ObservableExtraction, ParseOptions, StixObject};

use super::{SourceError, SourceErrorKind};

const METADATA_CAP: usize = 16;
const PARSE_OBJECT_CAP: usize = 1_000_000;

/// Why an indicator or one of its observables was left out of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// `revoked` is true.
    Revoked,
    /// `valid_until` is set and is not after `now`.
    Expired,
    /// `valid_from` is after `now`.
    NotYetValid,
    /// Confidence is set and below `min_confidence`.
    LowConfidence,
    /// `pattern_type` is not `stix`.
    PatternType,
    /// The pattern is not an independent list of equalities.
    UnsupportedPattern,
    /// The comparison path is not one of the configured observable keys.
    UnmappedObservable,
    /// `pattern_type` is `stix` but the pattern text did not parse.
    InvalidPattern,
    /// The indicator lost the confidence and id ordering past `max_indicators`.
    OverLimit,
}

impl SkipReason {
    /// Prometheus label for this reason.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::LowConfidence => "low_confidence",
            Self::PatternType => "pattern_type",
            Self::UnsupportedPattern => "unsupported_pattern",
            Self::UnmappedObservable => "unmapped_observable",
            Self::InvalidPattern => "invalid_pattern",
            Self::OverLimit => "over_limit",
        }
    }
}

/// Counts of indicators and observables left out of one build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SkipCounts {
    /// `revoked` is true.
    pub revoked: u64,
    /// `valid_until` is set and is not after `now`.
    pub expired: u64,
    /// `valid_from` is after `now`.
    pub not_yet_valid: u64,
    /// Confidence is set and below `min_confidence`.
    pub low_confidence: u64,
    /// `pattern_type` is not `stix`.
    pub pattern_type: u64,
    /// The pattern is not an independent list of equalities.
    pub unsupported_pattern: u64,
    /// A comparison path is outside the configured keys.
    pub unmapped_observable: u64,
    /// `pattern_type` is `stix` but the pattern text did not parse.
    pub invalid_pattern: u64,
    /// Indicators dropped by the `max_indicators` cap.
    pub over_limit: u64,
}

impl SkipCounts {
    fn add(&mut self, reason: SkipReason, count: u64) {
        let slot = match reason {
            SkipReason::Revoked => &mut self.revoked,
            SkipReason::Expired => &mut self.expired,
            SkipReason::NotYetValid => &mut self.not_yet_valid,
            SkipReason::LowConfidence => &mut self.low_confidence,
            SkipReason::PatternType => &mut self.pattern_type,
            SkipReason::UnsupportedPattern => &mut self.unsupported_pattern,
            SkipReason::UnmappedObservable => &mut self.unmapped_observable,
            SkipReason::InvalidPattern => &mut self.invalid_pattern,
            SkipReason::OverLimit => &mut self.over_limit,
        };
        *slot += count;
    }

    /// Each non-zero reason and its count.
    pub fn iter(&self) -> impl Iterator<Item = (SkipReason, u64)> + '_ {
        [
            (SkipReason::Revoked, self.revoked),
            (SkipReason::Expired, self.expired),
            (SkipReason::NotYetValid, self.not_yet_valid),
            (SkipReason::LowConfidence, self.low_confidence),
            (SkipReason::PatternType, self.pattern_type),
            (SkipReason::UnsupportedPattern, self.unsupported_pattern),
            (SkipReason::UnmappedObservable, self.unmapped_observable),
            (SkipReason::InvalidPattern, self.invalid_pattern),
            (SkipReason::OverLimit, self.over_limit),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
    }
}

/// One build of a STIX source value.
#[derive(Clone, Debug)]
pub struct StixBuild {
    /// Source value. Every configured observable key is present.
    pub value: serde_json::Value,
    /// Indicators and observables left out.
    pub skips: SkipCounts,
    /// Indicators that passed the lifecycle and the cap.
    pub active: usize,
    /// STIX objects in the bundle, of every type.
    pub objects: usize,
}

#[derive(Clone, Debug)]
struct Kept {
    id: String,
    name: Option<String>,
    confidence: Option<u8>,
    valid_until: Option<String>,
    labels: Vec<String>,
    kill_chain_phases: Vec<(String, String)>,
    observables: Vec<(String, String)>,
}

/// Latest version of each indicator id, then the lifecycle and the cap.
#[derive(Clone, Debug)]
pub struct IndicatorSet {
    by_id: HashMap<String, Candidate>,
}

#[derive(Clone, Debug)]
struct Candidate {
    modified: StixTimestamp,
    indicator: rstix::model::sdo::Indicator,
}

impl IndicatorSet {
    /// Empty set.
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    /// Keep `indicator` when it is newer than the copy already stored for its id.
    ///
    /// An older version that arrives later does not replace the newer one.
    /// A revoked newer version replaces an older active one, and the lifecycle
    /// then removes it.
    pub fn upsert(&mut self, indicator: rstix::model::sdo::Indicator) {
        let id = indicator.common.id.to_string();
        match self.by_id.get(&id) {
            Some(existing) if existing.modified >= indicator.common.modified => {}
            _ => {
                let modified = indicator.common.modified.clone();
                self.by_id.insert(
                    id,
                    Candidate {
                        modified,
                        indicator,
                    },
                );
            }
        }
    }

    /// Apply the lifecycle at `now`, then the cap, and build the source value.
    pub fn build(
        &self,
        options: &StixOptions,
        now: &StixTimestamp,
    ) -> (serde_json::Value, SkipCounts, usize) {
        let mut skips = SkipCounts::default();
        let configured: BTreeSet<&str> = options.observables.iter().map(String::as_str).collect();
        let mut kept = Vec::new();
        let mut unmapped = 0u64;
        for candidate in self.by_id.values() {
            match keep(&candidate.indicator, options, now, &configured) {
                Ok(accepted) => {
                    unmapped += accepted.unmapped;
                    kept.push(accepted.item);
                }
                Err(reason) => skips.add(reason, 1),
            }
        }
        if unmapped > 0 {
            skips.add(SkipReason::UnmappedObservable, unmapped);
        }
        kept.sort_by(|left, right| {
            right
                .confidence
                .cmp(&left.confidence)
                .then_with(|| left.id.cmp(&right.id))
        });
        if kept.len() > options.max_indicators {
            let extra = kept.len() - options.max_indicators;
            kept.truncate(options.max_indicators);
            skips.add(SkipReason::OverLimit, extra as u64);
        }
        let mut values: BTreeMap<String, BTreeSet<String>> = options
            .observables
            .iter()
            .map(|key| (key.clone(), BTreeSet::new()))
            .collect();
        let mut metadata: HashMap<String, Vec<Kept>> = HashMap::new();
        for item in &kept {
            for (key, value) in &item.observables {
                if let Some(bucket) = values.get_mut(key) {
                    bucket.insert(value.clone());
                    let entries = metadata.entry(value.clone()).or_default();
                    if entries.iter().all(|existing| existing.id != item.id) {
                        entries.push(item.clone());
                    }
                }
            }
        }
        let mut object = serde_json::Map::new();
        for key in &options.observables {
            let list = values
                .get(key)
                .map(|bucket| {
                    bucket
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect()
                })
                .unwrap_or_default();
            object.insert(key.clone(), serde_json::Value::Array(list));
        }
        let mut indicator_map = serde_json::Map::new();
        let mut meta_keys: Vec<_> = metadata.keys().cloned().collect();
        meta_keys.sort();
        for value in meta_keys {
            let mut entries = metadata.remove(&value).unwrap_or_default();
            entries.sort_by(|left, right| {
                right
                    .confidence
                    .cmp(&left.confidence)
                    .then_with(|| left.id.cmp(&right.id))
            });
            entries.truncate(METADATA_CAP);
            indicator_map.insert(
                value,
                serde_json::Value::Array(entries.iter().map(metadata_json).collect()),
            );
        }
        object.insert(
            "indicators".to_owned(),
            serde_json::Value::Object(indicator_map),
        );
        let active = kept.len();
        (serde_json::Value::Object(object), skips, active)
    }
}

impl Default for IndicatorSet {
    fn default() -> Self {
        Self::new()
    }
}

struct Accepted {
    item: Kept,
    unmapped: u64,
}

fn keep(
    indicator: &rstix::model::sdo::Indicator,
    options: &StixOptions,
    now: &StixTimestamp,
    configured: &BTreeSet<&str>,
) -> Result<Accepted, SkipReason> {
    if indicator.pattern.pattern_type() != "stix" {
        return Err(SkipReason::PatternType);
    }
    if indicator.common.revoked == Some(true) {
        return Err(SkipReason::Revoked);
    }
    if indicator.valid_from > *now {
        return Err(SkipReason::NotYetValid);
    }
    if indicator
        .valid_until
        .as_ref()
        .is_some_and(|until| *until <= *now)
    {
        return Err(SkipReason::Expired);
    }
    let confidence = indicator.common.confidence.map(|value| value.get());
    if let (Some(min), Some(value)) = (options.min_confidence, confidence)
        && value < min
    {
        return Err(SkipReason::LowConfidence);
    }
    let pattern = indicator
        .pattern
        .parsed_pattern()
        .map_err(|_| SkipReason::InvalidPattern)?;
    let observables = match pattern.simple_observables() {
        ObservableExtraction::Simple(items) => items,
        ObservableExtraction::Unsupported(_) => return Err(SkipReason::UnsupportedPattern),
    };
    let mut selected = Vec::new();
    let mut unmapped = 0u64;
    for item in observables {
        match item.kind {
            Some(kind) if configured.contains(kind.key()) => {
                selected.push((kind.key().to_owned(), item.value));
            }
            _ => unmapped += 1,
        }
    }
    Ok(Accepted {
        unmapped,
        item: Kept {
            id: indicator.common.id.to_string(),
            name: indicator.name.clone(),
            confidence,
            valid_until: indicator.valid_until.as_ref().map(|ts| ts.to_rfc3339()),
            labels: indicator.indicator_types.clone(),
            kill_chain_phases: indicator
                .kill_chain_phases
                .iter()
                .map(|phase| (phase.kill_chain_name.clone(), phase.phase_name.clone()))
                .collect(),
            observables: selected,
        },
    })
}

fn metadata_json(item: &Kept) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert("id".to_owned(), serde_json::Value::String(item.id.clone()));
    if let Some(name) = &item.name {
        object.insert("name".to_owned(), serde_json::Value::String(name.clone()));
    }
    if let Some(confidence) = item.confidence {
        object.insert("confidence".to_owned(), serde_json::Value::from(confidence));
    }
    if let Some(valid_until) = &item.valid_until {
        object.insert(
            "valid_until".to_owned(),
            serde_json::Value::String(valid_until.clone()),
        );
    }
    object.insert(
        "labels".to_owned(),
        serde_json::Value::Array(
            item.labels
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    object.insert(
        "kill_chain_phases".to_owned(),
        serde_json::Value::Array(
            item.kill_chain_phases
                .iter()
                .map(|(kill_chain_name, phase_name)| {
                    serde_json::json!({
                        "kill_chain_name": kill_chain_name,
                        "phase_name": phase_name,
                    })
                })
                .collect(),
        ),
    );
    serde_json::Value::Object(object)
}

/// Parse a bundle and build the source value at `now`.
///
/// Custom `x_*` objects are accepted and ignored. Nesting, string length, and
/// object count use finite parse limits.
pub fn build(
    raw: &str,
    options: &StixOptions,
    now: &StixTimestamp,
) -> Result<StixBuild, SourceError> {
    let parse_options = ParseOptions {
        allow_custom: true,
        max_object_count: PARSE_OBJECT_CAP,
        ..ParseOptions::default()
    };
    let bundle = Bundle::parse_with_options(raw, &parse_options).map_err(|err| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Parse(format!("invalid STIX bundle: {err}")),
    })?;
    let objects = bundle.objects().len();
    let mut set = IndicatorSet::new();
    for object in bundle.objects() {
        if let StixObject::Sdo(SdoObject::Indicator(indicator)) = object {
            set.upsert(indicator.clone());
        }
    }
    let (value, skips, active) = set.build(options, now);
    Ok(StixBuild {
        value,
        skips,
        active,
        objects,
    })
}

/// Report one build on `metrics`.
pub fn observe(metrics: &dyn crate::MetricsHook, source_id: &str, built: &StixBuild) {
    metrics.set_stix_source_indicators(source_id, built.active as u64);
    metrics.on_stix_source_objects(source_id, built.objects as u64);
    for (reason, count) in built.skips.iter() {
        metrics.on_stix_source_skipped(source_id, reason.key(), count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> StixTimestamp {
        StixTimestamp::parse("2026-06-01T00:00:00.000Z").unwrap()
    }

    fn bundle(objects: &[&str]) -> String {
        format!(
            r#"{{"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":[{}]}}"#,
            objects.join(",")
        )
    }

    fn indicator(n: u8, modified: &str, pattern: &str, extra: &str) -> String {
        format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2020-01-01T00:00:00.000Z","modified":"{modified}","name":"n{n}","pattern":"{pattern}","pattern_type":"stix","valid_from":"2020-01-01T00:00:00.000Z","indicator_types":["malicious-activity"]{extra}}}"#
        )
    }

    fn keys(value: &serde_json::Value) -> Vec<String> {
        value["ipv4"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn keeps_a_simple_indicator_and_emits_every_configured_key() {
        let raw = bundle(&[&indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        )]);
        let built = build(&raw, &StixOptions::all(), &now()).unwrap();
        assert_eq!(keys(&built.value), ["198.51.100.7"]);
        assert_eq!(built.value["domain"], serde_json::json!([]));
        assert!(built.value.get("sha256").is_some());
        assert_eq!(built.active, 1);
        assert_eq!(built.skips, SkipCounts::default());
        assert_eq!(
            built.value["indicators"]["198.51.100.7"][0]["id"],
            "indicator--00000000-0000-4000-8000-000000000001"
        );
    }

    #[test]
    fn lifecycle_rules_skip_indicators() {
        let cases = [
            (r#","revoked":true"#, SkipReason::Revoked),
            (
                r#","valid_until":"2026-01-01T00:00:00.000Z""#,
                SkipReason::Expired,
            ),
            (
                r#","valid_from":"2027-01-01T00:00:00.000Z""#,
                SkipReason::NotYetValid,
            ),
            (r#","confidence":10"#, SkipReason::LowConfidence),
        ];
        let mut options = StixOptions::all();
        options.min_confidence = Some(50);
        for (extra, reason) in cases {
            let mut body = indicator(
                1,
                "2024-01-01T00:00:00.000Z",
                "[ipv4-addr:value = '198.51.100.7']",
                extra,
            );
            if extra.contains("valid_from") {
                body = body.replacen(
                    r#""valid_from":"2020-01-01T00:00:00.000Z""#,
                    r#""valid_from":"2027-01-01T00:00:00.000Z""#,
                    1,
                );
            }
            let built = build(&bundle(&[&body]), &options, &now()).unwrap();
            assert_eq!(built.active, 0, "{extra}");
            assert_eq!(built.skips.iter().collect::<Vec<_>>(), vec![(reason, 1)]);
        }
    }

    #[test]
    fn skips_non_stix_and_unsupported_patterns() {
        let yara = r#"{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-000000000001","created":"2020-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","pattern":"rule x { condition: true }","pattern_type":"yara","valid_from":"2020-01-01T00:00:00.000Z"}"#;
        let built = build(&bundle(&[yara]), &StixOptions::all(), &now()).unwrap();
        assert_eq!(built.skips.pattern_type, 1);

        let joined = indicator(
            2,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7'] AND [domain-name:value = 'bad.example']",
            "",
        );
        let built = build(&bundle(&[&joined]), &StixOptions::all(), &now()).unwrap();
        assert_eq!(built.skips.unsupported_pattern, 1);
    }

    fn load(raw: &str) -> rstix::model::sdo::Indicator {
        let bundle = Bundle::parse_with_options(raw, &ParseOptions::default()).unwrap();
        match &bundle.objects()[0] {
            StixObject::Sdo(SdoObject::Indicator(indicator)) => indicator.clone(),
            other => panic!("expected an indicator, got {other:?}"),
        }
    }

    #[test]
    fn newer_version_wins_and_a_revoked_newer_version_removes_it() {
        let older = load(&bundle(&[&indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        )]));
        let newer = load(&bundle(&[&indicator(
            1,
            "2025-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.8']",
            "",
        )]));
        let mut set = IndicatorSet::new();
        set.upsert(newer);
        set.upsert(older);
        let (value, _, active) = set.build(&StixOptions::all(), &now());
        assert_eq!(active, 1);
        assert_eq!(keys(&value), ["198.51.100.8"]);

        let revoked = load(&bundle(&[&indicator(
            1,
            "2025-06-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.8']",
            r#","revoked":true"#,
        )]));
        set.upsert(revoked);
        let (_, skips, active) = set.build(&StixOptions::all(), &now());
        assert_eq!(active, 0);
        assert_eq!(skips.revoked, 1);
    }

    #[test]
    fn cap_keeps_highest_confidence_then_id() {
        let mut options = StixOptions::all();
        options.max_indicators = 2;
        let low = indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.1']",
            r#","confidence":10"#,
        );
        let high_b = indicator(
            3,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.3']",
            r#","confidence":90"#,
        );
        let high_a = indicator(
            2,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.2']",
            r#","confidence":90"#,
        );
        let built = build(&bundle(&[&low, &high_b, &high_a]), &options, &now()).unwrap();
        assert_eq!(keys(&built.value), ["198.51.100.2", "198.51.100.3"]);
        assert_eq!(built.skips.over_limit, 1);
    }

    #[test]
    fn metadata_is_ordered_and_capped_at_sixteen() {
        let mut objects = Vec::new();
        for n in 1..=17 {
            objects.push(indicator(
                n,
                "2024-01-01T00:00:00.000Z",
                "[ipv4-addr:value = '198.51.100.7']",
                &format!(r#","confidence":{}"#, 100 - n),
            ));
        }
        let refs: Vec<&str> = objects.iter().map(String::as_str).collect();
        let built = build(&bundle(&refs), &StixOptions::all(), &now()).unwrap();
        let meta = built.value["indicators"]["198.51.100.7"]
            .as_array()
            .unwrap();
        assert_eq!(meta.len(), 16);
        assert_eq!(meta[0]["confidence"], 99);
        assert_eq!(meta[1]["confidence"], 98);
    }

    #[test]
    fn counts_an_unmapped_path() {
        let raw = bundle(&[&indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[file:size = 12]",
            "",
        )]);
        let mut options = StixOptions::all();
        options.observables = vec!["ipv4".to_owned()];
        let built = build(&raw, &options, &now()).unwrap();
        assert_eq!(built.skips.unmapped_observable, 1);
        assert_eq!(built.value["ipv4"], serde_json::json!([]));
        assert!(built.value.get("domain").is_none());
        assert_eq!(built.active, 1);
    }
}
