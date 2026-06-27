//! Inhibition, modeled on Alertmanager `inhibit_rules`.
//!
//! Each rule is `{ source_match, target_match, equal, duration }`. While an
//! active source alert exists (one matching `source_match`, seen within
//! `duration`), any target alert matching `target_match` that shares the same
//! `equal` selector values is muted.
//!
//! Two behaviors from the plan are encoded by the evaluation order in
//! [`InhibitStore::evaluate`]:
//!
//! - A *silenced* source still inhibits its targets: the source index is
//!   updated for every non-inhibited result before silencing runs.
//! - An *inhibited* target does not become a source: an inhibited result is
//!   dropped before the source index is updated, so it never inhibits others.
//!
//! Inhibition is non-transitive and carries the same self-inhibition guard as
//! Alertmanager: a result matching both `source_match` and `target_match` does
//! not inhibit itself.

use std::collections::HashMap;
use std::time::Duration;

use rsigma_eval::EvaluationResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::matcher::MatcherSet;
use crate::selector::Selector;

/// Persisted form of one active inhibition source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InhibitSourceSnap {
    pub rule: String,
    pub equal_key: String,
    pub last_seen: i64,
}

/// A validated inhibition rule.
#[derive(Debug, Clone)]
pub struct InhibitRule {
    /// Stable name, used as the metric label.
    pub name: String,
    /// Matchers a source alert must satisfy.
    pub source_match: MatcherSet,
    /// Matchers a target alert must satisfy.
    pub target_match: MatcherSet,
    /// Selectors whose values must be equal between source and target.
    pub equal: Vec<Selector>,
    /// How long a source remains active after it was last seen.
    pub duration: Duration,
}

/// Validated inhibition config (an ordered rule list).
#[derive(Debug, Clone)]
pub struct InhibitConfig {
    pub rules: Vec<InhibitRule>,
}

/// Active-source index: `(rule_name, equal_key) -> last_seen`.
#[derive(Debug, Default)]
pub struct InhibitStore {
    sources: HashMap<(String, String), i64>,
}

impl InhibitStore {
    /// True when no active sources are tracked.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Evaluate a result. If it is an inhibited target, return the inhibiting
    /// rule name (and do not record it as a source). Otherwise record it as a
    /// source for every rule whose `source_match` it satisfies, and return
    /// `None`.
    pub fn evaluate(
        &mut self,
        cfg: &InhibitConfig,
        result: &EvaluationResult,
        now: i64,
    ) -> Option<String> {
        // 1. Inhibited target? Checked against sources from prior results.
        for rule in &cfg.rules {
            // Self-inhibition guard: a result that is itself a source of this
            // rule is never inhibited by it.
            if rule.target_match.matches(result) && !rule.source_match.matches(result) {
                let key = (rule.name.clone(), equal_key(&rule.equal, result));
                if let Some(&last) = self.sources.get(&key)
                    && now - last < rule.duration.as_secs() as i64
                {
                    return Some(rule.name.clone());
                }
            }
        }
        // 2. Not inhibited: record as a source where applicable.
        for rule in &cfg.rules {
            if rule.source_match.matches(result) {
                let key = (rule.name.clone(), equal_key(&rule.equal, result));
                self.sources.insert(key, now);
            }
        }
        None
    }

    /// Drop sources older than their rule's `duration` (or whose rule no longer
    /// exists after a reload).
    pub fn gc(&mut self, cfg: &InhibitConfig, now: i64) {
        self.sources.retain(|(name, _), &mut last| {
            cfg.rules
                .iter()
                .find(|r| &r.name == name)
                .is_some_and(|r| now - last < r.duration.as_secs() as i64)
        });
    }

    /// Snapshot the active sources for persistence.
    pub(crate) fn snapshot(&self) -> Vec<InhibitSourceSnap> {
        self.sources
            .iter()
            .map(|((rule, equal_key), &last_seen)| InhibitSourceSnap {
                rule: rule.clone(),
                equal_key: equal_key.clone(),
                last_seen,
            })
            .collect()
    }

    /// Restore active sources, dropping any whose rule no longer exists or that
    /// are already past their rule's `duration` at `now`.
    pub(crate) fn restore(&mut self, snaps: Vec<InhibitSourceSnap>, cfg: &InhibitConfig, now: i64) {
        for snap in snaps {
            if let Some(rule) = cfg.rules.iter().find(|r| r.name == snap.rule)
                && now - snap.last_seen < rule.duration.as_secs() as i64
            {
                self.sources
                    .insert((snap.rule, snap.equal_key), snap.last_seen);
            }
        }
    }

    /// Count of currently-active sources.
    pub fn active_count(&self, cfg: &InhibitConfig, now: i64) -> usize {
        self.sources
            .iter()
            .filter(|entry| {
                let name = &entry.0.0;
                let last = *entry.1;
                cfg.rules
                    .iter()
                    .find(|r| &r.name == name)
                    .is_some_and(|r| now - last < r.duration.as_secs() as i64)
            })
            .count()
    }
}

/// The joined `equal` selector values for a result (absent selectors resolve to
/// the empty string, matching the matcher semantics).
fn equal_key(equal: &[Selector], result: &EvaluationResult) -> String {
    let mut buf = String::new();
    for sel in equal {
        let value = sel
            .resolve(result)
            .map(|v| match v {
                Value::String(s) => s,
                other => other.to_string(),
            })
            .unwrap_or_default();
        buf.push('\u{1f}');
        buf.push_str(&value);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap as Map;
    use std::sync::Arc;

    use super::super::matcher::{MatchOp, MatcherSet, MatcherSpec};

    fn detection(ip: &str, level: Level) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "t".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(Map::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: None,
            }),
        }
    }

    fn matcher(selector: &str, value: &str) -> MatcherSpec {
        MatcherSpec {
            selector: selector.to_string(),
            op: MatchOp::Eq,
            value: value.to_string(),
        }
    }

    fn cfg() -> InhibitConfig {
        InhibitConfig {
            rules: vec![InhibitRule {
                name: "critical-inhibits-high".to_string(),
                source_match: MatcherSet::compile(&[matcher("level", "critical")]).unwrap(),
                target_match: MatcherSet::compile(&[matcher("level", "high")]).unwrap(),
                equal: vec![Selector::parse("match.SourceIp").unwrap()],
                duration: Duration::from_secs(300),
            }],
        }
    }

    #[test]
    fn source_inhibits_matching_target() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        // A critical source on 10.0.0.1 registers.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::Critical), 0),
            None
        );
        // A high target on the same IP is inhibited.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 1),
            Some("critical-inhibits-high".to_string())
        );
        // A high target on a different IP is not inhibited.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.2", Level::High), 2),
            None
        );
    }

    #[test]
    fn source_expires_after_duration() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        store.evaluate(&cfg, &detection("10.0.0.1", Level::Critical), 0);
        // After the 300s window, the source no longer inhibits.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 400),
            None
        );
    }

    #[test]
    fn self_inhibition_guard() {
        // A rule whose source and target both match the same result must not
        // inhibit it.
        let cfg = InhibitConfig {
            rules: vec![InhibitRule {
                name: "self".to_string(),
                source_match: MatcherSet::compile(&[matcher("level", "high")]).unwrap(),
                target_match: MatcherSet::compile(&[matcher("level", "high")]).unwrap(),
                equal: vec![Selector::parse("match.SourceIp").unwrap()],
                duration: Duration::from_secs(300),
            }],
        };
        let mut store = InhibitStore::default();
        store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 0);
        // The same kind of result is a source, not an inhibited target.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 1),
            None
        );
    }

    #[test]
    fn gc_and_active_count() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        store.evaluate(&cfg, &detection("10.0.0.1", Level::Critical), 0);
        assert_eq!(store.active_count(&cfg, 100), 1);
        assert_eq!(store.active_count(&cfg, 400), 0, "past duration");
        store.gc(&cfg, 400);
        assert!(store.is_empty());
    }
}
