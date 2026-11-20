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
use rsigma_eval::TenantId;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
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
    /// Ceiling on tracked sources across all rules. At the cap, a result that
    /// would open a new source is still evaluated as a target but is not
    /// tracked; already-tracked sources keep refreshing.
    pub max_sources: usize,
}

type SourceKey = (String, Option<TenantId>, String);

/// Active-source index: `(rule_name, tenant, equal_key) -> last_seen`.
#[derive(Debug, Default)]
pub struct InhibitStore {
    sources: HashMap<SourceKey, i64>,
    /// Tracked sources per tenant, for the per-tenant cap.
    tenant_counts: HashMap<Option<TenantId>, usize>,
}

impl InhibitStore {
    /// True when no active sources are tracked.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Evaluate a result. If it is an inhibited target, return the inhibiting
    /// rule name (and do not record it as a source). Otherwise record it as a
    /// source for every rule whose `source_match` it satisfies, and return
    /// `None`. A new source refused by `max_sources`, or by `max_per_tenant`
    /// for its tenant, is reported to `on_refused` with its rule name.
    pub fn evaluate(
        &mut self,
        cfg: &InhibitConfig,
        result: &EvaluationResult,
        now: i64,
        max_per_tenant: Option<usize>,
        mut on_refused: impl FnMut(&str),
    ) -> Option<String> {
        let tenant = result.header.tenant_id.clone();
        // 1. Inhibited target? Checked against sources from prior results.
        for rule in &cfg.rules {
            // Self-inhibition guard: a result that is itself a source of this
            // rule is never inhibited by it.
            if rule.target_match.matches(result) && !rule.source_match.matches(result) {
                let key = (
                    rule.name.clone(),
                    tenant.clone(),
                    equal_key(&rule.equal, result),
                );
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
                let key = (
                    rule.name.clone(),
                    tenant.clone(),
                    equal_key(&rule.equal, result),
                );
                if let Some(last) = self.sources.get_mut(&key) {
                    *last = now;
                } else if self.sources.len() < cfg.max_sources
                    && max_per_tenant.is_none_or(|max| self.tenant_len(tenant.as_ref()) < max)
                {
                    *self.tenant_counts.entry(tenant.clone()).or_default() += 1;
                    self.sources.insert(key, now);
                } else {
                    on_refused(&rule.name);
                }
            }
        }
        None
    }

    /// Drop sources older than their rule's `duration` (or whose rule no longer
    /// exists after a reload).
    pub fn gc(&mut self, cfg: &InhibitConfig, now: i64) {
        self.sources.retain(|(name, _, _), &mut last| {
            cfg.rules
                .iter()
                .find(|r| &r.name == name)
                .is_some_and(|r| now - last < r.duration.as_secs() as i64)
        });
        self.recount();
    }

    fn tenant_len(&self, tenant: Option<&TenantId>) -> usize {
        self.tenant_counts
            .get(&tenant.cloned())
            .copied()
            .unwrap_or(0)
    }

    fn recount(&mut self) {
        self.tenant_counts.clear();
        for (_, tenant, _) in self.sources.keys() {
            *self.tenant_counts.entry(tenant.clone()).or_default() += 1;
        }
    }

    /// Snapshot the active sources for persistence.
    pub(crate) fn snapshot(&self) -> Vec<InhibitSourceSnap> {
        self.sources
            .iter()
            .map(
                |((rule, tenant, equal_key), &last_seen)| InhibitSourceSnap {
                    rule: rule.clone(),
                    equal_key: equal_key.clone(),
                    last_seen,
                    tenant: tenant.clone(),
                },
            )
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
                    .insert((snap.rule, snap.tenant, snap.equal_key), snap.last_seen);
            }
        }
        self.recount();
    }

    /// Evict the least recently seen sources beyond `max`, returning how many
    /// were evicted.
    pub(crate) fn enforce_cap(&mut self, max: usize) -> usize {
        let excess = self.sources.len().saturating_sub(max);
        if excess == 0 {
            return 0;
        }
        let mut by_age: Vec<(i64, SourceKey)> = self
            .sources
            .iter()
            .map(|(key, &last_seen)| (last_seen, key.clone()))
            .collect();
        by_age.sort_unstable();
        for (_, key) in by_age.into_iter().take(excess) {
            self.sources.remove(&key);
        }
        self.recount();
        excess
    }

    /// Evict each tenant's least recently seen sources beyond `max`,
    /// returning how many were evicted.
    pub(crate) fn enforce_tenant_cap(&mut self, max: usize) -> usize {
        if self.tenant_counts.values().all(|&count| count <= max) {
            return 0;
        }
        let mut by_tenant: HashMap<Option<TenantId>, Vec<(i64, SourceKey)>> = HashMap::new();
        for (key, &last_seen) in &self.sources {
            by_tenant
                .entry(key.1.clone())
                .or_default()
                .push((last_seen, key.clone()));
        }
        let mut evicted = 0;
        for (_, mut sources) in by_tenant {
            let excess = sources.len().saturating_sub(max);
            sources.sort_unstable();
            for (_, key) in sources.into_iter().take(excess) {
                self.sources.remove(&key);
                evicted += 1;
            }
        }
        self.recount();
        evicted
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
                tenant_id: None,
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(Map::new()),
                enrichments: None,
                ruleset: None,
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
            max_sources: 100,
        }
    }

    #[test]
    fn source_inhibits_matching_target() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        // A critical source on 10.0.0.1 registers.
        assert_eq!(
            store.evaluate(
                &cfg,
                &detection("10.0.0.1", Level::Critical),
                0,
                None,
                |_| {}
            ),
            None
        );
        // A high target on the same IP is inhibited.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 1, None, |_| {}),
            Some("critical-inhibits-high".to_string())
        );
        // A high target on a different IP is not inhibited.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.2", Level::High), 2, None, |_| {}),
            None
        );
    }

    #[test]
    fn source_expires_after_duration() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        store.evaluate(
            &cfg,
            &detection("10.0.0.1", Level::Critical),
            0,
            None,
            |_| {},
        );
        // After the 300s window, the source no longer inhibits.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 400, None, |_| {}),
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
            max_sources: 100,
        };
        let mut store = InhibitStore::default();
        store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 0, None, |_| {});
        // The same kind of result is a source, not an inhibited target.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 1, None, |_| {}),
            None
        );
    }

    #[test]
    fn gc_and_active_count() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        store.evaluate(
            &cfg,
            &detection("10.0.0.1", Level::Critical),
            0,
            None,
            |_| {},
        );
        assert_eq!(store.active_count(&cfg, 100), 1);
        assert_eq!(store.active_count(&cfg, 400), 0, "past duration");
        store.gc(&cfg, 400);
        assert!(store.is_empty());
    }

    #[test]
    fn new_sources_past_the_cap_are_refused() {
        let cfg = InhibitConfig {
            max_sources: 2,
            ..cfg()
        };
        let mut store = InhibitStore::default();
        let mut refused = Vec::new();
        for (i, ip) in ["10.0.0.1", "10.0.0.2", "10.0.0.3"].into_iter().enumerate() {
            store.evaluate(
                &cfg,
                &detection(ip, Level::Critical),
                i as i64,
                None,
                |rule| refused.push(rule.to_string()),
            );
        }
        assert_eq!(refused, ["critical-inhibits-high"]);
        assert_eq!(store.active_count(&cfg, 10), 2);

        // The refused source does not inhibit; tracked ones still do and
        // still refresh at the cap.
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.3", Level::High), 10, None, |_| {}),
            None
        );
        store.evaluate(
            &cfg,
            &detection("10.0.0.1", Level::Critical),
            200,
            None,
            |_| panic!("refreshing a tracked source is not a refusal"),
        );
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.1", Level::High), 450, None, |_| {}),
            Some("critical-inhibits-high".to_string())
        );
    }

    #[test]
    fn enforce_cap_keeps_the_most_recently_seen() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        for (ip, now) in [("10.0.0.1", 30), ("10.0.0.2", 10), ("10.0.0.3", 20)] {
            store.evaluate(&cfg, &detection(ip, Level::Critical), now, None, |_| {});
        }
        assert_eq!(store.enforce_cap(5), 0);
        assert_eq!(store.enforce_cap(2), 1);
        assert_eq!(
            store.evaluate(&cfg, &detection("10.0.0.2", Level::High), 40, None, |_| {}),
            None,
            "the least recently seen source was evicted"
        );
        for ip in ["10.0.0.1", "10.0.0.3"] {
            assert!(
                store
                    .evaluate(&cfg, &detection(ip, Level::High), 40, None, |_| {})
                    .is_some()
            );
        }
    }

    fn tenant_detection(ip: &str, level: Level, tenant: &str) -> EvaluationResult {
        let mut r = detection(ip, level);
        r.header.tenant_id = Some(TenantId::new(tenant).unwrap());
        r
    }

    #[test]
    fn inhibition_stays_within_a_tenant() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        store.evaluate(
            &cfg,
            &tenant_detection("10.0.0.1", Level::Critical, "a"),
            0,
            None,
            |_| {},
        );
        assert_eq!(
            store.evaluate(
                &cfg,
                &tenant_detection("10.0.0.1", Level::High, "b"),
                1,
                None,
                |_| {}
            ),
            None,
            "tenant b has no critical source"
        );
        assert_eq!(
            store.evaluate(
                &cfg,
                &tenant_detection("10.0.0.1", Level::High, "a"),
                1,
                None,
                |_| {}
            ),
            Some("critical-inhibits-high".to_string())
        );
    }

    #[test]
    fn a_tenant_at_its_cap_cannot_crowd_out_another_tenant() {
        let cfg = cfg();
        let mut store = InhibitStore::default();
        let mut refused = 0;
        for i in 0..5 {
            store.evaluate(
                &cfg,
                &tenant_detection(&format!("10.0.0.{i}"), Level::Critical, "a"),
                i,
                Some(2),
                |_| refused += 1,
            );
        }
        assert_eq!(refused, 3, "tenant a keeps only its quota of sources");
        store.evaluate(
            &cfg,
            &tenant_detection("10.9.9.9", Level::Critical, "b"),
            10,
            Some(2),
            |_| panic!("tenant b has room"),
        );
        assert_eq!(
            store.evaluate(
                &cfg,
                &tenant_detection("10.9.9.9", Level::High, "b"),
                11,
                Some(2),
                |_| {}
            ),
            Some("critical-inhibits-high".to_string())
        );

        assert_eq!(store.enforce_tenant_cap(1), 1);
        assert_eq!(store.active_count(&cfg, 12), 2);
    }
}
