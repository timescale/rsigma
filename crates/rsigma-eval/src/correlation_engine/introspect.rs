//! Read-only introspection of correlation window state.
//!
//! The only built-in visibility into correlation state is the aggregate
//! `correlation_state_entries` count. That answers "is there state?" but not
//! the operator's real question: "why did this correlation not fire?"
//! [`CorrelationEngine::introspect`] projects, per correlation and per group,
//! the current aggregate versus the threshold (the gap made explicit), the
//! window contents, the last alert and remaining suppression, and the seconds
//! until the next eviction. It is a read-only projection over the existing
//! state with no hot-path cost.

use serde::Serialize;

use rsigma_parser::{ConditionOperator, CorrelationType};

use super::CorrelationEngine;
use crate::correlation::{CompiledCorrelation, GroupKey, WindowState};

/// A snapshot of every compiled correlation and its live per-group window
/// state at the moment [`CorrelationEngine::introspect`] was called.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationStateSnapshot {
    /// One entry per compiled correlation (independent of whether it has
    /// active state).
    pub correlations: Vec<CorrelationInfo>,
    /// One entry per live `(correlation, group_key)` window.
    pub groups: Vec<GroupStateInfo>,
}

/// Static description of one compiled correlation.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationInfo {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub title: String,
    #[serde(rename = "type")]
    pub correlation_type: CorrelationType,
    pub timespan_secs: u64,
    pub group_by: Vec<String>,
    pub rule_refs: Vec<String>,
    /// The threshold predicates rendered for display, e.g. `>= 5`.
    pub threshold: String,
    /// Number of live group windows for this correlation.
    pub active_groups: usize,
}

/// One field of a resolved group key.
#[derive(Debug, Clone, Serialize)]
pub struct GroupKeyPart {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Live state of one `(correlation, group_key)` window.
#[derive(Debug, Clone, Serialize)]
pub struct GroupStateInfo {
    pub correlation_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_name: Option<String>,
    pub correlation_title: String,
    #[serde(rename = "type")]
    pub correlation_type: CorrelationType,
    /// The resolved group key, field by field.
    pub group_key: Vec<GroupKeyPart>,
    /// A flat `field=value` rendering of the group key for display and
    /// substring filtering.
    pub group_key_display: String,
    /// The current aggregate (count / sum / avg / distinct / fired-rule count).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub got: Option<f64>,
    /// The threshold predicates rendered for display.
    pub threshold: String,
    /// Whether the threshold condition is currently satisfied.
    pub met: bool,
    /// Number of retained entries in the window.
    pub entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<i64>,
    pub timespan_secs: u64,
    /// Seconds until the oldest entry leaves the window, relative to the
    /// latest observed event time (`earliest + timespan - latest`, clamped at
    /// zero).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds_to_eviction: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_alert: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_secs: Option<u64>,
    /// Seconds remaining in the suppression window after the last alert,
    /// relative to the latest observed event time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_remaining: Option<i64>,
    /// The raw window state (timestamps / values), serialized as-is.
    pub window: WindowState,
}

impl CorrelationEngine {
    /// Snapshot every compiled correlation and its live per-group window state.
    pub fn introspect(&self) -> CorrelationStateSnapshot {
        self.introspect_filtered(None, None)
    }

    /// Like [`introspect`](CorrelationEngine::introspect) but keeps only the
    /// correlations whose id, name, or title equals `id_filter` and the groups
    /// whose rendered key contains `group_filter`.
    pub fn introspect_filtered(
        &self,
        id_filter: Option<&str>,
        group_filter: Option<&str>,
    ) -> CorrelationStateSnapshot {
        let mut active_per_corr = vec![0usize; self.correlations.len()];
        for (ci, _) in self.state.keys() {
            active_per_corr[*ci] += 1;
        }

        let correlations = self
            .correlations
            .iter()
            .enumerate()
            .filter(|(_, c)| matches_id(c, id_filter))
            .map(|(i, c)| CorrelationInfo {
                index: i,
                id: c.id.clone(),
                name: c.name.clone(),
                title: c.title.clone(),
                correlation_type: c.correlation_type,
                timespan_secs: c.timespan_secs,
                group_by: c.group_by.iter().map(|g| g.name().to_string()).collect(),
                rule_refs: c.rule_refs.clone(),
                threshold: render_threshold(c),
                active_groups: active_per_corr[i],
            })
            .collect();

        let mut groups = Vec::new();
        for ((ci, gk), ws) in &self.state {
            let corr = &self.correlations[*ci];
            if !matches_id(corr, id_filter) {
                continue;
            }
            let parts = group_key_parts(corr, gk);
            let display = render_group_key(&parts);
            if let Some(filter) = group_filter
                && !display.contains(filter)
            {
                continue;
            }

            let got = ws.current_value(
                corr.correlation_type,
                &corr.rule_refs,
                corr.condition.percentile,
            );
            let met = ws
                .check_condition(
                    &corr.condition,
                    corr.correlation_type,
                    &corr.rule_refs,
                    corr.extended_expr.as_ref(),
                )
                .is_some();
            let earliest = ws.earliest_timestamp();
            let latest = ws.latest_timestamp();
            let seconds_to_eviction = match (earliest, latest) {
                (Some(e), Some(l)) => Some((e + corr.timespan_secs as i64 - l).max(0)),
                _ => None,
            };
            let last_alert = self.last_alert.get(&(*ci, gk.clone())).copied();
            let suppress_secs = corr.suppress_secs.or(self.config.suppress);
            let suppression_remaining = match (last_alert, suppress_secs, latest) {
                (Some(la), Some(s), Some(l)) => Some((la + s as i64 - l).max(0)),
                _ => None,
            };

            groups.push(GroupStateInfo {
                correlation_index: *ci,
                correlation_id: corr.id.clone(),
                correlation_name: corr.name.clone(),
                correlation_title: corr.title.clone(),
                correlation_type: corr.correlation_type,
                group_key: parts,
                group_key_display: display,
                got,
                threshold: render_threshold(corr),
                met,
                entries: ws.entry_count(),
                earliest,
                latest,
                timespan_secs: corr.timespan_secs,
                seconds_to_eviction,
                last_alert,
                suppress_secs,
                suppression_remaining,
                window: ws.clone(),
            });
        }

        // Deterministic order for stable output and golden tests.
        groups.sort_by(|a, b| {
            a.correlation_index
                .cmp(&b.correlation_index)
                .then_with(|| a.group_key_display.cmp(&b.group_key_display))
        });

        CorrelationStateSnapshot {
            correlations,
            groups,
        }
    }
}

fn matches_id(corr: &CompiledCorrelation, id_filter: Option<&str>) -> bool {
    match id_filter {
        None => true,
        Some(f) => {
            corr.id.as_deref() == Some(f) || corr.name.as_deref() == Some(f) || corr.title == f
        }
    }
}

fn group_key_parts(corr: &CompiledCorrelation, key: &GroupKey) -> Vec<GroupKeyPart> {
    corr.group_by
        .iter()
        .enumerate()
        .map(|(i, field)| GroupKeyPart {
            field: field.name().to_string(),
            value: key.0.get(i).and_then(|v| v.clone()),
        })
        .collect()
}

fn render_group_key(parts: &[GroupKeyPart]) -> String {
    if parts.is_empty() {
        return "(no group-by)".to_string();
    }
    parts
        .iter()
        .map(|p| format!("{}={}", p.field, p.value.as_deref().unwrap_or("<none>")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_threshold(corr: &CompiledCorrelation) -> String {
    let preds: Vec<String> = corr
        .condition
        .predicates
        .iter()
        .map(|(op, v)| format!("{} {}", op_symbol(*op), v))
        .collect();
    if preds.is_empty() {
        "(none)".to_string()
    } else {
        preds.join(", ")
    }
}

fn op_symbol(op: ConditionOperator) -> &'static str {
    match op {
        ConditionOperator::Lt => "<",
        ConditionOperator::Lte => "<=",
        ConditionOperator::Gt => ">",
        ConditionOperator::Gte => ">=",
        ConditionOperator::Eq => "==",
        ConditionOperator::Neq => "!=",
    }
}

#[cfg(test)]
mod tests {
    use crate::event::JsonEvent;
    use crate::{CorrelationConfig, CorrelationEngine};
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    const RULES: &str = r#"
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
level: high
"#;

    fn engine() -> CorrelationEngine {
        let coll = parse_sigma_yaml(RULES).unwrap();
        let mut e = CorrelationEngine::new(CorrelationConfig::default());
        e.add_collection(&coll).unwrap();
        e
    }

    #[test]
    fn introspect_reports_gap_below_threshold() {
        let mut e = engine();
        // Two logins for admin: below the gte:3 threshold.
        for i in 0..2 {
            let v = json!({"EventType": "login", "User": "admin"});
            e.process_event_at(&JsonEvent::borrow(&v), 1000 + i);
        }
        let snap = e.introspect();
        assert_eq!(snap.correlations.len(), 1);
        assert_eq!(snap.correlations[0].threshold, ">= 3");
        assert_eq!(snap.correlations[0].active_groups, 1);

        let g = snap
            .groups
            .iter()
            .find(|g| g.group_key_display.contains("admin"))
            .expect("admin group present");
        assert_eq!(g.got, Some(2.0));
        assert!(!g.met);
        assert_eq!(g.entries, 2);
        assert_eq!(g.threshold, ">= 3");
        assert_eq!(g.group_key_display, "User=admin");
    }

    #[test]
    fn introspect_marks_met_when_threshold_reached() {
        let mut e = engine();
        for i in 0..3 {
            let v = json!({"EventType": "login", "User": "admin"});
            e.process_event_at(&JsonEvent::borrow(&v), 1000 + i);
        }
        let snap = e.introspect();
        let g = &snap.groups[0];
        assert_eq!(g.got, Some(3.0));
        assert!(g.met);
        // The window spans ts 1000..=1002 with a 60s timespan, so the oldest
        // entry (1000) is evicted 60s after it arrived, relative to the latest.
        assert_eq!(g.seconds_to_eviction, Some(1000 + 60 - 1002));
    }

    #[test]
    fn introspect_filter_by_group_substring() {
        let mut e = engine();
        for u in ["admin", "alice"] {
            let v = json!({"EventType": "login", "User": u});
            e.process_event_at(&JsonEvent::borrow(&v), 1000);
        }
        let snap = e.introspect_filtered(None, Some("alice"));
        assert_eq!(snap.groups.len(), 1);
        assert!(snap.groups[0].group_key_display.contains("alice"));
    }

    #[test]
    fn introspect_filter_by_unknown_id_is_empty() {
        let mut e = engine();
        let v = json!({"EventType": "login", "User": "admin"});
        e.process_event_at(&JsonEvent::borrow(&v), 1000);
        let snap = e.introspect_filtered(Some("nope"), None);
        assert!(snap.correlations.is_empty());
        assert!(snap.groups.is_empty());
    }
}
