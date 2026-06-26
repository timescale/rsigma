//! Operator silences, modeled on Alertmanager.
//!
//! A silence mutes results matching a [`MatcherSet`] for a time window. The
//! first fire matching an active silence is acked and dropped before dedup, so
//! a silenced result neither emits nor opens an incident.
//!
//! Silences come from two origins: `static` ones declared in the
//! `--alert-pipeline` config (replaced on hot-reload) and `api` ones created at
//! runtime over `POST /api/v1/silences` (independent of the config file).

use serde::{Deserialize, Serialize};

use rsigma_eval::EvaluationResult;

use super::matcher::{MatcherError, MatcherSet, MatcherSpec};

/// Where a silence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SilenceOrigin {
    /// Declared in the config `silences:` block.
    Static,
    /// Created at runtime over the API.
    Api,
}

/// A silence's lifecycle state, derived from the time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SilenceState {
    /// `now` is before `starts_at`.
    Pending,
    /// Within the window (or unbounded).
    Active,
    /// `now` is at or after `ends_at`.
    Expired,
}

/// A silence input from config or the API.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SilenceSpec {
    /// Optional client-supplied id; a UUID is assigned when absent.
    #[serde(default)]
    pub id: Option<String>,
    /// Matchers (ANDed). At least one is required.
    #[serde(default)]
    pub matchers: Vec<MatcherSpec>,
    /// RFC 3339 start; absent means active immediately.
    #[serde(default)]
    pub starts_at: Option<String>,
    /// RFC 3339 end; absent means it never expires.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// Who created it (recorded, does not affect matching).
    #[serde(default)]
    pub created_by: Option<String>,
    /// Free-text comment (recorded).
    #[serde(default)]
    pub comment: Option<String>,
}

/// The serialized view of a silence (the GET response shape).
#[derive(Debug, Clone, Serialize)]
pub struct SilenceView {
    pub id: String,
    pub matchers: Vec<MatcherSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub origin: SilenceOrigin,
    pub state: SilenceState,
}

/// Persisted form of a dynamic (API) silence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilenceSnap {
    pub id: String,
    pub matchers: Vec<MatcherSpec>,
    pub starts_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

/// Errors building a silence from a spec.
#[derive(Debug, Clone)]
pub enum SilenceError {
    /// No matchers supplied.
    EmptyMatchers,
    /// A matcher failed to compile.
    Matcher(MatcherError),
    /// A time field failed to parse as RFC 3339.
    Time { field: &'static str, value: String },
    /// `ends_at` is not after `starts_at`.
    Window,
}

impl std::fmt::Display for SilenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SilenceError::EmptyMatchers => write!(f, "a silence requires at least one matcher"),
            SilenceError::Matcher(e) => write!(f, "{e}"),
            SilenceError::Time { field, value } => {
                write!(
                    f,
                    "invalid {field} '{value}': expected an RFC 3339 timestamp"
                )
            }
            SilenceError::Window => write!(f, "ends_at must be after starts_at"),
        }
    }
}

impl std::error::Error for SilenceError {}

/// A compiled silence.
#[derive(Debug, Clone)]
pub struct Silence {
    id: String,
    matchers: MatcherSet,
    starts_at: Option<i64>,
    ends_at: Option<i64>,
    created_by: Option<String>,
    comment: Option<String>,
    origin: SilenceOrigin,
}

impl Silence {
    /// Build and validate a silence from a spec.
    pub fn build(spec: SilenceSpec, origin: SilenceOrigin) -> Result<Self, SilenceError> {
        if spec.matchers.is_empty() {
            return Err(SilenceError::EmptyMatchers);
        }
        let matchers = MatcherSet::compile(&spec.matchers).map_err(SilenceError::Matcher)?;
        let starts_at = parse_time(spec.starts_at.as_deref(), "starts_at")?;
        let ends_at = parse_time(spec.ends_at.as_deref(), "ends_at")?;
        if let (Some(s), Some(e)) = (starts_at, ends_at)
            && e <= s
        {
            return Err(SilenceError::Window);
        }
        Ok(Silence {
            id: spec.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            matchers,
            starts_at,
            ends_at,
            created_by: spec.created_by,
            comment: spec.comment,
            origin,
        })
    }

    /// The silence id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The lifecycle state at `now`.
    pub fn state(&self, now: i64) -> SilenceState {
        if self.starts_at.is_some_and(|s| now < s) {
            SilenceState::Pending
        } else if self.ends_at.is_some_and(|e| now >= e) {
            SilenceState::Expired
        } else {
            SilenceState::Active
        }
    }

    /// True when active and every matcher matches the result.
    fn mutes(&self, result: &EvaluationResult, now: i64) -> bool {
        self.state(now) == SilenceState::Active && self.matchers.matches(result)
    }

    /// Persisted form (for API-origin silences).
    fn to_snap(&self) -> SilenceSnap {
        SilenceSnap {
            id: self.id.clone(),
            matchers: self.matchers.to_specs(),
            starts_at: self.starts_at,
            ends_at: self.ends_at,
            created_by: self.created_by.clone(),
            comment: self.comment.clone(),
        }
    }

    /// Rebuild an API-origin silence from its persisted form.
    fn from_snap(snap: SilenceSnap) -> Result<Self, SilenceError> {
        if snap.matchers.is_empty() {
            return Err(SilenceError::EmptyMatchers);
        }
        let matchers = MatcherSet::compile(&snap.matchers).map_err(SilenceError::Matcher)?;
        Ok(Silence {
            id: snap.id,
            matchers,
            starts_at: snap.starts_at,
            ends_at: snap.ends_at,
            created_by: snap.created_by,
            comment: snap.comment,
            origin: SilenceOrigin::Api,
        })
    }

    fn view(&self, now: i64) -> SilenceView {
        SilenceView {
            id: self.id.clone(),
            matchers: self.matchers.to_specs(),
            starts_at: self.starts_at.map(unix_to_rfc3339),
            ends_at: self.ends_at.map(unix_to_rfc3339),
            created_by: self.created_by.clone(),
            comment: self.comment.clone(),
            origin: self.origin,
            state: self.state(now),
        }
    }
}

/// The runtime silence set, owned single-threaded by the sink task and shared
/// behind an `RwLock` so the silence API can mutate it.
#[derive(Debug, Default)]
pub struct SilenceStore {
    silences: Vec<Silence>,
}

impl SilenceStore {
    /// True when no silences are tracked.
    pub fn is_empty(&self) -> bool {
        self.silences.is_empty()
    }

    /// Add a silence (used by restore and tests). Prefer [`try_add`] on the API
    /// path so the dynamic-silence cap is enforced.
    ///
    /// [`try_add`]: SilenceStore::try_add
    pub fn add(&mut self, silence: Silence) {
        self.silences.push(silence);
    }

    /// Count of dynamic (API-origin) silences currently tracked.
    pub fn dynamic_count(&self) -> usize {
        self.silences
            .iter()
            .filter(|s| s.origin == SilenceOrigin::Api)
            .count()
    }

    /// Add an API-origin silence unless the dynamic-silence cap is reached.
    /// Returns `false` (and does not add) when at or over `max_dynamic`.
    pub fn try_add(&mut self, silence: Silence, max_dynamic: usize) -> bool {
        if self.dynamic_count() >= max_dynamic {
            return false;
        }
        self.silences.push(silence);
        true
    }

    /// Remove a silence by id. Returns whether one was removed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.silences.len();
        self.silences.retain(|s| s.id != id);
        self.silences.len() != before
    }

    /// Replace all `static`-origin silences with `statics`, keeping `api` ones.
    /// Used on config load and hot-reload.
    pub fn set_static(&mut self, statics: Vec<Silence>) {
        self.silences.retain(|s| s.origin != SilenceOrigin::Static);
        self.silences.extend(statics);
    }

    /// Drop expired silences.
    pub fn gc(&mut self, now: i64) {
        self.silences
            .retain(|s| s.state(now) != SilenceState::Expired);
    }

    /// The id of the first active silence muting the result, if any.
    pub fn active_match(&self, result: &EvaluationResult, now: i64) -> Option<&str> {
        self.silences
            .iter()
            .find(|s| s.mutes(result, now))
            .map(|s| s.id.as_str())
    }

    /// Count of currently-active silences.
    pub fn active_count(&self, now: i64) -> usize {
        self.silences
            .iter()
            .filter(|s| s.state(now) == SilenceState::Active)
            .count()
    }

    /// A snapshot of every silence for the API.
    pub fn snapshot(&self, now: i64) -> Vec<SilenceView> {
        self.silences.iter().map(|s| s.view(now)).collect()
    }

    /// Persisted form of the dynamic (API) silences only; static ones come from
    /// config and are re-seeded on boot.
    pub(crate) fn api_snapshot(&self) -> Vec<SilenceSnap> {
        self.silences
            .iter()
            .filter(|s| s.origin == SilenceOrigin::Api)
            .map(|s| s.to_snap())
            .collect()
    }

    /// Restore API silences from persisted form, skipping any already expired at
    /// `now` or that fail to recompile.
    pub(crate) fn restore_api(&mut self, snaps: Vec<SilenceSnap>, now: i64) {
        for snap in snaps {
            match Silence::from_snap(snap) {
                Ok(silence) if silence.state(now) != SilenceState::Expired => {
                    self.silences.push(silence);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Dropping unrestorable silence"),
            }
        }
    }
}

/// Parse an optional RFC 3339 timestamp into unix seconds.
fn parse_time(raw: Option<&str>, field: &'static str) -> Result<Option<i64>, SilenceError> {
    match raw {
        None => Ok(None),
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| Some(dt.timestamp()))
            .map_err(|_| SilenceError::Time {
                field,
                value: s.to_string(),
            }),
    }
}

/// Format unix seconds as an RFC 3339 timestamp (UTC).
fn unix_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_default()
        .to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::super::matcher::MatchOp;

    fn detection(ip: &str) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "t".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: None,
            }),
        }
    }

    fn spec(ip: &str) -> SilenceSpec {
        SilenceSpec {
            matchers: vec![MatcherSpec {
                selector: "match.SourceIp".to_string(),
                op: MatchOp::Eq,
                value: ip.to_string(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn unbounded_silence_is_active_and_mutes() {
        let mut store = SilenceStore::default();
        store.add(Silence::build(spec("10.0.0.1"), SilenceOrigin::Api).unwrap());
        assert!(store.active_match(&detection("10.0.0.1"), 100).is_some());
        assert!(store.active_match(&detection("10.0.0.2"), 100).is_none());
        assert_eq!(store.active_count(100), 1);
    }

    #[test]
    fn time_window_pending_active_expired() {
        let s = Silence::build(
            SilenceSpec {
                starts_at: Some("2026-01-01T00:00:00Z".to_string()),
                ends_at: Some("2026-01-02T00:00:00Z".to_string()),
                ..spec("10.0.0.1")
            },
            SilenceOrigin::Api,
        )
        .unwrap();
        let before = 1_767_139_200; // 2025-12-31
        let during = 1_767_283_200; // 2026-01-01T12:00
        let after = 1_767_312_000; // 2026-01-02T...
        assert_eq!(s.state(before), SilenceState::Pending);
        assert_eq!(s.state(during), SilenceState::Active);
        assert_eq!(s.state(after), SilenceState::Expired);
    }

    #[test]
    fn gc_drops_expired() {
        let mut store = SilenceStore::default();
        store.add(
            Silence::build(
                SilenceSpec {
                    ends_at: Some("2026-01-01T00:00:00Z".to_string()),
                    ..spec("10.0.0.1")
                },
                SilenceOrigin::Api,
            )
            .unwrap(),
        );
        store.gc(1_700_000_000); // before end: kept
        assert!(!store.is_empty());
        store.gc(1_800_000_000); // after end: dropped
        assert!(store.is_empty());
    }

    #[test]
    fn set_static_replaces_static_keeps_api() {
        let mut store = SilenceStore::default();
        store.add(Silence::build(spec("10.0.0.9"), SilenceOrigin::Api).unwrap());
        store.set_static(vec![
            Silence::build(spec("10.0.0.1"), SilenceOrigin::Static).unwrap(),
        ]);
        assert_eq!(store.snapshot(0).len(), 2);
        // Reseed with a different static set: the API one survives.
        store.set_static(vec![
            Silence::build(spec("10.0.0.2"), SilenceOrigin::Static).unwrap(),
        ]);
        let ips: Vec<String> = store
            .snapshot(0)
            .into_iter()
            .flat_map(|v| v.matchers.into_iter().map(|m| m.value))
            .collect();
        assert!(ips.contains(&"10.0.0.9".to_string()), "api silence kept");
        assert!(ips.contains(&"10.0.0.2".to_string()), "new static seeded");
        assert!(
            !ips.contains(&"10.0.0.1".to_string()),
            "old static replaced"
        );
    }

    #[test]
    fn remove_by_id() {
        let mut store = SilenceStore::default();
        let s = Silence::build(spec("10.0.0.1"), SilenceOrigin::Api).unwrap();
        let id = s.id().to_string();
        store.add(s);
        assert!(store.remove(&id));
        assert!(!store.remove(&id));
        assert!(store.is_empty());
    }

    #[test]
    fn empty_matchers_rejected() {
        let err = Silence::build(SilenceSpec::default(), SilenceOrigin::Api).unwrap_err();
        assert!(matches!(err, SilenceError::EmptyMatchers));
    }

    #[test]
    fn try_add_enforces_dynamic_cap() {
        let mut store = SilenceStore::default();
        // A static silence does not count against the dynamic cap.
        store.add(Silence::build(spec("10.0.0.0"), SilenceOrigin::Static).unwrap());
        assert!(store.try_add(
            Silence::build(spec("10.0.0.1"), SilenceOrigin::Api).unwrap(),
            2
        ));
        assert!(store.try_add(
            Silence::build(spec("10.0.0.2"), SilenceOrigin::Api).unwrap(),
            2
        ));
        // Third dynamic silence is rejected at the cap of 2.
        assert!(!store.try_add(
            Silence::build(spec("10.0.0.3"), SilenceOrigin::Api).unwrap(),
            2
        ));
        assert_eq!(store.dynamic_count(), 2);
    }
}
