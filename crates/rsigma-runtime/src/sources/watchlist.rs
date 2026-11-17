//! In-memory indicator sets for `type: watchlist` sources.
//!
//! A watchlist has nothing to fetch. Callers push values, and resolution
//! returns the unexpired values in byte order.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rsigma_eval::pipeline::sources::{DynamicSource, SourceType};
use serde::Deserialize;

/// Most indicators one push, replace, or delete request may carry.
pub const MAX_WATCHLIST_ITEMS_PER_REQUEST: usize = 10_000;

/// One watchlist indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchlistEntry {
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// A row stored for one indicator, including the source it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchlistRow {
    pub source_id: String,
    pub value: String,
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// One item in a push or replace body. A JSON string is the value alone.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum WatchlistItem {
    /// A bare indicator value.
    Bare(String),
    /// A value with its own lifetime.
    Detailed(WatchlistItemFields),
}

/// Fields of an object-form indicator.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WatchlistItemFields {
    /// Indicator value.
    pub value: String,
    /// Lifetime from now, such as `24h`. Ignored when `expires_at` is set.
    #[serde(default)]
    pub ttl: Option<String>,
    /// Absolute expiry, RFC 3339.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Counts from a successful add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddSummary {
    /// Values that were not already in the unexpired set.
    pub added: usize,
    /// Values that were already present and whose expiry was replaced.
    pub updated: usize,
    /// Unexpired values after the change.
    pub total: usize,
}

/// Counts from a successful replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaceSummary {
    /// Unexpired values after the replace.
    pub total: usize,
    /// Previously unexpired values that the new set does not contain.
    pub removed: usize,
}

/// Counts from a delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveSummary {
    /// Values that were present and are now gone.
    pub removed: usize,
    /// Requested values that were not in the unexpired set.
    pub not_found: usize,
    /// Unexpired values after the change.
    pub total: usize,
}

/// Why a watchlist change was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchlistError {
    /// No watchlist is declared with this id.
    UnknownSource,
    /// The id names a source that is not a watchlist.
    NotAWatchlist,
    /// `items[index]` failed a value or expiry rule.
    InvalidValue {
        /// Index in the request's indicator list.
        index: usize,
        /// What was wrong.
        reason: &'static str,
    },
    /// The request listed more than [`MAX_WATCHLIST_ITEMS_PER_REQUEST`] items.
    TooManyItems,
    /// The change would exceed the source's `max_indicators`.
    LimitExceeded {
        /// The source's configured maximum.
        max: usize,
    },
}

impl std::fmt::Display for WatchlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSource => write!(f, "unknown watchlist"),
            Self::NotAWatchlist => write!(f, "source is not a watchlist"),
            Self::InvalidValue { index, reason } => {
                write!(f, "indicator {index}: {reason}")
            }
            Self::TooManyItems => write!(
                f,
                "a request accepts at most {MAX_WATCHLIST_ITEMS_PER_REQUEST} indicators"
            ),
            Self::LimitExceeded { max } => {
                write!(f, "watchlist would exceed {max} indicators")
            }
        }
    }
}

impl std::error::Error for WatchlistError {}

struct Watchlist {
    entries: BTreeMap<String, WatchlistEntry>,
    /// The `max_indicators` declared on the source.
    configured_max: usize,
    /// The cap in force. A pipeline reference lowers this to the placeholder limit.
    max_indicators: usize,
    max_value_length: usize,
    default_ttl: Option<Duration>,
}

impl Watchlist {
    fn from_source(
        max_indicators: usize,
        max_value_length: usize,
        default_ttl: Option<Duration>,
    ) -> Self {
        Self {
            entries: BTreeMap::new(),
            configured_max: max_indicators,
            max_indicators,
            max_value_length,
            default_ttl,
        }
    }

    fn live(&self, now: DateTime<Utc>) -> BTreeMap<String, WatchlistEntry> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.expires_at.is_none_or(|exp| exp > now))
            .map(|(value, entry)| (value.clone(), entry.clone()))
            .collect()
    }

    fn add(
        &mut self,
        items: &[WatchlistItem],
        request_ttl: Option<Duration>,
        now: DateTime<Utc>,
    ) -> Result<AddSummary, WatchlistError> {
        check_batch(items)?;
        let original = self.live(now);
        let mut next = original.clone();
        let mut added = 0;
        let mut updated = 0;
        for (index, item) in items.iter().enumerate() {
            let (value, expires_at) = prepare_item(item, index, self, request_ttl, now)?;
            match next.entry(value) {
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().expires_at = expires_at;
                    updated += 1;
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(WatchlistEntry {
                        added_at: now,
                        expires_at,
                    });
                    added += 1;
                }
            }
        }
        if next.len() > self.max_indicators {
            return Err(WatchlistError::LimitExceeded {
                max: self.max_indicators,
            });
        }
        self.entries = next;
        Ok(AddSummary {
            added,
            updated,
            total: self.entries.len(),
        })
    }

    fn replace(
        &mut self,
        items: &[WatchlistItem],
        request_ttl: Option<Duration>,
        now: DateTime<Utc>,
    ) -> Result<ReplaceSummary, WatchlistError> {
        check_batch(items)?;
        let previous = self.live(now);
        let mut next = BTreeMap::new();
        for (index, item) in items.iter().enumerate() {
            let (value, expires_at) = prepare_item(item, index, self, request_ttl, now)?;
            let added_at = previous
                .get(&value)
                .map(|entry| entry.added_at)
                .unwrap_or(now);
            next.insert(
                value,
                WatchlistEntry {
                    added_at,
                    expires_at,
                },
            );
        }
        if next.len() > self.max_indicators {
            return Err(WatchlistError::LimitExceeded {
                max: self.max_indicators,
            });
        }
        let removed = previous
            .keys()
            .filter(|value| !next.contains_key(*value))
            .count();
        let total = next.len();
        self.entries = next;
        Ok(ReplaceSummary { total, removed })
    }

    fn remove(
        &mut self,
        values: &[String],
        now: DateTime<Utc>,
    ) -> Result<RemoveSummary, WatchlistError> {
        if values.len() > MAX_WATCHLIST_ITEMS_PER_REQUEST {
            return Err(WatchlistError::TooManyItems);
        }
        let mut next = self.live(now);
        let mut removed = 0;
        let mut not_found = 0;
        for (index, raw) in values.iter().enumerate() {
            let value = normalize_value(raw, index, self.max_value_length)?;
            if next.remove(&value).is_some() {
                removed += 1;
            } else {
                not_found += 1;
            }
        }
        let total = next.len();
        self.entries = next;
        Ok(RemoveSummary {
            removed,
            not_found,
            total,
        })
    }

    fn sweep(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.expires_at.is_none_or(|exp| exp > now));
        before - self.entries.len()
    }
}

/// How many stored rows [`WatchlistRegistry::restore`] did not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchlistRestore {
    /// Rows whose `expires_at` was not in the future.
    pub expired: usize,
    /// Unexpired rows left out because the source was already at its cap.
    pub over_cap: usize,
}

/// The declared watchlists and their indicators.
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use chrono::{TimeZone, Utc};
/// use rsigma_eval::pipeline::sources::{
///     DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
/// };
/// use rsigma_runtime::sources::watchlist::{WatchlistItem, WatchlistRegistry};
///
/// let registry = WatchlistRegistry::from_sources(&[DynamicSource {
///     id: "c2_ips".into(),
///     source_type: SourceType::Watchlist {
///         max_indicators: 10,
///         max_value_length: 64,
///         default_ttl: Some(Duration::from_secs(60)),
///     },
///     refresh: RefreshPolicy::Once,
///     timeout: None,
///     on_error: ErrorPolicy::UseCached,
///     required: true,
///     default: None,
/// }]);
/// let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
/// let summary = registry
///     .add("c2_ips", &[WatchlistItem::Bare("198.51.100.7".into())], None, now)
///     .unwrap();
/// assert_eq!(summary.added, 1);
/// assert_eq!(registry.values("c2_ips", now).unwrap(), vec!["198.51.100.7"]);
/// let _ = Arc::new(registry);
/// ```
#[derive(Clone)]
pub struct WatchlistRegistry {
    lists: Arc<RwLock<HashMap<String, Watchlist>>>,
    writes: Arc<tokio::sync::Mutex<()>>,
}

impl WatchlistRegistry {
    /// Build an empty set for every declared watchlist. Other source types are ignored.
    pub fn from_sources(sources: &[DynamicSource]) -> Self {
        let mut lists = HashMap::new();
        for source in sources {
            if let SourceType::Watchlist {
                max_indicators,
                max_value_length,
                default_ttl,
            } = &source.source_type
            {
                lists.insert(
                    source.id.clone(),
                    Watchlist::from_source(*max_indicators, *max_value_length, *default_ttl),
                );
            }
        }
        Self {
            lists: Arc::new(RwLock::new(lists)),
            writes: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// The lock that serializes a memory change with its state-database write.
    ///
    /// Hold it across the mutation, the persist, and any rollback. The guard
    /// borrows this clone, so the registry can still be updated while it is held.
    pub fn write_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.writes)
    }

    /// Set each watchlist's effective cap from the sources referenced now.
    ///
    /// A referenced watchlist is held to `min(configured max_indicators, cap)`.
    /// A watchlist that is not referenced returns to its configured maximum.
    /// The returned count is how many stored indicators sit above the new cap.
    /// Those indicators stay until a later restore; a push that would grow the
    /// set past the cap is rejected.
    pub fn apply_reference_limits(&self, source_ids: &HashSet<String>, cap: usize) -> usize {
        let mut lists = self.lists.write();
        let mut over = 0;
        for (id, list) in lists.iter_mut() {
            list.max_indicators = if source_ids.contains(id) {
                list.configured_max.min(cap)
            } else {
                list.configured_max
            };
            over += list.entries.len().saturating_sub(list.max_indicators);
        }
        over
    }

    /// Add or refresh indicators. The change is kept only when every item is valid
    /// and the result fits in `max_indicators`.
    pub fn add(
        &self,
        source_id: &str,
        items: &[WatchlistItem],
        request_ttl: Option<Duration>,
        now: DateTime<Utc>,
    ) -> Result<AddSummary, WatchlistError> {
        let mut lists = self.lists.write();
        let list = lists
            .get_mut(source_id)
            .ok_or(WatchlistError::UnknownSource)?;
        list.add(items, request_ttl, now)
    }

    /// Replace the unexpired set. A failure leaves the previous set in place.
    pub fn replace(
        &self,
        source_id: &str,
        items: &[WatchlistItem],
        request_ttl: Option<Duration>,
        now: DateTime<Utc>,
    ) -> Result<ReplaceSummary, WatchlistError> {
        let mut lists = self.lists.write();
        let list = lists
            .get_mut(source_id)
            .ok_or(WatchlistError::UnknownSource)?;
        list.replace(items, request_ttl, now)
    }

    /// Delete the named values. Missing values are counted and not an error.
    pub fn remove(
        &self,
        source_id: &str,
        values: &[String],
        now: DateTime<Utc>,
    ) -> Result<RemoveSummary, WatchlistError> {
        let mut lists = self.lists.write();
        let list = lists
            .get_mut(source_id)
            .ok_or(WatchlistError::UnknownSource)?;
        list.remove(values, now)
    }

    /// Drop expired indicators. Each pair is a source id and how many it lost.
    /// Sources that lost nothing are omitted.
    pub fn sweep(&self, now: DateTime<Utc>) -> Vec<(String, usize)> {
        let mut lists = self.lists.write();
        let mut changed = Vec::new();
        for (id, list) in lists.iter_mut() {
            let removed = list.sweep(now);
            if removed > 0 {
                changed.push((id.clone(), removed));
            }
        }
        changed.sort_by(|a, b| a.0.cmp(&b.0));
        changed
    }

    /// Unexpired values in byte order.
    pub fn values(
        &self,
        source_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>, WatchlistError> {
        let lists = self.lists.read();
        let list = lists.get(source_id).ok_or(WatchlistError::UnknownSource)?;
        Ok(list.live(now).into_keys().collect())
    }

    /// A page of unexpired indicators, sorted by value.
    pub fn list(
        &self,
        source_id: &str,
        now: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<(usize, Vec<(String, WatchlistEntry)>), WatchlistError> {
        let lists = self.lists.read();
        let list = lists.get(source_id).ok_or(WatchlistError::UnknownSource)?;
        let live = list.live(now);
        let total = live.len();
        let page = live.into_iter().skip(offset).take(limit).collect();
        Ok((total, page))
    }

    /// Every stored row, including ones that are already expired.
    pub fn snapshot(&self) -> Vec<WatchlistRow> {
        let lists = self.lists.read();
        let mut rows = Vec::new();
        for (source_id, list) in lists.iter() {
            for (value, entry) in &list.entries {
                rows.push(WatchlistRow {
                    source_id: source_id.clone(),
                    value: value.clone(),
                    added_at: entry.added_at,
                    expires_at: entry.expires_at,
                });
            }
        }
        rows.sort_by(|a, b| (&a.source_id, &a.value).cmp(&(&b.source_id, &b.value)));
        rows
    }

    /// Replace stored rows. Expired rows are dropped. Rows for an unknown
    /// source id are skipped. A source keeps at most its effective cap, so a
    /// stored set larger than the placeholder limit cannot be loaded into a
    /// rule. [`WatchlistRestore::over_cap`] counts the unexpired rows left out.
    pub fn restore(&self, rows: &[WatchlistRow], now: DateTime<Utc>) -> WatchlistRestore {
        let mut lists = self.lists.write();
        for list in lists.values_mut() {
            list.entries.clear();
        }
        let mut expired = 0;
        let mut over_cap = 0;
        for row in rows {
            if row.expires_at.is_some_and(|exp| exp <= now) {
                expired += 1;
                continue;
            }
            let Some(list) = lists.get_mut(&row.source_id) else {
                continue;
            };
            if list.entries.len() >= list.max_indicators {
                over_cap += 1;
                continue;
            }
            list.entries.insert(
                row.value.clone(),
                WatchlistEntry {
                    added_at: row.added_at,
                    expires_at: row.expires_at,
                },
            );
        }
        WatchlistRestore { expired, over_cap }
    }

    /// Put one source back to `rows`. Other sources are left as they are.
    pub fn restore_source(&self, source_id: &str, rows: &[WatchlistRow], now: DateTime<Utc>) {
        let mut lists = self.lists.write();
        let Some(list) = lists.get_mut(source_id) else {
            return;
        };
        list.entries.clear();
        for row in rows {
            if row.source_id != source_id || row.expires_at.is_some_and(|exp| exp <= now) {
                continue;
            }
            if list.entries.len() >= list.max_indicators {
                break;
            }
            list.entries.insert(
                row.value.clone(),
                WatchlistEntry {
                    added_at: row.added_at,
                    expires_at: row.expires_at,
                },
            );
        }
    }
}

pub(crate) fn now_utc() -> DateTime<Utc> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    DateTime::from_timestamp(secs, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

fn check_batch(items: &[WatchlistItem]) -> Result<(), WatchlistError> {
    if items.len() > MAX_WATCHLIST_ITEMS_PER_REQUEST {
        Err(WatchlistError::TooManyItems)
    } else {
        Ok(())
    }
}

fn prepare_item(
    item: &WatchlistItem,
    index: usize,
    list: &Watchlist,
    request_ttl: Option<Duration>,
    now: DateTime<Utc>,
) -> Result<(String, Option<DateTime<Utc>>), WatchlistError> {
    let (raw, item_ttl, item_expires) = match item {
        WatchlistItem::Bare(value) => (value.as_str(), None, None),
        WatchlistItem::Detailed(fields) => (
            fields.value.as_str(),
            fields.ttl.as_deref(),
            fields.expires_at.as_deref(),
        ),
    };
    let value = normalize_value(raw, index, list.max_value_length)?;
    let expires_at = expiry(
        index,
        item_expires,
        item_ttl,
        request_ttl,
        list.default_ttl,
        now,
    )?;
    if expires_at.is_some_and(|exp| exp <= now) {
        return Err(WatchlistError::InvalidValue {
            index,
            reason: "expires_at is in the past",
        });
    }
    Ok((value, expires_at))
}

fn normalize_value(
    raw: &str,
    index: usize,
    max_value_length: usize,
) -> Result<String, WatchlistError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(WatchlistError::InvalidValue {
            index,
            reason: "value is empty",
        });
    }
    if value.len() > max_value_length {
        return Err(WatchlistError::InvalidValue {
            index,
            reason: "value exceeds max_value_length",
        });
    }
    if value.chars().any(|c| c.is_ascii_control()) {
        return Err(WatchlistError::InvalidValue {
            index,
            reason: "value contains a control character",
        });
    }
    Ok(value.to_string())
}

fn expiry(
    index: usize,
    expires_at: Option<&str>,
    ttl: Option<&str>,
    request_ttl: Option<Duration>,
    default_ttl: Option<Duration>,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, WatchlistError> {
    if let Some(text) = expires_at {
        let parsed =
            DateTime::parse_from_rfc3339(text).map_err(|_| WatchlistError::InvalidValue {
                index,
                reason: "expires_at is not RFC 3339",
            })?;
        return Ok(Some(parsed.with_timezone(&Utc)));
    }
    let ttl = if let Some(text) = ttl {
        Some(
            humantime::parse_duration(text).map_err(|_| WatchlistError::InvalidValue {
                index,
                reason: "ttl is not a duration",
            })?,
        )
    } else {
        request_ttl.or(default_ttl)
    };
    let Some(ttl) = ttl else {
        return Ok(None);
    };
    let signed = chrono::Duration::from_std(ttl).map_err(|_| WatchlistError::InvalidValue {
        index,
        reason: "ttl is too large",
    })?;
    now.checked_add_signed(signed)
        .map(Some)
        .ok_or(WatchlistError::InvalidValue {
            index,
            reason: "ttl is too large",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap()
    }

    fn sample(max: usize, default_ttl: Option<Duration>) -> WatchlistRegistry {
        WatchlistRegistry::from_sources(&[DynamicSource {
            id: "c2".into(),
            source_type: SourceType::Watchlist {
                max_indicators: max,
                max_value_length: 16,
                default_ttl,
            },
            refresh: rsigma_eval::pipeline::sources::RefreshPolicy::Once,
            timeout: None,
            on_error: rsigma_eval::pipeline::sources::ErrorPolicy::UseCached,
            required: true,
            default: None,
        }])
    }

    fn bare(value: &str) -> WatchlistItem {
        WatchlistItem::Bare(value.into())
    }

    #[test]
    fn value_rules_reject_empty_long_and_control_characters() {
        let registry = sample(10, None);
        let err = registry.add("c2", &[bare("   ")], None, now()).unwrap_err();
        assert!(matches!(err, WatchlistError::InvalidValue { index: 0, .. }));
        let err = registry
            .add("c2", &[bare("0123456789abcdefX")], None, now())
            .unwrap_err();
        assert!(err.to_string().contains("max_value_length"));
        let err = registry
            .add("c2", &[bare("bad\nvalue")], None, now())
            .unwrap_err();
        assert!(err.to_string().contains("control"));
        assert!(registry.values("c2", now()).unwrap().is_empty());
    }

    #[test]
    fn expiry_prefers_item_expires_at_then_item_ttl_then_request_then_default() {
        let registry = sample(10, Some(Duration::from_secs(10)));
        let item = WatchlistItem::Detailed(WatchlistItemFields {
            value: "a".into(),
            ttl: Some("1h".into()),
            expires_at: Some("2026-06-01T00:01:00Z".into()),
        });
        registry
            .add("c2", &[item], Some(Duration::from_secs(30)), now())
            .unwrap();
        let rows = registry.snapshot();
        assert_eq!(
            rows[0].expires_at,
            Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 1, 0).unwrap())
        );

        let item = WatchlistItem::Detailed(WatchlistItemFields {
            value: "b".into(),
            ttl: Some("2m".into()),
            expires_at: None,
        });
        registry
            .add("c2", &[item], Some(Duration::from_secs(30)), now())
            .unwrap();
        assert_eq!(
            registry.snapshot()[1].expires_at,
            Some(now() + chrono::Duration::seconds(120))
        );

        registry
            .add("c2", &[bare("c")], Some(Duration::from_secs(30)), now())
            .unwrap();
        assert_eq!(
            registry
                .snapshot()
                .iter()
                .find(|row| row.value == "c")
                .unwrap()
                .expires_at,
            Some(now() + chrono::Duration::seconds(30))
        );

        let no_request = sample(10, Some(Duration::from_secs(10)));
        no_request.add("c2", &[bare("d")], None, now()).unwrap();
        assert_eq!(
            no_request.snapshot()[0].expires_at,
            Some(now() + chrono::Duration::seconds(10))
        );

        let forever = sample(10, None);
        forever.add("c2", &[bare("e")], None, now()).unwrap();
        assert_eq!(forever.snapshot()[0].expires_at, None);
    }

    #[test]
    fn add_is_rejected_as_a_whole_when_the_limit_would_be_exceeded() {
        let registry = sample(1, None);
        let err = registry
            .add("c2", &[bare("a"), bare("b")], None, now())
            .unwrap_err();
        assert_eq!(err, WatchlistError::LimitExceeded { max: 1 });
        assert!(registry.values("c2", now()).unwrap().is_empty());
    }

    #[test]
    fn replace_removes_values_that_are_absent_from_the_new_set() {
        let registry = sample(10, None);
        registry
            .add("c2", &[bare("a"), bare("b")], None, now())
            .unwrap();
        let summary = registry
            .replace("c2", &[bare("b"), bare("c")], None, now())
            .unwrap();
        assert_eq!(summary.removed, 1);
        assert_eq!(summary.total, 2);
        assert_eq!(registry.values("c2", now()).unwrap(), vec!["b", "c"]);
    }

    #[test]
    fn sweep_counts_only_sources_that_lost_an_indicator() {
        let registry = sample(10, None);
        registry
            .add(
                "c2",
                &[WatchlistItem::Detailed(WatchlistItemFields {
                    value: "gone".into(),
                    ttl: None,
                    expires_at: Some("2026-06-01T00:00:01Z".into()),
                })],
                None,
                now(),
            )
            .unwrap();
        let later = now() + chrono::Duration::seconds(2);
        assert_eq!(registry.sweep(later), vec![("c2".into(), 1)]);
        assert!(registry.sweep(later).is_empty());
    }

    #[test]
    fn values_are_sorted_and_a_repeat_counts_as_an_update() {
        let registry = sample(10, None);
        registry
            .add("c2", &[bare("b"), bare("a")], None, now())
            .unwrap();
        assert_eq!(registry.values("c2", now()).unwrap(), vec!["a", "b"]);
        let summary = registry.add("c2", &[bare("a")], None, now()).unwrap();
        assert_eq!(summary.added, 0);
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.total, 2);
    }

    #[test]
    fn snapshot_restore_drops_expired_rows() {
        let registry = sample(10, None);
        registry.add("c2", &[bare("keep")], None, now()).unwrap();
        let mut rows = registry.snapshot();
        rows.push(WatchlistRow {
            source_id: "c2".into(),
            value: "old".into(),
            added_at: now(),
            expires_at: Some(now() - chrono::Duration::seconds(1)),
        });
        let later = now() + chrono::Duration::seconds(1);
        assert_eq!(
            registry.restore(&rows, later),
            WatchlistRestore {
                expired: 1,
                over_cap: 0,
            }
        );
        assert_eq!(registry.values("c2", later).unwrap(), vec!["keep"]);
    }

    #[test]
    fn an_already_expired_indicator_is_rejected() {
        let registry = sample(10, None);
        let err = registry
            .add(
                "c2",
                &[WatchlistItem::Detailed(WatchlistItemFields {
                    value: "old".into(),
                    ttl: None,
                    expires_at: Some("2020-01-01T00:00:00Z".into()),
                })],
                None,
                now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            WatchlistError::InvalidValue {
                index: 0,
                reason: "expires_at is in the past"
            }
        ));
        assert!(registry.values("c2", now()).unwrap().is_empty());
    }

    #[test]
    fn a_referenced_watchlist_rejects_past_the_placeholder_cap() {
        let registry = sample(100_000, None);
        let mut ids = HashSet::new();
        ids.insert("c2".into());
        assert_eq!(registry.apply_reference_limits(&ids, 2), 0);
        registry
            .add("c2", &[bare("a"), bare("b")], None, now())
            .unwrap();
        let err = registry.add("c2", &[bare("c")], None, now()).unwrap_err();
        assert!(matches!(err, WatchlistError::LimitExceeded { max: 2 }));
        assert_eq!(registry.values("c2", now()).unwrap(), vec!["a", "b"]);
        assert_eq!(registry.apply_reference_limits(&HashSet::new(), 2), 0);
        registry.add("c2", &[bare("c")], None, now()).unwrap();
        assert_eq!(registry.values("c2", now()).unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn restore_keeps_at_most_the_referenced_cap() {
        let registry = sample(100_000, None);
        let mut ids = HashSet::new();
        ids.insert("c2".into());
        registry.apply_reference_limits(&ids, 2);
        let rows = ["a", "b", "c"].map(|value| WatchlistRow {
            source_id: "c2".into(),
            value: value.into(),
            added_at: now(),
            expires_at: None,
        });
        assert_eq!(
            registry.restore(&rows, now()),
            WatchlistRestore {
                expired: 0,
                over_cap: 1,
            }
        );
        assert_eq!(registry.values("c2", now()).unwrap(), vec!["a", "b"]);
    }
}
