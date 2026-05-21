//! In-memory response cache for [`HttpEnricher`](super::http::HttpEnricher).
//!
//! Keyed on `(method, url, body_hash)` with a configurable TTL. Each
//! `HttpEnricher` instance owns its own cache so two recipes that hit
//! the same URL with different API keys (different `Authorization`
//! headers) cannot accidentally share each other's cached responses.
//!
//! Mandatory in practice for any rate-limited API (VirusTotal: 4 req/min
//! on the free tier) and a major win for any duplicate-detection burst.
//! Off by default; `cache_ttl: <duration>` on the enricher config flips
//! it on.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Composite cache key for one cached HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Request method, normalized to upper case (`GET`, `POST`, …).
    pub method: String,
    /// Full request URL.
    pub url: String,
    /// 64-bit hash of the request body (zero when no body).
    pub body_hash: u64,
}

impl CacheKey {
    /// Build a cache key from raw components. Hashes the body once at
    /// insert time so subsequent lookups are O(key-size).
    pub fn new(method: &str, url: &str, body: Option<&[u8]>) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        body.unwrap_or(&[]).hash(&mut hasher);
        Self {
            method: method.to_ascii_uppercase(),
            url: url.to_string(),
            body_hash: hasher.finish(),
        }
    }
}

#[derive(Clone)]
struct CacheEntry {
    value: serde_json::Value,
    stored_at: Instant,
}

/// Outcome of a cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Entry was present and within TTL; the cached value was returned.
    Hit,
    /// No entry for this key.
    Miss,
    /// Entry was present but past its TTL; lazily evicted on read.
    Expired,
}

/// Stats counters that survive across [`HttpResponseCache::lookup`] /
/// [`HttpResponseCache::insert`] calls. Wired into Prometheus metrics
/// in Phase 4 (`rsigma_enrichment_http_cache_{hits,misses,expirations}_total`).
#[derive(Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub expirations: u64,
}

impl std::fmt::Debug for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheStats")
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .field("expirations", &self.expirations)
            .finish()
    }
}

/// In-memory `(method, url, body_hash) → JSON value` cache with TTL.
///
/// Cheap to clone (`Arc`-wrapped internals); each enricher instance keeps
/// its own clone in its hot path, and the daemon may share instances
/// across enricher reload cycles when the config has not changed.
#[derive(Clone)]
pub struct HttpResponseCache {
    inner: Arc<HttpResponseCacheInner>,
}

struct HttpResponseCacheInner {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    stats: RwLock<CacheStats>,
    ttl: Duration,
}

impl HttpResponseCache {
    /// Build a new cache with the given TTL.
    ///
    /// A `ttl` of zero is treated as "disabled" — every lookup returns
    /// [`CacheOutcome::Miss`] and inserts are no-ops, so call sites can
    /// always go through the cache without checking `cache_ttl > 0`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(HttpResponseCacheInner {
                entries: RwLock::new(HashMap::new()),
                stats: RwLock::new(CacheStats::default()),
                ttl,
            }),
        }
    }

    /// Returns true when this cache is "off" (TTL is zero).
    pub fn is_disabled(&self) -> bool {
        self.inner.ttl.is_zero()
    }

    /// Configured TTL.
    pub fn ttl(&self) -> Duration {
        self.inner.ttl
    }

    /// Look up `key`. Returns the cached value if it is present and
    /// within TTL; expires it lazily otherwise.
    pub fn lookup(&self, key: &CacheKey) -> (CacheOutcome, Option<serde_json::Value>) {
        if self.is_disabled() {
            self.inner.stats.write().misses += 1;
            return (CacheOutcome::Miss, None);
        }

        // Fast path: read lock for the common hit / miss case.
        {
            let map = self.inner.entries.read();
            if let Some(entry) = map.get(key) {
                if entry.stored_at.elapsed() <= self.inner.ttl {
                    self.inner.stats.write().hits += 1;
                    return (CacheOutcome::Hit, Some(entry.value.clone()));
                }
                // Expired — fall through to write-locked eviction.
            } else {
                self.inner.stats.write().misses += 1;
                return (CacheOutcome::Miss, None);
            }
        }

        // Slow path: take write lock to evict expired entry.
        let mut map = self.inner.entries.write();
        if let Some(entry) = map.get(key) {
            if entry.stored_at.elapsed() > self.inner.ttl {
                map.remove(key);
                self.inner.stats.write().expirations += 1;
                return (CacheOutcome::Expired, None);
            }
            // Race: re-validated by another thread.
            self.inner.stats.write().hits += 1;
            return (CacheOutcome::Hit, Some(entry.value.clone()));
        }
        // Race: removed by another thread.
        self.inner.stats.write().misses += 1;
        (CacheOutcome::Miss, None)
    }

    /// Insert `value` under `key`. No-op when the cache is disabled.
    pub fn insert(&self, key: CacheKey, value: serde_json::Value) {
        if self.is_disabled() {
            return;
        }
        self.inner.entries.write().insert(
            key,
            CacheEntry {
                value,
                stored_at: Instant::now(),
            },
        );
    }

    /// Remove every entry whose stored_at + TTL is in the past. Called
    /// periodically by a background sweep when the daemon's enrichment
    /// pipeline has at least one cache configured.
    pub fn evict_expired(&self) -> usize {
        if self.is_disabled() {
            return 0;
        }
        let mut map = self.inner.entries.write();
        let before = map.len();
        let ttl = self.inner.ttl;
        map.retain(|_, e| e.stored_at.elapsed() <= ttl);
        let removed = before - map.len();
        if removed > 0 {
            self.inner.stats.write().expirations += removed as u64;
        }
        removed
    }

    /// Snapshot the cumulative cache stats since construction.
    pub fn stats(&self) -> (u64, u64, u64) {
        let s = self.inner.stats.read();
        (s.hits, s.misses, s.expirations)
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.inner.entries.read().len()
    }

    /// True when no entries are held.
    pub fn is_empty(&self) -> bool {
        self.inner.entries.read().is_empty()
    }
}

impl std::fmt::Debug for HttpResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (h, m, x) = self.stats();
        f.debug_struct("HttpResponseCache")
            .field("ttl", &self.inner.ttl)
            .field("len", &self.len())
            .field("hits", &h)
            .field("misses", &m)
            .field("expirations", &x)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_cache_always_misses() {
        let cache = HttpResponseCache::new(Duration::from_secs(0));
        assert!(cache.is_disabled());
        let key = CacheKey::new("GET", "https://x", None);
        cache.insert(key.clone(), serde_json::json!("v"));
        let (out, val) = cache.lookup(&key);
        assert_eq!(out, CacheOutcome::Miss);
        assert!(val.is_none());
    }

    #[test]
    fn hit_then_miss_after_ttl() {
        let cache = HttpResponseCache::new(Duration::from_millis(50));
        let key = CacheKey::new("GET", "https://x", None);
        cache.insert(key.clone(), serde_json::json!("v"));
        let (out, val) = cache.lookup(&key);
        assert_eq!(out, CacheOutcome::Hit);
        assert_eq!(val, Some(serde_json::json!("v")));

        std::thread::sleep(Duration::from_millis(80));
        let (out, val) = cache.lookup(&key);
        assert_eq!(out, CacheOutcome::Expired);
        assert!(val.is_none());
    }

    #[test]
    fn body_hash_separates_keys() {
        let a = CacheKey::new("POST", "https://x", Some(b"a"));
        let b = CacheKey::new("POST", "https://x", Some(b"b"));
        assert_ne!(a, b);
        let cache = HttpResponseCache::new(Duration::from_secs(60));
        cache.insert(a.clone(), serde_json::json!(1));
        let (out, _) = cache.lookup(&b);
        assert_eq!(out, CacheOutcome::Miss);
    }

    #[test]
    fn method_difference_separates_keys() {
        let a = CacheKey::new("GET", "https://x", None);
        let b = CacheKey::new("POST", "https://x", None);
        assert_ne!(a, b);
    }

    #[test]
    fn evict_expired_drops_old_entries() {
        let cache = HttpResponseCache::new(Duration::from_millis(20));
        for i in 0..5 {
            cache.insert(
                CacheKey::new("GET", &format!("https://x/{i}"), None),
                serde_json::json!(i),
            );
        }
        std::thread::sleep(Duration::from_millis(40));
        let evicted = cache.evict_expired();
        assert_eq!(evicted, 5);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn stats_counters_increment() {
        let cache = HttpResponseCache::new(Duration::from_secs(60));
        let key = CacheKey::new("GET", "https://x", None);
        let (_, _) = cache.lookup(&key);
        cache.insert(key.clone(), serde_json::json!("v"));
        let (_, _) = cache.lookup(&key);
        let (_, _) = cache.lookup(&key);
        let (hits, misses, _exp) = cache.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
    }
}
