//! Source resolution cache with in-memory and optional SQLite persistence.
//!
//! Stores last-known-good values so that `on_error: use_cached` can serve
//! stale data when a source fetch fails. Supports optional TTL-based expiration.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A cached entry with its stored timestamp.
#[derive(Clone)]
struct CacheEntry {
    value: serde_json::Value,
    stored_at: Instant,
}

/// Thread-safe cache for resolved source data.
///
/// Provides an in-memory layer with optional SQLite-backed disk persistence
/// and optional TTL-based expiration.
pub struct SourceCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    db: Option<Mutex<rusqlite::Connection>>,
    ttl: Option<Duration>,
}

impl SourceCache {
    /// Create a new in-memory-only cache (no TTL).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            db: None,
            ttl: None,
        }
    }

    /// Create a new in-memory-only cache with a TTL.
    /// Entries older than `ttl` are considered expired and will not be returned.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            db: None,
            ttl: Some(ttl),
        }
    }

    /// Create a cache backed by a SQLite database at the given path.
    ///
    /// The table is created if it does not exist. Existing cached values
    /// are loaded into memory on construction.
    pub fn with_sqlite(path: &Path) -> Result<Self, String> {
        Self::with_sqlite_and_ttl(path, None)
    }

    /// Create a SQLite-backed cache with an optional TTL.
    pub fn with_sqlite_and_ttl(path: &Path, ttl: Option<Duration>) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("failed to open source cache DB: {e}"))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS source_cache (
                source_id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .map_err(|e| format!("failed to create source_cache table: {e}"))?;

        let entries = {
            let mut map = HashMap::new();
            let mut stmt = conn
                .prepare("SELECT source_id, value FROM source_cache")
                .map_err(|e| format!("failed to prepare SELECT: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    let id: String = row.get(0)?;
                    let val: String = row.get(1)?;
                    Ok((id, val))
                })
                .map_err(|e| format!("failed to query source_cache: {e}"))?;

            for (id, val_str) in rows.flatten() {
                if let Ok(val) = serde_json::from_str(&val_str) {
                    map.insert(
                        id,
                        CacheEntry {
                            value: val,
                            stored_at: Instant::now(),
                        },
                    );
                }
            }
            map
        };

        Ok(Self {
            entries: Mutex::new(entries),
            db: Some(Mutex::new(conn)),
            ttl,
        })
    }

    /// Store a resolved value in the cache (memory + disk if available).
    pub fn store(&self, source_id: &str, value: &serde_json::Value) {
        {
            let mut entries = self.entries.lock().unwrap();
            entries.insert(
                source_id.to_string(),
                CacheEntry {
                    value: value.clone(),
                    stored_at: Instant::now(),
                },
            );
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let val_str = serde_json::to_string(value).unwrap_or_default();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO source_cache (source_id, value, updated_at) VALUES (?1, ?2, datetime('now'))",
                rusqlite::params![source_id, val_str],
            );
        }
    }

    /// Retrieve a cached value for a source.
    /// Returns `None` if no entry exists or if the entry has expired (when TTL is set).
    pub fn get(&self, source_id: &str) -> Option<serde_json::Value> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(source_id)?;

        if let Some(ttl) = self.ttl
            && entry.stored_at.elapsed() > ttl
        {
            return None;
        }

        Some(entry.value.clone())
    }

    /// Remove a cached entry (memory + disk).
    pub fn invalidate(&self, source_id: &str) {
        {
            let mut entries = self.entries.lock().unwrap();
            entries.remove(source_id);
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let _ = conn.execute(
                "DELETE FROM source_cache WHERE source_id = ?1",
                rusqlite::params![source_id],
            );
        }
    }

    /// Clear all cached entries (memory + disk).
    pub fn clear(&self) {
        {
            let mut entries = self.entries.lock().unwrap();
            entries.clear();
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let _ = conn.execute("DELETE FROM source_cache", []);
        }
    }

    /// Remove all expired entries from the cache (memory + disk).
    /// Only meaningful when a TTL is configured.
    pub fn evict_expired(&self) {
        let Some(ttl) = self.ttl else { return };

        let expired_ids: Vec<String> = {
            let entries = self.entries.lock().unwrap();
            entries
                .iter()
                .filter(|(_, entry)| entry.stored_at.elapsed() > ttl)
                .map(|(id, _)| id.clone())
                .collect()
        };

        if expired_ids.is_empty() {
            return;
        }

        {
            let mut entries = self.entries.lock().unwrap();
            for id in &expired_ids {
                entries.remove(id);
            }
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            for id in &expired_ids {
                let _ = conn.execute(
                    "DELETE FROM source_cache WHERE source_id = ?1",
                    rusqlite::params![id],
                );
            }
        }
    }

    /// Returns the number of cached entries (including potentially expired ones).
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the configured TTL, if any.
    pub fn ttl(&self) -> Option<Duration> {
        self.ttl
    }
}

impl Default for SourceCache {
    fn default() -> Self {
        Self::new()
    }
}
