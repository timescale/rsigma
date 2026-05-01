use std::path::Path;
use std::sync::{Arc, Mutex};

use rsigma_eval::CorrelationSnapshot;

/// Position of the last acked event from the source stream.
///
/// Stored alongside the correlation snapshot so the daemon can make an
/// informed decision about whether to restore state during replay:
/// restoring is safe when the replay starts *after* the stored position,
/// but would cause double-counting when replaying backwards.
#[derive(Debug, Clone, Copy)]
pub struct SourcePosition {
    /// JetStream stream sequence of the last acked message.
    pub sequence: u64,
    /// Unix timestamp (seconds) of the last acked message's `published` time.
    pub timestamp: i64,
}

/// SQLite-backed state store for persisting correlation state across restarts.
///
/// Follows the same pattern as helr's `SqliteStateStore`: a single
/// `rusqlite::Connection` behind `Arc<Mutex<_>>`, with all DB work running
/// in `tokio::task::spawn_blocking` to avoid blocking the async runtime.
pub struct SqliteStateStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteStateStore {
    /// Open (or create) a SQLite database at `path` and initialize the schema.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("open sqlite {:?}: {}", path, e))?;

        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS rsigma_correlation_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                snapshot TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            "#,
        )
        .map_err(|e| format!("init sqlite schema: {e}"))?;

        Self::migrate(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Add columns introduced after the initial schema.
    fn migrate(conn: &rusqlite::Connection) -> Result<(), String> {
        let has_column = |col: &str| -> Result<bool, String> {
            let mut stmt = conn
                .prepare("PRAGMA table_info(rsigma_correlation_state)")
                .map_err(|e| format!("pragma table_info: {e}"))?;
            let names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| format!("query pragma: {e}"))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(names.iter().any(|n| n == col))
        };

        if !has_column("source_sequence")? {
            conn.execute_batch(
                r#"
                ALTER TABLE rsigma_correlation_state
                    ADD COLUMN source_sequence INTEGER;
                ALTER TABLE rsigma_correlation_state
                    ADD COLUMN source_timestamp INTEGER;
                "#,
            )
            .map_err(|e| format!("migrate source position columns: {e}"))?;
        }

        Ok(())
    }

    /// Save a correlation snapshot (and optional source position) to the database.
    /// Replaces any existing snapshot (single-row table).
    pub async fn save(
        &self,
        snapshot: &CorrelationSnapshot,
        position: Option<&SourcePosition>,
    ) -> Result<(), String> {
        let json =
            serde_json::to_string(snapshot).map_err(|e| format!("serialize snapshot: {e}"))?;
        let conn = self.conn.clone();
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let seq = position.map(|p| p.sequence as i64);
        let ts = position.map(|p| p.timestamp);

        tokio::task::spawn_blocking(move || {
            let c = conn.lock().map_err(|_| "state store lock poisoned")?;
            c.execute(
                "INSERT INTO rsigma_correlation_state
                    (id, snapshot, updated_at, source_sequence, source_timestamp)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT (id) DO UPDATE SET
                    snapshot = ?1, updated_at = ?2,
                    source_sequence = ?3, source_timestamp = ?4",
                rusqlite::params![&json, updated_at, seq, ts],
            )
            .map_err(|e| format!("save snapshot: {e}"))?;
            Ok(())
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))?
    }

    /// Load the most recent correlation snapshot and source position from the database.
    /// Returns `None` if no snapshot has been saved yet.
    pub async fn load(
        &self,
    ) -> Result<Option<(CorrelationSnapshot, Option<SourcePosition>)>, String> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let c = conn.lock().map_err(|_| "state store lock poisoned")?;
            let mut stmt = c
                .prepare(
                    "SELECT snapshot, source_sequence, source_timestamp
                     FROM rsigma_correlation_state WHERE id = 1",
                )
                .map_err(|e| format!("prepare load: {e}"))?;
            let mut rows = stmt.query([]).map_err(|e| format!("query: {e}"))?;
            if let Some(row) = rows.next().map_err(|e| format!("next: {e}"))? {
                let json: String = row.get(0).map_err(|e| format!("get snapshot: {e}"))?;
                let snapshot: CorrelationSnapshot = serde_json::from_str(&json)
                    .map_err(|e| format!("deserialize snapshot: {e}"))?;

                let seq: Option<i64> = row
                    .get(1)
                    .map_err(|e| format!("get source_sequence: {e}"))?;
                let ts: Option<i64> = row
                    .get(2)
                    .map_err(|e| format!("get source_timestamp: {e}"))?;

                let position = match (seq, ts) {
                    (Some(s), Some(t)) => Some(SourcePosition {
                        sequence: s as u64,
                        timestamp: t,
                    }),
                    _ => None,
                };

                Ok(Some((snapshot, position)))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_snapshot() -> CorrelationSnapshot {
        CorrelationSnapshot {
            version: 1,
            windows: HashMap::new(),
            last_alert: HashMap::new(),
            event_buffers: HashMap::new(),
            event_ref_buffers: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn round_trip_without_position() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteStateStore::open(&db).unwrap();

        let snap = empty_snapshot();
        store.save(&snap, None).await.unwrap();

        let (loaded, pos) = store.load().await.unwrap().unwrap();
        assert_eq!(loaded.version, 1);
        assert!(pos.is_none());
    }

    #[tokio::test]
    async fn round_trip_with_position() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteStateStore::open(&db).unwrap();

        let snap = empty_snapshot();
        let pos = SourcePosition {
            sequence: 42,
            timestamp: 1714500000,
        };
        store.save(&snap, Some(&pos)).await.unwrap();

        let (loaded, loaded_pos) = store.load().await.unwrap().unwrap();
        assert_eq!(loaded.version, 1);
        let p = loaded_pos.unwrap();
        assert_eq!(p.sequence, 42);
        assert_eq!(p.timestamp, 1714500000);
    }

    #[tokio::test]
    async fn position_updates_on_subsequent_save() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteStateStore::open(&db).unwrap();

        let snap = empty_snapshot();
        let pos1 = SourcePosition {
            sequence: 10,
            timestamp: 1000,
        };
        store.save(&snap, Some(&pos1)).await.unwrap();

        let pos2 = SourcePosition {
            sequence: 50,
            timestamp: 5000,
        };
        store.save(&snap, Some(&pos2)).await.unwrap();

        let (_, loaded_pos) = store.load().await.unwrap().unwrap();
        let p = loaded_pos.unwrap();
        assert_eq!(p.sequence, 50);
        assert_eq!(p.timestamp, 5000);
    }

    #[tokio::test]
    async fn migration_from_old_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Create old-format database without source position columns.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                CREATE TABLE rsigma_correlation_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    snapshot TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                "#,
            )
            .unwrap();
            let snap = empty_snapshot();
            let json = serde_json::to_string(&snap).unwrap();
            conn.execute(
                "INSERT INTO rsigma_correlation_state (id, snapshot, updated_at) VALUES (1, ?1, ?2)",
                rusqlite::params![&json, 1000i64],
            )
            .unwrap();
        }

        // Open with SqliteStateStore, which should auto-migrate.
        let store = SqliteStateStore::open(&db_path).unwrap();
        let (loaded, pos) = store.load().await.unwrap().unwrap();
        assert_eq!(loaded.version, 1);
        assert!(pos.is_none(), "old rows should have NULL source columns");

        // Saving with position should work on the migrated schema.
        let new_pos = SourcePosition {
            sequence: 99,
            timestamp: 9999,
        };
        store.save(&loaded, Some(&new_pos)).await.unwrap();
        let (_, loaded_pos) = store.load().await.unwrap().unwrap();
        assert_eq!(loaded_pos.unwrap().sequence, 99);
    }

    #[tokio::test]
    async fn empty_database_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("test.db");
        let store = SqliteStateStore::open(&db).unwrap();

        assert!(store.load().await.unwrap().is_none());
    }
}
