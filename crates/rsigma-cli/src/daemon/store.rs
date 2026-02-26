use std::path::Path;
use std::sync::{Arc, Mutex};

use rsigma_eval::CorrelationSnapshot;

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

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Save a correlation snapshot to the database.
    /// Replaces any existing snapshot (single-row table).
    pub async fn save(&self, snapshot: &CorrelationSnapshot) -> Result<(), String> {
        let json =
            serde_json::to_string(snapshot).map_err(|e| format!("serialize snapshot: {e}"))?;
        let conn = self.conn.clone();
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        tokio::task::spawn_blocking(move || {
            let c = conn.lock().map_err(|_| "state store lock poisoned")?;
            c.execute(
                "INSERT INTO rsigma_correlation_state (id, snapshot, updated_at) VALUES (1, ?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET snapshot = ?1, updated_at = ?2",
                rusqlite::params![&json, updated_at],
            )
            .map_err(|e| format!("save snapshot: {e}"))?;
            Ok(())
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))?
    }

    /// Load the most recent correlation snapshot from the database.
    /// Returns `None` if no snapshot has been saved yet.
    pub async fn load(&self) -> Result<Option<CorrelationSnapshot>, String> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let c = conn.lock().map_err(|_| "state store lock poisoned")?;
            let mut stmt = c
                .prepare("SELECT snapshot FROM rsigma_correlation_state WHERE id = 1")
                .map_err(|e| format!("prepare load: {e}"))?;
            let mut rows = stmt.query([]).map_err(|e| format!("query: {e}"))?;
            if let Some(row) = rows.next().map_err(|e| format!("next: {e}"))? {
                let json: String = row.get(0).map_err(|e| format!("get: {e}"))?;
                let snapshot: CorrelationSnapshot = serde_json::from_str(&json)
                    .map_err(|e| format!("deserialize snapshot: {e}"))?;
                Ok(Some(snapshot))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))?
    }
}
