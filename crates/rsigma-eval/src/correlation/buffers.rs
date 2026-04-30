use std::collections::VecDeque;
use std::io::{Read as IoRead, Write as IoWrite};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use serde::Serialize;

// =============================================================================
// Compressed Event Buffer
// =============================================================================

/// Default compression level — fast compression (level 1) for minimal latency.
/// Deflate level 1 still achieves ~2-3x compression on JSON while being very fast.
const COMPRESSION_LEVEL: Compression = Compression::fast();

/// Compressed event storage for correlation event inclusion.
///
/// Stores event JSON payloads as individually deflate-compressed blobs alongside
/// their timestamps. This enables per-event eviction (matching `WindowState`
/// eviction) while keeping memory usage low.
///
/// # Memory Model
///
/// Each stored event costs approximately `compressed_size + 24` bytes
/// (8 for timestamp, 16 for Vec overhead). Typical JSON events (500B–5KB)
/// compress to 100B–1KB with deflate, giving 3–5x memory savings.
///
/// The buffer enforces a hard cap (`max_events`) so memory is bounded at:
///   `max_events × (avg_compressed_size + 24)` bytes per group key.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EventBuffer {
    /// (timestamp, deflate-compressed event JSON) pairs, ordered by timestamp.
    #[serde(with = "event_buffer_serde")]
    entries: VecDeque<(i64, Vec<u8>)>,
    /// Maximum number of events to retain. When exceeded, the oldest event is
    /// evicted regardless of the time window.
    max_events: usize,
}

/// Custom serde for EventBuffer entries: encodes compressed bytes as base64
/// instead of JSON number arrays, cutting snapshot size ~3x.
mod event_buffer_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::VecDeque;

    #[derive(Serialize, Deserialize)]
    struct Entry {
        ts: i64,
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    }

    mod base64_bytes {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use serde::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&STANDARD.encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let s: String = serde::Deserialize::deserialize(d)?;
            STANDARD.decode(s).map_err(serde::de::Error::custom)
        }
    }

    pub fn serialize<S: Serializer>(
        entries: &VecDeque<(i64, Vec<u8>)>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let v: Vec<Entry> = entries
            .iter()
            .map(|(ts, data)| Entry {
                ts: *ts,
                data: data.clone(),
            })
            .collect();
        v.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<VecDeque<(i64, Vec<u8>)>, D::Error> {
        let v: Vec<Entry> = Vec::deserialize(d)?;
        Ok(v.into_iter().map(|e| (e.ts, e.data)).collect())
    }
}

impl EventBuffer {
    /// Create a new event buffer with the given capacity cap.
    pub fn new(max_events: usize) -> Self {
        EventBuffer {
            entries: VecDeque::with_capacity(max_events.min(64)),
            max_events,
        }
    }

    /// Compress and store an event. Evicts the oldest entry if at capacity.
    pub fn push(&mut self, ts: i64, event: &serde_json::Value) {
        // Compress the event JSON with deflate
        if let Some(compressed) = compress_event(event) {
            if self.entries.len() >= self.max_events {
                self.entries.pop_front();
            }
            self.entries.push_back((ts, compressed));
        }
    }

    /// Remove all entries older than the cutoff timestamp.
    pub fn evict(&mut self, cutoff: i64) {
        while self.entries.front().is_some_and(|(t, _)| *t < cutoff) {
            self.entries.pop_front();
        }
    }

    /// Decompress and return all stored events.
    pub fn decompress_all(&self) -> Vec<serde_json::Value> {
        self.entries
            .iter()
            .filter_map(|(_, compressed)| decompress_event(compressed))
            .collect()
    }

    /// Returns true if there are no stored events.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all stored events.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Total compressed bytes stored (for monitoring/diagnostics).
    pub fn compressed_bytes(&self) -> usize {
        self.entries.iter().map(|(_, data)| data.len()).sum()
    }

    /// Number of stored events.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Compress an event JSON value using deflate.
pub(super) fn compress_event(event: &serde_json::Value) -> Option<Vec<u8>> {
    let json_bytes = serde_json::to_vec(event).ok()?;
    let mut encoder = DeflateEncoder::new(Vec::new(), COMPRESSION_LEVEL);
    encoder.write_all(&json_bytes).ok()?;
    encoder.finish().ok()
}

/// Decompress a deflate-compressed event back to a JSON value.
pub(super) fn decompress_event(compressed: &[u8]) -> Option<serde_json::Value> {
    let mut decoder = DeflateDecoder::new(compressed);
    let mut json_bytes = Vec::new();
    decoder.read_to_end(&mut json_bytes).ok()?;
    serde_json::from_slice(&json_bytes).ok()
}

// =============================================================================
// Event Reference (lightweight mode)
// =============================================================================

/// A lightweight event reference: timestamp plus optional event ID.
///
/// Used in `Refs` mode for memory-efficient correlation event tracking.
/// Each ref costs ~40 bytes (vs. 100–1000+ bytes for compressed events),
/// making this mode suitable for high-volume correlations where only
/// traceability is needed.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EventRef {
    /// Event timestamp (epoch seconds).
    pub timestamp: i64,
    /// Event ID extracted from common fields (`id`, `_id`, `event_id`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Lightweight event reference buffer for `Refs` mode.
///
/// Stores only timestamps and optional event IDs — no event payload,
/// no compression. This is the minimal-memory alternative to `EventBuffer`.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EventRefBuffer {
    /// Event references, ordered by timestamp.
    entries: VecDeque<EventRef>,
    /// Maximum number of refs to retain.
    max_events: usize,
}

impl EventRefBuffer {
    /// Create a new ref buffer with the given capacity cap.
    pub fn new(max_events: usize) -> Self {
        EventRefBuffer {
            entries: VecDeque::with_capacity(max_events.min(64)),
            max_events,
        }
    }

    /// Store a reference to an event. Evicts the oldest ref if at capacity.
    pub fn push(&mut self, ts: i64, event: &serde_json::Value) {
        if self.entries.len() >= self.max_events {
            self.entries.pop_front();
        }
        let id = extract_event_id(event);
        self.entries.push_back(EventRef { timestamp: ts, id });
    }

    /// Remove all refs older than the cutoff timestamp.
    pub fn evict(&mut self, cutoff: i64) {
        while self.entries.front().is_some_and(|r| r.timestamp < cutoff) {
            self.entries.pop_front();
        }
    }

    /// Return cloned refs.
    pub fn refs(&self) -> Vec<EventRef> {
        self.entries.iter().cloned().collect()
    }

    /// Returns true if there are no stored refs.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all stored refs.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of stored refs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Try to extract an event ID from common fields.
///
/// Checks (in order): `id`, `_id`, `event_id`, `EventRecordID`, `event.id`.
/// Returns the first found value as a string.
pub(super) fn extract_event_id(event: &serde_json::Value) -> Option<String> {
    const ID_FIELDS: &[&str] = &["id", "_id", "event_id", "EventRecordID", "event.id"];
    for field in ID_FIELDS {
        if let Some(val) = event.get(field) {
            return match val {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            };
        }
    }
    None
}
