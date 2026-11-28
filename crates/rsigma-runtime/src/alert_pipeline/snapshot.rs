//! Versioned persistence snapshot for the alert pipeline.
//!
//! Captures the four pieces of mutable state (dedup active alerts, open
//! incidents, dynamic silences, inhibition active sources) in a single
//! serializable struct. The entity index and cardinality counters are not
//! persisted; the index is rebuilt from the restored incidents on boot.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use super::dedup::DedupSnap;
use super::grouping::Incident;
use super::inhibit::InhibitSourceSnap;
use super::silence::SilenceSnap;

/// Bumped when the snapshot layout changes. Restore reads every version up to
/// this one; a newer version logs a warning and the daemon starts with fresh
/// state.
pub const SNAPSHOT_VERSION: u32 = 3;

/// Deepest nesting the alert pipeline keeps in a retained value (a dedup
/// sample or field, an incident's `group_by` value or result). An array or
/// object nested deeper is kept as its JSON text. Events parsed at ingest
/// nest far less, so their values are never rewritten.
pub(crate) const MAX_RETAINED_DEPTH: usize = 160;

/// Deepest nesting one snapshot entry may have: a retained value plus the
/// entry's own structure around it.
const MAX_ENTRY_DEPTH: usize = MAX_RETAINED_DEPTH + 16;

/// A point-in-time snapshot of the alert pipeline's mutable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPipelineSnapshot {
    /// Snapshot layout version.
    pub version: u32,
    /// Active dedup alerts with their identity keys and display ids (bare
    /// `(fingerprint, alert)` pairs before version 3).
    #[serde(default)]
    pub(crate) dedup: Vec<DedupSnap>,
    /// Open incidents.
    #[serde(default)]
    pub(crate) incidents: Vec<Incident>,
    /// Dynamic (API) silences; static ones are re-seeded from config.
    #[serde(default)]
    pub(crate) silences: Vec<SilenceSnap>,
    /// Inhibition active sources.
    #[serde(default)]
    pub(crate) inhibit_sources: Vec<InhibitSourceSnap>,
}

/// Entries [`AlertPipelineSnapshot::from_json`] could not read, per list.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotSkips {
    /// Dedup active alerts.
    pub dedup: usize,
    /// Open incidents.
    pub incidents: usize,
    /// Dynamic silences.
    pub silences: usize,
    /// Inhibition active sources.
    pub inhibit_sources: usize,
}

impl SnapshotSkips {
    /// Unreadable entries across every list.
    pub fn total(&self) -> usize {
        self.dedup + self.incidents + self.silences + self.inhibit_sources
    }
}

#[derive(Deserialize)]
struct RawSnapshot<'a> {
    version: u32,
    #[serde(default, borrow)]
    dedup: Vec<&'a RawValue>,
    #[serde(default, borrow)]
    incidents: Vec<&'a RawValue>,
    #[serde(default, borrow)]
    silences: Vec<&'a RawValue>,
    #[serde(default, borrow)]
    inhibit_sources: Vec<&'a RawValue>,
}

impl AlertPipelineSnapshot {
    /// An empty snapshot at [`SNAPSHOT_VERSION`].
    pub fn empty() -> Self {
        AlertPipelineSnapshot {
            version: SNAPSHOT_VERSION,
            dedup: Vec::new(),
            incidents: Vec::new(),
            silences: Vec::new(),
            inhibit_sources: Vec::new(),
        }
    }

    /// Parse a persisted snapshot entry by entry.
    ///
    /// Only the outer layout and `version` must be readable. An entry that
    /// fails to parse, or nests deeper than any snapshot the daemon writes,
    /// is logged, counted in the returned [`SnapshotSkips`], and left out, so
    /// the rest of the state still restores. A version this build does not
    /// read yields an empty snapshot carrying that version, which
    /// [`AlertPipeline::restore`](super::AlertPipeline::restore) refuses.
    pub fn from_json(json: &str) -> Result<(Self, SnapshotSkips), String> {
        let raw: RawSnapshot<'_> = serde_json::from_str(json)
            .map_err(|e| format!("deserialize alert-pipeline snapshot: {e}"))?;
        let mut snapshot = AlertPipelineSnapshot {
            version: raw.version,
            ..AlertPipelineSnapshot::empty()
        };
        let mut skips = SnapshotSkips::default();
        if !matches!(raw.version, 1..=SNAPSHOT_VERSION) {
            return Ok((snapshot, skips));
        }
        snapshot.dedup = parse_entries(&raw.dedup, "dedup", &mut skips.dedup);
        snapshot.incidents = parse_entries(&raw.incidents, "incident", &mut skips.incidents);
        snapshot.silences = parse_entries(&raw.silences, "silence", &mut skips.silences);
        snapshot.inhibit_sources = parse_entries(
            &raw.inhibit_sources,
            "inhibit_source",
            &mut skips.inhibit_sources,
        );
        Ok((snapshot, skips))
    }
}

fn parse_entries<T: DeserializeOwned>(
    raws: &[&RawValue],
    kind: &'static str,
    skipped: &mut usize,
) -> Vec<T> {
    let mut out = Vec::with_capacity(raws.len());
    for (index, raw) in raws.iter().enumerate() {
        match parse_entry(raw.get()) {
            Ok(entry) => out.push(entry),
            Err(error) => {
                tracing::warn!(
                    kind,
                    index,
                    error = %error,
                    "Skipping an unreadable alert-pipeline snapshot entry"
                );
                *skipped += 1;
            }
        }
    }
    out
}

fn parse_entry<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    if nesting_depth(text) > MAX_ENTRY_DEPTH {
        return Err(format!("nested deeper than {MAX_ENTRY_DEPTH} levels"));
    }
    // The depth check above bounds the recursion the limit would otherwise
    // stop at 128 levels, below what a retained value may reach.
    let mut de = serde_json::Deserializer::from_str(text);
    de.disable_recursion_limit();
    let entry = T::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(entry)
}

/// The deepest array or object nesting in `text`, which must be one JSON
/// value. Brackets inside strings do not count.
fn nesting_depth(text: &str) -> usize {
    let mut depth = 0usize;
    let mut deepest = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// Keep at most [`MAX_RETAINED_DEPTH`] levels of nesting in `value`, storing
/// each array or object below that as its JSON text.
pub(crate) fn bound_depth(value: &mut Value) {
    fn walk(value: &mut Value, remaining: usize) {
        match value {
            Value::Array(_) | Value::Object(_) if remaining == 0 => {
                *value = Value::String(value.to_string());
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, remaining - 1);
                }
            }
            Value::Object(map) => {
                for item in map.values_mut() {
                    walk(item, remaining - 1);
                }
            }
            _ => {}
        }
    }
    walk(value, MAX_RETAINED_DEPTH);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(depth: usize) -> Value {
        let mut value = Value::from("leaf");
        for _ in 0..depth {
            value = serde_json::json!({ "k": value });
        }
        value
    }

    #[test]
    fn nesting_depth_ignores_brackets_in_strings() {
        assert_eq!(nesting_depth(r#"{"a":"[[{{","b":[1,[2]]}"#), 3);
        assert_eq!(nesting_depth(r#""\"[""#), 0);
        assert_eq!(nesting_depth(r#"[{"a":"\\"},{}]"#), 2);
    }

    #[test]
    fn bound_depth_keeps_shallow_values_and_stringifies_deep_subtrees() {
        let mut shallow = nested(MAX_RETAINED_DEPTH);
        let before = shallow.clone();
        bound_depth(&mut shallow);
        assert_eq!(shallow, before);

        let mut deep = nested(MAX_RETAINED_DEPTH + 3);
        bound_depth(&mut deep);
        let mut cursor = &deep;
        for _ in 0..MAX_RETAINED_DEPTH {
            cursor = &cursor["k"];
        }
        let text = cursor
            .as_str()
            .expect("the subtree below the bound is text");
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), nested(3));
    }

    #[test]
    fn an_unreadable_entry_is_skipped_and_counted() {
        let json = r#"{"version":3,"silences":[{"id":"ok","matchers":[{"selector":"rule","op":"=","value":"r"}],"starts_at":null,"ends_at":null,"created_by":null,"comment":null},{"id":7}]}"#;
        let (snap, skips) = AlertPipelineSnapshot::from_json(json).unwrap();
        assert_eq!(snap.silences.len(), 1);
        assert_eq!(skips.silences, 1);
        assert_eq!(skips.total(), 1);
    }

    #[test]
    fn an_entry_deeper_than_any_written_snapshot_is_skipped() {
        let deep = nested(MAX_ENTRY_DEPTH + 1).to_string();
        let json = format!(r#"{{"version":3,"silences":[{deep}]}}"#);
        let (snap, skips) = AlertPipelineSnapshot::from_json(&json).unwrap();
        assert!(snap.silences.is_empty());
        assert_eq!(skips.silences, 1);
    }

    #[test]
    fn an_unknown_version_parses_no_entries() {
        let (snap, skips) =
            AlertPipelineSnapshot::from_json(r#"{"version":99,"dedup":[1,2]}"#).unwrap();
        assert_eq!(snap.version, 99);
        assert!(snap.dedup.is_empty());
        assert_eq!(skips.total(), 0);
    }

    #[test]
    fn a_broken_outer_layout_is_an_error() {
        assert!(AlertPipelineSnapshot::from_json(r#"{"dedup":[]}"#).is_err());
        assert!(AlertPipelineSnapshot::from_json("not json").is_err());
    }
}
