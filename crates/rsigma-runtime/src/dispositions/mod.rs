//! Triage feedback loop: analyst dispositions and the per-rule false-positive
//! ratio.
//!
//! This module captures an analyst's verdict (true positive, false positive, or
//! benign true positive) on the alerts a ruleset produces and turns the stream
//! of verdicts into a live per-rule false-positive ratio over a rolling window.
//! It is a measurement loop, not a case manager: it ingests a verdict and emits
//! a ratio, and nothing more.
//!
//! The pieces:
//!
//! - [`record`]: the [`Disposition`] wire shape, its [`Verdict`] and
//!   [`DispositionScope`] enums, and the [`parse_dispositions`] parser that
//!   accepts a single object, a JSON array, or NDJSON.
//! - [`store`]: the rolling [`DispositionStore`], the [`Numerator`] knob, and
//!   the false-positive [`ratio`](DispositionStore::ratio) computation.
//! - [`snapshot`]: the versioned [`DispositionSnapshot`] for persistence.
//!
//! The store is deliberately decoupled from the eval and sink paths: it is fed
//! only by its ingestion paths and reads rule identity from each record, so it
//! cannot affect detection throughput.

pub mod record;
pub mod snapshot;
pub mod store;

pub use record::{
    Disposition, DispositionError, DispositionScope, RawDisposition, Verdict, parse_dispositions,
};
pub use snapshot::{DispositionSnapshot, RuleBucketsSnapshot, SNAPSHOT_VERSION};
pub use store::{
    DEFAULT_BUCKET, DEFAULT_MAX_SEEN_IDS, DEFAULT_MIN_SAMPLE, DEFAULT_WINDOW, DispositionConfig,
    DispositionStore, IngestOutcome, Numerator, RuleSummary, VerdictCounts,
};

use serde_json::json;

/// Render the store's per-rule summaries as the `TriageFeed` JSON shape the
/// `rule scorecard` command consumes through its `--triage` input: a `rules`
/// array keyed by `rule_id`, each entry carrying the true/false-positive counts
/// and the derived `fp_ratio`. This is the contract the scorecard documents as
/// owned here, so the feedback loop and the scorecard stay in sync.
pub fn triage_feed(store: &DispositionStore) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = store
        .summaries()
        .into_iter()
        .map(|s| {
            let mut entry = json!({
                "rule_id": s.rule_id,
                "true_positives": s.true_positives,
                "false_positives": s.false_positives,
            });
            if let Some(ratio) = s.fp_ratio {
                entry["fp_ratio"] = json!(ratio);
            }
            entry
        })
        .collect();
    json!({ "rules": rules })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triage_feed_matches_scorecard_shape() {
        let mut store = DispositionStore::new(DispositionConfig {
            min_sample: 1,
            ..Default::default()
        });
        let raw: RawDisposition =
            serde_json::from_str(r#"{"rule_id": "r1", "verdict": "false_positive"}"#).unwrap();
        let d = Disposition::from_raw(raw, 100).unwrap();
        store.apply(&d, 100);

        let feed = triage_feed(&store);
        let rules = feed["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["rule_id"], "r1");
        assert_eq!(rules[0]["false_positives"], 1);
        assert_eq!(rules[0]["true_positives"], 0);
        assert_eq!(rules[0]["fp_ratio"], 1.0);
    }
}
