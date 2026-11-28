//! Fuzz alert-pipeline snapshot restore.
//!
//! A snapshot parses entry by entry, so unreadable entries are skipped
//! rather than failing the whole restore, and whatever restores must save
//! to a snapshot that reads back with no entry skipped.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rsigma_runtime::{AlertPipeline, AlertPipelineSnapshot, AlertPipelineState};

const NOW: i64 = 1_767_225_600;

fn pipeline() -> &'static AlertPipeline {
    static PIPELINE: OnceLock<AlertPipeline> = OnceLock::new();
    PIPELINE.get_or_init(|| {
        rsigma_runtime::parse_alert_pipeline_config(
            "dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  include: results\n  resolve_timeout: 1h\ninhibit_rules:\n  - name: crit\n    source_match:\n      - selector: level\n        op: \"=\"\n        value: critical\n    target_match:\n      - selector: level\n        op: \"=\"\n        value: high\n    equal: [match.SourceIp]\n    duration: 5m\n",
        )
        .expect("fuzz pipeline config")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok((snapshot, _)) = AlertPipelineSnapshot::from_json(text) else {
        return;
    };
    let mut state = AlertPipelineState::default();
    for tenancy in [false, true] {
        if !pipeline().restore(&mut state, snapshot.clone(), NOW, tenancy) {
            return;
        }
    }
    let saved = serde_json::to_string(&pipeline().snapshot(&state)).expect("snapshot serializes");
    let (_, skips) = AlertPipelineSnapshot::from_json(&saved).expect("a saved snapshot parses");
    assert_eq!(skips.total(), 0, "a saved snapshot reads back whole: {saved}");
});
