#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use rsigma_eval::DraftConfig;
use rsigma_eval::rule_draft::correlation::{
    CorrelationDraftConfig, GroupedExemplar, SourceLocation, TimedEvent, draft_correlation,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let mut grouped: BTreeMap<String, Vec<TimedEvent>> = BTreeMap::new();
    for line in input.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };
        let group = object
            .get("group")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        grouped.entry(group).or_default().push(TimedEvent {
            timestamp: object
                .get("timestamp")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            offset: object
                .get("offset")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            event: object
                .get("event")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            source: SourceLocation::default(),
        });
    }
    let groups: Vec<GroupedExemplar> = grouped
        .into_iter()
        .map(|(id, events)| GroupedExemplar { id, events })
        .collect();
    let config = CorrelationDraftConfig {
        correlation_id: Some("00000000-0000-4000-8000-000000000003".to_string()),
        slot_ids: (0..32)
            .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
            .collect(),
        detection: DraftConfig {
            date: Some("2026-09-04".to_string()),
            ..DraftConfig::default()
        },
        ..CorrelationDraftConfig::default()
    };
    let _ = draft_correlation(&groups, &[], &[], &config);
});
