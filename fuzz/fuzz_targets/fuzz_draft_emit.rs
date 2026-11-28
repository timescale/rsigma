#![no_main]

//! Event field names and values written into generated YAML: a rule draft
//! must never fail its own round-trip check, and discovered schema signatures
//! must read back exactly through `parse_schema_signatures`.

use libfuzzer_sys::fuzz_target;
use rsigma_eval::event::JsonEvent;
use rsigma_eval::{
    DiscoveryConfig, DraftConfig, DraftError, SchemaClassifier, draft_rule, mine_events,
    parse_schema_signatures,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let values: Vec<serde_json::Value> = input
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .filter(serde_json::Value::is_object)
        .take(16)
        .collect();
    if values.is_empty() {
        return;
    }
    let events: Vec<JsonEvent<'_>> = values.iter().map(JsonEvent::borrow).collect();

    let config = DraftConfig {
        min_fields: 1,
        rule_id: Some("00000000-0000-4000-8000-000000000000".to_string()),
        date: Some("2026-01-01".to_string()),
        evaluate_baseline: false,
        ..DraftConfig::default()
    };
    if let Err(DraftError::Internal { stage, message }) = draft_rule(&events, &[], &config) {
        panic!("draft failed its {stage} check: {message}");
    }

    let report = mine_events(
        values.iter().map(JsonEvent::borrow),
        &SchemaClassifier::builtin(),
        &DiscoveryConfig {
            min_support: 1,
            ..DiscoveryConfig::default()
        },
    );
    let yaml = report.to_signatures_yaml();
    let parsed = parse_schema_signatures(&yaml)
        .unwrap_or_else(|error| panic!("signatures do not parse: {error}\n{yaml}"));
    assert_eq!(parsed.len(), report.candidates.len(), "{yaml}");
    for (parsed, candidate) in parsed.iter().zip(&report.candidates) {
        assert_eq!(parsed.name, candidate.name, "{yaml}");
        assert_eq!(
            format!("{:?}", parsed.predicates),
            format!("{:?}", candidate.predicates),
            "{yaml}"
        );
    }
});
