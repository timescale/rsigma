#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_eval::{TuneConfig, TuneError, tune_rule};

const RULE: &str = r#"
title: Fuzz Target
id: fuzz-target
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '.exe'
    condition: selection
"#;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Some(object) = value.as_object() else {
        return;
    };
    let Some(mut fps) = object.get("fp").and_then(|value| value.as_array()).cloned() else {
        return;
    };
    let Some(mut tps) = object.get("tp").and_then(|value| value.as_array()).cloned() else {
        return;
    };
    fps.truncate(32);
    tps.truncate(32);

    let rule = rsigma_parser::parse_sigma_yaml(RULE)
        .expect("fixed rule parses")
        .rules
        .remove(0);
    let config = TuneConfig {
        max_fields: 4,
        max_clusters: 5,
        ..TuneConfig::default()
    };
    if let Err(TuneError::Internal { stage, message }) = tune_rule(&rule, &fps, &tps, &config)
        && stage == "round-trip"
    {
        panic!("tuning filter failed its round-trip check: {message}");
    }
});
