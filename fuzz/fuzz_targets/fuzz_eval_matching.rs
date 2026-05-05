#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::{CompiledRule, JsonEvent, compile_rule, evaluate_rule};
use std::sync::LazyLock;

static RULES: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    let yaml = include_str!("../corpus/fuzz_eval_matching/rules.yml");
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    collection
        .rules
        .iter()
        .filter_map(|r| compile_rule(r).ok())
        .collect()
});

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let event = JsonEvent::borrow(&value);
    for rule in RULES.iter() {
        let _ = evaluate_rule(rule, &event);
    }
});
