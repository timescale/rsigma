#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_eval::{ValueDraftSpec, ValueSelection, draft_rule_from_values};
use rstix::{Bundle, ObservableExtraction, ParseOptions, SdoObject, StixObject};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return;
    };
    let text = match value.get("type").and_then(serde_json::Value::as_str) {
        Some("bundle") => raw.to_string(),
        Some("indicator") => serde_json::json!({
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000001",
            "objects": [value],
        })
        .to_string(),
        _ => return,
    };
    // The harness bounds the bundle so one input cannot force an unbounded compile.
    let mut options = ParseOptions::new().allow_custom(true);
    options.max_object_count = 1_000;
    let Ok(bundle) = Bundle::parse_with_options(&text, &options) else {
        return;
    };
    let mut title = String::from("draft");
    let mut selections = Vec::new();
    for object in bundle.objects() {
        let StixObject::Sdo(SdoObject::Indicator(indicator)) = object else {
            continue;
        };
        if title == "draft"
            && let Some(name) = indicator.name.as_deref().filter(|name| !name.trim().is_empty())
        {
            title = name.to_string();
        }
        let Ok(pattern) = indicator.pattern.parsed_pattern() else {
            continue;
        };
        let ObservableExtraction::Simple(items) = pattern.simple_observables() else {
            continue;
        };
        for item in items {
            if selections.len() == 32 {
                break;
            }
            let field = item.kind.map(|kind| kind.key()).unwrap_or("value");
            selections.push(ValueSelection {
                name: format!("selection_{}", selections.len()),
                field: field.to_string(),
                modifiers: Vec::new(),
                values: vec![item.value.clone()],
            });
        }
    }
    if selections.is_empty() || title.trim().is_empty() {
        return;
    }
    let Ok(yaml) = draft_rule_from_values(&ValueDraftSpec {
        title,
        description: None,
        references: Vec::new(),
        tags: Vec::new(),
        rule_id: None,
        date: Some("2026-06-01".to_string()),
        logsource_category: Some("network_connection".to_string()),
        logsource_product: None,
        logsource_service: None,
        level: Some("medium".to_string()),
        selections,
    }) else {
        return;
    };
    if rsigma_parser::parse_sigma_yaml(&yaml).is_err() {
        panic!("drafted YAML did not parse");
    }
});
