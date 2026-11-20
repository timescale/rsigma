#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_eval::{ValueDraftSpec, ValueSelection, draft_rule_from_values};
use rstix::{Bundle, ObservableExtraction, ObservableKind, ParseOptions, SdoObject, StixObject};

const TEXT_MODIFIERS: &[&str] = &["contains", "endswith"];

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
    let mut description = None;
    let mut references = Vec::new();
    let mut tags = Vec::new();
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
        if description.is_none()
            && let Some(text) = indicator
                .description
                .as_deref()
                .filter(|text| !text.trim().is_empty())
        {
            description = Some(text.chars().take(1_000).collect());
        }
        for reference in &indicator.common.external_references {
            if references.len() == 8 {
                break;
            }
            if let Some(url) = reference.url.as_deref().filter(|url| !url.trim().is_empty()) {
                references.push(url.to_string());
            }
        }
        for phase in &indicator.kill_chain_phases {
            if tags.len() == 8 {
                break;
            }
            if !phase.phase_name.trim().is_empty() {
                tags.push(phase.phase_name.clone());
            }
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
            let modifier = match item.kind {
                Some(ObservableKind::Ipv4Cidr | ObservableKind::Ipv6Cidr) => "cidr",
                _ => TEXT_MODIFIERS[selections.len() % TEXT_MODIFIERS.len()],
            };
            selections.push(ValueSelection {
                name: format!("selection_{}", selections.len()),
                field: field.to_string(),
                modifiers: vec![modifier.to_string()],
                values: vec![item.value.clone()],
            });
        }
    }
    if selections.is_empty() || title.trim().is_empty() {
        return;
    }
    let Ok(yaml) = draft_rule_from_values(&ValueDraftSpec {
        title,
        description,
        references,
        tags,
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
