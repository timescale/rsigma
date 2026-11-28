#![no_main]
//! Event values in `lookup` extract programs.
//!
//! Input: one selector byte, then `<program>\0<value>`.
//!
//! - Selector below 128 picks one of the fixed lookup programs below and
//!   ignores `<program>`. The source holds `<value>` as a key and as a
//!   record name, plus a decoy and a secret, so the program must find
//!   exactly the value's own record: never an error, the decoy, or the
//!   secret, whatever the value contains.
//! - Otherwise `<program>` is an extract template in the language the
//!   selector picks, evaluated with `<value>` bound to every reference. It
//!   may fail, but must not panic or run past its limits.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_runtime::{Enricher, EnricherKind, LookupEnricher, OnError, Scope, SourceCache};
use serde_json::{Value, json};

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
});

const PROGRAMS: &[(u8, &str)] = &[
    (0, r#".records[] | select(.name == "${detection.fields.V}") | .hit"#),
    (0, r#".by_key["${detection.fields.V}"].hit"#),
    (0, r#".by_key[${detection.fields.V}].hit"#),
    (1, "$.records[?@.name == '${detection.fields.V}'].hit"),
    (1, r#"$.records[?@.name == "${detection.fields.V}"].hit"#),
    (1, "$.by_key[${detection.fields.V}].hit"),
    (2, "data.records.filter(r, r.name == '${detection.fields.V}').map(r, r.hit)"),
    (2, r#"data.records.filter(r, r.name == """${detection.fields.V}""").map(r, r.hit)"#),
    (2, "data.records.filter(r, r.name == ${detection.fields.V}).map(r, r.hit)"),
];

fn expr(language: u8, text: &str) -> ExtractExpr {
    match language % 3 {
        0 => ExtractExpr::Jq(text.to_string()),
        1 => ExtractExpr::JsonPath(text.to_string()),
        _ => ExtractExpr::Cel(text.to_string()),
    }
}

fn detection(value: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "fuzz".to_string(),
            rule_id: Some("fuzz".to_string()),
            tenant_id: None,
            level: None,
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec![],
            matched_fields: vec![FieldMatch::new("V", json!(value))],
            event: None,
        }),
    }
}

fn run(extract: ExtractExpr, source: &Value, value: &str) -> (Result<(), String>, Option<Value>) {
    let cache = Arc::new(SourceCache::new());
    cache.store("s", source);
    let enricher = LookupEnricher::new(
        "fuzz".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        "s".to_string(),
        Some(extract),
        None,
        Duration::from_secs(1),
        OnError::Skip,
        Scope::default(),
        cache,
    );
    let mut result = detection(value);
    let outcome = RUNTIME
        .block_on(enricher.enrich(&mut result))
        .map_err(|e| e.to_string());
    let injected = result.header.enrichments.and_then(|mut m| m.remove("out"));
    (outcome, injected)
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let (program, value) = text.split_once('\0').unwrap_or(("", text));

    if selector < 128 {
        let (language, template) = PROGRAMS[selector as usize % PROGRAMS.len()];
        let decoy = format!("{value}decoy");
        let mut by_key = serde_json::Map::new();
        by_key.insert(value.to_string(), json!({"hit": "own"}));
        by_key.insert(decoy.clone(), json!({"hit": "decoy"}));
        let source = json!({
            "by_key": by_key,
            "records": [{"name": decoy, "hit": "decoy"}, {"name": value, "hit": "own"}],
            "secret": "secret",
        });
        let (outcome, injected) = run(expr(language, template), &source, value);
        assert!(outcome.is_ok(), "{template} with {value:?}: {outcome:?}");
        let hit = match injected {
            Some(Value::Array(mut items)) if items.len() == 1 => items.remove(0),
            other => other.unwrap_or(Value::Null),
        };
        assert_eq!(hit, json!("own"), "{template} with {value:?}");
    } else {
        let source = json!({"a": [1, "two", {"three": 3}], "s": value});
        let _ = run(expr(selector - 128, program), &source, value);
    }
});
