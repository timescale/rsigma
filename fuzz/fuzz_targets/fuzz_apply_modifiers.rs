#![no_main]
//! A pipeline with `apply_modifiers: first` and no other transformations must
//! match exactly the events the rule matches without it.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use serde_json::json;

const MODIFIERS: &[&str] = &[
    "contains",
    "startswith",
    "endswith",
    "all",
    "cased",
    "neq",
    "base64",
    "base64offset",
    "wide",
    "utf16be",
    "utf16",
    "windash",
    "re",
    "cidr",
    "exists",
    "fieldref",
    "gt",
    "expand",
];

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    field_less: bool,
    modifiers: Vec<u8>,
    values: Vec<String>,
    haystack: String,
}

fn engine(collection: &rsigma_parser::SigmaCollection, mode: &str) -> Option<Engine> {
    let pipeline = parse_pipeline(&format!(
        "name: p\napply_modifiers: {mode}\ntransformations: []\n"
    ))
    .unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(collection).ok()?;
    Some(engine)
}

fuzz_target!(|input: FuzzInput| {
    if input.modifiers.len() > 4
        || input.values.len() > 4
        || input.values.iter().any(|v| v.len() > 32)
        // Each dash multiplies the windash variants by five.
        || input.values.iter().any(|v| {
            v.chars()
                .filter(|c| matches!(c, '-' | '/' | '\u{2013}' | '\u{2014}' | '\u{2015}'))
                .count()
                > 3
        })
        || input.haystack.len() > 256
    {
        return;
    }
    let mut key = String::from(if input.field_less { "" } else { "F" });
    for m in &input.modifiers {
        key.push('|');
        key.push_str(MODIFIERS[*m as usize % MODIFIERS.len()]);
    }
    let yaml = format!(
        "title: fuzz\nlogsource:\n  category: test\ndetection:\n  sel: {{{}: {}}}\n  condition: sel\n",
        serde_json::to_string(&key).unwrap(),
        serde_json::to_string(&input.values).unwrap()
    );
    let Ok(collection) = rsigma_parser::parse_sigma_yaml(&yaml) else {
        return;
    };
    if collection.rules.is_empty() {
        return;
    }

    let last = engine(&collection, "last");
    let first = engine(&collection, "first");
    assert_eq!(last.is_some(), first.is_some(), "{yaml}");
    let (Some(last), Some(first)) = (last, first) else {
        return;
    };
    for event in [
        json!({ "F": input.haystack }),
        json!({ "G": input.haystack }),
    ] {
        let event = JsonEvent::borrow(&event);
        assert_eq!(
            last.evaluate(&event).len(),
            first.evaluate(&event).len(),
            "{yaml}\nevent: {:?}",
            input.haystack
        );
    }
});
