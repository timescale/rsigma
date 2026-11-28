//! `|windash` in evaluation: rules over the expansion budget are rejected
//! with an error naming the rule, also when a pipeline adds the dashes, and
//! rules inside it compile into one regex per value rather than one matcher
//! per dash combination.

use std::time::{Duration, Instant};

use rsigma_eval::{Engine, JsonEvent, parse_pipeline};
use rsigma_parser::{SigmaString, SigmaValue, parse_sigma_yaml};
use serde_json::json;

fn dashed(dashes: usize, wildcard: bool) -> String {
    let kinds = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
    let mut value = String::from("tool");
    for i in 0..dashes {
        value.push(' ');
        value.push(kinds[i % kinds.len()]);
        value.push(char::from(b'a' + (i % 26) as u8));
    }
    if wildcard {
        value.push_str(" *");
    }
    value
}

const BASE: &str = r#"
title: Windash Rule
id: 5d4c0b56-38f2-4d6b-9d36-1d4c2d0b8f11
logsource:
    product: windows
detection:
    selection:
        CommandLine|windash|contains: placeholder
    condition: selection
"#;

#[test]
fn rule_over_the_budget_is_rejected_naming_the_rule() {
    for wildcard in [false, true] {
        let mut collection = parse_sigma_yaml(BASE).unwrap();
        let rule = &mut collection.rules[0];
        let rsigma_parser::Detection::AllOf(items) = rule
            .detection
            .named
            .get_mut("selection")
            .expect("selection")
        else {
            panic!("expected a mapping selection");
        };
        items[0].values = (0..4)
            .map(|_| SigmaValue::String(SigmaString::new(&dashed(8, wildcard))))
            .collect();

        let start = Instant::now();
        let error = Engine::new().add_rule(rule).unwrap_err().to_string();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(error.contains("rule 'Windash Rule'"), "{error}");
        assert!(error.contains("4096"), "{error}");
    }
}

#[test]
fn dashes_a_pipeline_adds_count_against_the_budget() {
    let pipeline = parse_pipeline(
        r#"
name: Add Dashes
transformations:
  - type: replace_string
    regex: "X"
    replacement: " -a /b -c /d -e /f -g /h"
"#,
    )
    .unwrap();
    let yaml = r#"
title: Pipeline Windash
logsource:
    product: windows
detection:
    selection:
        CommandLine|windash|contains:
            - 'oneX'
            - 'twoX'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors().next().is_none(),
        "the source rule is fine"
    );
    let mut engine = Engine::new_with_pipeline(pipeline);
    let error = engine.add_collection(&collection).unwrap_err().to_string();
    assert!(error.contains("rule 'Pipeline Windash'"), "{error}");
}

#[test]
fn rule_at_the_budget_compiles_quickly_and_matches_every_dash() {
    // Five items of 5^5 = 3125 variants: 15625 in total, just under the rule
    // budget. Expanded, this was 15625 matchers; each value is now one regex.
    let mut yaml =
        String::from("title: Heavy Windash\nlogsource:\n    product: windows\ndetection:\n");
    for i in 0..5 {
        yaml.push_str(&format!(
            "    sel{i}:\n        CommandLine|windash|contains: '{}'\n",
            dashed(5, i % 2 == 0)
        ));
    }
    yaml.push_str("    condition: 1 of sel*\n");
    let collection = parse_sigma_yaml(&yaml).unwrap();
    assert!(collection.errors().next().is_none());

    let start = Instant::now();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "compiling took {:?}",
        start.elapsed()
    );

    let event = json!({"CommandLine": "run TOOL \u{2015}A /B \u{2013}c \u{2014}D -e now"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&event)).len(), 1);
    let miss = json!({"CommandLine": "run TOOL +A /B \u{2013}c \u{2014}D -e now"});
    assert!(engine.evaluate(&JsonEvent::borrow(&miss)).is_empty());
}
