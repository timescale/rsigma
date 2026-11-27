//! Differential tests for the substring prefilters: every result set with a
//! prefilter on must equal the result set with it off.
//!
//! Each case targets a state the prefilters reach only through a specific
//! build path (a field over the cross-rule automaton's pattern cap, an empty
//! needle, rules folded in one at a time, a field evicted by the bloom memory
//! budget), so the comparison runs against engines loaded the same way.

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::{SigmaRule, parse_sigma_yaml};
use serde_json::{Value, json};

/// Sorted rule titles per event, so result order does not matter.
fn titles_per_event(engine: &Engine, events: &[Value]) -> Vec<Vec<String>> {
    events
        .iter()
        .map(|event| {
            let event = JsonEvent::borrow(event);
            let mut titles: Vec<String> = engine
                .evaluate(&event)
                .into_iter()
                .map(|r| r.header.rule_title.clone())
                .collect();
            titles.sort();
            titles
        })
        .collect()
}

fn rules(yaml: &str) -> Vec<SigmaRule> {
    let collection = parse_sigma_yaml(yaml).expect("rules parse");
    assert!(
        collection.diagnostics.is_empty(),
        "rules parse cleanly: {:?}",
        collection.diagnostics
    );
    collection.rules
}

/// Load `rules` one at a time through `add_rule`, the incremental index path.
fn engine_incremental(rules: &[SigmaRule], configure: impl Fn(&mut Engine)) -> Engine {
    let mut engine = Engine::new();
    configure(&mut engine);
    for rule in rules {
        engine.add_rule(rule).expect("rule compiles");
    }
    engine
}

/// Load `rules` in one batch, the full index rebuild path.
fn engine_batch(rules: &[SigmaRule], configure: impl Fn(&mut Engine)) -> Engine {
    let mut engine = Engine::new();
    configure(&mut engine);
    let errors = engine.add_rules(rules);
    assert!(errors.is_empty(), "rules compile: {errors:?}");
    engine
}

#[track_caller]
fn assert_same_results(baseline: &Engine, candidate: &Engine, events: &[Value], context: &str) {
    let expected = titles_per_event(baseline, events);
    assert!(
        expected.iter().any(|titles| !titles.is_empty()),
        "{context}: the baseline must match at least one event, or the comparison proves nothing"
    );
    assert_eq!(
        titles_per_event(candidate, events),
        expected,
        "{context}: prefilter changed the results"
    );
}

const SHORT_NEEDLE: &str = r#"
title: Short Needle
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: '&&'
    condition: selection
"#;

const LONG_NEEDLE: &str = r#"
title: Long Needle
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;

const OTHER_LONG_NEEDLE: &str = r#"
title: Other Long Needle
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'sekurlsa'
    condition: selection
"#;

fn short_needle_events() -> Vec<Value> {
    vec![
        json!({"CommandLine": "cmd /c dir && del x"}),
        json!({"CommandLine": "run mimikatz now"}),
        json!({"CommandLine": "sekurlsa::logonpasswords"}),
        json!({"CommandLine": "nothing to see"}),
        json!({"CommandLine": "0123456789"}),
    ]
}

/// A field left unfiltered because of a sub-trigram needle must stay
/// unfiltered when a later long-needle rule lands on the same field, in any
/// load order.
#[test]
fn bloom_incremental_short_needle_in_any_order() {
    let orders: [&[&str]; 4] = [
        &[SHORT_NEEDLE, LONG_NEEDLE],
        &[LONG_NEEDLE, SHORT_NEEDLE],
        &[LONG_NEEDLE, SHORT_NEEDLE, OTHER_LONG_NEEDLE],
        &[SHORT_NEEDLE, LONG_NEEDLE, OTHER_LONG_NEEDLE],
    ];
    let events = short_needle_events();
    for order in orders {
        let loaded: Vec<SigmaRule> = order.iter().flat_map(|yaml| rules(yaml)).collect();
        let off = engine_incremental(&loaded, |_| {});
        let on = engine_incremental(&loaded, |e| e.set_bloom_prefilter(true));
        let titles: Vec<&str> = loaded.iter().map(|r| r.title.as_str()).collect();
        assert_same_results(&off, &on, &events, &format!("load order {titles:?}"));
    }
}

/// A field the batch build evicted to fit the memory budget carries no
/// filter. A rule appended later on that field must not give it a filter
/// built from the new rule's needles alone.
///
/// A small filter has a real false-positive rate, so a single probe could pass
/// by luck. Many evicted needles, each probed by an event holding exactly that
/// needle, make a lucky pass on all of them implausible.
#[test]
fn bloom_budget_evicted_field_stays_unfiltered_on_append() {
    use std::fmt::Write as _;

    let mut yaml = String::new();
    for i in 0..32 {
        write!(
            yaml,
            "title: Evicted {i}\nlogsource:\n    category: test\ndetection:\n    selection:\n        CommandLine|contains: 'qz{i:02}wv'\n    condition: selection\n---\n"
        )
        .unwrap();
    }
    yaml.push_str(
        r#"
title: Evicted Image
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\rundll32.exe'
    condition: selection
"#,
    );
    let initial = rules(&yaml);
    let appended = rules(
        r#"
title: Appended
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'sekurlsa'
    condition: selection
"#,
    );
    let mut events: Vec<Value> = (0..32)
        .map(|i| json!({"CommandLine": format!("qz{i:02}wv")}))
        .collect();
    events.extend([
        json!({"CommandLine": "sekurlsa::logonpasswords"}),
        json!({"Image": r"C:\Windows\System32\rundll32.exe"}),
        json!({"CommandLine": "0123456789", "Image": "0123456789"}),
    ]);

    // A zero budget evicts every field the batch build sees.
    let load = |bloom: bool| {
        let mut engine = engine_batch(&initial, |e| {
            e.set_bloom_max_bytes(0);
            e.set_bloom_prefilter(bloom);
        });
        for rule in &appended {
            engine.add_rule(rule).expect("rule compiles");
        }
        engine
    };
    assert_same_results(&load(false), &load(true), &events, "budget-evicted field");
}

/// One rule with more distinct needles on `CommandLine` than the cross-rule
/// automaton indexes, so that field gets no automaton while `Image` does.
#[cfg(feature = "daachorse-index")]
fn over_cap_rules() -> String {
    use std::fmt::Write as _;

    let mut yaml = String::from(
        "title: Huge IOC List\nlogsource:\n    category: test\ndetection:\n    selection:\n        CommandLine|contains:\n",
    );
    for i in 0..=100_000 {
        writeln!(yaml, "            - 'ioc-{i:06}'").unwrap();
    }
    yaml.push_str("    condition: selection\n");
    yaml.push_str(
        r#"---
title: Unindexed Field Needle
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'needle-alpha'
    condition: selection
---
title: Indexed Field Needle
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
"#,
    );
    yaml
}

/// Rules on a field with no automaton must be kept, even when another field
/// keeps the index non-empty.
#[cfg(feature = "daachorse-index")]
#[test]
fn cross_rule_ac_keeps_rules_on_a_field_over_the_pattern_cap() {
    let loaded = rules(&over_cap_rules());
    let events = vec![
        json!({"CommandLine": "run needle-alpha now"}),
        json!({"CommandLine": "beacon ioc-000042 seen"}),
        json!({"CommandLine": "beacon ioc-100000 seen", "Image": r"C:\Windows\cmd.exe"}),
        json!({"Image": r"C:\Windows\cmd.exe"}),
        json!({"CommandLine": "benign", "Image": "benign"}),
    ];
    let off = engine_batch(&loaded, |_| {});
    let on = engine_batch(&loaded, |e| e.set_cross_rule_ac(true));
    assert_same_results(&off, &on, &events, "field over the pattern cap");
    assert_eq!(on.cross_rule_ac_unindexed_fields(), 1);
    assert_eq!(off.cross_rule_ac_unindexed_fields(), 0);

    // Incremental loads rebuild the automaton on every add.
    let on_incremental = engine_incremental(&loaded, |e| e.set_cross_rule_ac(true));
    assert_same_results(
        &off,
        &on_incremental,
        &events,
        "field over the pattern cap, incremental",
    );
}

/// An empty substring needle matches every string, so the automaton cannot
/// witness it and its rule must not be pruned.
#[cfg(feature = "daachorse-index")]
#[test]
fn cross_rule_ac_keeps_rules_with_an_empty_needle() {
    let loaded = rules(
        r#"
title: Empty Contains
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: ''
    condition: selection
---
title: Empty Startswith
logsource:
    category: test
detection:
    selection:
        Image|startswith: ''
    condition: selection
---
title: Empty Among Others
logsource:
    category: test
detection:
    selection:
        User|contains:
            - ''
            - 'admin'
    condition: selection
---
title: Whoami
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
    );
    let events = vec![
        json!({"CommandLine": "anything at all"}),
        json!({"CommandLine": "whoami /all"}),
        json!({"Image": r"C:\Windows\cmd.exe"}),
        json!({"User": "bob"}),
        json!({"Other": "value"}),
    ];
    let off = engine_batch(&loaded, |_| {});
    let on = engine_batch(&loaded, |e| e.set_cross_rule_ac(true));
    assert_same_results(&off, &on, &events, "empty needle");
}

/// Both prefilters together, loaded incrementally, over the short-needle and
/// empty-needle shapes at once.
#[cfg(feature = "daachorse-index")]
#[test]
fn both_prefilters_agree_on_incremental_loads() {
    let mut yaml = String::new();
    for rule in [SHORT_NEEDLE, LONG_NEEDLE, OTHER_LONG_NEEDLE] {
        yaml.push_str(rule);
        yaml.push_str("---\n");
    }
    yaml.push_str(
        r#"
title: Empty Contains
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: ''
    condition: selection
"#,
    );
    let loaded = rules(&yaml);
    let events = short_needle_events();
    let off = engine_incremental(&loaded, |_| {});
    let on = engine_incremental(&loaded, |e| {
        e.set_bloom_prefilter(true);
        e.set_cross_rule_ac(true);
    });
    assert_same_results(&off, &on, &events, "bloom and cross-rule AC");
}

/// The router's prefilter setters reach every per-schema engine, and turning
/// the prefilters on changes no routed result.
#[cfg(feature = "daachorse-index")]
#[test]
fn schema_router_applies_prefilters_to_every_engine() {
    use rsigma_eval::schema::{RoutingConfig, RoutingPlan, SchemaBinding, SchemaClassifier};
    use rsigma_eval::{CorrelationConfig, MatchDetailLevel, SchemaRouter, parse_pipeline};

    let mut collection = parse_sigma_yaml(&over_cap_rules()).expect("rules parse");
    collection
        .rules
        .extend(rules(&format!("{SHORT_NEEDLE}---\n{LONG_NEEDLE}")));
    let config = RoutingConfig {
        bindings: vec![SchemaBinding {
            schema: "ecs".to_string(),
            pipelines: vec!["noop".to_string()],
            logsource: None,
        }],
        ..RoutingConfig::default()
    };
    let noop = parse_pipeline(
        "name: noop\npriority: 10\ntransformations:\n  - id: noop\n    type: field_name_mapping\n    mapping:\n      __unused_a: __unused_b\n",
    )
    .expect("pipeline parses");
    let build = |prefilters: bool| {
        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            RoutingPlan::from_config(&config),
            vec![vec![], vec![noop.clone()]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .expect("router builds");
        router.set_bloom_prefilter(prefilters);
        router.set_cross_rule_ac(prefilters);
        router
    };
    let off = build(false);
    let on = build(true);
    assert_eq!(off.cross_rule_ac_unindexed_fields(), 0);
    assert_eq!(
        on.cross_rule_ac_unindexed_fields(),
        2,
        "both per-schema engines index the rules and skip the over-cap field"
    );

    let mut events = short_needle_events();
    events.extend([
        json!({"CommandLine": "run needle-alpha now"}),
        json!({"ecs.version": "8.0.0", "CommandLine": "run needle-alpha now"}),
        json!({"ecs.version": "8.0.0", "CommandLine": "cmd /c dir && del x"}),
    ]);
    let titles = |router: &SchemaRouter| -> Vec<Vec<String>> {
        events
            .iter()
            .map(|event| {
                let event = JsonEvent::borrow(event);
                let mut titles: Vec<String> = router.detect_batch(&[&event])[0]
                    .iter()
                    .map(|r| r.header.rule_title.clone())
                    .collect();
                titles.sort();
                titles
            })
            .collect()
    };
    let expected = titles(&off);
    assert!(expected.iter().any(|t| !t.is_empty()));
    assert_eq!(titles(&on), expected);
}
