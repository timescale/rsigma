//! Differential regression tests for the eval engine.
//!
//! For each phase that introduces a new optimization, this suite captures the
//! exact `MatchResult` set produced by `Engine::evaluate` on a fixed corpus
//! of rules and events. Subsequent runs must produce identical output.
//!
//! Snapshots are stored as in-line literal expectations rather than golden
//! files: the corpus is small enough that locality matters more than
//! externalization, and a snapshot diff is easier to review in a PR.

use rsigma_eval::{Engine, JsonEvent, MatchResult};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

/// Build an engine from a multi-document YAML string.
fn engine_from(yaml: &str) -> Engine {
    let collection = parse_sigma_yaml(yaml).expect("rules parse");
    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("compile");
    engine
}

/// Sort match results by `rule_id` for stable comparison.
fn sorted_titles(results: Vec<MatchResult>) -> Vec<String> {
    let mut titles: Vec<String> = results.into_iter().map(|m| m.rule_title).collect();
    titles.sort();
    titles
}

/// Evaluate a list of events against an engine and produce per-event sorted
/// rule-title lists. This is the canonical regression artifact.
fn evaluate_corpus(engine: &Engine, events: &[Value]) -> Vec<Vec<String>> {
    events
        .iter()
        .map(|ev| {
            let event = JsonEvent::borrow(ev);
            sorted_titles(engine.evaluate(&event))
        })
        .collect()
}

const CONTAINS_HEAVY_RULES: &str = r#"
title: Suspicious LOLBAS
id: lolbas-bench
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - 'whoami'
            - 'mimikatz'
            - 'invoke-mimikatz'
            - 'powershell'
            - 'rundll32'
            - 'regsvr32'
            - 'certutil'
            - 'bitsadmin'
            - 'mshta'
            - 'wscript'
    condition: selection
level: high
---
title: Process Create Login
id: login-event
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventType: 'login'
    condition: selection
level: low
---
title: Mixed Modifiers
id: mixed-mods
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '-encodedcommand'
            - '-enc'
            - 'frombase64string'
            - 'iex'
            - 'invoke-expression'
            - 'downloadstring'
        Image|endswith: '.exe'
    condition: selection
level: medium
"#;

const ALL_OF_CONTAINS_RULES: &str = r#"
title: AllOf Contains Sentinel
id: allof-contains
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '-enc'
            - 'http'
    condition: selection
level: medium
"#;

#[test]
fn baseline_contains_heavy_corpus() {
    let engine = engine_from(CONTAINS_HEAVY_RULES);

    let events = vec![
        json!({"EventType": "login", "Image": "C:/Windows/System32/explorer.exe"}),
        json!({"Image": "C:/Tools/MIMIKATZ.exe", "CommandLine": "mimikatz.exe sekurlsa::logonpasswords"}),
        json!({"Image": "C:/Windows/System32/powershell.exe", "CommandLine": "powershell.exe -enc aHR0cHM6Ly9ldmls"}),
        json!({"Image": "/usr/bin/whoami", "CommandLine": "whoami /all"}),
        json!({"Image": "/usr/bin/notepad.exe", "CommandLine": "notepad readme.txt"}),
        json!({}),
    ];
    let actual = evaluate_corpus(&engine, &events);

    let expected: Vec<Vec<String>> = vec![
        vec!["Process Create Login".into()],
        vec!["Suspicious LOLBAS".into()],
        vec!["Mixed Modifiers".into(), "Suspicious LOLBAS".into()],
        vec!["Suspicious LOLBAS".into()],
        Vec::<String>::new(),
        Vec::<String>::new(),
    ];

    assert_eq!(actual, expected, "regression: optimizer changed results");
}

#[test]
fn allof_contains_semantics_preserved() {
    // Hardens the optimizer's invariant: AllOf(Contains(...)) MUST keep AND
    // semantics. If anyone accidentally collapses |all into AhoCorasickSet,
    // partial matches would fire the rule and this test would catch it.
    let engine = engine_from(ALL_OF_CONTAINS_RULES);

    let events = vec![
        // All three substrings present — should match.
        json!({"CommandLine": "powershell.exe -enc http://evil.com/x"}),
        // Two of three present — must NOT match.
        json!({"CommandLine": "powershell.exe -enc dummy"}),
        // One of three present — must NOT match.
        json!({"CommandLine": "powershell.exe foo"}),
        // Zero of three — must NOT match.
        json!({"CommandLine": "notepad.exe"}),
    ];
    let actual = evaluate_corpus(&engine, &events);

    let expected: Vec<Vec<String>> = vec![
        vec!["AllOf Contains Sentinel".into()],
        Vec::<String>::new(),
        Vec::<String>::new(),
        Vec::<String>::new(),
    ];

    assert_eq!(
        actual, expected,
        "AllOf|contains semantics broken: rule fired on partial match"
    );
}

#[test]
fn keyword_aho_corasick_path_correct() {
    // Keywords are field-less, case-insensitive, and OR-semantics by spec.
    // Keep the keyword count above the optimizer threshold so AC kicks in.
    let yaml = r#"
title: Keyword AC Path
id: keyword-ac
logsource:
    product: windows
detection:
    keywords:
        - 'whoami'
        - 'MIMIKATZ'
        - 'invoke-expression'
        - 'powershell'
        - 'rundll32'
        - 'regsvr32'
        - 'certutil'
        - 'bitsadmin'
        - 'mshta.exe'
    condition: keywords
"#;
    let engine = engine_from(yaml);

    let events = vec![
        // Hits via lowercased haystack + lowered needles.
        json!({"some_field": "oops MIMIKATZ"}),
        json!({"some_field": "Invoke-Expression"}),
        json!({"path": "C:/Windows/System32/CertUtil.exe"}),
        // No match.
        json!({"path": "C:/Windows/System32/explorer.exe"}),
        // Nested object: keyword traversal must descend.
        json!({"outer": {"inner": "powershell foo"}}),
    ];
    let actual = evaluate_corpus(&engine, &events);

    let expected: Vec<Vec<String>> = vec![
        vec!["Keyword AC Path".into()],
        vec!["Keyword AC Path".into()],
        vec!["Keyword AC Path".into()],
        Vec::<String>::new(),
        vec!["Keyword AC Path".into()],
    ];

    assert_eq!(actual, expected);
}

#[test]
fn bloom_prefilter_preserves_match_results() {
    // The bloom pre-filter is purely an optimization: enabling or disabling
    // it must never change which rules fire on any event.
    let mut engine = engine_from(CONTAINS_HEAVY_RULES);

    let events = vec![
        json!({"EventType": "login", "Image": "C:/Windows/System32/explorer.exe"}),
        json!({"Image": "C:/Tools/MIMIKATZ.exe", "CommandLine": "mimikatz.exe sekurlsa::logonpasswords"}),
        json!({"Image": "C:/Windows/System32/powershell.exe", "CommandLine": "powershell.exe -enc aHR0cHM6Ly9ldmls"}),
        json!({"Image": "/usr/bin/whoami", "CommandLine": "whoami /all"}),
        json!({"Image": "/usr/bin/notepad.exe", "CommandLine": "notepad readme.txt"}),
        // Pure-digit event: bloom should reject every substring item.
        json!({"Image": "0000000000", "CommandLine": "0000111122223333"}),
        json!({}),
    ];

    engine.set_bloom_prefilter(false);
    let no_bloom = evaluate_corpus(&engine, &events);

    engine.set_bloom_prefilter(true);
    let with_bloom = evaluate_corpus(&engine, &events);

    assert_eq!(
        no_bloom, with_bloom,
        "bloom pre-filter changed match output"
    );
}

#[test]
fn bloom_prefilter_handles_condition_negation() {
    // The condition `selection and not other` evaluates `other` first and
    // negates the result. When `other` is a positive substring detection
    // and the bloom verdict is `DefinitelyNoMatch`, the bloom short-circuits
    // `other` to false; the negation flips it to true. This is the correct
    // behavior at the Sigma semantic layer because the bloom only short-
    // circuits cases where the underlying matcher would have returned false.
    let yaml = r#"
title: Selection Without Substring
id: selection-without-substring
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventType: 'process_create'
    other:
        CommandLine|contains: 'whoami'
    condition: selection and not other
level: medium
"#;
    let mut engine = engine_from(yaml);
    engine.set_bloom_prefilter(true);

    let events = vec![
        // No 'whoami' in CommandLine -> `other` false -> rule fires.
        json!({"EventType": "process_create", "CommandLine": "notepad foo"}),
        // 'whoami' present -> `other` true -> rule does NOT fire.
        json!({"EventType": "process_create", "CommandLine": "exec whoami"}),
        // Pure digits -> bloom rejects `other`'s substring -> `other` false
        // -> rule fires (the bloom-driven rejection is the right answer).
        json!({"EventType": "process_create", "CommandLine": "0123456789"}),
    ];
    let actual = evaluate_corpus(&engine, &events);

    let expected: Vec<Vec<String>> = vec![
        vec!["Selection Without Substring".into()],
        Vec::<String>::new(),
        vec!["Selection Without Substring".into()],
    ];

    assert_eq!(actual, expected);

    // Also assert the result is identical without bloom.
    engine.set_bloom_prefilter(false);
    let no_bloom = evaluate_corpus(&engine, &events);
    assert_eq!(no_bloom, expected);
}
