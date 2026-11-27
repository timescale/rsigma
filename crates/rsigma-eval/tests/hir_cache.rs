//! HIR cache round-trip: `Engine::save_hir` then `load_hir` into a fresh engine
//! must evaluate identically to the original, byte-for-byte on the wire.
//!
//! This is the daemon restart-cache path: a warm engine serializes its lowered
//! rules, and a cold engine rebuilds from the blob without re-parsing,
//! re-piping, or re-lowering.

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

const RULES: &str = r#"
title: Contains
logsource: { product: windows, category: process_creation }
detection:
    sel:
        CommandLine|contains: 'whoami'
    condition: sel
---
title: Numeric and endswith
logsource: { product: windows, service: security, definition: 'audit on' }
detection:
    sel:
        Image|endswith: '\net.exe'
        EventID|gte: 4624
    condition: sel
---
title: Keywords or selector
logsource: { product: linux }
detection:
    keywords:
        - 'mimikatz'
        - 'sekurlsa'
    sel_a:
        User: 'root'
    condition: keywords or sel_a
---
title: Regex and cidr
logsource: { product: windows }
detection:
    re:
        CommandLine|re: 'powershell\s+-enc'
    net:
        SourceIp|cidr: '10.0.0.0/8'
    condition: re or net
"#;

fn results(engine: &Engine, ev: &Value) -> Vec<Value> {
    let event = JsonEvent::borrow(ev);
    engine
        .evaluate(&event)
        .iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect()
}

#[test]
fn save_load_round_trip_matches_original() {
    let collection = parse_sigma_yaml(RULES).expect("parse");

    let mut warm = Engine::new();
    warm.set_retain_hir(true);
    warm.add_collection(&collection).expect("add");

    let blob = warm.save_hir().expect("save_hir");

    let mut cold = Engine::new();
    cold.load_hir(&blob).expect("load_hir");

    let events = [
        json!({"CommandLine": "cmd /c whoami"}),
        json!({"Image": "C:\\Windows\\net.exe", "EventID": 4624}),
        json!({"Image": "C:\\Windows\\net.exe", "EventID": 1}),
        json!({"CommandLine": "run mimikatz"}),
        json!({"User": "root"}),
        json!({"CommandLine": "powershell -enc AAAA"}),
        json!({"SourceIp": "10.1.2.3"}),
        json!({"SourceIp": "192.168.1.1"}),
        json!({"Unrelated": "x"}),
    ];

    for ev in &events {
        assert_eq!(
            results(&warm, ev),
            results(&cold, ev),
            "warm/cold divergence for event {ev}"
        );
    }
}

#[test]
fn load_rejects_schema_mismatch() {
    let collection = parse_sigma_yaml(RULES).expect("parse");
    let mut warm = Engine::new();
    warm.set_retain_hir(true);
    warm.add_collection(&collection).expect("add");
    let mut blob = warm.save_hir().expect("save_hir");

    // Corrupt the leading header bytes so the schema version no longer matches.
    // The decode must fail rather than silently load stale rules.
    blob[0] = blob[0].wrapping_add(7);
    blob[1] = blob[1].wrapping_add(7);

    let mut cold = Engine::new();
    assert!(cold.load_hir(&blob).is_err());
}

#[test]
fn empty_engine_round_trips() {
    let mut warm = Engine::new();
    warm.set_retain_hir(true);
    let blob = warm.save_hir().expect("save_hir");
    let mut cold = Engine::new();
    cold.load_hir(&blob).expect("load_hir");
    let out = results(&cold, &json!({"CommandLine": "whoami"}));
    assert!(out.is_empty());
}

#[test]
fn save_requires_retention() {
    let collection = parse_sigma_yaml(RULES).expect("parse");
    let mut engine = Engine::new();
    assert!(!engine.retain_hir_enabled());
    engine.add_collection(&collection).expect("add");
    let err = engine.save_hir().expect_err("retention is off by default");
    assert!(err.to_string().contains("set_retain_hir(true)"), "{err}");
}

#[test]
fn save_refuses_rules_loaded_before_retention() {
    let collection = parse_sigma_yaml(RULES).expect("parse");
    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("add");
    engine.set_retain_hir(true);
    engine.add_collection(&collection).expect("add");
    let err = engine
        .save_hir()
        .expect_err("a cache missing the first four rules must not be written");
    assert!(err.to_string().contains("4 rules"), "{err}");
}

#[test]
fn disabling_retention_drops_retained_hir() {
    let collection = parse_sigma_yaml(RULES).expect("parse");
    let mut engine = Engine::new();
    engine.set_retain_hir(true);
    engine.add_collection(&collection).expect("add");
    engine.set_retain_hir(false);
    engine.set_retain_hir(true);
    assert!(engine.save_hir().is_err());
}

fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// A rule whose detection nests `Conditional` blocks to the HIR depth limit,
/// encoded by hand into a cache blob.
fn deepest_hir_blob() -> Vec<u8> {
    use rsigma_ir::{
        IrCondition, IrDetection, IrDetectionItem, IrMatcher, IrRule, IrRuleMetadata, MAX_HIR_DEPTH,
    };
    let mut detection = IrDetection::AllOf(vec![IrDetectionItem {
        field: Some("User".into()),
        matcher: IrMatcher::Exists(true),
        exists: Some(true),
    }]);
    // The `ArrayMatch` around the chain is the last level.
    for _ in 2..MAX_HIR_DEPTH {
        detection = IrDetection::Conditional {
            named: [("x".to_string(), detection)].into(),
            condition: IrCondition::Detection("x".into()),
        };
    }
    let detection = IrDetection::ArrayMatch {
        field: "items".into(),
        quantifier: rsigma_parser::ArrayQuantifier::Any,
        body: Box::new(detection),
    };
    let rule = IrRule {
        metadata: IrRuleMetadata {
            title: "Deep".into(),
            ..Default::default()
        },
        logsource: Default::default(),
        sigma_version: Some(3),
        detections: [("selection".to_string(), detection)].into(),
        conditions: vec![IrCondition::Detection("selection".into())],
    };
    rsigma_ir::encode_rules(&[rule]).unwrap()
}

#[test]
fn deepest_hir_loads_and_evaluates_on_small_stack() {
    let blob = deepest_hir_blob();
    let result = on_small_stack(move || {
        let mut engine = Engine::new();
        engine.load_hir(&blob).map(|()| {
            let event = json!({"items": [{"User": "a"}]});
            engine.evaluate(&JsonEvent::borrow(&event)).len()
        })
    });
    assert_eq!(result.unwrap(), 1);
}
