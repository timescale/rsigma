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
    let warm = Engine::new();
    let blob = warm.save_hir().expect("save_hir");
    let mut cold = Engine::new();
    cold.load_hir(&blob).expect("load_hir");
    let out = results(&cold, &json!({"CommandLine": "whoami"}));
    assert!(out.is_empty());
}
