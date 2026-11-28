#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rsigma_eval::{CorrelationConfig, CorrelationEngine, JsonEvent, TenantId};
use serde_json::json;

const BASE: i64 = 1_000_000;

const SEED_RULES: &[&str] = &[
    // Ordered login without MFA.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: Login without MFA
correlation:
    type: temporal_ordered
    rules: [a-rule, b-rule]
    group-by: [User]
    timespan: 60s
    condition: a-rule and not b-rule
"#,
    // Temporal with a negated hit before the positive one.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: A without B
correlation:
    type: temporal
    rules: [a-rule, b-rule]
    group-by: [User]
    timespan: 60s
    condition: a-rule and not b-rule
"#,
    // Tumbling bucket.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: Tumbling
correlation:
    type: temporal
    rules: [a-rule, b-rule]
    group-by: [User]
    timespan: 60s
    window: tumbling
    condition: a-rule and not b-rule
"#,
    // Deadman.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: Silent
correlation:
    type: temporal
    group-by: [User]
    timespan: 60s
    condition: not a-rule
"#,
    // Negated disjunction.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: A without B or D
correlation:
    type: temporal
    rules: [a-rule, b-rule, d-rule]
    group-by: [User]
    timespan: 60s
    condition: a-rule and not (b-rule or d-rule)
"#,
    // Positive disjunction.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: A or C without B
correlation:
    type: temporal
    rules: [a-rule, b-rule, c-rule]
    group-by: [User]
    timespan: 60s
    condition: (a-rule or c-rule) and not b-rule
"#,
    // Chained parent over an absence child.
    r#"
title: A
id: a-rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b-rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: C
id: c-rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: D
id: d-rule
logsource:
    category: test
detection:
    selection:
        Action: d
    condition: selection
---
title: Missing
name: missing
correlation:
    type: temporal_ordered
    rules: [a-rule, b-rule]
    group-by: [User]
    timespan: 60s
    condition: a-rule and not b-rule
---
title: Parent
correlation:
    type: event_count
    rules: [missing]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 1
"#,
];

#[derive(Debug, Arbitrary)]
enum Op {
    Hit {
        ref_idx: u8,
        group: u8,
        tenant: u8,
        dt: i8,
    },
    Advance {
        tenant: u8,
        dt: u8,
    },
    Finalize,
    SnapshotRoundTrip,
}

#[derive(Debug)]
struct Input {
    rule_selector: u8,
    rule_yaml: Option<String>,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let rule_selector = u.arbitrary::<u8>()?;
        let has_yaml = u.arbitrary::<bool>()?;
        let rule_yaml = if has_yaml {
            Some(u.arbitrary::<String>()?)
        } else {
            None
        };
        let mut ops = Vec::new();
        while !u.is_empty() && ops.len() < 128 {
            let kind = u.arbitrary::<u8>()?;
            let op = match kind % 4 {
                0 => Op::Hit {
                    ref_idx: u.arbitrary::<u8>()?,
                    group: u.arbitrary::<u8>()?,
                    tenant: u.arbitrary::<u8>()?,
                    dt: u.arbitrary::<i8>()?,
                },
                1 => Op::Advance {
                    tenant: u.arbitrary::<u8>()?,
                    dt: u.arbitrary::<u8>()?,
                },
                2 => Op::Finalize,
                _ => Op::SnapshotRoundTrip,
            };
            ops.push(op);
        }
        Ok(Input {
            rule_selector,
            rule_yaml,
            ops,
        })
    }
}

fn tenant(index: u8) -> TenantId {
    TenantId::new(&format!("t{}", index % 4)).expect("valid tenant")
}

fn engine(yaml: &str) -> Option<CorrelationEngine> {
    let collection = rsigma_parser::parse_sigma_yaml(yaml).ok()?;
    if collection.correlations.is_empty() {
        return None;
    }
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        require_tenant: true,
        emit_detections: true,
        ..CorrelationConfig::default()
    });
    engine.add_collection(&collection).ok()?;
    Some(engine)
}

fn absence_pending_from_introspection(engine: &CorrelationEngine) -> usize {
    engine
        .introspect()
        .groups
        .iter()
        .filter(|group| {
            group
                .absence
                .as_ref()
                .is_some_and(|absence| absence.pending > 0 || absence.deadman_deadline.is_some())
        })
        .count()
}

fn check_invariants(engine: &CorrelationEngine) {
    assert_eq!(
        engine.absence_pending(),
        absence_pending_from_introspection(engine)
    );
}

fn canonical_snapshot(mut value: serde_json::Value) -> serde_json::Value {
    fn canonicalize(value: &mut serde_json::Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        for key in [
            "windows",
            "last_alert",
            "event_buffers",
            "event_ref_buffers",
        ] {
            if let Some(map) = object.get_mut(key).and_then(|value| value.as_object_mut()) {
                for entries in map.values_mut().filter_map(|value| value.as_array_mut()) {
                    entries.sort_by_key(|entry| {
                        serde_json::to_string(entry.get(0).unwrap_or(&serde_json::Value::Null))
                            .unwrap_or_default()
                    });
                }
            }
        }
        if let Some(tenants) = object.get_mut("tenants").and_then(|value| value.as_array_mut()) {
            for tenant in tenants {
                canonicalize(tenant);
            }
        }
        if let Some(rulesets) = object.get_mut("rulesets").and_then(|value| value.as_object_mut()) {
            for inner in rulesets.values_mut() {
                canonicalize(inner);
            }
        }
    }
    canonicalize(&mut value);
    value
}

fn run(input: Input) {
    let fallback = SEED_RULES[input.rule_selector as usize % SEED_RULES.len()];
    let yaml_text = match input.rule_yaml.as_deref() {
        Some(text) if engine(text).is_some() => text,
        _ => fallback,
    };
    let Some(mut engine) = engine(yaml_text) else {
        return;
    };
    check_invariants(&engine);

    let actions = ["a", "b", "c", "d"];
    for op in input.ops {
        match op {
            Op::Hit {
                ref_idx,
                group,
                tenant: tenant_idx,
                dt,
            } => {
                let event = json!({
                    "@timestamp": BASE + dt as i64,
                    "Action": actions[ref_idx as usize % actions.len()],
                    "User": format!("g{}", group % 4),
                });
                let tenant = tenant(tenant_idx);
                let _ = engine.process_event_at_for_tenant(
                    &JsonEvent::borrow(&event),
                    BASE + dt as i64,
                    Some(&tenant),
                );
            }
            Op::Advance { tenant: tenant_idx, dt } => {
                let tenant = tenant(tenant_idx);
                let _ = engine.advance_clock(Some(&tenant), BASE + dt as i64);
            }
            Op::Finalize => {
                let _ = engine.finalize();
                for group in engine.introspect().groups {
                    if let Some(absence) = group.absence {
                        assert_eq!(absence.pending, 0, "finalize must clear obligations");
                    }
                }
            }
            Op::SnapshotRoundTrip => {
                let snapshot = engine.export_state();
                let json = canonical_snapshot(
                    serde_json::to_value(&snapshot).expect("snapshot serializes"),
                );
                let decoded: rsigma_eval::CorrelationSnapshot =
                    serde_json::from_value(json.clone()).expect("snapshot deserializes");
                let mut restored = CorrelationEngine::new(CorrelationConfig {
                    require_tenant: true,
                    emit_detections: true,
                    ..CorrelationConfig::default()
                });
                let collection =
                    rsigma_parser::parse_sigma_yaml(yaml_text).expect("the chosen rule parses");
                restored.add_collection(&collection).expect("the chosen rule compiles");
                assert!(restored.import_state(decoded));
                assert_eq!(
                    canonical_snapshot(
                        serde_json::to_value(restored.export_state()).expect("re-export serializes")
                    ),
                    json,
                    "a snapshot round trip must export identical JSON"
                );
                check_invariants(&restored);
            }
        }
        check_invariants(&engine);
    }
}

fuzz_target!(|input: Input| {
    run(input);
});
