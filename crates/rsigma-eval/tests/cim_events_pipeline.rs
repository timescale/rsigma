//! Regression for the shipped path-only `cim_events` pipeline.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const CIM_PIPELINE: &str = include_str!("../pipelines/cim_events.yml");

#[test]
fn cim_events_pipeline_parses() {
    let pipeline = parse_pipeline(CIM_PIPELINE).expect("parse cim_events");
    assert_eq!(pipeline.name, "cim_events");
    assert_eq!(pipeline.priority, 20);
    assert_eq!(pipeline.transformations.len(), 5);
}

#[test]
fn cim_events_maps_process_creation() {
    let rule = r#"
title: CIM process
id: 00000000-0000-0000-0000-0000000000c1
logsource:
    category: process_creation
detection:
    selection:
        Image: '/usr/bin/bash'
        CommandLine: 'bash -c id'
        User: 'alice'
    condition: selection
"#;
    let event = JsonEvent::borrow(&json!({
        "process": "/usr/bin/bash",
        "process_cmdline": "bash -c id",
        "user": "alice"
    }));
    let pipeline = parse_pipeline(CIM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn cim_events_maps_network_connection() {
    let rule = r#"
title: CIM net
id: 00000000-0000-0000-0000-0000000000c2
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '93.184.216.34'
        DestinationPort: 443
        Protocol: 'tcp'
    condition: selection
"#;
    let event = JsonEvent::borrow(&json!({
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "transport": "tcp"
    }));
    let pipeline = parse_pipeline(CIM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn cim_events_maps_file_dns_and_image_load() {
    let pipeline = parse_pipeline(CIM_PIPELINE).expect("parse");

    let file_rule = r#"
title: file
id: 00000000-0000-0000-0000-0000000000c3
logsource:
    category: file_event
detection:
    selection:
        TargetFilename: '/tmp/evil.bin'
    condition: selection
"#;
    let file_event = JsonEvent::borrow(&json!({"file_path": "/tmp/evil.bin"}));
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(file_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&file_event).len(), 1);

    let dns_rule = r#"
title: dns
id: 00000000-0000-0000-0000-0000000000c4
logsource:
    category: dns_query
detection:
    selection:
        QueryName: 'evil.example.org'
    condition: selection
"#;
    let dns_event = JsonEvent::borrow(&json!({"query": "evil.example.org"}));
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(dns_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&dns_event).len(), 1);

    let image_rule = r#"
title: mod
id: 00000000-0000-0000-0000-0000000000c5
logsource:
    category: image_load
detection:
    selection:
        ImageLoaded: 'C:\\Windows\\System32\\evil.dll'
    condition: selection
"#;
    let image_event = JsonEvent::borrow(&json!({"file_path": "C:\\Windows\\System32\\evil.dll"}));
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(image_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&image_event).len(), 1);
}

#[test]
fn without_pipeline_sigma_names_do_not_match_cim() {
    let rule = r#"
title: net
id: 00000000-0000-0000-0000-0000000000c6
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '1.2.3.4'
    condition: selection
"#;
    let event = JsonEvent::borrow(&json!({"dest_ip": "1.2.3.4"}));
    let mut engine = Engine::new();
    engine
        .add_collection(&parse_sigma_yaml(rule).unwrap())
        .unwrap();
    assert!(engine.evaluate(&event).is_empty());
}
