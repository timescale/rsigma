//! Regression for the shipped path-only `cim_network_traffic` pipeline.
//!
//! Sigma `network_connection` rules use PascalCase Sysmon-style names. Splunk CIM
//! Network Traffic events use `src_ip`, `dest_ip`, `transport`, and related fields.
//! This pipeline rewrites rule fields so those rules evaluate against CIM-shaped JSON.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const CIM_NETWORK_PIPELINE: &str = include_str!("../pipelines/cim_network_traffic.yml");

fn cim_network_event() -> serde_json::Value {
    json!({
        "src_ip": "10.0.0.5",
        "src_port": 51514,
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "transport": "tcp",
        "app": "https",
        "user": "alice"
    })
}

#[test]
fn cim_network_traffic_pipeline_parses() {
    let pipeline = parse_pipeline(CIM_NETWORK_PIPELINE).expect("parse cim_network_traffic");
    assert_eq!(pipeline.name, "cim_network_traffic");
    assert_eq!(pipeline.priority, 20);
    assert_eq!(pipeline.transformations.len(), 1);
}

#[test]
fn cim_network_traffic_maps_rule_to_cim_event() {
    let rule = r#"
title: Outbound HTTPS
id: 00000000-0000-0000-0000-0000000000c1
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '93.184.216.34'
        DestinationPort: 443
        Protocol: 'tcp'
        User: 'alice'
    condition: selection
"#;
    let pipeline = parse_pipeline(CIM_NETWORK_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event = JsonEvent::borrow(&cim_network_event());

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn cim_network_traffic_maps_hostname_and_app_fields() {
    let rule = r#"
title: CIM host and app names
id: 00000000-0000-0000-0000-0000000000c2
logsource:
    category: network_connection
detection:
    selection:
        SourceIp: '10.0.0.5'
        DestinationPortName: 'https'
    condition: selection
"#;
    let pipeline = parse_pipeline(CIM_NETWORK_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event = JsonEvent::borrow(&cim_network_event());

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn without_pipeline_sysmon_rule_does_not_match_cim_event() {
    let rule = r#"
title: Outbound HTTPS
id: 00000000-0000-0000-0000-0000000000c3
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '93.184.216.34'
        DestinationPort: 443
    condition: selection
"#;
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event = JsonEvent::borrow(&cim_network_event());

    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("compile");
    assert!(
        engine.evaluate(&event).is_empty(),
        "Sigma field names must not match CIM fields without the pipeline"
    );
}
