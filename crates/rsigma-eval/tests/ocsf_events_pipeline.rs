//! Regression for the shipped path-only `ocsf_events` pipeline.
//!
//! Rewrites Sigma rule fields to OCSF attribute paths on live JSON input. This
//! is not OCSF Detection Finding export (`?format=ocsf`) and not Postgres convert
//! pipelines under `rsigma-convert`.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const OCSF_EVENTS_PIPELINE: &str = include_str!("../pipelines/ocsf_events.yml");

fn ocsf_process_event() -> serde_json::Value {
    json!({
        "class_uid": 1007,
        "category_uid": 1,
        "activity_id": 1,
        "metadata": { "version": "1.3.0" },
        "process": {
            "cmd_line": "bash -c whoami",
            "file": { "path": "/usr/bin/bash" },
            "pid": 4242,
            "user": { "name": "alice" }
        }
    })
}

fn ocsf_network_event() -> serde_json::Value {
    json!({
        "class_uid": 4001,
        "category_uid": 4,
        "metadata": { "version": "1.3.0" },
        "src_endpoint": { "ip": "10.0.0.5", "port": 51514 },
        "dst_endpoint": { "ip": "93.184.216.34", "port": 443 },
        "connection_info": { "protocol_name": "tcp" },
        "actor": {
            "process": { "file": { "path": "/usr/bin/curl" } },
            "user": { "name": "alice" }
        }
    })
}

#[test]
fn ocsf_events_pipeline_parses() {
    let pipeline = parse_pipeline(OCSF_EVENTS_PIPELINE).expect("parse ocsf_events");
    assert_eq!(pipeline.name, "ocsf_events");
    assert_eq!(pipeline.priority, 20);
    assert_eq!(pipeline.transformations.len(), 5);
}

#[test]
fn ocsf_events_maps_process_creation_rule() {
    let rule = r#"
title: Linux process
id: 00000000-0000-0000-0000-0000000000o1
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: 'bash -c whoami'
        Image: '/usr/bin/bash'
        User: 'alice'
    condition: selection
"#;
    let pipeline = parse_pipeline(OCSF_EVENTS_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event_val = ocsf_process_event();
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn ocsf_events_maps_network_connection_rule() {
    let rule = r#"
title: Outbound TCP
id: 00000000-0000-0000-0000-0000000000o2
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '93.184.216.34'
        DestinationPort: 443
        Protocol: 'tcp'
    condition: selection
"#;
    let pipeline = parse_pipeline(OCSF_EVENTS_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event_val = ocsf_network_event();
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn without_pipeline_sigma_fields_do_not_match_ocsf_event() {
    let rule = r#"
title: Process without pipeline
id: 00000000-0000-0000-0000-0000000000o3
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: 'bash -c whoami'
    condition: selection
"#;
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event_val = ocsf_process_event();
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("compile");
    assert!(
        engine.evaluate(&event).is_empty(),
        "Sigma field names must not match OCSF paths without the pipeline"
    );
}

#[test]
fn ocsf_events_maps_file_dns_and_image_load() {
    let pipeline = parse_pipeline(OCSF_EVENTS_PIPELINE).expect("parse");

    let file_rule = r#"
title: OCSF file
id: 00000000-0000-0000-0000-0000000000o4
logsource:
    category: file_event
detection:
    selection:
        TargetFilename: '/etc/shadow'
    condition: selection
"#;
    let file_val = json!({
        "class_uid": 1001,
        "file": { "path": "/etc/shadow" },
        "actor": { "process": { "file": { "path": "/usr/bin/cp" } } }
    });
    let file_event = JsonEvent::borrow(&file_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(file_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&file_event).len(), 1);

    let dns_rule = r#"
title: OCSF dns
id: 00000000-0000-0000-0000-0000000000o5
logsource:
    category: dns_query
detection:
    selection:
        QueryName: 'malware.example'
    condition: selection
"#;
    let dns_val = json!({
        "class_uid": 4003,
        "query": { "hostname": "malware.example" },
        "actor": { "process": { "file": { "path": "/usr/bin/dig" } } }
    });
    let dns_event = JsonEvent::borrow(&dns_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(dns_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&dns_event).len(), 1);

    let image_rule = r#"
title: OCSF module
id: 00000000-0000-0000-0000-0000000000o6
logsource:
    category: image_load
detection:
    selection:
        ImageLoaded: '/lib/evil.so'
    condition: selection
"#;
    let image_val = json!({
        "class_uid": 1005,
        "module": { "file": { "path": "/lib/evil.so" } },
        "actor": { "process": { "file": { "path": "/usr/bin/app" } } }
    });
    let image_event = JsonEvent::borrow(&image_val);
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
fn without_pipeline_file_rule_does_not_match_ocsf_event() {
    let rule = r#"
title: file
id: 00000000-0000-0000-0000-0000000000o7
logsource:
    category: file_event
detection:
    selection:
        TargetFilename: '/etc/shadow'
    condition: selection
"#;
    let event_val = json!({
        "file": { "path": "/etc/shadow" }
    });
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection(&parse_sigma_yaml(rule).unwrap())
        .unwrap();
    assert!(engine.evaluate(&event).is_empty());
}
