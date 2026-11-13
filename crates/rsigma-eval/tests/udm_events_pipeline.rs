//! Regression for the shipped path-only `udm_events` pipeline.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const UDM_PIPELINE: &str = include_str!("../pipelines/udm_events.yml");

fn udm_process_launch_event() -> serde_json::Value {
    json!({
        "metadata": {
            "event_timestamp": "2020-01-01T13:27:41+00:00",
            "event_type": "PROCESS_LAUNCH"
        },
        "principal": {
            "hostname": "host.example",
            "process": {
                "file": { "full_path": "C:\\Windows\\System32\\cmd.exe" },
                "command_line": "cmd.exe /c whoami",
                "pid": "1000"
            },
            "user": { "userid": "alice" }
        },
        "target": {
            "process": {
                "file": { "full_path": "C:\\Windows\\regedit.exe" },
                "command_line": "regedit.exe",
                "pid": "3140"
            }
        }
    })
}

fn udm_network_connection_event() -> serde_json::Value {
    json!({
        "metadata": {
            "event_timestamp": "2023-07-04T18:50:00Z",
            "event_type": "NETWORK_CONNECTION"
        },
        "principal": {
            "ip": ["10.0.0.5"],
            "port": 51514,
            "process": {
                "file": { "full_path": "/usr/bin/curl" }
            },
            "user": { "userid": "alice" }
        },
        "target": {
            "ip": ["93.184.216.34"],
            "port": 443
        },
        "network": {
            "ip_protocol": "TCP"
        }
    })
}

#[test]
fn udm_events_pipeline_parses() {
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse udm_events");
    assert_eq!(pipeline.name, "udm_events");
    assert_eq!(pipeline.priority, 20);
    assert_eq!(pipeline.transformations.len(), 10);
}

#[test]
fn udm_events_maps_process_creation_on_target_process() {
    let rule = r#"
title: UDM process launch
id: 00000000-0000-0000-0000-0000000000u1
logsource:
    category: process_creation
detection:
    selection:
        Image: 'C:\\Windows\\regedit.exe'
        CommandLine: 'regedit.exe'
        User: 'alice'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = udm_process_launch_event();
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn udm_events_wrong_event_type_does_not_match_process_rule() {
    let rule = r#"
title: launch gate
id: 00000000-0000-0000-0000-0000000000u2
logsource:
    category: process_creation
detection:
    selection:
        Image: 'C:\\Windows\\regedit.exe'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let mut event_val = udm_process_launch_event();
    event_val["metadata"]["event_type"] = json!("PROCESS_TERMINATION");
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert!(engine.evaluate(&event).is_empty());
}

#[test]
fn udm_events_maps_network_connection_rule() {
    let rule = r#"
title: UDM net
id: 00000000-0000-0000-0000-0000000000u3
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '93.184.216.34'
        DestinationPort: 443
        Protocol: 'tcp'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = udm_network_connection_event();
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn udm_events_maps_destination_hostname() {
    let rule = r#"
title: UDM net hostname
id: 00000000-0000-0000-0000-0000000000u3b
logsource:
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: '.ngrok.io'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = json!({
        "metadata": { "event_type": "NETWORK_CONNECTION" },
        "target": { "hostname": "abc.ngrok.io", "port": 443 }
    });
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn udm_events_wrong_event_type_does_not_match_network_rule() {
    let rule = r#"
title: net gate
id: 00000000-0000-0000-0000-0000000000u8
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '93.184.216.34'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let mut event_val = udm_network_connection_event();
    event_val["metadata"]["event_type"] = json!("NETWORK_HTTP");
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert!(engine.evaluate(&event).is_empty());
}

#[test]
fn udm_events_wrong_event_type_does_not_match_dns_rule() {
    let rule = r#"
title: dns gate
id: 00000000-0000-0000-0000-0000000000u9
logsource:
    category: dns_query
detection:
    selection:
        QueryName: 'www.acme.com'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = json!({
        "metadata": { "event_type": "NETWORK_CONNECTION" },
        "network": {
            "dns": { "questions": { "name": "www.acme.com" } }
        }
    });
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert!(engine.evaluate(&event).is_empty());
}

#[test]
fn udm_events_wrong_event_type_does_not_match_image_load_rule() {
    let rule = r#"
title: module gate
id: 00000000-0000-0000-0000-0000000000ua
logsource:
    category: image_load
detection:
    selection:
        ImageLoaded: '/lib/evil.so'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = json!({
        "metadata": { "event_type": "PROCESS_LAUNCH" },
        "target": {
            "process": { "file": { "full_path": "/lib/evil.so" } }
        }
    });
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert!(engine.evaluate(&event).is_empty());
}

#[test]
fn udm_events_wrong_event_type_does_not_match_file_rule_on_file_open() {
    let rule = r#"
title: file gate
id: 00000000-0000-0000-0000-0000000000ub
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '\\lsass.dmp'
    condition: selection
"#;
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = json!({
        "metadata": { "event_type": "FILE_OPEN" },
        "target": { "file": { "full_path": "C:\\Temp\\lsass.dmp" } }
    });
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile");
    assert!(engine.evaluate(&event).is_empty());
}

#[test]
fn udm_events_maps_file_dns_and_image_load() {
    let pipeline = parse_pipeline(UDM_PIPELINE).expect("parse");

    let file_rule = r#"
title: file mod
id: 00000000-0000-0000-0000-0000000000u4
logsource:
    category: file_event
detection:
    selection:
        TargetFilename: 'foo.bar'
        Image: '/usr/bin/cp'
    condition: selection
"#;
    let file_val = json!({
        "metadata": { "event_type": "FILE_MODIFICATION" },
        "principal": {
            "process": { "file": { "full_path": "/usr/bin/cp" } }
        },
        "target": { "file": { "full_path": "foo.bar" } }
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

    let file_created_val = json!({
        "metadata": { "event_type": "FILE_CREATION" },
        "target": { "file": { "full_path": "new.bin" } }
    });
    let file_created_rule = r#"
title: create
id: 00000000-0000-0000-0000-0000000000u4b
logsource:
    category: file_event
detection:
    selection:
        TargetFilename: 'new.bin'
    condition: selection
"#;
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(file_created_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(
        engine.evaluate(&JsonEvent::borrow(&file_created_val)).len(),
        1
    );

    let dns_rule = r#"
title: dns
id: 00000000-0000-0000-0000-0000000000u5
logsource:
    category: dns_query
detection:
    selection:
        QueryName: 'www.acme.com'
    condition: selection
"#;
    let dns_val = json!({
        "metadata": { "event_type": "NETWORK_DNS" },
        "principal": { "ip": ["1.2.3.4"] },
        "network": {
            "application_protocol": "DNS",
            "dns": { "questions": { "name": "www.acme.com" } }
        }
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
title: module
id: 00000000-0000-0000-0000-0000000000u6
logsource:
    category: image_load
detection:
    selection:
        ImageLoaded: '/lib/evil.so'
    condition: selection
"#;
    let image_val = json!({
        "metadata": { "event_type": "PROCESS_MODULE_LOAD" },
        "principal": {
            "process": { "file": { "full_path": "/usr/bin/app" } }
        },
        "target": {
            "process": { "file": { "full_path": "/lib/evil.so" } }
        }
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
fn without_pipeline_sigma_names_do_not_match_udm_event() {
    let rule = r#"
title: no pipeline
id: 00000000-0000-0000-0000-0000000000u7
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: 'regedit.exe'
    condition: selection
"#;
    let collection = parse_sigma_yaml(rule).expect("rule");
    let event_val = udm_process_launch_event();
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("compile");
    assert!(engine.evaluate(&event).is_empty());
}
