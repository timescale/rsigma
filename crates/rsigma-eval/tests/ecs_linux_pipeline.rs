//! Regression for the shipped `ecs_linux` pipeline (builtin `-p ecs_linux` or YAML path).
//!
//! Sigma rules use Sysmon-style field names (`Image`, `CommandLine`, ...). ECS
//! documents use `process.*`, `source.*`, `destination.*`, `dns.*`. This
//! pipeline rewrites rule fields for `product: linux` the same way `ecs_windows`
//! does for Windows categories covered here.
//!
//! v1 scope is defined by this file and the integration tests: `process_creation`,
//! `network_connection`, `file_event`, `image_load`, and `dns_query`. Other
//! categories are intentionally omitted until fixture-backed mappings land.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline, resolve_builtin_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const ECS_LINUX_PIPELINE: &str = include_str!("../pipelines/ecs_linux.yml");

fn ecs_linux_process_event() -> serde_json::Value {
    // Synthetic ECS-shaped document matching `ecs_linux` schema classification
    // (`ecs.version` + Linux marker). Field paths are what the pipeline maps onto.
    json!({
        "ecs.version": "8.11.0",
        "host.os.type": "linux",
        "process.executable": "/usr/bin/bash",
        "process.command_line": "bash -c whoami",
        "user.name": "alice"
    })
}

fn ecs_json_linux() -> serde_json::Value {
    json!({
        "ecs.version": "8.11.0",
        "host.os.type": "linux",
    })
}

#[test]
fn ecs_linux_pipeline_parses() {
    let pipeline = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux pipeline");
    assert_eq!(pipeline.name, "ecs_linux");
    assert_eq!(pipeline.priority, 20);
    assert!(
        !pipeline.transformations.is_empty(),
        "ecs_linux should declare at least one transformation"
    );
}

#[test]
fn ecs_linux_pipeline_maps_process_creation_rule_to_ecs_event() {
    let rule = r#"
title: Linux process suspicious
id: 00000000-0000-0000-0000-0000000000aa
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image: '/usr/bin/bash'
        CommandLine: '*whoami*'
        User: 'alice'
    condition: selection
"#;
    let pipeline = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event_val = ecs_linux_process_event();
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(
        engine.evaluate(&event).len(),
        1,
        "ecs_linux pipeline should map Sigma fields to ECS so the rule matches"
    );

    let mut bare = Engine::new();
    bare.add_collection(&collection)
        .expect("compile without pipeline");
    assert!(
        bare.evaluate(&event).is_empty(),
        "without the pipeline, Image/CommandLine/User must not match ECS field paths"
    );
}

#[test]
fn ecs_linux_pipeline_maps_network_connection_rule_to_ecs_event() {
    let rule = r#"
title: Linux network
id: 00000000-0000-0000-0000-0000000000bb
logsource:
    product: linux
    category: network_connection
detection:
    selection:
        DestinationIp: '203.0.113.50'
        Image: '/usr/bin/curl'
    condition: selection
"#;
    let pipeline = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let mut event_val = ecs_json_linux();
    event_val.as_object_mut().expect("object").extend(
        json!({
            "destination.ip": "203.0.113.50",
            "process.executable": "/usr/bin/curl"
        })
        .as_object()
        .expect("inner object")
        .clone(),
    );
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);

    let mut bare = Engine::new();
    bare.add_collection(&collection).expect("compile");
    assert!(bare.evaluate(&event).is_empty());
}

#[test]
fn ecs_linux_pipeline_maps_file_event_rule_to_ecs_event() {
    let rule = r#"
title: Linux file write
id: 00000000-0000-0000-0000-0000000000cc
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename: '/etc/passwd.bak'
        Image: '/usr/bin/cp'
        User: 'bob'
    condition: selection
"#;
    let pipeline = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let mut event_val = ecs_json_linux();
    event_val.as_object_mut().expect("object").extend(
        json!({
            "file.path": "/etc/passwd.bak",
            "process.executable": "/usr/bin/cp",
            "user.name": "bob"
        })
        .as_object()
        .expect("inner object")
        .clone(),
    );
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);

    let mut bare = Engine::new();
    bare.add_collection(&collection).expect("compile");
    assert!(bare.evaluate(&event).is_empty());
}

#[test]
fn ecs_linux_pipeline_maps_image_load_rule_to_ecs_event() {
    let rule = r#"
title: Linux library load
id: 00000000-0000-0000-0000-0000000000dd
logsource:
    product: linux
    category: image_load
detection:
    selection:
        ImageLoaded: '/lib/x86_64-linux-gnu/libcrypt.so.1'
        Image: '/usr/bin/app'
    condition: selection
"#;
    let pipeline = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let mut event_val = ecs_json_linux();
    event_val.as_object_mut().expect("object").extend(
        json!({
            "file.path": "/lib/x86_64-linux-gnu/libcrypt.so.1",
            "process.executable": "/usr/bin/app"
        })
        .as_object()
        .expect("inner object")
        .clone(),
    );
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);

    let mut bare = Engine::new();
    bare.add_collection(&collection).expect("compile");
    assert!(bare.evaluate(&event).is_empty());
}

#[test]
fn ecs_linux_pipeline_maps_dns_query_rule_to_ecs_event() {
    let rule = r#"
title: Linux dns
id: 00000000-0000-0000-0000-0000000000ee
logsource:
    product: linux
    category: dns_query
detection:
    selection:
        QueryName: 'evil.example.org'
        Image: '/usr/bin/dig'
    condition: selection
"#;
    let pipeline = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let mut event_val = ecs_json_linux();
    event_val.as_object_mut().expect("object").extend(
        json!({
            "dns.question.name": "evil.example.org",
            "process.executable": "/usr/bin/dig"
        })
        .as_object()
        .expect("inner object")
        .clone(),
    );
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);

    let mut bare = Engine::new();
    bare.add_collection(&collection).expect("compile");
    assert!(bare.evaluate(&event).is_empty());
}

#[test]
fn ecs_linux_builtin_matches_embedded_yaml() {
    let from_builtin = resolve_builtin_pipeline("ecs_linux")
        .expect("ecs_linux is a builtin")
        .expect("parse builtin ecs_linux");
    let from_file = parse_pipeline(ECS_LINUX_PIPELINE).expect("parse ecs_linux.yml");
    assert_eq!(from_builtin.name, from_file.name);
    assert_eq!(
        from_builtin.transformations.len(),
        from_file.transformations.len()
    );
}
