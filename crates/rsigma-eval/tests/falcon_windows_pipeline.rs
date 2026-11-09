//! Regression for the shipped path-only `falcon_windows` pipeline.
//!
//! Sigma rules keep Sysmon-style names; Falcon JSON uses `event_simpleName`
//! discriminators and sensor field names (`ImageFileName`, `RemoteAddressIP4`, ...).

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const FALCON_PIPELINE: &str = include_str!("../pipelines/falcon_windows.yml");

fn falcon_process_event() -> serde_json::Value {
    // Shape aligned with public Falcon ProcessRollup2 export examples.
    json!({
        "event_simpleName": "ProcessRollup2",
        "event_platform": "Win",
        "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
        "UserName": "jdoe",
        "RawProcessId": 4892_u64
    })
}

fn falcon_network_event() -> serde_json::Value {
    json!({
        "event_simpleName": "NetworkConnectIP4",
        "event_platform": "Win",
        "ComputerName": "ENG-LAPTOP-22",
        "UserName": "jdoe",
        "LocalAddressIP4": "10.149.139.64",
        "LocalPort": 51523,
        "RemoteAddressIP4": "104.18.12.123",
        "RemotePort": 443,
        "DomainName": "api.example.com",
        "ImageFileName": "\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "ProcessId": "4892"
    })
}

#[test]
fn falcon_windows_pipeline_parses() {
    let pipeline = parse_pipeline(FALCON_PIPELINE).expect("parse falcon_windows");
    assert_eq!(pipeline.name, "falcon_windows");
    assert_eq!(pipeline.priority, 20);
    assert_eq!(pipeline.transformations.len(), 10);
}

#[test]
fn falcon_windows_maps_process_creation_rule() {
    let rule = r#"
title: Suspicious cmd
id: 00000000-0000-0000-0000-0000000000f1
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains: 'System32\\cmd.exe'
        CommandLine|contains: 'whoami'
        User: 'jdoe'
    condition: selection
"#;
    let pipeline = parse_pipeline(FALCON_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event = JsonEvent::borrow(&falcon_process_event());

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn falcon_windows_wrong_simple_name_does_not_match_process_rule() {
    let rule = r#"
title: Process rollup only
id: 00000000-0000-0000-0000-0000000000f2
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
    let pipeline = parse_pipeline(FALCON_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let mut event_val = falcon_process_event();
    event_val["event_simpleName"] = json!("SyntheticProcessRollup2");
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert!(engine.evaluate(&event).is_empty());
}

#[test]
fn falcon_windows_maps_network_connection_rule() {
    let rule = r#"
title: Outbound HTTPS
id: 00000000-0000-0000-0000-0000000000f3
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationIp: '104.18.12.123'
        DestinationPort: 443
        DestinationHostname: 'api.example.com'
    condition: selection
"#;
    let pipeline = parse_pipeline(FALCON_PIPELINE).expect("parse pipeline");
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event = JsonEvent::borrow(&falcon_network_event());

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn without_pipeline_sigma_fields_do_not_match_falcon_event() {
    let rule = r#"
title: Network without remap
id: 00000000-0000-0000-0000-0000000000f4
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationIp: '104.18.12.123'
    condition: selection
"#;
    let collection = parse_sigma_yaml(rule).expect("parse rule");
    let event = JsonEvent::borrow(&falcon_network_event());

    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("compile");
    assert!(
        engine.evaluate(&event).is_empty(),
        "Sigma names must not match Falcon fields without the pipeline"
    );
}

#[test]
fn falcon_windows_maps_file_dns_and_image_load() {
    let pipeline = parse_pipeline(FALCON_PIPELINE).expect("parse");

    let file_rule = r#"
title: PE write
id: 00000000-0000-0000-0000-0000000000f5
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: 'Temp'
    condition: selection
"#;
    let file_event = JsonEvent::borrow(&json!({
        "event_simpleName": "PeFileWritten",
        "event_platform": "Win",
        "TargetFileName": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\Temp\\\\evil.exe",
        "UserName": "jdoe"
    }));
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(file_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&file_event).len(), 1);

    let dns_rule = r#"
title: DNS
id: 00000000-0000-0000-0000-0000000000f6
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName: 'evil.example.org'
    condition: selection
"#;
    let dns_event = JsonEvent::borrow(&json!({
        "event_simpleName": "DnsRequest",
        "event_platform": "Win",
        "DomainName": "evil.example.org"
    }));
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(
            &parse_sigma_yaml(dns_rule).unwrap(),
            std::slice::from_ref(&pipeline),
        )
        .unwrap();
    assert_eq!(engine.evaluate(&dns_event).len(), 1);

    let image_rule = r#"
title: DLL load
id: 00000000-0000-0000-0000-0000000000f7
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|contains: 'evil.dll'
    condition: selection
"#;
    let image_event = JsonEvent::borrow(&json!({
        "event_simpleName": "ImageLoadRollup2",
        "event_platform": "Win",
        "FilePath": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\evil.dll",
        "ImageFileName": "\\\\Device\\\\HarddiskVolume2\\\\Program Files\\\\app\\\\app.exe"
    }));
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
fn falcon_windows_wrong_simple_name_does_not_match_dns_rule() {
    let rule = r#"
title: DNS gate
id: 00000000-0000-0000-0000-0000000000f8
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName: 'evil.example.org'
    condition: selection
"#;
    let pipeline = parse_pipeline(FALCON_PIPELINE).expect("parse");
    let collection = parse_sigma_yaml(rule).expect("rule");
    let mut event_val = json!({
        "event_simpleName": "NetworkConnectIP4",
        "DomainName": "evil.example.org"
    });
    let event = JsonEvent::borrow(&event_val);
    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .unwrap();
    assert!(engine.evaluate(&event).is_empty());
    event_val["event_simpleName"] = json!("DnsRequest");
    let event = JsonEvent::borrow(&event_val);
    assert_eq!(
        engine.evaluate(&event).len(),
        1,
        "DnsRequest discriminator required"
    );
}

#[test]
fn without_pipeline_file_rule_does_not_match_falcon_event() {
    let rule = r#"
title: file
id: 00000000-0000-0000-0000-0000000000f9
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: 'evil.exe'
    condition: selection
"#;
    let event = JsonEvent::borrow(&json!({
        "event_simpleName": "PeFileWritten",
        "TargetFileName": "\\\\Device\\\\HarddiskVolume2\\\\Temp\\\\evil.exe"
    }));
    let mut engine = Engine::new();
    engine
        .add_collection(&parse_sigma_yaml(rule).unwrap())
        .unwrap();
    assert!(engine.evaluate(&event).is_empty());
}
