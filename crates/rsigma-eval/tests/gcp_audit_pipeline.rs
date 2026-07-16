//! End-to-end regression for the shipped `gcp_audit` pipeline.
//!
//! SigmaHQ's `gcp.audit` rules reference fields under a `data.` prefix
//! (`data.protoPayload.serviceName`, ...), while a native GCP Cloud Audit
//! event, as recognized by the `gcp_audit` schema signature, carries those
//! fields without the prefix (`protoPayload.serviceName`, ...). The pipeline
//! strips `data.` from rule field names so the rules match. This test guards
//! that routing against silent breakage: without the pipeline the rule must
//! not match, with it the rule must match.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const GCP_PIPELINE: &str = include_str!("../pipelines/gcp_audit.yml");

const GCP_RULE: &str = r#"
title: GCP List Buckets
id: 00000000-0000-0000-0000-000000000001
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        data.protoPayload.serviceName: storage.googleapis.com
        data.protoPayload.methodName: storage.buckets.list
    condition: selection
"#;

fn native_gcp_event() -> serde_json::Value {
    // Native Cloud Logging LogEntry shape: protoPayload.* at top level, no
    // `data.` envelope. This is what the `gcp_audit` signature classifies.
    json!({
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.buckets.list"
        },
        "resource": { "type": "cloud_audit" },
        "severity": "INFO"
    })
}

#[test]
fn gcp_audit_pipeline_routes_native_event_to_data_prefixed_rule() {
    let pipeline = parse_pipeline(GCP_PIPELINE).expect("parse gcp_audit pipeline");
    let collection = parse_sigma_yaml(GCP_RULE).expect("parse rule");
    let event_val = native_gcp_event();
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine
        .add_collection_with_pipelines(&collection, std::slice::from_ref(&pipeline))
        .expect("compile with pipeline");
    assert_eq!(
        engine.evaluate(&event).len(),
        1,
        "gcp_audit pipeline should route a native GCP event to a data.-prefixed SigmaHQ rule"
    );
}

#[test]
fn without_pipeline_data_prefixed_rule_does_not_match_native_event() {
    // Negative control: proves the assertion above is exercised by the
    // pipeline and not by an unrelated match.
    let collection = parse_sigma_yaml(GCP_RULE).expect("parse rule");
    let event_val = native_gcp_event();
    let event = JsonEvent::borrow(&event_val);

    let mut engine = Engine::new();
    engine.add_collection(&collection).expect("compile");
    assert!(
        engine.evaluate(&event).is_empty(),
        "without the pipeline, data.protoPayload.* rule fields must not match native protoPayload.* fields"
    );
}
