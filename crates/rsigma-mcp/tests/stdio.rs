//! Integration tests for the MCP boundary: a full client/server round-trip over
//! an in-process duplex transport (the same `AsyncRead + AsyncWrite` transport
//! rmcp drives over stdio). Covers `initialize` (implicit in `serve`),
//! `tools/list`, and `tools/call` for the representative tools.

use rmcp::model::CallToolRequestParams;
use rmcp::{ServiceExt, object};
use rsigma_mcp::RsigmaMcp;

const RULE: &str = r#"
title: Whoami Execution
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: test
description: Detects whoami execution
author: rsigma
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
"#;

/// Connect a `RsigmaMcp` server to a `()` client over an in-process pipe.
async fn connect() -> (
    rmcp::service::RunningService<rmcp::RoleServer, RsigmaMcp>,
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
) {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    // The server's `serve` blocks on the initialize handshake, so the client
    // must be connecting concurrently. Spawn the server, then drive the client.
    let server_task = tokio::spawn(async move { RsigmaMcp::default().serve(server_io).await });
    let client = ().serve(client_io).await.expect("client initialize");
    let server = server_task
        .await
        .expect("server task join")
        .expect("server initialize");
    (server, client)
}

/// Extract the JSON text content of a tool result.
fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content present");
    serde_json::from_str(&text).expect("content is JSON")
}

#[tokio::test]
async fn tools_list_exposes_all_core_tools() {
    let (server, client) = connect().await;

    let tools = client.list_all_tools().await.expect("list tools");
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();

    for expected in [
        "parse_rule",
        "parse_condition",
        "lint_rules",
        "validate_rules",
        "evaluate_events",
        "convert_rules",
        "list_backends",
        "list_fields",
        "resolve_pipeline",
        "list_builtin_pipelines",
        "fix_rules",
        "author_ads",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "missing tool {expected}"
        );
    }
    assert_eq!(tools.len(), 12, "expected exactly 12 tools, got {names:?}");

    // parse_rule advertises an input schema with the `yaml` property.
    let parse_rule = tools.iter().find(|t| t.name == "parse_rule").unwrap();
    let schema = serde_json::to_value(&parse_rule.input_schema).unwrap();
    assert!(
        schema.to_string().contains("yaml"),
        "parse_rule schema should mention `yaml`: {schema}"
    );

    client.cancel().await.ok();
    server.cancel().await.ok();
}

#[tokio::test]
async fn call_parse_rule_round_trip() {
    let (server, client) = connect().await;

    let mut req = CallToolRequestParams::new("parse_rule");
    req.arguments = Some(object!({ "yaml": RULE }));
    let result = client.call_tool(req).await.expect("call parse_rule");
    let v = result_json(&result);
    assert_eq!(v["ok"], true);
    assert_eq!(v["rule_count"], 1);

    client.cancel().await.ok();
    server.cancel().await.ok();
}

#[tokio::test]
async fn call_lint_rules_round_trip() {
    let (server, client) = connect().await;

    let mut req = CallToolRequestParams::new("lint_rules");
    req.arguments = Some(
        object!({ "yaml": "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n" }),
    );
    let result = client.call_tool(req).await.expect("call lint_rules");
    let v = result_json(&result);
    let findings = v["files"][0]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule"] == "non_lowercase_key"));

    client.cancel().await.ok();
    server.cancel().await.ok();
}

#[tokio::test]
async fn resources_list_and_read_round_trip() {
    use rmcp::model::ReadResourceRequestParams;

    let (server, client) = connect().await;

    let resources = client.list_all_resources().await.expect("list resources");
    let uris: Vec<String> = resources.iter().map(|r| r.uri.clone()).collect();
    assert!(uris.contains(&"rsigma://lint/catalogue".to_string()));
    assert!(uris.contains(&"rsigma://ads/schema".to_string()));
    assert!(uris.contains(&"rsigma://reference/modifiers".to_string()));
    assert!(uris.contains(&"rsigma://reference/mitre-tactics".to_string()));

    let read = client
        .read_resource(ReadResourceRequestParams::new("rsigma://lint/catalogue"))
        .await
        .expect("read resource");
    let text = read
        .contents
        .iter()
        .find_map(|c| match c {
            rmcp::model::ResourceContents::TextResourceContents { text, .. } => Some(text.clone()),
            _ => None,
        })
        .expect("text resource");
    let catalogue: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(catalogue.as_array().unwrap().len(), 86);

    let ads = client
        .read_resource(ReadResourceRequestParams::new("rsigma://ads/schema"))
        .await
        .expect("read ads schema");
    let ads_text = ads
        .contents
        .iter()
        .find_map(|c| match c {
            rmcp::model::ResourceContents::TextResourceContents { text, .. } => Some(text.clone()),
            _ => None,
        })
        .expect("text resource");
    let schema: serde_json::Value = serde_json::from_str(&ads_text).unwrap();
    assert_eq!(schema.as_array().unwrap().len(), 9);

    client.cancel().await.ok();
    server.cancel().await.ok();
}

#[tokio::test]
async fn call_evaluate_events_round_trip() {
    let (server, client) = connect().await;

    let mut req = CallToolRequestParams::new("evaluate_events");
    req.arguments = Some(object!({
        "yaml": RULE,
        "events": [ { "CommandLine": "cmd /c whoami" } ],
    }));
    let result = client.call_tool(req).await.expect("call evaluate_events");
    let v = result_json(&result);
    assert_eq!(v["ok"], true);
    assert_eq!(v["summary"]["detection_matches"], 1);

    client.cancel().await.ok();
    server.cancel().await.ok();
}
