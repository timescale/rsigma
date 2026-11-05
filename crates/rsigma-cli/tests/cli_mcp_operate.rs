//! E2E: operate-cycle MCP tools against a real daemon.
//!
//! Spawns `rsigma engine daemon` with dispositions enabled, points an
//! in-process MCP handler at it, and chains create_silence -> list_silences
//! -> post_disposition -> get_rule_quality over the MCP tool surface. A
//! catch-all silence is refused with the daemon's hint.

#![cfg(all(feature = "daemon", feature = "mcp"))]

mod common;

use common::{DaemonProcess, SIMPLE_RULE, temp_file};
use rmcp::model::CallToolRequestParams;
use rmcp::{ServiceExt, object};
use rsigma_mcp::{DaemonConnect, RsigmaMcp};
use rsigma_parser::LintConfig;

fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content present");
    serde_json::from_str(&text).expect("content is JSON")
}

async fn call_tool(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: impl Into<std::borrow::Cow<'static, str>>,
    arguments: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let name = name.into();
    let mut req = CallToolRequestParams::new(name.clone());
    req.arguments = Some(arguments);
    let result = client
        .call_tool(req)
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    result_json(&result)
}

#[tokio::test]
async fn operate_tools_chain_against_a_live_daemon() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", "{}");
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--enable-dispositions",
            "--alert-pipeline",
            pipeline.path().to_str().unwrap(),
        ],
    );
    let url = daemon.url("");
    let url = url.trim_end_matches('/').to_string();

    let handler = RsigmaMcp::with_daemon(
        None,
        LintConfig::default(),
        false,
        DaemonConnect {
            url,
            ca_pem: None,
            token: None,
        },
        true,
    )
    .expect("operate handler");

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move { handler.serve(server_io).await });
    let client = ().serve(client_io).await.expect("client initialize");

    let refused = call_tool(
        &client,
        "create_silence",
        object!({
            "matchers": [{ "selector": "rule", "op": "=~", "value": ".*" }],
            "duration": "1h"
        }),
    )
    .await;
    assert_eq!(refused["ok"], false, "{refused}");
    assert!(
        refused["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("allow_broad_silences")),
        "{refused}"
    );

    let created = call_tool(
        &client,
        "create_silence",
        object!({
            "matchers": [{ "selector": "rule", "value": "00000000-0000-0000-0000-000000000001" }],
            "duration": "1h",
            "id": "mcp-e2e-silence",
            "comment": "operate-tools e2e"
        }),
    )
    .await;
    assert_eq!(created["ok"], true, "{created}");
    assert_eq!(created["id"], "mcp-e2e-silence");

    let listed = call_tool(&client, "list_silences", object!({})).await;
    assert_eq!(listed["ok"], true, "{listed}");
    assert!(
        listed["silences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|silence| silence["id"] == "mcp-e2e-silence"),
        "created silence missing from {listed}"
    );

    let ingested = call_tool(
        &client,
        "post_disposition",
        object!({
            "verdict": "false_positive",
            "fingerprint": "e2e-fp-1",
            "rule_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }),
    )
    .await;
    assert_eq!(ingested["ok"], true, "{ingested}");
    assert_eq!(ingested["accepted"], 1, "{ingested}");

    let quality = call_tool(
        &client,
        "get_rule_quality",
        object!({ "rule_id": "00000000-0000-0000-0000-000000000001" }),
    )
    .await;
    assert_eq!(quality["ok"], true, "{quality}");
    assert!(
        quality["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["rule_id"] == "00000000-0000-0000-0000-000000000001"),
        "posted verdict missing from {quality}"
    );

    client.cancel().await.ok();
    let server = server_task.await.expect("server join").expect("server");
    server.cancel().await.ok();
}
