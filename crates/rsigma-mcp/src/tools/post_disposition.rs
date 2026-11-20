//! The `post_disposition` tool: wrap `POST /api/v1/dispositions`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `post_disposition`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PostDispositionInput {
    /// Analyst verdict: `true_positive`, `false_positive`, or
    /// `benign_true_positive`.
    pub verdict: String,
    /// Detection-scoped alert identity. Required unless `incident_id` is set.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Incident-scoped identity. Fans out to contributing rules.
    #[serde(default)]
    pub incident_id: Option<String>,
    /// Target rule id. The daemon requires it for detection-scoped verdicts.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// `detection` (default) or `incident`.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 3339 time for rolling-window placement; defaults to ingest time.
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Who recorded the verdict. Defaults to `rsigma-mcp`.
    #[serde(default)]
    pub analyst: Option<String>,
    /// Free-text note.
    #[serde(default)]
    pub note: Option<String>,
    /// Tenant to bind the disposition to. Required when the daemon token can
    /// see every tenant. A tenant-bound token may omit it or send its own
    /// tenant; naming another tenant is refused with `403`.
    #[serde(default)]
    pub tenant: Option<String>,
}

#[tool_router(router = post_disposition_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Record an analyst disposition on the daemon.
    #[tool(
        description = "Record an analyst disposition on the configured rsigma daemon (POST /api/v1/dispositions). verdict is required. Supply fingerprint (detection scope) or incident_id (incident scope) so a retry is counted as a duplicate rather than a second verdict. Returns the ingest summary (accepted/duplicate/rejected)."
    )]
    async fn post_disposition(
        &self,
        Parameters(input): Parameters<PostDispositionInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_post_disposition(input).await?))
    }

    pub(crate) async fn run_post_disposition(
        &self,
        input: PostDispositionInput,
    ) -> Result<Value, McpError> {
        validate_verdict(&input.verdict)?;
        let fingerprint = input.fingerprint.as_deref().filter(|s| !s.is_empty());
        let incident_id = input.incident_id.as_deref().filter(|s| !s.is_empty());
        if fingerprint.is_none() && incident_id.is_none() {
            return Err(invalid(
                "provide `fingerprint` or `incident_id`; a verdict without an alert identity is not idempotent on retry",
            ));
        }

        let mut body = json!({
            "verdict": input.verdict,
            "analyst": input.analyst.as_deref().unwrap_or("rsigma-mcp"),
        });
        if let Some(fingerprint) = fingerprint {
            body["fingerprint"] = json!(fingerprint);
        }
        if let Some(incident_id) = incident_id {
            body["incident_id"] = json!(incident_id);
        }
        if let Some(rule_id) = input.rule_id.filter(|s| !s.is_empty()) {
            body["rule_id"] = json!(rule_id);
        }
        if let Some(scope) = input.scope.filter(|s| !s.is_empty()) {
            body["scope"] = json!(scope);
        }
        if let Some(timestamp) = input.timestamp.filter(|s| !s.is_empty()) {
            body["timestamp"] = json!(timestamp);
        }
        if let Some(note) = input.note {
            body["note"] = json!(note);
        }
        if let Some(tenant) = input.tenant.filter(|t| !t.is_empty()) {
            body["tenant"] = json!(tenant);
        }
        Ok(self.daemon_post("/api/v1/dispositions", &body).await)
    }
}

fn validate_verdict(verdict: &str) -> Result<(), McpError> {
    match verdict {
        "true_positive" | "false_positive" | "benign_true_positive" => Ok(()),
        other => Err(invalid(format!(
            "unknown verdict '{other}'; expected true_positive, false_positive, or benign_true_positive"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::Json;
    use axum::extract::Json as AxumJson;
    use axum::routing::post;

    async fn ingest(AxumJson(body): AxumJson<Value>) -> Json<Value> {
        Json(json!({
            "accepted": 1,
            "duplicate": 0,
            "rejected": 0,
            "echo_fingerprint": body.get("fingerprint"),
            "echo_analyst": body.get("analyst"),
            "echo_timestamp": body.get("timestamp"),
            "echo_tenant": body.get("tenant"),
        }))
    }

    #[test]
    fn refuses_missing_identity() {
        let handler = operate_handler("http://127.0.0.1:9090", true);
        let err = block_on(handler.run_post_disposition(PostDispositionInput {
            verdict: "false_positive".into(),
            fingerprint: None,
            incident_id: None,
            rule_id: Some("r1".into()),
            scope: None,
            timestamp: None,
            analyst: None,
            note: None,
            tenant: None,
        }))
        .unwrap_err();
        assert!(format!("{err:?}").contains("fingerprint"));
    }

    #[test]
    fn posts_disposition_with_defaults() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/dispositions", post(ingest))).await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_post_disposition(PostDispositionInput {
                    verdict: "false_positive".into(),
                    fingerprint: Some("fp1".into()),
                    incident_id: None,
                    rule_id: Some("r1".into()),
                    scope: None,
                    timestamp: None,
                    analyst: None,
                    note: None,
                    tenant: None,
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["accepted"], 1);
            assert_eq!(value["echo_analyst"], "rsigma-mcp");
            insta::with_settings!({sort_maps => true}, {
                insta::assert_json_snapshot!("post_disposition", value);
            });
        });
    }

    #[test]
    fn timestamp_is_passed_through_as_rfc3339_string() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/dispositions", post(ingest))).await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_post_disposition(PostDispositionInput {
                    verdict: "true_positive".into(),
                    fingerprint: Some("fp2".into()),
                    incident_id: None,
                    rule_id: Some("r1".into()),
                    scope: None,
                    timestamp: Some("2026-09-07T12:00:00Z".into()),
                    analyst: None,
                    note: None,
                    tenant: None,
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["echo_timestamp"], "2026-09-07T12:00:00Z");
        });
    }

    #[test]
    fn tenant_is_passed_through() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/dispositions", post(ingest))).await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_post_disposition(PostDispositionInput {
                    verdict: "true_positive".into(),
                    fingerprint: Some("fp3".into()),
                    incident_id: None,
                    rule_id: Some("r1".into()),
                    scope: None,
                    timestamp: None,
                    analyst: None,
                    note: None,
                    tenant: Some("tenant-a".into()),
                })
                .await
                .unwrap();
            assert_eq!(value["echo_tenant"], "tenant-a");
        });
    }
}
