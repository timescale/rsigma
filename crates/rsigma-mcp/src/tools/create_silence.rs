//! The `create_silence` tool: wrap `POST /api/v1/silences` with a TTL.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `create_silence`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateSilenceInput {
    /// Matchers (ANDed). At least one is required.
    pub matchers: Vec<Value>,
    /// RFC 3339 end. Mutually exclusive with `duration`.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// Humantime duration converted to `ends_at` at call time (e.g. `1h`).
    /// Mutually exclusive with `ends_at`.
    #[serde(default)]
    pub duration: Option<String>,
    /// RFC 3339 start; absent means active immediately.
    #[serde(default)]
    pub starts_at: Option<String>,
    /// Client-supplied id. When the id already exists, the existing silence
    /// is returned instead of creating a duplicate.
    #[serde(default)]
    pub id: Option<String>,
    /// Free-text comment recorded on the silence.
    #[serde(default)]
    pub comment: Option<String>,
    /// Who created it. Defaults to `rsigma-mcp`.
    #[serde(default)]
    pub created_by: Option<String>,
    /// Tenant to bind the silence to. Required when the daemon token can see
    /// every tenant. A tenant-bound token may omit it or send its own tenant;
    /// naming another tenant is refused with `403`.
    #[serde(default)]
    pub tenant: Option<String>,
}

#[tool_router(router = create_silence_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Create a time-bounded silence on the daemon.
    #[tool(
        description = "Create a silence on the configured rsigma daemon (POST /api/v1/silences). matchers are required. Supply exactly one of ends_at (RFC 3339) or duration (humantime, converted at call time); unbounded silences are refused. The daemon also requires an = matcher on rule, match.<field>, or correlation.group_key.<field>, and caps the window at its max_silence_duration (default 720h). An optional id is pre-checked against the silence list so a retried create is a no-op."
    )]
    async fn create_silence(
        &self,
        Parameters(input): Parameters<CreateSilenceInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_create_silence(input).await?))
    }

    pub(crate) async fn run_create_silence(
        &self,
        input: CreateSilenceInput,
    ) -> Result<Value, McpError> {
        if input.matchers.is_empty() {
            return Err(invalid("`matchers` must not be empty"));
        }
        let ends_at = resolve_ends_at(input.ends_at.as_deref(), input.duration.as_deref())?;
        let tenant = input.tenant.as_deref().filter(|t| !t.is_empty());
        if let Some(id) = input.id.as_deref().filter(|id| !id.is_empty()) {
            let listed = self.daemon_get("/api/v1/silences").await;
            if listed.get("ok") == Some(&json!(true))
                && let Some(existing) =
                    listed
                        .get("silences")
                        .and_then(Value::as_array)
                        .and_then(|silences| {
                            silences.iter().find(|s| {
                                s.get("id").and_then(Value::as_str) == Some(id)
                                    && same_tenant(s, tenant)
                            })
                        })
            {
                return Ok(json!({
                    "ok": true,
                    "status": "exists",
                    "silence": existing,
                }));
            }
        }

        let mut body = json!({
            "matchers": input.matchers,
            "ends_at": ends_at,
            "created_by": input.created_by.as_deref().unwrap_or("rsigma-mcp"),
        });
        if let Some(id) = input.id {
            body["id"] = json!(id);
        }
        if let Some(starts_at) = input.starts_at {
            body["starts_at"] = json!(starts_at);
        }
        if let Some(comment) = input.comment {
            body["comment"] = json!(comment);
        }
        if let Some(tenant) = input.tenant.filter(|t| !t.is_empty()) {
            body["tenant"] = json!(tenant);
        }
        Ok(self.daemon_post("/api/v1/silences", &body).await)
    }
}

/// Whether a listed silence belongs to `tenant` or to every tenant. With no
/// tenant named, the daemon lists only what the token can see.
fn same_tenant(silence: &Value, tenant: Option<&str>) -> bool {
    match (tenant, silence.get("tenant").and_then(Value::as_str)) {
        (None, _) | (_, None) => true,
        (Some(tenant), Some(own)) => tenant == own,
    }
}

fn resolve_ends_at(ends_at: Option<&str>, duration: Option<&str>) -> Result<String, McpError> {
    match (ends_at, duration) {
        (Some(ends), None) => {
            if ends.is_empty() {
                return Err(invalid("`ends_at` must not be empty"));
            }
            Ok(ends.to_string())
        }
        (None, Some(raw)) => {
            let parsed = humantime::parse_duration(raw).map_err(|e| {
                invalid(format!(
                    "invalid duration '{raw}': {e}; expected a humantime string such as 15m or 1h"
                ))
            })?;
            if parsed.is_zero() {
                return Err(invalid("`duration` must be greater than zero"));
            }
            let ends = chrono::Utc::now()
                + chrono::Duration::from_std(parsed)
                    .map_err(|_| invalid("`duration` is too large"))?;
            Ok(ends.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        }
        (Some(_), Some(_)) => Err(invalid("provide exactly one of `ends_at` or `duration`")),
        (None, None) => Err(invalid(
            "provide `ends_at` or `duration`; unbounded silences are refused",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::Json;
    use axum::extract::Json as AxumJson;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Store(Arc<Mutex<Vec<Value>>>);

    async fn list(axum::extract::State(store): axum::extract::State<Store>) -> Json<Value> {
        let silences = store.0.lock().expect("store").clone();
        let count = silences.len();
        Json(json!({ "silences": silences, "count": count }))
    }

    async fn create(
        axum::extract::State(store): axum::extract::State<Store>,
        AxumJson(body): AxumJson<Value>,
    ) -> Response {
        if body.get("ends_at").and_then(Value::as_str).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "ends_at required by stub" })),
            )
                .into_response();
        }
        let id = body
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("sil-assigned")
            .to_string();
        let mut stored = body.clone();
        stored["id"] = json!(id.clone());
        stored["origin"] = json!("api");
        stored["state"] = json!("active");
        store.0.lock().expect("store").push(stored);
        (
            StatusCode::CREATED,
            Json(json!({ "status": "created", "id": id })),
        )
            .into_response()
    }

    #[test]
    fn refuses_unbounded_silence() {
        let handler = operate_handler("http://127.0.0.1:9090", true);
        let err = block_on(handler.run_create_silence(CreateSilenceInput {
            matchers: vec![json!({ "selector": "rule", "value": "r1" })],
            ends_at: None,
            duration: None,
            starts_at: None,
            id: None,
            comment: None,
            created_by: None,
            tenant: None,
        }))
        .unwrap_err();
        assert!(format!("{err:?}").contains("unbounded"));
    }

    #[test]
    fn duration_becomes_ends_at() {
        block_on(async {
            let store = Store::default();
            let url = spawn_stub(
                axum::Router::new()
                    .route("/api/v1/silences", get(list).post(create))
                    .with_state(store.clone()),
            )
            .await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_create_silence(CreateSilenceInput {
                    matchers: vec![json!({ "selector": "rule", "value": "r1" })],
                    ends_at: None,
                    duration: Some("1h".into()),
                    starts_at: None,
                    id: Some("sil-1".into()),
                    comment: Some("known benign".into()),
                    created_by: None,
                    tenant: None,
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["id"], "sil-1");
            let stored = store.0.lock().expect("store")[0].clone();
            assert!(stored["ends_at"].as_str().unwrap().contains('T'));
            assert_eq!(stored["created_by"], "rsigma-mcp");
            insta::with_settings!({sort_maps => true}, {
                insta::assert_json_snapshot!("create_silence", value);
            });
        });
    }

    #[test]
    fn retried_id_returns_existing() {
        block_on(async {
            let store = Store::default();
            store.0.lock().expect("store").push(json!({
                "id": "sil-1",
                "origin": "api",
                "state": "active"
            }));
            let url = spawn_stub(
                axum::Router::new()
                    .route("/api/v1/silences", get(list).post(create))
                    .with_state(store),
            )
            .await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_create_silence(CreateSilenceInput {
                    matchers: vec![json!({ "selector": "rule", "value": "r1" })],
                    ends_at: Some("2026-12-01T00:00:00Z".into()),
                    duration: None,
                    starts_at: None,
                    id: Some("sil-1".into()),
                    comment: None,
                    created_by: None,
                    tenant: None,
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["status"], "exists");
            assert_eq!(value["silence"]["id"], "sil-1");
        });
    }

    #[test]
    fn tenant_is_passed_through() {
        block_on(async {
            let store = Store::default();
            let url = spawn_stub(
                axum::Router::new()
                    .route("/api/v1/silences", get(list).post(create))
                    .with_state(store.clone()),
            )
            .await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_create_silence(CreateSilenceInput {
                    matchers: vec![json!({ "selector": "rule", "value": "r1" })],
                    ends_at: Some("2026-12-01T00:00:00Z".into()),
                    duration: None,
                    starts_at: None,
                    id: Some("sil-tenant".into()),
                    comment: None,
                    created_by: None,
                    tenant: Some("tenant-a".into()),
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            let stored = store.0.lock().expect("store")[0].clone();
            assert_eq!(stored["tenant"], "tenant-a");
        });
    }

    #[test]
    fn another_tenants_silence_with_the_id_is_not_an_existing_one() {
        block_on(async {
            let store = Store::default();
            store
                .0
                .lock()
                .expect("store")
                .push(json!({ "id": "maint", "tenant": "tenant-b" }));
            let url = spawn_stub(
                axum::Router::new()
                    .route("/api/v1/silences", get(list).post(create))
                    .with_state(store.clone()),
            )
            .await;
            let handler = operate_handler(&url, true);
            let value = handler
                .run_create_silence(CreateSilenceInput {
                    matchers: vec![json!({ "selector": "rule", "value": "r1" })],
                    ends_at: Some("2026-12-01T00:00:00Z".into()),
                    duration: None,
                    starts_at: None,
                    id: Some("maint".into()),
                    comment: None,
                    created_by: None,
                    tenant: Some("tenant-a".into()),
                })
                .await
                .unwrap();
            assert_ne!(value["status"], "exists");
            let stored = store.0.lock().expect("store").clone();
            assert_eq!(stored.len(), 2);
            assert_eq!(stored[1]["tenant"], "tenant-a");
        });
    }
}
