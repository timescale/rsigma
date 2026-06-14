//! The `resolve_pipeline` tool: resolve a pipeline and report its structure.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

/// Input for `resolve_pipeline`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ResolvePipelineInput {
    /// A builtin pipeline name (`ecs_windows`, `fibratus_windows`, `sysmon`) or
    /// a path to a pipeline YAML file.
    pub pipeline: String,
    /// Resolve dynamic sources (file/command/HTTP) and report their data keys.
    #[serde(default)]
    pub resolve_sources: bool,
}

#[tool_router(router = resolve_pipeline_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Resolve a pipeline (builtin or file) and report its structure.
    #[tool(
        description = "Resolve a processing pipeline (a builtin name like `ecs_windows` or a YAML file path) and report its name, priority, transformations, and dynamic sources. With `resolve_sources`, dynamic file/command/HTTP sources are resolved and their data keys reported."
    )]
    async fn resolve_pipeline(
        &self,
        Parameters(input): Parameters<ResolvePipelineInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_resolve_pipeline(input).await?))
    }

    pub(crate) async fn run_resolve_pipeline(
        &self,
        input: ResolvePipelineInput,
    ) -> Result<Value, McpError> {
        let pipeline = self.load_one_pipeline(&input.pipeline)?;

        let mut resolved: Option<Value> = None;
        if input.resolve_sources && pipeline.is_dynamic() {
            let resolver = rsigma_runtime::DefaultSourceResolver::new();
            match rsigma_runtime::sources::resolve_all(&resolver, &pipeline.sources).await {
                Ok(map) => {
                    let mut keys: Vec<&String> = map.keys().collect();
                    keys.sort();
                    resolved = Some(json!({ "ok": true, "source_ids": keys }));
                }
                Err(e) => resolved = Some(json!({ "ok": false, "error": e.to_string() })),
            }
        }

        Ok(json!({
            "ok": true,
            "name": pipeline.name,
            "priority": pipeline.priority,
            "is_dynamic": pipeline.is_dynamic(),
            "transformation_count": pipeline.transformations.len(),
            "source_ids": pipeline.sources.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            "dynamic_reference_count": pipeline.dynamic_references().len(),
            "resolved": resolved,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::handler;

    #[tokio::test]
    async fn resolve_pipeline_builtin() {
        let v = handler()
            .run_resolve_pipeline(ResolvePipelineInput {
                pipeline: "sysmon".to_string(),
                resolve_sources: false,
            })
            .await
            .unwrap();
        assert_eq!(v["name"], "sysmon");
        assert_eq!(v["is_dynamic"], false);
    }

    #[tokio::test]
    async fn resolve_pipeline_unknown_is_error() {
        let err = handler()
            .run_resolve_pipeline(ResolvePipelineInput {
                pipeline: "definitely_not_a_pipeline.yml".to_string(),
                resolve_sources: false,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("pipeline"));
    }
}
