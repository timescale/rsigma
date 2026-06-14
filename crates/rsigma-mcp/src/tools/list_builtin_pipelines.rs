//! The `list_builtin_pipelines` tool: list the builtin processing pipelines.

use rmcp::{ErrorData as McpError, model::CallToolResult, tool, tool_router};
use rsigma_eval::{builtin_pipeline_names, resolve_builtin_pipeline};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

#[tool_router(router = list_builtin_pipelines_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List the builtin processing pipelines.
    #[tool(description = "List the builtin processing pipelines with their priority and shape.")]
    async fn list_builtin_pipelines(&self) -> Result<CallToolResult, McpError> {
        Ok(json_result(&run_list_builtin_pipelines()))
    }
}

pub(crate) fn run_list_builtin_pipelines() -> Value {
    let mut pipelines = Vec::new();
    for name in builtin_pipeline_names() {
        let entry = match resolve_builtin_pipeline(name) {
            Some(Ok(p)) => json!({
                "name": name,
                "priority": p.priority,
                "is_dynamic": p.is_dynamic(),
                "transformation_count": p.transformations.len(),
            }),
            Some(Err(e)) => json!({ "name": name, "error": e.to_string() }),
            None => json!({ "name": name, "error": "unknown builtin pipeline" }),
        };
        pipelines.push(entry);
    }
    json!({ "ok": true, "pipelines": pipelines })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_builtin_pipelines_lists_three() {
        let v = run_list_builtin_pipelines();
        let names: Vec<&str> = v["pipelines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"ecs_windows"));
        assert!(names.contains(&"fibratus_windows"));
        assert!(names.contains(&"sysmon"));
    }
}
