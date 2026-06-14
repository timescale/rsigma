//! The `list_backends` tool: list conversion backends and their formats.

use std::collections::HashMap;

use rmcp::{ErrorData as McpError, model::CallToolResult, tool, tool_router};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{get_backend, json_result};

#[tool_router(router = list_backends_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List available conversion backends and their output formats.
    #[tool(
        description = "List available conversion backends (targets) with their output formats and correlation methods."
    )]
    async fn list_backends(&self) -> Result<CallToolResult, McpError> {
        Ok(json_result(&run_list_backends()?))
    }
}

pub(crate) fn run_list_backends() -> Result<Value, McpError> {
    let opts = HashMap::new();
    let mut backends = Vec::new();
    for (target, aliases) in [
        ("postgres", &["postgresql", "pg"][..]),
        ("lynxdb", &[][..]),
        ("fibratus", &[][..]),
    ] {
        let backend = get_backend(target, &opts)?;
        backends.push(json!({
            "target": target,
            "aliases": aliases,
            "requires_pipeline": backend.requires_pipeline(),
            "default_format": backend.default_format(),
            "formats": backend.formats().iter().map(|(n, d)| json!({ "name": n, "description": d })).collect::<Vec<_>>(),
            "default_correlation_method": backend.default_correlation_method(),
            "correlation_methods": backend.correlation_methods().iter().map(|(n, d)| json!({ "name": n, "description": d })).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({ "ok": true, "backends": backends }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_backends_includes_postgres() {
        let v = run_list_backends().unwrap();
        let targets: Vec<&str> = v["backends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["target"].as_str().unwrap())
            .collect();
        assert!(targets.contains(&"postgres"));
        assert!(targets.contains(&"fibratus"));
    }
}
