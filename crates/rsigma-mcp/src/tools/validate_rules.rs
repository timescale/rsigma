//! The `validate_rules` tool: parse and compile Sigma rules, with optional
//! pipelines and dynamic source resolution.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, Pipeline};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

/// Input for `validate_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidateInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Processing pipelines (builtin names like `ecs_windows` or file paths).
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Resolve dynamic pipeline sources (file/command/HTTP) during validation.
    #[serde(default)]
    pub resolve_sources: bool,
}

#[tool_router(router = validate_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Validate that Sigma rules parse and compile (with optional pipelines and source resolution).
    #[tool(
        description = "Validate that Sigma rules parse and compile cleanly: parse, build the detection engine, and check correlation references. Optional `pipelines` and `resolve_sources` (resolve dynamic sources). Accepts inline `yaml` or a file/directory `path`."
    )]
    async fn validate_rules(
        &self,
        Parameters(input): Parameters<ValidateInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_validate_rules(input).await?))
    }

    pub(crate) async fn run_validate_rules(&self, input: ValidateInput) -> Result<Value, McpError> {
        let collection = self.load_collection(input.yaml.as_deref(), input.path.as_deref())?;
        let mut pipelines = self.load_pipelines(&input.pipelines)?;

        let mut source_errors: Vec<String> = Vec::new();
        if input.resolve_sources {
            pipelines = resolve_pipeline_sources(pipelines, &mut source_errors).await;
        }

        let mut engine = Engine::new();
        for p in &pipelines {
            engine.add_pipeline(p.clone());
        }
        let compile_errors: Vec<Value> = engine
            .add_rules(&collection.rules)
            .into_iter()
            .map(|(idx, e)| {
                let rule = &collection.rules[idx];
                let id = rule.id.as_deref().unwrap_or(rule.title.as_str());
                json!({ "rule": id, "error": e.to_string() })
            })
            .collect();

        let mut correlation_error: Option<String> = None;
        if !collection.correlations.is_empty() {
            let mut corr = CorrelationEngine::new(CorrelationConfig::default());
            for p in &pipelines {
                corr.add_pipeline(p.clone());
            }
            if let Err(e) = corr.add_collection(&collection) {
                correlation_error = Some(e.to_string());
            }
        }

        let ok = collection.errors.is_empty()
            && compile_errors.is_empty()
            && correlation_error.is_none()
            && source_errors.is_empty();

        Ok(json!({
            "ok": ok,
            "summary": {
                "detection_rules": collection.rules.len(),
                "correlation_rules": collection.correlations.len(),
                "filter_rules": collection.filters.len(),
                "parse_errors": collection.errors.len(),
                "compile_errors": compile_errors.len(),
            },
            "parse_errors": collection.errors,
            "compile_errors": compile_errors,
            "correlation_error": correlation_error,
            "source_errors": source_errors,
        }))
    }
}

/// Resolve dynamic sources for every dynamic pipeline, returning expanded
/// pipelines and collecting any resolution errors.
async fn resolve_pipeline_sources(
    pipelines: Vec<Pipeline>,
    source_errors: &mut Vec<String>,
) -> Vec<Pipeline> {
    let resolver = rsigma_runtime::DefaultSourceResolver::new();
    let mut resolved_pipelines = Vec::with_capacity(pipelines.len());
    for pipeline in pipelines {
        if pipeline.is_dynamic() {
            match rsigma_runtime::sources::resolve_all(&resolver, &pipeline.sources).await {
                Ok(data) => {
                    let expanded = rsigma_runtime::sources::template::TemplateExpander::expand(
                        &pipeline, &data,
                    );
                    resolved_pipelines.push(expanded);
                }
                Err(e) => {
                    source_errors.push(format!("pipeline '{}': {e}", pipeline.name));
                    resolved_pipelines.push(pipeline);
                }
            }
        } else {
            resolved_pipelines.push(pipeline);
        }
    }
    resolved_pipelines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{VALID_RULE, handler};

    #[tokio::test]
    async fn validate_rules_ok_and_compile_error() {
        let ok = handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                pipelines: vec![],
                resolve_sources: false,
            })
            .await
            .unwrap();
        assert_eq!(ok["ok"], true);

        let bad_yaml = "title: T\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: missing_ref\n";
        let bad = handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(bad_yaml.to_string()),
                path: None,
                pipelines: vec![],
                resolve_sources: false,
            })
            .await
            .unwrap();
        assert_eq!(bad["ok"], false);
        assert!(!bad["compile_errors"].as_array().unwrap().is_empty());
    }
}
