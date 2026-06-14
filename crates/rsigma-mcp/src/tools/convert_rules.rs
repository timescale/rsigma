//! The `convert_rules` tool: convert Sigma rules to backend-native queries.

use std::collections::HashMap;

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_convert::convert_collection;
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{get_backend, invalid, json_result};

/// Input for `convert_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ConvertInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Backend target: `postgres` (aliases `postgresql`, `pg`), `lynxdb`, or `fibratus`.
    pub target: String,
    /// Backend-specific output format. Defaults to `default`.
    #[serde(default)]
    pub format: Option<String>,
    /// Processing pipelines (builtin names or file paths).
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Backend options as key=value pairs (e.g. `table` -> `events`).
    #[serde(default)]
    pub options: HashMap<String, String>,
    /// Report unconvertible rules as warnings instead of failing the call.
    #[serde(default)]
    pub skip_unsupported: bool,
}

#[tool_router(router = convert_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Convert Sigma rules to backend-native queries.
    #[tool(
        description = "Convert Sigma rules to backend-native queries. `target` is one of postgres/lynxdb/fibratus. Accepts inline `yaml` or a file/directory `path`, optional `pipelines`, `format`, backend `options`, and `skip_unsupported`."
    )]
    async fn convert_rules(
        &self,
        Parameters(input): Parameters<ConvertInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_convert_rules(input)?))
    }

    pub(crate) fn run_convert_rules(&self, input: ConvertInput) -> Result<Value, McpError> {
        let collection = self.load_collection(input.yaml.as_deref(), input.path.as_deref())?;
        let pipelines = self.load_pipelines(&input.pipelines)?;
        let backend = get_backend(&input.target, &input.options)?;
        let format = input.format.as_deref().unwrap_or("default");

        if !backend.formats().iter().any(|(f, _)| *f == format) {
            return Err(invalid(format!(
                "unknown format '{format}' for backend '{}'; available: {}",
                input.target,
                backend
                    .formats()
                    .iter()
                    .map(|(f, _)| *f)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        Ok(
            match convert_collection(backend.as_ref(), &collection, &pipelines, format) {
                Ok(output) => {
                    let queries: Vec<Value> = output
                        .queries
                        .iter()
                        .flat_map(|r| {
                            r.queries.iter().map(move |q| {
                            json!({ "rule_title": r.rule_title, "rule_id": r.rule_id, "query": q })
                        })
                        })
                        .collect();
                    let errors: Vec<Value> = output
                        .errors
                        .iter()
                        .map(|(title, e)| json!({ "rule_title": title, "error": e.to_string() }))
                        .collect();
                    let warnings: Vec<Value> = output
                        .warnings()
                        .map(|(title, w)| json!({ "rule_title": title, "warning": w }))
                        .collect();
                    let ok = errors.is_empty() || input.skip_unsupported;
                    json!({
                        "ok": ok,
                        "target": input.target,
                        "format": format,
                        "queries": queries,
                        "errors": errors,
                        "warnings": warnings,
                    })
                }
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{GOLDEN_RULE, VALID_RULE, handler};

    #[test]
    fn convert_rules_postgres_and_unknown_target() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert!(!v["queries"].as_array().unwrap().is_empty());

        let err = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                target: "nope".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("unknown target"));
    }

    #[test]
    fn golden_convert_rules_postgres() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("convert_rules_postgres", v);
        });
    }
}
