//! The `list_fields` tool: list the event fields referenced by Sigma rules.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::RuleFieldSet;
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

/// Input for `list_fields`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FieldsInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Processing pipelines to apply before extracting fields.
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Include fields referenced by filter rules. Defaults to true.
    #[serde(default = "default_true")]
    pub include_filters: bool,
}

fn default_true() -> bool {
    true
}

#[tool_router(router = list_fields_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List the fields referenced by a set of Sigma rules.
    #[tool(
        description = "List the event fields referenced by Sigma rules, with provenance (which rules and source kinds reference each field). Optional `pipelines` are applied first so the field names match what the engine evaluates. Accepts inline `yaml` or a file/directory `path`."
    )]
    async fn list_fields(
        &self,
        Parameters(input): Parameters<FieldsInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_list_fields(input)?))
    }

    pub(crate) fn run_list_fields(&self, input: FieldsInput) -> Result<Value, McpError> {
        let collection = self.load_collection(input.yaml.as_deref(), input.path.as_deref())?;
        let pipelines = self.load_pipelines(&input.pipelines)?;
        let field_set = RuleFieldSet::collect(&collection, &pipelines, input.include_filters);

        let fields: Vec<Value> = field_set
            .iter()
            .map(|(name, origin)| {
                json!({
                    "field": name,
                    "rule_titles": origin.rule_titles.iter().collect::<Vec<_>>(),
                    "sources": origin.sources.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect();

        Ok(json!({
            "ok": true,
            "field_count": field_set.len(),
            "fields": fields,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{VALID_RULE, handler};

    #[test]
    fn list_fields_reports_command_line() {
        let v = handler()
            .run_list_fields(FieldsInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                pipelines: vec![],
                include_filters: true,
            })
            .unwrap();
        let names: Vec<&str> = v["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["field"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"CommandLine"));
    }
}
