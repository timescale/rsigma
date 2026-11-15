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
    /// Inline Sigma YAML. Mutually exclusive with `path` and `ruleset`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml` and
    /// `ruleset`.
    #[serde(default)]
    pub path: Option<String>,
    /// Named ruleset from the server's rsigma.yaml. Mutually exclusive with
    /// `yaml` and `path`.
    #[serde(default)]
    pub ruleset: Option<String>,
    /// Processing pipelines to apply before extracting fields.
    /// When set, these replace the pipelines of a `ruleset`.
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
        description = "List the event fields referenced by Sigma rules, with provenance (which rules and source kinds reference each field). Optional `pipelines` are applied first so the field names match what the engine evaluates. Provide exactly one of inline `yaml`, a file/directory `path`, or a named `ruleset` from the server's configuration."
    )]
    async fn list_fields(
        &self,
        Parameters(input): Parameters<FieldsInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_list_fields(input)?))
    }

    pub(crate) fn run_list_fields(&self, input: FieldsInput) -> Result<Value, McpError> {
        let (collection, ruleset_pipelines) = self.load_collection(
            input.yaml.as_deref(),
            input.path.as_deref(),
            input.ruleset.as_deref(),
        )?;
        let pipeline_specs = if input.pipelines.is_empty() {
            ruleset_pipelines
        } else {
            input.pipelines
        };
        let pipelines = self.load_pipelines(&pipeline_specs)?;
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
    use std::collections::BTreeMap;

    use super::*;
    use crate::tools::{VALID_RULE, handler, ruleset_handler, ruleset_spec};

    #[test]
    fn list_fields_reports_command_line() {
        let v = handler()
            .run_list_fields(FieldsInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                ruleset: None,
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

    #[test]
    fn list_fields_accepts_a_ruleset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "base".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &[]),
        )]);
        let value = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_list_fields(FieldsInput {
                yaml: None,
                path: None,
                ruleset: Some("base".to_string()),
                pipelines: vec![],
                include_filters: true,
            })
            .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["field_count"], 1);
    }

    #[test]
    fn list_fields_rejects_ruleset_and_path() {
        let error = handler()
            .run_list_fields(FieldsInput {
                yaml: None,
                path: Some("rule.yml".to_string()),
                ruleset: Some("base".to_string()),
                pipelines: vec![],
                include_filters: true,
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("exactly one"), "{error:?}");
    }
}
