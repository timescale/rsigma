//! The `parse_rule` tool: parse Sigma YAML into a structured AST as JSON.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{SourceInput, json_result};

#[tool_router(router = parse_rule_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Parse Sigma YAML (rules, correlations, filters; multi-document) to AST JSON.
    #[tool(
        description = "Parse Sigma YAML (rules, correlations, filters; multi-document supported) into a structured AST as JSON, or return structured parse errors. Accepts inline `yaml` or a file `path`."
    )]
    async fn parse_rule(
        &self,
        Parameters(input): Parameters<SourceInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_parse_rule(input)?))
    }

    pub(crate) fn run_parse_rule(&self, input: SourceInput) -> Result<Value, McpError> {
        let (source, _) = self.load_source(input.yaml.as_deref(), input.path.as_deref())?;
        Ok(match parse_sigma_yaml(&source) {
            Ok(collection) => json!({
                // `parse_sigma_yaml` records syntax errors in `errors` rather
                // than returning `Err`, so `ok` reflects whether parsing was clean.
                "ok": collection.errors.is_empty(),
                "rule_count": collection.rules.len(),
                "correlation_count": collection.correlations.len(),
                "filter_count": collection.filters.len(),
                "parse_errors": collection.errors,
                "collection": collection,
            }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{VALID_RULE, handler, src};

    #[test]
    fn parse_rule_happy_path() {
        let v = handler().run_parse_rule(src(VALID_RULE)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["rule_count"], 1);
    }

    #[test]
    fn parse_rule_invalid_yaml_reports_error() {
        let v = handler()
            .run_parse_rule(src("title: [unterminated"))
            .unwrap();
        assert_eq!(v["ok"], false);
        assert!(!v["parse_errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parse_rule_requires_input() {
        let err = handler()
            .run_parse_rule(SourceInput {
                yaml: None,
                path: None,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("required"));
    }
}
