//! The `parse_condition` tool: parse a Sigma condition expression to a tree.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::parse_condition;
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

/// Input for `parse_condition`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ConditionInput {
    /// A Sigma condition expression, e.g. `selection and not filter`.
    pub condition: String,
}

#[tool_router(router = parse_condition_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Parse a Sigma condition expression into a parse-tree.
    #[tool(
        description = "Parse a Sigma condition expression (e.g. `selection and not 1 of filter_*`) into a parse-tree as JSON, or return a structured parse error."
    )]
    async fn parse_condition(
        &self,
        Parameters(input): Parameters<ConditionInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&run_parse_condition(input)))
    }
}

pub(crate) fn run_parse_condition(input: ConditionInput) -> Value {
    match parse_condition(&input.condition) {
        Ok(expr) => json!({ "ok": true, "expression": expr }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_condition_happy_and_error() {
        let ok = run_parse_condition(ConditionInput {
            condition: "sel and not 1 of filter_*".to_string(),
        });
        assert_eq!(ok["ok"], true);
        let bad = run_parse_condition(ConditionInput {
            condition: "sel and and".to_string(),
        });
        assert_eq!(bad["ok"], false);
    }
}
