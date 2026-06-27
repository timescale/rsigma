//! The `author_ads` tool: report a rule's ADS sections, the sections it is
//! missing under the active config, and a scaffold an agent can complete.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::ads::{is_exempt, scaffold_missing};
use rsigma_parser::{AdsConfig, AdsSection, SigmaRule, Status};
use serde_json::{Map, Value, json};

use super::RsigmaMcp;
use super::shared::{SourceInput, json_result, to_value};

#[tool_router(router = author_ads_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Report ADS sections and a scaffold for the missing ones.
    #[tool(
        description = "Report each detection rule's ADS (Alerting and Detection Strategy) sections, the required sections it is missing under the active config, and a scaffolded `rsigma.ads.*` template to complete. Accepts inline `yaml` or a file `path`."
    )]
    async fn author_ads(
        &self,
        Parameters(input): Parameters<SourceInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_author_ads(input)?))
    }

    pub(crate) fn run_author_ads(&self, input: SourceInput) -> Result<Value, McpError> {
        let collection = self.load_collection(input.yaml.as_deref(), input.path.as_deref())?;
        let bar = self.lint_config().ads.clone().unwrap_or_default();

        let rules: Vec<Value> = collection
            .rules
            .iter()
            .map(|rule| author_ads_for_rule(rule, &bar))
            .collect();

        Ok(json!({
            "ok": true,
            "rule_count": rules.len(),
            "rules": rules,
        }))
    }
}

/// Build the ADS report for one rule against the active ADS bar.
fn author_ads_for_rule(rule: &SigmaRule, bar: &AdsConfig) -> Value {
    let status = rule.status.map(status_str);
    let enforced = bar.enforces_status(status);
    let exempt = is_exempt(rule);

    let sections: Vec<Value> = AdsSection::all()
        .iter()
        .map(|&s| {
            let content = s.content(rule);
            json!({
                "id": s.id(),
                "required": bar.requires(s.id()),
                "present": content.is_some(),
                "carrier": s.carrier_field(),
                "content": content.map(|c| to_value(&c)),
            })
        })
        .collect();

    let missing_required: Vec<&str> = AdsSection::all()
        .iter()
        .filter(|s| bar.requires(s.id()) && !s.is_present(rule))
        .map(|s| s.id())
        .collect();

    let mut scaffold = Map::new();
    for entry in scaffold_missing(rule) {
        scaffold.insert(entry.key.to_string(), to_value(&entry.placeholder));
    }

    json!({
        "title": rule.title,
        "id": rule.id,
        "status": status,
        "enforced": enforced,
        "exempt": exempt,
        "sections": sections,
        "missing_required": missing_required,
        "scaffold": { "custom_attributes": scaffold },
    })
}

/// The lowercase wire form of a status.
fn status_str(s: Status) -> &'static str {
    match s {
        Status::Stable => "stable",
        Status::Test => "test",
        Status::Experimental => "experimental",
        Status::Deprecated => "deprecated",
        Status::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{handler, src};

    const BARE: &str = r#"
title: Bare stable rule
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#;

    #[test]
    fn reports_missing_and_scaffold() {
        let v = handler().run_author_ads(src(BARE)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["rule_count"], 1);
        let rule = &v["rules"][0];
        let missing = rule["missing_required"].as_array().unwrap();
        assert!(missing.iter().any(|m| m == "strategy"));
        let scaffold = &rule["scaffold"]["custom_attributes"];
        assert!(scaffold.get("rsigma.ads.validation").is_some());
    }

    #[test]
    fn present_sections_are_reported() {
        let yaml = format!("{BARE}description: A real goal.\n");
        let v = handler().run_author_ads(src(&yaml)).unwrap();
        let sections = v["rules"][0]["sections"].as_array().unwrap();
        let goal = sections.iter().find(|s| s["id"] == "goal").unwrap();
        assert_eq!(goal["present"], true);
    }

    #[test]
    fn requires_input() {
        let err = handler()
            .run_author_ads(SourceInput {
                yaml: None,
                path: None,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("required"));
    }
}
