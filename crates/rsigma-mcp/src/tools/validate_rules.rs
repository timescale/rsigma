//! The `validate_rules` tool: parse and compile Sigma rules, with optional
//! pipelines and dynamic source resolution.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, Pipeline};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{diagnostic_messages, json_result};

/// Input for `validate_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidateInput {
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
    /// Processing pipelines (builtin names like `ecs_windows` or file paths).
    /// When set, these replace the pipelines of a `ruleset`.
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Resolve dynamic pipeline sources (file/command/HTTP) during validation.
    #[serde(default)]
    pub resolve_sources: bool,
    /// Lowest parse diagnostic severity that makes `ok` false: `error`
    /// (default) or `warning`.
    #[serde(default)]
    pub fail_level: FailLevel,
}

/// Lowest parse diagnostic severity that fails validation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FailLevel {
    /// Fail on parse errors only.
    #[default]
    Error,
    /// Fail on parse errors and parse warnings.
    Warning,
}

#[tool_router(router = validate_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Validate that Sigma rules parse and compile (with optional pipelines and source resolution).
    #[tool(
        description = "Validate that Sigma rules parse and compile cleanly: parse, build the detection engine, and check correlation references. Optional `pipelines`, `resolve_sources` (resolve dynamic sources), and `fail_level` (`error` by default; `warning` also fails on parse warnings such as an invalid `status`). Provide exactly one of inline `yaml`, a file/directory `path`, or a named `ruleset` from the server's configuration."
    )]
    async fn validate_rules(
        &self,
        Parameters(input): Parameters<ValidateInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_validate_rules(input).await?))
    }

    pub(crate) async fn run_validate_rules(&self, input: ValidateInput) -> Result<Value, McpError> {
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
        let mut pipelines = self.load_pipelines(&pipeline_specs)?;

        let mut source_errors: Vec<String> = Vec::new();
        if input.resolve_sources {
            pipelines = resolve_pipeline_sources(pipelines, &mut source_errors);
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

        let parse_failed = match input.fail_level {
            FailLevel::Error => collection.has_errors(),
            FailLevel::Warning => !collection.diagnostics.is_empty(),
        };
        let ok = !parse_failed
            && compile_errors.is_empty()
            && correlation_error.is_none()
            && source_errors.is_empty();

        Ok(json!({
            "ok": ok,
            "summary": {
                "detection_rules": collection.rules.len(),
                "correlation_rules": collection.correlations.len(),
                "filter_rules": collection.filters.len(),
                "parse_errors": collection.error_count(),
                "parse_warnings": collection.warning_count(),
                "compile_errors": compile_errors.len(),
            },
            "parse_errors": diagnostic_messages(collection.errors()),
            "parse_warnings": diagnostic_messages(collection.warnings()),
            "compile_errors": compile_errors,
            "correlation_error": correlation_error,
            "source_errors": source_errors,
        }))
    }
}

/// Note any dynamic pipelines whose `${source.*}` references cannot be
/// resolved: source declarations live in external `--source` files, which the
/// MCP server does not accept. The pipelines pass through unexpanded.
fn resolve_pipeline_sources(
    pipelines: Vec<Pipeline>,
    source_errors: &mut Vec<String>,
) -> Vec<Pipeline> {
    for pipeline in &pipelines {
        if pipeline.is_dynamic() {
            source_errors.push(format!(
                "pipeline '{}' references dynamic sources declared in external `--source` files, \
                 which the MCP server cannot resolve; validate it with `rsigma rule validate \
                 --resolve-sources --source <file>`",
                pipeline.name
            ));
        }
    }
    pipelines
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::tools::{VALID_RULE, block_on, handler, ruleset_handler, ruleset_spec};

    async fn validate(yaml: &str) -> Result<Value, McpError> {
        handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(yaml.to_string()),
                path: None,
                ruleset: None,
                pipelines: vec![],
                resolve_sources: false,
                fail_level: FailLevel::Error,
            })
            .await
    }

    #[tokio::test]
    async fn validate_rules_ok_parse_error_and_compile_error() {
        let ok = handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                ruleset: None,
                pipelines: vec![],
                resolve_sources: false,
                fail_level: FailLevel::Error,
            })
            .await
            .unwrap();
        assert_eq!(ok["ok"], true);

        let unparsable = "title: T\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: missing_ref\n";
        let bad = validate(unparsable).await.unwrap();
        assert_eq!(bad["ok"], false);
        assert!(!bad["parse_errors"].as_array().unwrap().is_empty());

        let uncompilable = "title: T\nlogsource:\n  category: test\ndetection:\n  sel:\n    a|re: '(?<!x)y'\n  condition: sel\n";
        let bad = validate(uncompilable).await.unwrap();
        assert_eq!(bad["ok"], false);
        assert!(!bad["compile_errors"].as_array().unwrap().is_empty());
    }

    async fn validate_at(yaml: &str, fail_level: FailLevel) -> Value {
        handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(yaml.to_string()),
                path: None,
                ruleset: None,
                pipelines: vec![],
                resolve_sources: false,
                fail_level,
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn validate_rules_fail_level_decides_whether_warnings_fail() {
        let warned = VALID_RULE.replace("status: test", "status: bogus");

        let lenient = validate_at(&warned, FailLevel::Error).await;
        assert_eq!(lenient["ok"], true);
        assert_eq!(lenient["parse_errors"], json!([]));
        assert_eq!(
            lenient["parse_warnings"],
            json!(["invalid status: 'bogus'"])
        );
        assert_eq!(lenient["summary"]["parse_errors"], 0);
        assert_eq!(lenient["summary"]["parse_warnings"], 1);

        let strict = validate_at(&warned, FailLevel::Warning).await;
        assert_eq!(strict["ok"], false);

        let clean = validate_at(VALID_RULE, FailLevel::Warning).await;
        assert_eq!(clean["ok"], true);
    }

    #[test]
    fn validate_rules_accepts_a_ruleset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "base".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &[]),
        )]);
        let value = block_on(
            ruleset_handler(Some(dir.path().to_path_buf()), rulesets).run_validate_rules(
                ValidateInput {
                    yaml: None,
                    path: None,
                    ruleset: Some("base".to_string()),
                    pipelines: vec![],
                    resolve_sources: false,
                    fail_level: FailLevel::Error,
                },
            ),
        )
        .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["summary"]["detection_rules"], 1);
    }

    #[test]
    fn validate_rules_unknown_ruleset_lists_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([
            (
                "base".to_string(),
                ruleset_spec(dir.path(), &["rule.yml"], &[]),
            ),
            (
                "other".to_string(),
                ruleset_spec(dir.path(), &["rule.yml"], &[]),
            ),
        ]);
        let error = block_on(
            ruleset_handler(Some(dir.path().to_path_buf()), rulesets).run_validate_rules(
                ValidateInput {
                    yaml: None,
                    path: None,
                    ruleset: Some("nope".to_string()),
                    pipelines: vec![],
                    resolve_sources: false,
                    fail_level: FailLevel::Error,
                },
            ),
        )
        .unwrap_err();
        let text = format!("{error:?}");
        assert!(text.contains("unknown ruleset 'nope'"), "{text}");
        assert!(text.contains("base"), "{text}");
        assert!(text.contains("other"), "{text}");
    }

    #[test]
    fn validate_rules_rejects_ruleset_and_path() {
        let error = block_on(handler().run_validate_rules(ValidateInput {
            yaml: None,
            path: Some("rule.yml".to_string()),
            ruleset: Some("base".to_string()),
            pipelines: vec![],
            resolve_sources: false,
            fail_level: FailLevel::Error,
        }))
        .unwrap_err();
        assert!(format!("{error:?}").contains("exactly one"));
    }

    #[test]
    fn fail_level_defaults_to_error() {
        let input: ValidateInput = serde_json::from_value(json!({ "yaml": "x" })).unwrap();
        assert_eq!(input.fail_level, FailLevel::Error);
        let input: ValidateInput =
            serde_json::from_value(json!({ "yaml": "x", "fail_level": "warning" })).unwrap();
        assert_eq!(input.fail_level, FailLevel::Warning);
    }
}
