//! The `format_rules` tool: rewrite Sigma YAML into the canonical layout.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::{FormatError, format_yaml};
use serde_json::{Value, json};

use crate::input::resolve_confined_path;

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `format_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FormatInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a single Sigma YAML file. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Persist the formatted YAML back to disk. Only valid with a `path` input,
    /// and only when the server has a rules root (`--rules-dir`).
    #[serde(default)]
    pub write: bool,
}

#[tool_router(router = format_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Format Sigma rules into the canonical layout.
    #[tool(
        description = "Rewrite Sigma YAML into the canonical layout: four-space indentation, block collections, canonical key order, and normalized scalar quoting. Comments keep their text and their attachment, and anchors, aliases, tags, and directives are preserved. A semantic guard reparses the result and refuses the rewrite unless YAML values, parsed rules, correlations, filters, parser diagnostics, comment attachment, anchors, aliases, tags, directives, and action values all match. Returns the formatted YAML and whether it changed. Non-Sigma documents are reported as skipped. With `write: true` (only valid with a file `path`, and only when the server runs with --rules-dir) the change is persisted to disk."
    )]
    async fn format_rules(
        &self,
        Parameters(input): Parameters<FormatInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_format_rules(input)?))
    }

    pub(crate) fn run_format_rules(&self, input: FormatInput) -> Result<Value, McpError> {
        if input.write && input.path.is_none() {
            return Err(invalid(
                "`write: true` is only valid with a file `path` input",
            ));
        }
        if input.write && self.root().is_none() {
            return Err(invalid(
                "`write: true` requires the server to be started with --rules-dir",
            ));
        }
        let (source, label) = self.load_source(input.yaml.as_deref(), input.path.as_deref())?;

        let outcome = match format_yaml(&source) {
            Ok(outcome) => outcome,
            Err(FormatError::NotSigma { .. }) => {
                return Ok(json!({
                    "ok": true,
                    "source": label,
                    "skipped": true,
                    "changed": false,
                    "written": false,
                    "formatted_yaml": source,
                }));
            }
            Err(error) => {
                return Ok(json!({
                    "ok": false,
                    "source": label,
                    "error": error.to_string(),
                }));
            }
        };

        let changed = outcome.changed;
        let mut written = false;
        if input.write && changed {
            // `write` requires a path, validated above; resolve and persist.
            let path = resolve_confined_path(
                input.path.as_deref().expect("path required for write"),
                self.root(),
            )?;
            std::fs::write(&path, &outcome.formatted)
                .map_err(|e| invalid(format!("cannot write '{}': {e}", path.display())))?;
            written = true;
        }

        Ok(json!({
            "ok": true,
            "source": label,
            "skipped": false,
            "changed": changed,
            "written": written,
            "formatted_yaml": outcome.formatted,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::handler;

    const UNFORMATTED: &str = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";

    #[test]
    fn format_rules_rewrites_inline_yaml() {
        let v = handler()
            .run_format_rules(FormatInput {
                yaml: Some(UNFORMATTED.to_string()),
                path: None,
                write: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["skipped"], false);
        assert_eq!(v["changed"], true);
        assert_eq!(v["written"], false);
        let formatted = v["formatted_yaml"].as_str().unwrap();
        assert!(formatted.contains("\n    category: test\n"));
        assert!(!formatted.contains("\n  category: test\n"));
    }

    #[test]
    fn format_rules_reports_a_canonical_document_as_unchanged() {
        let yaml = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";
        let v = handler()
            .run_format_rules(FormatInput {
                yaml: Some(yaml.to_string()),
                path: None,
                write: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["changed"], false);
        assert_eq!(v["formatted_yaml"], yaml);
    }

    #[test]
    fn format_rules_skips_non_sigma_documents() {
        let yaml = "name: test\npipeline:\n    - id: one\n";
        let v = handler()
            .run_format_rules(FormatInput {
                yaml: Some(yaml.to_string()),
                path: None,
                write: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["skipped"], true);
        assert_eq!(v["changed"], false);
        assert_eq!(v["formatted_yaml"], yaml);
    }

    #[test]
    fn format_rules_reports_malformed_yaml() {
        let v = handler()
            .run_format_rules(FormatInput {
                yaml: Some("title: [unclosed\n".to_string()),
                path: None,
                write: false,
            })
            .unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("YAML syntax error"));
    }

    #[test]
    fn format_rules_write_without_path_is_error() {
        let err = handler()
            .run_format_rules(FormatInput {
                yaml: Some(UNFORMATTED.to_string()),
                path: None,
                write: true,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("write"));
    }

    #[test]
    fn format_rules_write_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yml");
        std::fs::write(&path, UNFORMATTED).unwrap();

        let v = RsigmaMcp::new(
            Some(dir.path().to_path_buf()),
            rsigma_parser::LintConfig::default(),
            false,
        )
        .run_format_rules(FormatInput {
            yaml: None,
            path: Some("rule.yml".to_string()),
            write: true,
        })
        .unwrap();
        assert_eq!(v["written"], true);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("\n    category: test\n"));
    }

    #[test]
    fn format_rules_write_without_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yml");
        std::fs::write(&path, UNFORMATTED).unwrap();

        let err = handler()
            .run_format_rules(FormatInput {
                yaml: None,
                path: Some(path.display().to_string()),
                write: true,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("--rules-dir"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), UNFORMATTED);
    }
}
