//! The `fix_rules` tool: apply safe auto-fixes to Sigma YAML.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::lint::FixDisposition;
use rsigma_parser::{LintWarning, apply_fixes_to_source, lint_yaml_str_with_config};
use serde_json::{Value, json};

use crate::input::resolve_path;

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `fix_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FixInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a single Sigma YAML file. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Restrict fixes to these lint rule ids (e.g. `non_lowercase_key`). Empty
    /// means apply every available safe fix.
    #[serde(default)]
    pub lint_rules: Vec<String>,
    /// Persist the fixed YAML back to disk. Only valid with a `path` input.
    #[serde(default)]
    pub write: bool,
}

#[tool_router(router = fix_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Apply safe auto-fixes to Sigma rules.
    #[tool(
        description = "Apply safe auto-fixes (lowercase keys, status/level typos, duplicate removal, ...) to Sigma YAML, preserving comments and formatting. Returns the fixed YAML and applied/failed/skipped-unsafe counts. Unsafe fixes are never auto-applied. With `write: true` (only valid with a file `path`) the change is persisted to disk. Optional `lint_rules` restricts which lint rules are fixed."
    )]
    async fn fix_rules(
        &self,
        Parameters(input): Parameters<FixInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_fix_rules(input)?))
    }

    pub(crate) fn run_fix_rules(&self, input: FixInput) -> Result<Value, McpError> {
        if input.write && input.path.is_none() {
            return Err(invalid(
                "`write: true` is only valid with a file `path` input",
            ));
        }
        let (source, label) = self.load_source(input.yaml.as_deref(), input.path.as_deref())?;

        let cfg = self.lint_config();
        let warnings = lint_yaml_str_with_config(&source, cfg);

        // The lint-rule filter (empty = every rule).
        let allow = |w: &LintWarning| {
            input.lint_rules.is_empty() || input.lint_rules.contains(&w.rule.to_string())
        };

        // Unsafe fixes are never auto-applied; count them for reporting.
        let skipped_unsafe = warnings
            .iter()
            .filter(|w| {
                allow(w)
                    && w.fix
                        .as_ref()
                        .is_some_and(|f| f.disposition == FixDisposition::Unsafe)
            })
            .count();

        let fixable: Vec<&LintWarning> = warnings
            .iter()
            .filter(|w| allow(w) && w.fix.is_some())
            .collect();

        let outcome = apply_fixes_to_source(&source, &fixable);
        let changed = outcome.fixed_source != source;

        let mut written = false;
        if input.write && changed {
            // `write` requires a path, validated above; resolve and persist.
            let path = resolve_path(
                input.path.as_deref().expect("path required for write"),
                self.root(),
            );
            std::fs::write(&path, &outcome.fixed_source)
                .map_err(|e| invalid(format!("cannot write '{}': {e}", path.display())))?;
            written = true;
        }

        Ok(json!({
            "ok": true,
            "source": label,
            "applied": outcome.applied,
            "failed": outcome.failed,
            "skipped_unsafe": skipped_unsafe,
            "changed": changed,
            "written": written,
            "fixed_yaml": outcome.fixed_source,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::handler;

    #[test]
    fn fix_rules_applies_safe_fix() {
        let yaml = "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler()
            .run_fix_rules(FixInput {
                yaml: Some(yaml.to_string()),
                path: None,
                lint_rules: vec![],
                write: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert!(v["applied"].as_u64().unwrap() >= 1);
        assert_eq!(v["skipped_unsafe"], 0);
        assert_eq!(v["written"], false);
        let fixed = v["fixed_yaml"].as_str().unwrap();
        assert!(fixed.contains("status: test"));
        assert!(!fixed.contains("Status: test"));
    }

    #[test]
    fn fix_rules_lint_rule_filter() {
        // Restrict to a lint rule that does not fire here, so nothing applies.
        let yaml = "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler()
            .run_fix_rules(FixInput {
                yaml: Some(yaml.to_string()),
                path: None,
                lint_rules: vec!["duplicate_tags".to_string()],
                write: false,
            })
            .unwrap();
        assert_eq!(v["applied"], 0);
        assert_eq!(v["changed"], false);
    }

    #[test]
    fn fix_rules_write_without_path_is_error() {
        let err = handler()
            .run_fix_rules(FixInput {
                yaml: Some("title: T\nStatus: test\n".to_string()),
                path: None,
                lint_rules: vec![],
                write: true,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("write"));
    }

    #[test]
    fn fix_rules_write_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yml");
        std::fs::write(
            &path,
            "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
        )
        .unwrap();

        let v = handler()
            .run_fix_rules(FixInput {
                yaml: None,
                path: Some(path.display().to_string()),
                lint_rules: vec![],
                write: true,
            })
            .unwrap();
        assert_eq!(v["written"], true);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("status: test"));
    }

    #[test]
    fn golden_fix_rules() {
        let yaml = "title: T\nStatus: test\ntags:\n  - attack.execution\n  - attack.execution\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler()
            .run_fix_rules(FixInput {
                yaml: Some(yaml.to_string()),
                path: None,
                lint_rules: vec![],
                write: false,
            })
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("fix_rules", v);
        });
    }
}
