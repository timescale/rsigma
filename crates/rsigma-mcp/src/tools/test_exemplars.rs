//! The `test_exemplars` tool: replay embedded `rsigma.exemplars`.

use std::path::{Path, PathBuf};

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{parse_pipeline, resolve_builtin_pipeline, run_exemplars};
use rsigma_parser::{SigmaCollection, parse_sigma_yaml};
use serde_json::{Value, json};

use crate::input::resolve_confined_path;

use super::RsigmaMcp;
use super::shared::{invalid, json_result, to_value};

/// Input for `test_exemplars`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TestExemplarsInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Sigma file or directory path. Confined to `--rules-dir` when configured.
    #[serde(default)]
    pub path: Option<String>,
    /// Processing pipelines as builtin names or confined file paths.
    #[serde(default)]
    pub pipelines: Vec<String>,
}

#[tool_router(router = test_exemplars_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Replay embedded `rsigma.exemplars` against their host rules.
    #[tool(
        description = "Replay embedded rsigma.exemplars on Sigma detection and correlation rules and return pass/fail results. Provide exactly one of inline `yaml` or a `path` confined to `--rules-dir`. Optional `pipelines` are builtin names or confined YAML files. Shape, identity, and reference problems are configuration errors; a failed assertion is a finding, not a load error."
    )]
    async fn test_exemplars(
        &self,
        Parameters(input): Parameters<TestExemplarsInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_test_exemplars(input)?))
    }

    pub(crate) fn run_test_exemplars(&self, input: TestExemplarsInput) -> Result<Value, McpError> {
        let (collection, source) =
            match self.load_test_collection(input.yaml.as_deref(), input.path.as_deref()) {
                Ok(loaded) => loaded,
                Err(LoadError::Request(error)) => return Err(error),
                Err(LoadError::Content(error)) => {
                    return Ok(json!({ "ok": false, "error": error }));
                }
            };
        let pipelines = match self.load_test_pipelines(&input.pipelines) {
            Ok(pipelines) => pipelines,
            Err(LoadError::Request(error)) => return Err(error),
            Err(LoadError::Content(error)) => {
                return Ok(json!({ "ok": false, "error": error }));
            }
        };

        match run_exemplars(&collection, &pipelines) {
            Ok(mut report) => {
                report.source = source;
                Ok(json!({ "ok": true, "report": to_value(&report) }))
            }
            Err(error) => Ok(json!({ "ok": false, "error": error.to_string() })),
        }
    }

    fn load_test_collection(
        &self,
        yaml: Option<&str>,
        path: Option<&str>,
    ) -> Result<(SigmaCollection, String), LoadError> {
        match (yaml, path) {
            (Some(_), Some(_)) => Err(LoadError::Request(invalid(
                "provide either `yaml` or `path`, not both",
            ))),
            (None, None) => Err(LoadError::Request(invalid(
                "one of `yaml` or `path` is required",
            ))),
            (Some(yaml), None) => {
                let collection = parse_sigma_yaml(yaml)
                    .map_err(|error| LoadError::Content(format!("rule parse error: {error}")))?;
                check_collection(&collection)?;
                Ok((collection, "inline".to_string()))
            }
            (None, Some(path)) => {
                let path = resolve_confined_path(path, self.root()).map_err(LoadError::Request)?;
                let collection = if path.is_dir() {
                    load_rule_directory(&path)?
                } else {
                    let yaml = std::fs::read_to_string(&path).map_err(|error| {
                        LoadError::Request(invalid(format!(
                            "cannot read '{}': {error}",
                            path.display()
                        )))
                    })?;
                    parse_sigma_yaml(&yaml).map_err(|error| {
                        LoadError::Content(format!(
                            "rule parse error in '{}': {error}",
                            path.display()
                        ))
                    })?
                };
                check_collection(&collection)?;
                Ok((collection, path.display().to_string()))
            }
        }
    }

    fn load_test_pipelines(
        &self,
        specs: &[String],
    ) -> Result<Vec<rsigma_eval::Pipeline>, LoadError> {
        let mut pipelines = Vec::with_capacity(specs.len());
        for spec in specs {
            if let Some(result) = resolve_builtin_pipeline(spec) {
                pipelines.push(result.map_err(|error| {
                    LoadError::Content(format!("builtin pipeline '{spec}': {error}"))
                })?);
            } else {
                let path = resolve_confined_path(spec, self.root()).map_err(LoadError::Request)?;
                let yaml = std::fs::read_to_string(&path).map_err(|error| {
                    LoadError::Request(invalid(format!(
                        "cannot read pipeline '{}': {error}",
                        path.display()
                    )))
                })?;
                pipelines.push(parse_pipeline(&yaml).map_err(|error| {
                    LoadError::Content(format!(
                        "pipeline parse error in '{}': {error}",
                        path.display()
                    ))
                })?);
            }
        }
        pipelines.sort_by_key(|pipeline| pipeline.priority);
        Ok(pipelines)
    }
}

enum LoadError {
    Request(McpError),
    Content(String),
}

fn check_collection(collection: &SigmaCollection) -> Result<(), LoadError> {
    if collection.has_errors() {
        return Err(LoadError::Content(format!(
            "rule collection contains parse errors: {:?}",
            collection.errors
        )));
    }
    Ok(())
}

fn load_rule_directory(root: &Path) -> Result<SigmaCollection, LoadError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::<PathBuf>::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            LoadError::Request(invalid(format!(
                "cannot read rule directory '{}': {error}",
                directory.display()
            )))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                LoadError::Request(invalid(format!(
                    "cannot read an entry under '{}': {error}",
                    directory.display()
                )))
            })?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                LoadError::Request(invalid(format!(
                    "cannot inspect '{}': {error}",
                    path.display()
                )))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(LoadError::Request(invalid(format!(
                    "rule directory contains a symlink, which is not allowed: '{}'",
                    path.display()
                ))));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.extension().is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
                })
            {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut collection = SigmaCollection::new();
    for path in files {
        let yaml = std::fs::read_to_string(&path).map_err(|error| {
            LoadError::Request(invalid(format!(
                "cannot read '{}': {error}",
                path.display()
            )))
        })?;
        let parsed = parse_sigma_yaml(&yaml).map_err(|error| {
            LoadError::Content(format!("rule parse error in '{}': {error}", path.display()))
        })?;
        collection.rules.extend(parsed.rules);
        collection.correlations.extend(parsed.correlations);
        collection.filters.extend(parsed.filters);
        collection.errors.extend(parsed.errors);
    }
    Ok(collection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::handler;

    const RULE: &str = r#"
title: Whoami
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event:
              CommandLine: whoami /all
        - expect: no-match
          event:
              CommandLine: hostname
"#;

    #[test]
    fn test_exemplars_returns_report() {
        let value = handler()
            .run_test_exemplars(TestExemplarsInput {
                yaml: Some(RULE.to_string()),
                path: None,
                pipelines: Vec::new(),
            })
            .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["report"]["results"].as_array().unwrap().len(), 2);
        assert!(
            value["report"]["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["passed"] == true)
        );
    }

    #[test]
    fn test_exemplars_requires_yaml_xor_path() {
        let error = handler()
            .run_test_exemplars(TestExemplarsInput {
                yaml: None,
                path: None,
                pipelines: Vec::new(),
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("yaml"));
    }

    #[test]
    fn test_exemplars_rejects_absolute_path_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), RULE).unwrap();
        let server = crate::tools::RsigmaMcp::new(
            Some(root.path().to_path_buf()),
            rsigma_parser::LintConfig::default(),
            false,
        );
        let error = server
            .run_test_exemplars(TestExemplarsInput {
                yaml: None,
                path: Some(outside.path().display().to_string()),
                pipelines: Vec::new(),
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("escapes"));
    }
}
