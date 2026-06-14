//! Helpers shared across the per-tool modules.
//!
//! This holds the JSON result/error shaping, the lint-warning projection, the
//! match-detail parser, backend construction, the [`SourceInput`] type used by
//! more than one tool, and the collection / pipeline / event / source loaders
//! on [`RsigmaMcp`].

use std::collections::HashMap;

use rmcp::{
    ErrorData as McpError,
    model::{CallToolResult, Content},
};
use rsigma_convert::Backend;
use rsigma_eval::{MatchDetailLevel, Pipeline, parse_pipeline_file, resolve_builtin_pipeline};
use rsigma_parser::{
    LintWarning, SigmaCollection, parse_sigma_directory, parse_sigma_file, parse_sigma_yaml,
};
use serde_json::{Value, json};

use crate::input::resolve_path;

use super::RsigmaMcp;

/// Input that accepts inline YAML xor a file path.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SourceInput {
    /// Inline Sigma YAML (single or multi-document). Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma YAML file (or directory, where the tool supports it).
    /// Mutually exclusive with `yaml`. Resolved against `--rules-dir` when relative.
    #[serde(default)]
    pub path: Option<String>,
}

// =============================================================================
// JSON shaping helpers
// =============================================================================

/// Wrap a serializable value as a successful tool result carrying pretty JSON text.
pub(crate) fn json_result(value: &Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![Content::text(text)])
}

/// Shorthand for an invalid-params MCP error.
pub(crate) fn invalid(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}

/// Serialize a value to JSON, falling back to null on the (unexpected) error.
pub(crate) fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// Project a `LintWarning` into the agent-facing JSON shape (snake_case rule id,
/// 1-indexed line, fixability).
pub(crate) fn warning_json(w: &LintWarning) -> Value {
    json!({
        "rule": w.rule.to_string(),
        "severity": w.severity.to_string(),
        "message": w.message,
        "path": w.path,
        "line": w.span.map(|s| s.start_line + 1),
        "fixable": w.fix.is_some(),
        "fix_title": w.fix.as_ref().map(|f| f.title.clone()),
    })
}

/// Parse the optional match-detail level string.
pub(crate) fn parse_match_detail(level: Option<&str>) -> Result<MatchDetailLevel, McpError> {
    match level {
        None => Ok(MatchDetailLevel::Off),
        Some(s) => s.parse::<MatchDetailLevel>().map_err(|_| {
            invalid(format!(
                "invalid match_detail '{s}'; expected off, summary, or full"
            ))
        }),
    }
}

/// Construct a conversion backend by target name, returning a structured error
/// for unknown targets. Test-only backends are intentionally excluded.
pub(crate) fn get_backend(
    target: &str,
    options: &HashMap<String, String>,
) -> Result<Box<dyn Backend>, McpError> {
    match target {
        "postgres" | "postgresql" | "pg" => Ok(Box::new(
            rsigma_convert::backends::postgres::PostgresBackend::from_options(options),
        )),
        "lynxdb" => Ok(Box::new(
            rsigma_convert::backends::lynxdb::LynxDbBackend::new(),
        )),
        "fibratus" => Ok(Box::new(
            rsigma_convert::backends::fibratus::FibratusBackend::from_options(options),
        )),
        other => Err(invalid(format!(
            "unknown target '{other}'; available: postgres, lynxdb, fibratus"
        ))),
    }
}

// =============================================================================
// Internal helpers (collection / pipeline / event / source loading)
// =============================================================================

impl RsigmaMcp {
    /// Resolve a tool's `yaml` xor `path` input into a source string plus a label.
    pub(crate) fn load_source(
        &self,
        yaml: Option<&str>,
        path: Option<&str>,
    ) -> Result<(String, String), McpError> {
        crate::input::load_source(yaml, path, self.root())
    }

    /// Load a `SigmaCollection` from inline YAML, a file, or a directory.
    pub(crate) fn load_collection(
        &self,
        yaml: Option<&str>,
        path: Option<&str>,
    ) -> Result<SigmaCollection, McpError> {
        match (yaml, path) {
            (Some(_), Some(_)) => Err(invalid("provide either `yaml` or `path`, not both")),
            (None, None) => Err(invalid("one of `yaml` or `path` is required")),
            (Some(text), None) => {
                parse_sigma_yaml(text).map_err(|e| invalid(format!("parse error: {e}")))
            }
            (None, Some(p)) => {
                let resolved = resolve_path(p, self.root());
                let result = if resolved.is_dir() {
                    parse_sigma_directory(&resolved)
                } else {
                    parse_sigma_file(&resolved)
                };
                result.map_err(|e| invalid(format!("cannot load '{}': {e}", resolved.display())))
            }
        }
    }

    /// Load and sort a list of pipelines (builtin names or file paths).
    pub(crate) fn load_pipelines(&self, specs: &[String]) -> Result<Vec<Pipeline>, McpError> {
        let mut pipelines = Vec::with_capacity(specs.len());
        for spec in specs {
            pipelines.push(self.load_one_pipeline(spec)?);
        }
        pipelines.sort_by_key(|p| p.priority);
        Ok(pipelines)
    }

    /// Load a single pipeline from a builtin name or a file path.
    pub(crate) fn load_one_pipeline(&self, spec: &str) -> Result<Pipeline, McpError> {
        if let Some(result) = resolve_builtin_pipeline(spec) {
            return result.map_err(|e| invalid(format!("builtin pipeline '{spec}': {e}")));
        }
        let path = resolve_path(spec, self.root());
        parse_pipeline_file(&path)
            .map_err(|e| invalid(format!("pipeline '{}': {e}", path.display())))
    }

    /// Load events from an inline JSON array or an NDJSON file path.
    pub(crate) fn load_events(
        &self,
        events: Option<Vec<Value>>,
        events_path: Option<&str>,
    ) -> Result<Vec<Value>, McpError> {
        match (events, events_path) {
            (Some(_), Some(_)) => Err(invalid(
                "provide either `events` or `events_path`, not both",
            )),
            (None, None) => Err(invalid("one of `events` or `events_path` is required")),
            (Some(list), None) => Ok(list),
            (None, Some(p)) => {
                let path = resolve_path(p, self.root());
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| invalid(format!("cannot read '{}': {e}", path.display())))?;
                let mut out = Vec::new();
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let value: Value = serde_json::from_str(line)
                        .map_err(|e| invalid(format!("invalid JSON on line {}: {e}", i + 1)))?;
                    out.push(value);
                }
                Ok(out)
            }
        }
    }
}
