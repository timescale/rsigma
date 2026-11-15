//! Helpers shared across the per-tool modules.
//!
//! This holds the JSON result/error shaping, the lint-warning projection, the
//! match-detail parser, backend construction, the [`SourceInput`] type used by
//! more than one tool, and the collection / pipeline / event / source loaders
//! on [`RsigmaMcp`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rmcp::{
    ErrorData as McpError,
    model::{CallToolResult, ContentBlock},
};
use rsigma_convert::Backend;
use rsigma_eval::{MatchDetailLevel, Pipeline, parse_pipeline_file, resolve_builtin_pipeline};
use rsigma_parser::ruleset::{ResolveOptions, RulesetError, RulesetSpec, resolve_ruleset};
use rsigma_parser::{
    CollectionDiagnostic, LintWarning, SigmaCollection, parse_sigma_directory, parse_sigma_file,
    parse_sigma_yaml,
};
use serde_json::{Value, json};

use crate::input::{ensure_no_symlinks, resolve_confined_path};

/// Why a named ruleset could not be resolved.
pub(crate) enum RulesetFailure {
    /// The name, a path, or the spec is wrong.
    Request(McpError),
    /// The rules themselves do not resolve: an unresolved correlation
    /// reference, a duplicate id, or an overlay that fails or matches nothing.
    Content(String),
}

use super::RsigmaMcp;

/// The messages of a run of collection diagnostics, in order.
pub(crate) fn diagnostic_messages<'a>(
    diagnostics: impl Iterator<Item = &'a CollectionDiagnostic>,
) -> Vec<String> {
    diagnostics.map(ToString::to_string).collect()
}

/// Input that accepts inline YAML xor a file path.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SourceInput {
    /// Inline Sigma YAML (single or multi-document). Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma YAML file (or directory, where the tool supports it).
    /// Mutually exclusive with `yaml`. Resolved against `--rules-dir` when
    /// relative, and must stay inside it when one is configured.
    #[serde(default)]
    pub path: Option<String>,
}

// =============================================================================
// JSON shaping helpers
// =============================================================================

/// Wrap a serializable value as a successful tool result carrying pretty JSON text.
pub(crate) fn json_result(value: &Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
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

/// Canonical names of the natively supported conversion targets, for error
/// messages and the sigma-cli install hint.
pub(crate) const NATIVE_TARGETS: &[&str] = &["postgres", "lynxdb", "fibratus"];

/// Return the native backend for `target`, or `None` when rsigma has no native
/// backend for it (the delegation dispatch point). Test-only backends are
/// intentionally excluded.
pub(crate) fn try_native_backend(
    target: &str,
    options: &HashMap<String, String>,
) -> Option<Box<dyn Backend>> {
    match target {
        "postgres" | "postgresql" | "pg" => Some(Box::new(
            rsigma_convert::backends::postgres::PostgresBackend::from_options(options),
        )),
        "lynxdb" => Some(Box::new(
            rsigma_convert::backends::lynxdb::LynxDbBackend::new(),
        )),
        "fibratus" => Some(Box::new(
            rsigma_convert::backends::fibratus::FibratusBackend::from_options(options),
        )),
        _ => None,
    }
}

/// Construct a conversion backend by target name, returning a structured error
/// for unknown targets.
pub(crate) fn get_backend(
    target: &str,
    options: &HashMap<String, String>,
) -> Result<Box<dyn Backend>, McpError> {
    try_native_backend(target, options).ok_or_else(|| {
        invalid(format!(
            "unknown target '{target}'; available: {}",
            NATIVE_TARGETS.join(", ")
        ))
    })
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

    /// Load a `SigmaCollection` from inline YAML, a file, a directory, or a
    /// named ruleset, together with any pipelines the ruleset declares.
    pub(crate) fn load_collection(
        &self,
        yaml: Option<&str>,
        path: Option<&str>,
        ruleset: Option<&str>,
    ) -> Result<(SigmaCollection, Vec<String>), McpError> {
        let selected = usize::from(yaml.is_some())
            + usize::from(path.is_some())
            + usize::from(ruleset.is_some());
        if selected != 1 {
            return Err(invalid(
                "provide exactly one of `yaml`, `path`, or `ruleset`",
            ));
        }
        match (yaml, path, ruleset) {
            (Some(text), None, None) => parse_sigma_yaml(text)
                .map(|collection| (collection, Vec::new()))
                .map_err(|e| invalid(format!("parse error: {e}"))),
            (None, Some(p), None) => {
                let resolved = resolve_confined_path(p, self.root())?;
                let result = if resolved.is_dir() {
                    ensure_no_symlinks(&resolved, self.root())?;
                    parse_sigma_directory(&resolved)
                } else {
                    parse_sigma_file(&resolved)
                };
                result
                    .map(|collection| (collection, Vec::new()))
                    .map_err(|e| invalid(format!("cannot load '{}': {e}", resolved.display())))
            }
            (None, None, Some(name)) => self.resolve_ruleset(name),
            _ => unreachable!("exactly one input was selected"),
        }
    }

    /// Load a collection from inline YAML xor a path, for tools that do not
    /// accept a ruleset.
    pub(crate) fn load_collection_only(
        &self,
        yaml: Option<&str>,
        path: Option<&str>,
    ) -> Result<SigmaCollection, McpError> {
        match (yaml, path) {
            (Some(_), Some(_)) => Err(invalid("provide either `yaml` or `path`, not both")),
            (None, None) => Err(invalid("one of `yaml` or `path` is required")),
            _ => self
                .load_collection(yaml, path, None)
                .map(|(collection, _)| collection),
        }
    }

    /// Resolve a named ruleset from the server's configuration, confined to
    /// `--rules-dir` when one is set.
    pub(crate) fn resolve_ruleset(
        &self,
        name: &str,
    ) -> Result<(SigmaCollection, Vec<String>), McpError> {
        self.resolve_ruleset_classified(name)
            .map_err(|failure| match failure {
                RulesetFailure::Request(error) => error,
                RulesetFailure::Content(message) => invalid(message),
            })
    }

    /// [`Self::resolve_ruleset`], keeping failures in the rules apart from
    /// failures in the request or the server configuration.
    pub(crate) fn resolve_ruleset_classified(
        &self,
        name: &str,
    ) -> Result<(SigmaCollection, Vec<String>), RulesetFailure> {
        let Some(spec) = self.rulesets.get(name) else {
            let defined: Vec<&str> = self.rulesets.keys().map(String::as_str).collect();
            let message = if defined.is_empty() {
                format!("unknown ruleset '{name}'; no rulesets are defined")
            } else {
                format!(
                    "unknown ruleset '{name}'; defined rulesets: {}",
                    defined.join(", ")
                )
            };
            return Err(RulesetFailure::Request(invalid(message)));
        };
        let confined = self.confine_spec(spec).map_err(RulesetFailure::Request)?;
        let options = ResolveOptions {
            confine_to: self.root().map(Path::to_path_buf),
        };
        let pipelines = confined.pipelines.clone();
        resolve_ruleset(name, &confined, &options)
            .map(|resolved| (resolved.collection, pipelines))
            .map_err(|error| {
                let content = matches!(
                    error,
                    RulesetError::Dependency(_)
                        | RulesetError::Duplicate(_)
                        | RulesetError::Overlay(_)
                        | RulesetError::StaleOverlay(_)
                );
                let message = error.to_string();
                let message = if message.starts_with(&format!("ruleset '{name}'")) {
                    message
                } else {
                    format!("ruleset '{name}': {message}")
                };
                if content {
                    RulesetFailure::Content(message)
                } else {
                    RulesetFailure::Request(invalid(message))
                }
            })
    }

    /// Check every source, overlay, and pipeline file path against the
    /// configured root before the resolver walks it. Relative paths in
    /// `rsigma.yaml` resolve against the working directory, as they do on the
    /// CLI, not against `--rules-dir`.
    fn confine_spec(&self, spec: &RulesetSpec) -> Result<RulesetSpec, McpError> {
        let Some(root) = self.root() else {
            return Ok(spec.clone());
        };
        let confine = |path: &Path| -> Result<PathBuf, McpError> {
            let absolute = std::path::absolute(path).map_err(|error| {
                invalid(format!("cannot resolve '{}': {error}", path.display()))
            })?;
            resolve_confined_path(&absolute.to_string_lossy(), Some(root))
        };
        let mut confined = spec.clone();
        for source in &mut confined.sources {
            let resolved = confine(source)?;
            if resolved.is_dir() {
                ensure_no_symlinks(&resolved, Some(root))?;
            }
            *source = resolved;
        }
        for overlay in &mut confined.overlays {
            if let Some(file) = &overlay.file {
                overlay.file = Some(confine(file)?);
            }
            if let Some(dir) = &overlay.dir {
                let resolved = confine(dir)?;
                ensure_no_symlinks(&resolved, Some(root))?;
                overlay.dir = Some(resolved);
            }
        }
        for pipeline in &mut confined.pipelines {
            if resolve_builtin_pipeline(pipeline).is_none() {
                *pipeline = confine(Path::new(pipeline.as_str()))?
                    .to_string_lossy()
                    .into_owned();
            }
        }
        Ok(confined)
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
        let path = resolve_confined_path(spec, self.root())?;
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
                let path = resolve_confined_path(p, self.root())?;
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
