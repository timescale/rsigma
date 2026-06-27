//! The `RsigmaMcp` handler, its `ServerHandler` implementation, and the
//! per-tool modules.
//!
//! Each MCP tool lives in its own submodule under `tools/`. A tool is a thin
//! `#[tool]` wrapper over a `run_*` helper that returns `serde_json::Value`;
//! the helpers carry the logic and are unit-tested directly. Errors in the
//! *input* (bad params, unreadable file) surface as MCP errors; errors in the
//! *content* (a rule that fails to parse or convert) come back inside a
//! successful result as `{ "ok": false, ... }` so an agent can read and act on
//! them.
//!
//! Per-tool routers are declared with `#[tool_router(router = ...)]` in each
//! submodule and summed together in [`RsigmaMcp::tool_router`]; rmcp's
//! [`ToolRouter`] implements `Add`, so the combined router exposes every tool
//! exactly as a single `#[tool_router]` block would.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{
        AnnotateAble, Implementation, ListResourcesResult, PaginatedRequestParams, RawResource,
        ReadResourceRequestParams, ReadResourceResult, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    service::RequestContext,
    tool_handler,
};
use rsigma_parser::reference::{MITRE_TACTICS, MODIFIERS};
use rsigma_parser::{LintConfig, ads_catalogue, catalogue};
use serde_json::{Value, json};

use shared::to_value;

mod author_ads;
mod convert_rules;
mod evaluate_events;
mod fix_rules;
mod lint_rules;
mod list_backends;
mod list_builtin_pipelines;
mod list_fields;
mod parse_condition;
mod parse_rule;
mod resolve_pipeline;
mod shared;
mod validate_rules;

/// Shared, immutable server state behind the cloneable handler.
struct State {
    /// Default root for relative path-based tool calls (`--rules-dir`).
    root: Option<PathBuf>,
    /// Lint configuration applied by `lint_rules` and `fix_rules`.
    lint_config: LintConfig,
}

/// The rsigma MCP handler. Cloned per request by rmcp; the real state lives
/// behind an `Arc` so cloning is cheap.
#[derive(Clone)]
pub struct RsigmaMcp {
    tool_router: ToolRouter<Self>,
    state: Arc<State>,
}

impl RsigmaMcp {
    /// Build a handler with an optional default root for path-based calls and a
    /// lint configuration.
    pub fn new(root: Option<PathBuf>, lint_config: LintConfig) -> Self {
        Self {
            tool_router: Self::tool_router(),
            state: Arc::new(State { root, lint_config }),
        }
    }

    fn root(&self) -> Option<&Path> {
        self.state.root.as_deref()
    }

    /// The lint configuration applied by `lint_rules` and `fix_rules`.
    fn lint_config(&self) -> &LintConfig {
        &self.state.lint_config
    }

    /// Combine the per-tool routers into the single router rmcp dispatches over.
    ///
    /// Each submodule contributes a `*_router()` built by `#[tool_router]`;
    /// [`ToolRouter`] implements `Add`, so summing them yields a router holding
    /// all 12 tools.
    fn tool_router() -> ToolRouter<Self> {
        Self::parse_rule_router()
            + Self::parse_condition_router()
            + Self::lint_rules_router()
            + Self::validate_rules_router()
            + Self::evaluate_events_router()
            + Self::convert_rules_router()
            + Self::list_backends_router()
            + Self::list_fields_router()
            + Self::resolve_pipeline_router()
            + Self::list_builtin_pipelines_router()
            + Self::fix_rules_router()
            + Self::author_ads_router()
    }
}

impl Default for RsigmaMcp {
    /// A handler with no path root and default lint configuration.
    fn default() -> Self {
        Self::new(None, LintConfig::default())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RsigmaMcp {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` and `Implementation` are `#[non_exhaustive]`, so build
        // from `default()` and override the fields we care about.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();
        info.server_info = Implementation::from_build_env();
        info.server_info.name = "rsigma-mcp".to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.instructions = Some(
            "Sigma detection-rule toolchain: parse, parse_condition, lint, validate, evaluate, \
             convert, fix, list fields, resolve pipelines, and author ADS detection-strategy \
             metadata. Every tool accepts inline content (e.g. `yaml`) or a file `path`. Resources \
             expose the lint catalogue, the ADS section catalogue, and modifier / MITRE reference \
             data."
                .to_string(),
        );
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let resources = vec![
            RawResource::new(RESOURCE_LINT_CATALOGUE, "Lint rule catalogue").no_annotation(),
            RawResource::new(RESOURCE_ADS_SCHEMA, "ADS section catalogue").no_annotation(),
            RawResource::new(RESOURCE_MODIFIERS, "Sigma field modifiers").no_annotation(),
            RawResource::new(RESOURCE_MITRE_TACTICS, "MITRE ATT&CK tactics").no_annotation(),
        ];
        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let value = match request.uri.as_str() {
            RESOURCE_LINT_CATALOGUE => to_value(&catalogue()),
            RESOURCE_ADS_SCHEMA => to_value(&ads_catalogue()),
            RESOURCE_MODIFIERS => reference_pairs_json(MODIFIERS),
            RESOURCE_MITRE_TACTICS => reference_pairs_json(MITRE_TACTICS),
            other => {
                return Err(McpError::resource_not_found(
                    format!("unknown resource '{other}'"),
                    None,
                ));
            }
        };
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text,
            &request.uri,
        )]))
    }
}

const RESOURCE_LINT_CATALOGUE: &str = "rsigma://lint/catalogue";
const RESOURCE_ADS_SCHEMA: &str = "rsigma://ads/schema";
const RESOURCE_MODIFIERS: &str = "rsigma://reference/modifiers";
const RESOURCE_MITRE_TACTICS: &str = "rsigma://reference/mitre-tactics";

/// Render a `(name, description)` reference table as a JSON array of objects.
fn reference_pairs_json(pairs: &[(&str, &str)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(name, description)| json!({ "name": name, "description": description }))
            .collect(),
    )
}

// =============================================================================
// Test-only helpers shared across the per-tool `mod tests` modules
// =============================================================================
//
// Defined at the module root (not inside a `mod tests`) so every per-tool test
// module can reach them as `crate::tools::{handler, src, VALID_RULE,
// GOLDEN_RULE}` without duplicating the bodies.

/// A handler with no path root and default lint configuration.
#[cfg(test)]
pub(crate) fn handler() -> RsigmaMcp {
    RsigmaMcp::new(None, LintConfig::default())
}

/// Wrap inline YAML as a [`shared::SourceInput`].
#[cfg(test)]
pub(crate) fn src(yaml: &str) -> shared::SourceInput {
    shared::SourceInput {
        yaml: Some(yaml.to_string()),
        path: None,
    }
}

/// A minimal valid rule reused across the per-tool tests.
#[cfg(test)]
pub(crate) const VALID_RULE: &str = r#"
title: Whoami Execution
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: test
description: Detects whoami
author: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
"#;

/// A fuller rule used by the golden snapshot tests.
#[cfg(test)]
pub(crate) const GOLDEN_RULE: &str = r#"
title: Whoami Execution
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: test
description: Detects whoami execution
author: rsigma
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_resources_round_trip() {
        // The data behind the MCP reference resources.
        let modifiers = reference_pairs_json(MODIFIERS);
        assert!(
            modifiers
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["name"] == "contains")
        );
        let cat = to_value(&catalogue());
        assert_eq!(cat.as_array().unwrap().len(), 86);
    }

    #[test]
    fn ads_schema_resource_round_trips() {
        // The data behind the rsigma://ads/schema resource: nine ADS sections,
        // each with an id and a carrier field.
        let schema = to_value(&ads_catalogue());
        let entries = schema.as_array().unwrap();
        assert_eq!(entries.len(), 9);
        assert!(entries.iter().any(|e| e["id"] == "validation"));
        let goal = entries.iter().find(|e| e["id"] == "goal").unwrap();
        assert_eq!(goal["carrier"]["field"], "description");
    }
}
