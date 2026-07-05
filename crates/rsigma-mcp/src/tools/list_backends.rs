//! The `list_backends` tool: list conversion backends and their formats.
//!
//! Native backends are always listed with their full format and correlation
//! metadata. When the server runs with `--allow-sigma-cli`, the installed
//! sigma-cli targets are appended (flagged `engine: "sigma-cli"`) so agents
//! can discover the delegated target set; the listing is best-effort and
//! silently absent when sigma-cli is not installed or fails.

use std::collections::HashMap;
use std::time::Duration;

use rmcp::{ErrorData as McpError, model::CallToolResult, tool, tool_router};
use rsigma_convert::sigma_cli::{SigmaCli, classify_output};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::convert_rules::DELEGATE_TIMEOUT;
use super::shared::{NATIVE_TARGETS, get_backend, json_result};

#[tool_router(router = list_backends_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List available conversion backends and their output formats.
    #[tool(
        description = "List available conversion backends (targets) with their output formats and correlation methods. When the server runs with --allow-sigma-cli, installed sigma-cli targets are appended with engine \"sigma-cli\"."
    )]
    async fn list_backends(&self) -> Result<CallToolResult, McpError> {
        let mut value = run_list_backends()?;
        if self.allow_sigma_cli() {
            let cli = SigmaCli::configured();
            if let Some(targets) = self.delegated_targets(&cli, DELEGATE_TIMEOUT).await {
                let backends = value["backends"]
                    .as_array_mut()
                    .expect("run_list_backends always emits a backends array");
                for target in targets {
                    // Native-first: a delegated target shadowed by a native
                    // backend is not reachable via delegation, so do not
                    // advertise it twice.
                    if NATIVE_TARGETS.contains(&target.as_str()) {
                        continue;
                    }
                    backends.push(json!({ "target": target, "engine": "sigma-cli" }));
                }
            }
        }
        Ok(json_result(&value))
    }

    /// Ask `cli` for its installed conversion targets. Best-effort: `None` on
    /// spawn failure, timeout, non-zero exit, or an unparseable listing.
    pub(crate) async fn delegated_targets(
        &self,
        cli: &SigmaCli,
        timeout: Duration,
    ) -> Option<Vec<String>> {
        let _permit = self.delegate_permits().acquire().await.ok()?;
        let mut command = tokio::process::Command::new(cli.program());
        command
            .args(["list", "targets"])
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .ok()?
            .ok()?;
        let conversion = classify_output(&output).ok()?;
        let targets = parse_targets(&conversion.raw);
        (!targets.is_empty()).then_some(targets)
    }
}

pub(crate) fn run_list_backends() -> Result<Value, McpError> {
    let opts = HashMap::new();
    let mut backends = Vec::new();
    for (target, aliases) in [
        ("postgres", &["postgresql", "pg"][..]),
        ("lynxdb", &[][..]),
        ("fibratus", &[][..]),
    ] {
        let backend = get_backend(target, &opts)?;
        backends.push(json!({
            "target": target,
            "engine": "native",
            "aliases": aliases,
            "requires_pipeline": backend.requires_pipeline(),
            "default_format": backend.default_format(),
            "formats": backend.formats().iter().map(|(n, d)| json!({ "name": n, "description": d })).collect::<Vec<_>>(),
            "default_correlation_method": backend.default_correlation_method(),
            "correlation_methods": backend.correlation_methods().iter().map(|(n, d)| json!({ "name": n, "description": d })).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({ "ok": true, "backends": backends }))
}

/// Extract target identifiers from `sigma list targets` output.
///
/// Tolerates both a plain identifier-per-line listing and sigma-cli's table
/// rendering (border lines of `+`/`-`, `|`-delimited cells with the identifier
/// in the first column and an `Identifier` header row).
fn parse_targets(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('+') || line.starts_with('-') {
                return None;
            }
            let cell = match line.strip_prefix('|') {
                Some(rest) => rest.split('|').next().unwrap_or("").trim().to_string(),
                None => line.split_whitespace().next().unwrap_or("").to_string(),
            };
            if cell.is_empty() || cell.eq_ignore_ascii_case("identifier") {
                return None;
            }
            Some(cell)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{block_on, delegating_handler, fake_sigma};

    #[test]
    fn list_backends_includes_postgres() {
        let v = run_list_backends().unwrap();
        let targets: Vec<&str> = v["backends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["target"].as_str().unwrap())
            .collect();
        assert!(targets.contains(&"postgres"));
        assert!(targets.contains(&"fibratus"));
    }

    #[test]
    fn native_backends_are_flagged_native() {
        let v = run_list_backends().unwrap();
        assert!(
            v["backends"]
                .as_array()
                .unwrap()
                .iter()
                .all(|b| b["engine"] == "native")
        );
    }

    #[test]
    fn parse_targets_handles_plain_and_table_listings() {
        assert_eq!(parse_targets("splunk\nloki\n"), vec!["splunk", "loki"]);
        let table = "\
+------------+----------------+
| Identifier | Description    |
+------------+----------------+
| splunk     | Splunk SPL     |
| loki       | Grafana Loki   |
+------------+----------------+
";
        assert_eq!(parse_targets(table), vec!["splunk", "loki"]);
        assert!(parse_targets("").is_empty());
    }

    /// Safety-net timeout: generous because the first execution of a fresh
    /// script can stall for seconds on loaded CI runners.
    const TEST_TIMEOUT: Duration = Duration::from_secs(60);

    #[test]
    fn delegated_targets_lists_from_fake_sigma() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_sigma(dir.path(), "splunk", "", 0, 0);
        let cli = SigmaCli::from_program(&program, true);
        let handler = delegating_handler(None);
        let targets = block_on(handler.delegated_targets(&cli, TEST_TIMEOUT)).unwrap();
        assert_eq!(targets, vec!["splunk"]);
    }

    #[test]
    fn delegated_targets_none_when_not_installed() {
        let cli = SigmaCli::from_program("/nonexistent/rsigma-test-sigma-cli", true);
        let handler = delegating_handler(None);
        assert!(block_on(handler.delegated_targets(&cli, TEST_TIMEOUT)).is_none());
    }
}
