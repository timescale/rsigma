//! The `convert_rules` tool: convert Sigma rules to backend-native queries.
//!
//! Dispatch is native-first: the three native backends convert in-process via
//! [`convert_collection`]. Any other target is delegated to an external
//! [sigma-cli](https://github.com/SigmaHQ/sigma-cli) subprocess, but only when
//! the server was started with `--allow-sigma-cli`; the default posture stays
//! pure and in-process. The delegated path is hardened: `path` and file-based
//! `pipelines` inputs are confined to `--rules-dir` when one is configured
//! (fail closed), inline `yaml` is staged to a temporary file, the subprocess
//! is killed on timeout, and concurrent delegations are bounded.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_convert::convert_collection;
use rsigma_convert::sigma_cli::{
    DelegateError, SigmaCli, build_convert_args, classify_output, install_hint,
};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{NATIVE_TARGETS, get_backend, invalid, json_result, try_native_backend};
use crate::input::resolve_path;

/// How long a delegated sigma-cli invocation may run before the subprocess is
/// killed. pySigma cold-start alone can take seconds; a plugin-heavy convert
/// over a rule directory can take tens of seconds.
pub(crate) const DELEGATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Input for `convert_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ConvertInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Path to a Sigma file or directory. Mutually exclusive with `yaml`.
    #[serde(default)]
    pub path: Option<String>,
    /// Backend target: `postgres` (aliases `postgresql`, `pg`), `lynxdb`, or
    /// `fibratus` convert natively; any other target is delegated to an
    /// installed sigma-cli when the server runs with `--allow-sigma-cli`.
    pub target: String,
    /// Backend-specific output format. Defaults to `default`.
    #[serde(default)]
    pub format: Option<String>,
    /// Processing pipelines (builtin names or file paths).
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Backend options as key=value pairs (e.g. `table` -> `events`).
    #[serde(default)]
    pub options: HashMap<String, String>,
    /// Report unconvertible rules as warnings instead of failing the call.
    #[serde(default)]
    pub skip_unsupported: bool,
}

#[tool_router(router = convert_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Convert Sigma rules to backend-native queries.
    #[tool(
        description = "Convert Sigma rules to backend-native queries. `target` is one of postgres/lynxdb/fibratus (native); when the server runs with --allow-sigma-cli, any other target is delegated to an installed sigma-cli, reaching the full pySigma backend set. Accepts inline `yaml` or a file/directory `path`, optional `pipelines`, `format`, backend `options`, and `skip_unsupported`."
    )]
    async fn convert_rules(
        &self,
        Parameters(input): Parameters<ConvertInput>,
    ) -> Result<CallToolResult, McpError> {
        if try_native_backend(&input.target, &input.options).is_some() {
            return Ok(json_result(&self.run_convert_rules(input)?));
        }
        if self.allow_sigma_cli() {
            return Ok(json_result(&self.run_convert_rules_delegated(input).await?));
        }
        Err(invalid(format!(
            "unknown target '{}'; available: {}. Additional targets are reachable by \
             delegating to an installed sigma-cli; start the server with --allow-sigma-cli \
             (or set mcp.allow_sigma_cli) to enable delegation.",
            input.target,
            NATIVE_TARGETS.join(", ")
        )))
    }

    pub(crate) fn run_convert_rules(&self, input: ConvertInput) -> Result<Value, McpError> {
        let collection = self.load_collection(input.yaml.as_deref(), input.path.as_deref())?;
        let pipelines = self.load_pipelines(&input.pipelines)?;
        let backend = get_backend(&input.target, &input.options)?;
        let format = input.format.as_deref().unwrap_or("default");

        if !backend.formats().iter().any(|(f, _)| *f == format) {
            return Err(invalid(format!(
                "unknown format '{format}' for backend '{}'; available: {}",
                input.target,
                backend
                    .formats()
                    .iter()
                    .map(|(f, _)| *f)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        Ok(
            match convert_collection(backend.as_ref(), &collection, &pipelines, format) {
                Ok(output) => {
                    let queries: Vec<Value> = output
                        .queries
                        .iter()
                        .flat_map(|r| {
                            r.queries.iter().map(move |q| {
                            json!({ "rule_title": r.rule_title, "rule_id": r.rule_id, "query": q })
                        })
                        })
                        .collect();
                    let errors: Vec<Value> = output
                        .errors
                        .iter()
                        .map(|(title, e)| json!({ "rule_title": title, "error": e.to_string() }))
                        .collect();
                    let warnings: Vec<Value> = output
                        .warnings()
                        .map(|(title, w)| json!({ "rule_title": title, "warning": w }))
                        .collect();
                    let ok = errors.is_empty() || input.skip_unsupported;
                    json!({
                        "ok": ok,
                        "target": input.target,
                        "format": format,
                        "queries": queries,
                        "errors": errors,
                        "warnings": warnings,
                    })
                }
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            },
        )
    }

    /// Delegate a conversion to the configured sigma-cli (the production entry
    /// point: environment discovery, 60s timeout).
    pub(crate) async fn run_convert_rules_delegated(
        &self,
        input: ConvertInput,
    ) -> Result<Value, McpError> {
        let cli = SigmaCli::configured();
        self.delegate_convert(&cli, input, DELEGATE_TIMEOUT).await
    }

    /// Delegate a conversion to `cli` with an explicit timeout. Split from
    /// [`Self::run_convert_rules_delegated`] so tests can stub the executable
    /// and shorten the timeout without touching process-global environment.
    pub(crate) async fn delegate_convert(
        &self,
        cli: &SigmaCli,
        input: ConvertInput,
        timeout: Duration,
    ) -> Result<Value, McpError> {
        // Bound concurrent subprocesses across all sessions. The semaphore is
        // never closed, so acquire only fails if it were; treat that as a bug.
        let _permit = self
            .delegate_permits()
            .acquire()
            .await
            .expect("delegation semaphore is never closed");

        // Stage the rule input: inline YAML goes to a temp file owned for the
        // duration of the call; a path is confined to --rules-dir when set.
        let mut _tempdir: Option<tempfile::TempDir> = None;
        let rule_path = match (input.yaml.as_deref(), input.path.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(invalid("provide either `yaml` or `path`, not both"));
            }
            (None, None) => return Err(invalid("one of `yaml` or `path` is required")),
            (Some(yaml), None) => {
                let dir = tempfile::TempDir::new()
                    .map_err(|e| invalid(format!("cannot create temp dir: {e}")))?;
                let path = dir.path().join("rules.yml");
                std::fs::write(&path, yaml)
                    .map_err(|e| invalid(format!("cannot stage inline yaml: {e}")))?;
                _tempdir = Some(dir);
                path
            }
            (None, Some(p)) => self.delegated_input_path(p)?,
        };

        // Pipelines: an existing file is confined like `path`; anything else
        // is passed through verbatim as a sigma-cli pipeline name. rsigma
        // builtin names (ecs_windows, sysmon) are not translated.
        let mut pipeline_paths = Vec::with_capacity(input.pipelines.len());
        for spec in &input.pipelines {
            if resolve_path(spec, self.root()).is_file() {
                pipeline_paths.push(self.delegated_input_path(spec)?);
            } else {
                pipeline_paths.push(PathBuf::from(spec));
            }
        }

        // Sorted for deterministic argv (HashMap iteration order is random).
        let mut options: Vec<String> = input
            .options
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        options.sort();

        let format = input.format.as_deref().unwrap_or("default");
        let argv = build_convert_args(
            &input.target,
            format,
            &pipeline_paths,
            false,
            input.skip_unsupported,
            &options,
            std::slice::from_ref(&rule_path),
        );

        // kill_on_drop ensures the timeout branch (which drops the output
        // future) reaps the subprocess instead of leaking it.
        let mut command = tokio::process::Command::new(cli.program());
        command
            .args(&argv)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);

        let output = match tokio::time::timeout(timeout, command.output()).await {
            Err(_) => {
                return Ok(json!({
                    "ok": false,
                    "error": format!(
                        "sigma-cli ('{}') timed out after {}s; the subprocess was killed",
                        cli.program().display(),
                        timeout.as_secs()
                    ),
                }));
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json!({
                    "ok": false,
                    "error": install_hint(
                        &input.target,
                        cli.program(),
                        cli.is_override(),
                        NATIVE_TARGETS,
                    ),
                }));
            }
            Ok(Err(e)) => {
                return Ok(json!({
                    "ok": false,
                    "error": format!(
                        "failed to launch sigma-cli ('{}'): {e}",
                        cli.program().display()
                    ),
                }));
            }
            Ok(Ok(output)) => output,
        };

        Ok(match classify_output(&output) {
            Ok(conversion) => {
                let queries: Vec<Value> = conversion
                    .queries
                    .iter()
                    .map(|q| json!({ "query": q }))
                    .collect();
                json!({
                    "ok": true,
                    "target": input.target,
                    "format": format,
                    "engine": "sigma-cli",
                    "queries": queries,
                    // Verbatim stdout: the faithful copy for multi-line output
                    // formats that the per-line `queries` split would mangle.
                    "raw": conversion.raw,
                    // sigma-cli stderr on a zero exit (skipped-rule notes,
                    // deprecation warnings).
                    "warnings": conversion.stderr,
                })
            }
            Err(DelegateError::NonZero { code, stderr, .. }) => json!({
                "ok": false,
                "error": format!(
                    "sigma-cli exited with status {}",
                    code.map_or_else(|| "unknown".to_string(), |c| c.to_string())
                ),
                "stderr": stderr,
            }),
            // classify_output never produces NotInstalled (spawn errors are
            // handled above), but keep the match exhaustive and safe.
            Err(DelegateError::NotInstalled { .. }) => json!({
                "ok": false,
                "error": install_hint(
                    &input.target,
                    cli.program(),
                    cli.is_override(),
                    NATIVE_TARGETS,
                ),
            }),
        })
    }

    /// Resolve a delegated `path`/pipeline input, confining it to the
    /// configured `--rules-dir` when one is set (fail closed, symlink-safe:
    /// both sides are canonicalized before the containment check). With no
    /// root configured the path passes through unvalidated, consistent with
    /// how the in-process tools read paths in that configuration.
    fn delegated_input_path(&self, path: &str) -> Result<PathBuf, McpError> {
        let resolved = resolve_path(path, self.root());
        let Some(root) = self.root() else {
            return Ok(resolved);
        };
        let canonical_root = root.canonicalize().map_err(|e| {
            invalid(format!(
                "cannot resolve rules dir '{}': {e}",
                root.display()
            ))
        })?;
        let canonical = resolved
            .canonicalize()
            .map_err(|e| invalid(format!("cannot read '{}': {e}", resolved.display())))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(invalid(format!(
                "path '{path}' escapes the configured --rules-dir; delegated conversions \
                 may only reference files under it"
            )));
        }
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{
        GOLDEN_RULE, VALID_RULE, block_on, delegating_handler, fake_sigma, handler,
    };

    fn convert_input(target: &str) -> ConvertInput {
        ConvertInput {
            yaml: Some(VALID_RULE.to_string()),
            path: None,
            target: target.to_string(),
            format: None,
            pipelines: vec![],
            options: HashMap::new(),
            skip_unsupported: false,
        }
    }

    #[test]
    fn convert_rules_postgres_and_unknown_target() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert!(!v["queries"].as_array().unwrap().is_empty());

        let err = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                target: "nope".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("unknown target"));
    }

    #[test]
    fn golden_convert_rules_postgres() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("convert_rules_postgres", v);
        });
    }

    #[test]
    fn delegation_off_unknown_target_error_mentions_allow_flag() {
        // The regression guard for the default posture: an unknown target is
        // still an invalid-params error, now carrying the enablement hint.
        let err =
            block_on(handler().convert_rules(Parameters(convert_input("splunk")))).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("unknown target 'splunk'"));
        assert!(msg.contains("--allow-sigma-cli"));
    }

    /// Safety-net timeout for tests that expect the fake to run to
    /// completion: generous because the first execution of a fresh script can
    /// stall for seconds on loaded CI runners (Windows Defender scans new
    /// executables) and the spawn happens synchronously on the future's first
    /// poll, inside the timed section.
    const TEST_TIMEOUT: Duration = Duration::from_secs(60);

    #[test]
    fn delegation_not_installed_returns_install_hint() {
        let cli = SigmaCli::from_program("/nonexistent/rsigma-test-sigma-cli", true);
        let v = block_on(delegating_handler(None).delegate_convert(
            &cli,
            convert_input("splunk"),
            TEST_TIMEOUT,
        ))
        .unwrap();
        assert_eq!(v["ok"], false);
        let error = v["error"].as_str().unwrap();
        assert!(error.contains("No native rsigma backend for target 'splunk'"));
        assert!(error.contains("RSIGMA_SIGMA_CLI"));
    }

    #[test]
    fn delegation_success_envelope_has_queries_raw_and_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_sigma(dir.path(), "index=main whoami", "note: skipped one", 0, 0);
        let cli = SigmaCli::from_program(&program, true);
        let v = block_on(delegating_handler(None).delegate_convert(
            &cli,
            convert_input("splunk"),
            TEST_TIMEOUT,
        ))
        .unwrap();
        assert_eq!(v["ok"], true, "envelope: {v}");
        assert_eq!(v["engine"], "sigma-cli");
        assert_eq!(v["target"], "splunk");
        assert_eq!(v["format"], "default");
        let queries = v["queries"].as_array().unwrap();
        assert_eq!(queries.len(), 1);
        assert!(
            queries[0]["query"]
                .as_str()
                .unwrap()
                .contains("index=main whoami")
        );
        assert!(v["raw"].as_str().unwrap().contains("index=main whoami"));
        assert!(v["warnings"].as_str().unwrap().contains("skipped one"));
    }

    #[test]
    fn delegation_nonzero_exit_maps_to_error_with_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_sigma(dir.path(), "", "Error: bad pipeline", 0, 2);
        let cli = SigmaCli::from_program(&program, true);
        let v = block_on(delegating_handler(None).delegate_convert(
            &cli,
            convert_input("splunk"),
            TEST_TIMEOUT,
        ))
        .unwrap();
        assert_eq!(v["ok"], false, "envelope: {v}");
        assert!(
            v["error"].as_str().unwrap().contains("exited with status"),
            "envelope: {v}"
        );
        assert!(v["stderr"].as_str().unwrap().contains("bad pipeline"));
    }

    #[test]
    fn delegation_timeout_kills_subprocess() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_sigma(dir.path(), "", "", 300, 0);
        let cli = SigmaCli::from_program(&program, true);
        let started = std::time::Instant::now();
        let v = block_on(delegating_handler(None).delegate_convert(
            &cli,
            convert_input("splunk"),
            Duration::from_millis(300),
        ))
        .unwrap();
        assert_eq!(v["ok"], false, "envelope: {v}");
        assert!(
            v["error"].as_str().unwrap().contains("timed out"),
            "envelope: {v}"
        );
        // The call returns at the timeout, not after the fake's 300s sleep,
        // which also demonstrates the child did not run to completion. The
        // bound is very generous because spawning the fresh script can stall
        // for many seconds on loaded CI runners (Windows Defender scans new
        // executables), but it stays far under the sleep length, so a
        // regression to waiting out the child still fails.
        assert!(started.elapsed() < Duration::from_secs(60));
    }

    #[test]
    fn delegation_refuses_path_escaping_rules_dir() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::with_suffix(".yml").unwrap();
        std::fs::write(outside.path(), VALID_RULE).unwrap();

        let handler = delegating_handler(Some(root.path().to_path_buf()));
        let mut input = convert_input("splunk");
        input.yaml = None;
        input.path = Some(outside.path().to_string_lossy().into_owned());

        let cli = SigmaCli::from_program("/nonexistent/never-spawned", true);
        let err = block_on(handler.delegate_convert(&cli, input, TEST_TIMEOUT)).unwrap_err();
        assert!(format!("{err:?}").contains("escapes the configured --rules-dir"));
    }

    #[test]
    fn delegation_stages_inline_yaml_to_a_temp_rule_file() {
        let dir = tempfile::tempdir().unwrap();
        // The fake echoes fixed output; success proves the staged file path
        // was accepted as the trailing argv entry without error.
        let program = fake_sigma(dir.path(), "q", "", 0, 0);
        let cli = SigmaCli::from_program(&program, true);
        let v = block_on(delegating_handler(None).delegate_convert(
            &cli,
            convert_input("loki"),
            TEST_TIMEOUT,
        ))
        .unwrap();
        assert_eq!(v["ok"], true, "envelope: {v}");
    }
}
