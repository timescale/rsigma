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
use rsigma_parser::{SigmaCollection, emit_correlation_yaml, emit_filter_yaml, emit_rule_yaml};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{NATIVE_TARGETS, get_backend, invalid, json_result, try_native_backend};
use crate::input::{ensure_no_symlinks, resolve_confined_path};

/// How long a delegated sigma-cli invocation may run before the subprocess is
/// killed. pySigma cold-start alone can take seconds; a plugin-heavy convert
/// over a rule directory can take tens of seconds.
pub(crate) const DELEGATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Input for `convert_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ConvertInput {
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
    /// Backend target: `postgres` (aliases `postgresql`, `pg`), `lynxdb`, or
    /// `fibratus` convert natively; any other target is delegated to an
    /// installed sigma-cli when the server runs with `--allow-sigma-cli`.
    pub target: String,
    /// Backend-specific output format. Defaults to `default`.
    #[serde(default)]
    pub format: Option<String>,
    /// Processing pipelines (builtin names or file paths).
    /// A ruleset's own pipelines are not applied; pass them here.
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
        description = "Convert Sigma rules to backend-native queries. `target` is one of postgres/lynxdb/fibratus (native); when the server runs with --allow-sigma-cli, any other target is delegated to an installed sigma-cli, reaching the full pySigma backend set. Provide exactly one of inline `yaml`, a file/directory `path`, or a named `ruleset` from the server's configuration; optional `pipelines`, `format`, backend `options`, and `skip_unsupported`."
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
        let (collection, _) = self.load_collection(
            input.yaml.as_deref(),
            input.path.as_deref(),
            input.ruleset.as_deref(),
        )?;
        // Ruleset pipelines map rules to rsigma's event shape; the backend's
        // pipelines are the subject of this tool, so they are never implied.
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
        let rule_path = match (
            input.yaml.as_deref(),
            input.path.as_deref(),
            input.ruleset.as_deref(),
        ) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
                return Err(invalid(
                    "provide exactly one of `yaml`, `path`, or `ruleset`",
                ));
            }
            (None, None, None) => {
                return Err(invalid(
                    "provide exactly one of `yaml`, `path`, or `ruleset`",
                ));
            }
            (Some(yaml), None, None) => {
                let dir = tempfile::TempDir::new()
                    .map_err(|e| invalid(format!("cannot create temp dir: {e}")))?;
                let path = dir.path().join("rules.yml");
                std::fs::write(&path, yaml)
                    .map_err(|e| invalid(format!("cannot stage inline yaml: {e}")))?;
                _tempdir = Some(dir);
                path
            }
            (None, Some(p), None) => self.delegated_input_path(p)?,
            (None, None, Some(name)) => {
                let (collection, _) = self.resolve_ruleset(name)?;
                let dir = tempfile::TempDir::new()
                    .map_err(|e| invalid(format!("cannot create temp dir: {e}")))?;
                let path = dir.path().join("rules.yml");
                std::fs::write(&path, emit_collection(&collection))
                    .map_err(|e| invalid(format!("cannot stage ruleset '{name}': {e}")))?;
                _tempdir = Some(dir);
                path
            }
        };

        // Pipelines: a bare identifier with no matching file under the root is
        // passed through verbatim as a sigma-cli pipeline name; anything else
        // is a path and is confined like `path`. rsigma builtin names
        // (ecs_windows, sysmon) are not translated.
        let mut pipeline_paths = Vec::with_capacity(input.pipelines.len());
        for spec in &input.pipelines {
            let path = if is_pipeline_name(spec) {
                match self.delegated_input_path(spec) {
                    Ok(path) if path.is_file() => path,
                    _ => PathBuf::from(spec),
                }
            } else {
                self.delegated_input_path(spec)?
            };
            pipeline_paths.push(path);
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
        // With a root, every path in argv is canonical and absolute, so the
        // subprocess runs in an empty directory: a bare pipeline name that
        // pySigma falls back to opening as a file cannot resolve to anything,
        // including a symlink at the root that points out of it.
        let _workdir = match self.root() {
            Some(_) => {
                let dir = tempfile::TempDir::new()
                    .map_err(|e| invalid(format!("cannot create temp dir: {e}")))?;
                command.current_dir(dir.path());
                Some(dir)
            }
            None => None,
        };

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
    /// both sides are canonicalized before the containment check). A
    /// directory is refused when anything under it is a symlink, because
    /// sigma-cli walks the tree itself and would follow links out of the
    /// root. With no root configured the path passes through unvalidated,
    /// consistent with how the in-process tools read paths in that
    /// configuration.
    fn delegated_input_path(&self, path: &str) -> Result<PathBuf, McpError> {
        let resolved = resolve_confined_path(path, self.root())?;
        if resolved.is_dir() {
            ensure_no_symlinks(&resolved, self.root())?;
        }
        Ok(resolved)
    }
}

/// Emit a resolved collection as one multi-document YAML stream.
fn emit_collection(collection: &SigmaCollection) -> String {
    let mut documents = Vec::new();
    for rule in &collection.rules {
        documents.push(emit_rule_yaml(rule));
    }
    for correlation in &collection.correlations {
        documents.push(emit_correlation_yaml(correlation));
    }
    for filter in &collection.filters {
        documents.push(emit_filter_yaml(filter));
    }
    documents.join("---\n")
}

/// Whether a pipeline spec is a bare sigma-cli pipeline name rather than a
/// path. Names cannot contain separators or dots, so they cannot escape the
/// rules root.
fn is_pipeline_name(spec: &str) -> bool {
    !spec.is_empty()
        && spec
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::tools::{
        GOLDEN_RULE, VALID_RULE, block_on, delegating_handler, fake_sigma, handler,
        ruleset_handler, ruleset_spec,
    };

    fn convert_input(target: &str) -> ConvertInput {
        ConvertInput {
            yaml: Some(VALID_RULE.to_string()),
            path: None,
            ruleset: None,
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
                ruleset: None,
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
                ruleset: None,
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
    fn convert_rules_accepts_a_ruleset_and_ignores_its_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "base".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &["ecs_windows"]),
        )]);
        let value = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_convert_rules(ConvertInput {
                yaml: None,
                path: None,
                ruleset: Some("base".to_string()),
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        assert_eq!(value["ok"], true);
        let query = value["queries"][0]["query"].as_str().unwrap();
        assert!(query.contains("\"CommandLine\""), "{query}");
        assert!(!query.contains("process.command_line"), "{query}");
    }

    #[test]
    fn convert_rules_unknown_ruleset_lists_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let rulesets = BTreeMap::from([(
            "base".to_string(),
            ruleset_spec(dir.path(), &["rule.yml"], &[]),
        )]);
        let error = ruleset_handler(Some(dir.path().to_path_buf()), rulesets)
            .run_convert_rules(ConvertInput {
                yaml: None,
                path: None,
                ruleset: Some("nope".to_string()),
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap_err();
        let text = format!("{error:?}");
        assert!(text.contains("unknown ruleset 'nope'"), "{text}");
        assert!(text.contains("base"), "{text}");
    }

    #[test]
    fn golden_convert_rules_postgres() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                ruleset: None,
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
    fn delegation_refuses_pipeline_escaping_rules_dir() {
        let root = tempfile::tempdir().unwrap();
        let handler = delegating_handler(Some(root.path().to_path_buf()));
        let cli = SigmaCli::from_program("/nonexistent/never-spawned", true);

        // Neither an existing nor a missing file outside the root may reach
        // sigma-cli, whose working directory would otherwise resolve it.
        let outside = tempfile::NamedTempFile::with_suffix(".yml").unwrap();
        for spec in [
            outside.path().to_string_lossy().into_owned(),
            "../rsigma-no-such-pipeline.yml".to_string(),
        ] {
            let mut input = convert_input("splunk");
            input.pipelines = vec![spec];
            let err = block_on(handler.delegate_convert(&cli, input, TEST_TIMEOUT)).unwrap_err();
            assert!(format!("{err:?}").contains("escapes the configured --rules-dir"));
        }
    }

    /// A rules directory under the root with `path` set to `rules`.
    fn directory_input(root: &std::path::Path) -> ConvertInput {
        let rules = root.join("rules");
        std::fs::create_dir(&rules).unwrap();
        std::fs::write(rules.join("rule.yml"), VALID_RULE).unwrap();
        let mut input = convert_input("splunk");
        input.yaml = None;
        input.path = Some("rules".into());
        input
    }

    #[cfg(unix)]
    #[test]
    fn delegation_refuses_directory_with_symlink_out_of_rules_dir() {
        let root = tempfile::tempdir().unwrap();
        let input = directory_input(root.path());
        let outside = tempfile::NamedTempFile::with_suffix(".yml").unwrap();
        std::fs::write(outside.path(), VALID_RULE).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("rules/leak.yml")).unwrap();

        // The fake would succeed if spawned, so an error proves it never ran.
        let bin = tempfile::tempdir().unwrap();
        let cli = SigmaCli::from_program(fake_sigma(bin.path(), "q", "", 0, 0), true);
        let handler = delegating_handler(Some(root.path().to_path_buf()));
        let err = block_on(handler.delegate_convert(&cli, input, TEST_TIMEOUT)).unwrap_err();
        assert!(
            format!("{err:?}").contains("directory contains a symlink"),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn delegation_hides_the_rules_dir_from_bare_pipeline_names() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let mut input = directory_input(root.path());
        input.pipelines = vec!["leak".into()];
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("leak")).unwrap();

        // pySigma opens an unknown pipeline name as a file relative to its
        // working directory; the fake reports whether `./leak` is reachable.
        let bin = tempfile::tempdir().unwrap();
        let program = bin.path().join("sigma");
        std::fs::write(
            &program,
            "#!/bin/sh\nif [ -e leak ]; then printf leaked; else printf hidden; fi\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cli = SigmaCli::from_program(&program, true);
        let handler = delegating_handler(Some(root.path().to_path_buf()));
        let v = block_on(handler.delegate_convert(&cli, input, TEST_TIMEOUT)).unwrap();
        assert_eq!(v["raw"], "hidden", "envelope: {v}");
    }

    #[test]
    fn delegation_accepts_a_confined_directory() {
        let root = tempfile::tempdir().unwrap();
        let input = directory_input(root.path());
        let bin = tempfile::tempdir().unwrap();
        let cli = SigmaCli::from_program(fake_sigma(bin.path(), "q", "", 0, 0), true);
        let handler = delegating_handler(Some(root.path().to_path_buf()));
        let v = block_on(handler.delegate_convert(&cli, input, TEST_TIMEOUT)).unwrap();
        assert_eq!(v["ok"], true, "envelope: {v}");
    }

    #[test]
    fn pipeline_names_are_bare_identifiers() {
        assert!(is_pipeline_name("sysmon"));
        assert!(is_pipeline_name("windows-logsources"));
        assert!(is_pipeline_name("ecs_windows"));
        assert!(!is_pipeline_name(""));
        assert!(!is_pipeline_name(".."));
        assert!(!is_pipeline_name("pipeline.yml"));
        assert!(!is_pipeline_name("../pipeline"));
        assert!(!is_pipeline_name("/etc/passwd"));
        assert!(!is_pipeline_name("dir\\pipeline"));
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

    #[test]
    fn convert_rules_rejects_ruleset_and_path() {
        let error = handler()
            .run_convert_rules(ConvertInput {
                path: Some("rule.yml".to_string()),
                ruleset: Some("base".to_string()),
                yaml: None,
                ..convert_input("postgres")
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("exactly one"), "{error:?}");
    }

    #[cfg(unix)]
    #[test]
    fn delegation_stages_the_resolved_ruleset() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rule.yml"), VALID_RULE).unwrap();
        let program = dir.path().join("sigma");
        std::fs::write(
            &program,
            "#!/bin/sh\nfor arg; do last=$arg; done\ncat \"$last\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut spec = ruleset_spec(dir.path(), &["rule.yml"], &[]);
        spec.overlays = vec![rsigma_parser::ruleset::OverlayEntry {
            id: Some("8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a".to_string()),
            set: Some(rsigma_parser::ruleset::OverlayPatch {
                level: Some("critical".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }];
        let server = delegating_handler(Some(dir.path().to_path_buf()))
            .with_rulesets(BTreeMap::from([("base".to_string(), spec)]));
        let cli = SigmaCli::from_program(&program, true);
        let v = block_on(server.delegate_convert(
            &cli,
            ConvertInput {
                yaml: None,
                ruleset: Some("base".to_string()),
                ..convert_input("splunk")
            },
            TEST_TIMEOUT,
        ))
        .unwrap();
        assert_eq!(v["ok"], true, "envelope: {v}");
        let raw = v["raw"].as_str().unwrap();
        assert!(raw.contains("title: Whoami Execution"), "{raw}");
        assert!(raw.contains("level: critical"), "{raw}");
    }
}
