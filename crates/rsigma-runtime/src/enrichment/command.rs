//! `CommandEnricher`: per-result local-process execution.
//!
//! Runs a local command via [`tokio::process::Command`] with a
//! template-expanded argv and an optional template-expanded environment.
//! Stdout is captured (capped at 10 MB to mirror the existing
//! dynamic-source command resolver) and parsed as either a JSON value or
//! a raw string (the [`OutputFormat`] knob).
//!
//! Non-zero exit codes map to [`EnrichErrorKind::Fetch`]. Stderr is read
//! into the error message (truncated at 4 KB) so operators can see what
//! went wrong without grepping the daemon's tracing output.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use rsigma_eval::EvaluationResult;
use tokio::process::Command;

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
    template::render_template,
};

/// Maximum stdout bytes captured per invocation. Mirrors
/// [`crate::sources::MAX_SOURCE_RESPONSE_BYTES`] so the two surfaces
/// share the same hard limit.
const MAX_COMMAND_STDOUT: usize = 10 * 1024 * 1024;
/// Maximum stderr bytes attached to error messages.
const MAX_COMMAND_STDERR_IN_ERROR: usize = 4 * 1024;

/// How to interpret captured stdout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Parse stdout as JSON. Non-JSON stdout produces a `Parse` error.
    /// Default — matches the dynamic-pipelines command source behaviour.
    #[default]
    Json,
    /// Inject stdout as a raw `serde_json::Value::String`. Trailing
    /// newlines are stripped.
    Raw,
}

/// One command enricher instance.
pub struct CommandEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    argv: Vec<String>,
    env: HashMap<String, String>,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
    output: OutputFormat,
}

impl CommandEnricher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        argv: Vec<String>,
        env: HashMap<String, String>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        output: OutputFormat,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            argv,
            env,
            timeout,
            on_error,
            scope,
            output,
        }
    }
}

#[async_trait]
impl Enricher for CommandEnricher {
    fn kind(&self) -> EnricherKind {
        self.kind
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn inject_field(&self) -> &str {
        &self.inject_field
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        if self.argv.is_empty() {
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch("empty argv".to_string()),
            });
        }

        let rendered: Vec<String> = self
            .argv
            .iter()
            .map(|a| render_template(a, result))
            .collect();

        let mut cmd = Command::new(&rendered[0]);
        cmd.args(&rendered[1..]);
        // Replace the inherited env wholesale with the configured env
        // when the operator supplies any entries; otherwise inherit the
        // daemon's env (so e.g. `PATH` resolves binary names normally).
        if !self.env.is_empty() {
            for (k, v) in &self.env {
                cmd.env(k, render_template(v, result));
            }
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let output = cmd.output().await.map_err(|e| EnrichError {
            enricher_id: self.id.clone(),
            kind: EnrichErrorKind::Fetch(format!("spawn: {e}")),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut snippet = stderr
                .chars()
                .take(MAX_COMMAND_STDERR_IN_ERROR)
                .collect::<String>();
            if stderr.len() > MAX_COMMAND_STDERR_IN_ERROR {
                snippet.push_str("…[truncated]");
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!(
                    "exit {:?}: {}",
                    output.status.code(),
                    snippet.trim()
                )),
            });
        }

        if output.stdout.len() > MAX_COMMAND_STDOUT {
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!(
                    "stdout exceeded {} bytes",
                    MAX_COMMAND_STDOUT
                )),
            });
        }

        let value = match self.output {
            OutputFormat::Json => serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .map_err(|e| EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Parse(format!("JSON: {e}")),
                })?,
            OutputFormat::Raw => {
                // Strip trailing CR and LF in any combination so that the
                // Windows CRLF line ending from `cmd /C echo ...` produces
                // the same captured value as the Unix LF from `sh -c
                // echo ...`. We do not call `.trim_end()` because that
                // would also strip trailing spaces, which a `Raw` capture
                // is otherwise expected to preserve verbatim.
                let s = String::from_utf8_lossy(&output.stdout);
                serde_json::Value::String(s.trim_end_matches(['\r', '\n']).to_string())
            }
        };
        inject_enrichment(result, &self.inject_field, value);
        Ok(())
    }
}
