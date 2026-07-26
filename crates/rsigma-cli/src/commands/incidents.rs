//! `rsigma engine incidents export`: fetch one incident's bundle from a running
//! daemon and write it to stdout or a file.
//!
//! A read-only client, following the `engine status` conventions (`--addr`
//! resolves from `daemon.api.addr`, synchronous `ureq` transport) so it builds
//! without the `daemon` feature and a lightweight build can still pull a bundle
//! from a remote daemon.

use std::io::Write;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand, ValueEnum};

use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;

/// The environment variable the API token is read from unless
/// `--auth-token-env` names another.
const DEFAULT_TOKEN_ENV: &str = "RSIGMA_API_TOKEN";

#[derive(Subcommand, Debug)]
pub(crate) enum IncidentsCommands {
    /// Export one incident's bundle (GET /api/v1/incidents/{id}/bundle)
    Export(IncidentsExportArgs),
}

pub(crate) fn dispatch_incidents(cmd: IncidentsCommands, ctx: OutputCtx) {
    match cmd {
        IncidentsCommands::Export(args) => cmd_incidents_export(args, ctx),
    }
}

/// How the daemon should render the bundle.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum BundleFormat {
    /// The full structured document.
    Json,
    /// A human-readable report.
    Markdown,
}

impl BundleFormat {
    fn as_query(self) -> &'static str {
        match self {
            BundleFormat::Json => "json",
            BundleFormat::Markdown => "markdown",
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct IncidentsExportArgs {
    /// Incident id, as reported by `GET /api/v1/incidents`.
    #[arg(value_name = "INCIDENT_ID")]
    pub id: String,

    /// Daemon API address as `host:port` or a full URL.
    /// Defaults to `daemon.api.addr` from the resolved config.
    #[arg(long)]
    pub addr: Option<String>,

    /// Explicit config file used to resolve the daemon address.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Bundle rendering to request.
    #[arg(long, value_enum, default_value_t = BundleFormat::Json)]
    pub bundle_format: BundleFormat,

    /// Write the bundle here instead of stdout. The file is replaced only
    /// after the whole bundle has been received.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Environment variable holding the API bearer token. The token itself is
    /// never taken as an argument, so it cannot leak through the process list.
    #[arg(long, value_name = "VAR", default_value = DEFAULT_TOKEN_ENV)]
    pub auth_token_env: String,
}

pub(crate) fn cmd_incidents_export(args: IncidentsExportArgs, ctx: OutputCtx) {
    // The daemon renders the bundle, so the global output format has no say in
    // how it looks; `--bundle-format` is the only control.
    ctx.warn_unsupported("engine incidents export", "bundle");

    let addr = config::resolve_daemon_addr(args.addr.clone(), args.config.as_deref());
    let url = format!(
        "{}?format={}",
        config::api_url(&addr, &format!("/api/v1/incidents/{}/bundle", args.id)),
        args.bundle_format.as_query()
    );

    // Surface non-2xx as a normal response so the daemon's JSON error hint
    // (401/403 auth, 404 unknown id, 409 still batching, 503 grouping off)
    // reaches the operator instead of being reduced to a status code.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut request = agent.get(&url);
    if let Some(token) = token_from_env(&args.auth_token_env) {
        request = request.header("authorization", format!("Bearer {token}"));
    }

    let response = match request.call() {
        Ok(response) => response,
        Err(e) => {
            eprintln!("incident export failed: could not reach {url}: {e}");
            eprintln!("(is the daemon running?)");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let status = response.status().as_u16();
    let body = match response.into_body().read_to_string() {
        Ok(body) => body,
        Err(e) => {
            eprintln!("incident export failed: could not read response from {url}: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    if !(200..300).contains(&status) {
        eprintln!("incident export failed: {url} returned HTTP {status}");
        if !body.trim().is_empty() {
            eprintln!("{}", describe_error(&body));
        }
        process::exit(exit_code::CONFIG_ERROR);
    }

    match &args.output {
        None => print!("{body}"),
        Some(path) => {
            if let Err(e) = write_atomically(path, &body) {
                eprintln!(
                    "incident export failed: could not write {}: {e}",
                    path.display()
                );
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
    }
}

/// The token held by `var`, or `None` when the variable is unset or empty.
///
/// An empty variable is treated as absent so an unset deployment secret sends
/// no header at all rather than an obviously invalid one.
fn token_from_env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|t| !t.trim().is_empty())
}

/// Render the daemon's error body for the terminal: its `error` and `hint`
/// when it is the usual JSON shape, and the raw body otherwise.
fn describe_error(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.trim().to_string();
    };
    let Some(error) = value.get("error").and_then(|v| v.as_str()) else {
        return body.trim().to_string();
    };
    match value.get("hint").and_then(|v| v.as_str()) {
        Some(hint) => format!("{error}\n({hint})"),
        None => error.to_string(),
    }
}

/// Write `contents` to `path` by way of a sibling temporary file and a rename.
///
/// A bundle is commonly written over a previous export of the same incident, so
/// a failed write must leave that previous export intact rather than truncating
/// it. The temporary file is a sibling, which keeps the rename within one
/// filesystem and therefore atomic.
fn write_atomically(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let Some(file_name) = path.file_name() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output path has no file name",
        ));
    };
    let mut temporary = path.to_path_buf();
    temporary.set_file_name(format!(
        ".{}.rsigma-{}.tmp",
        file_name.to_string_lossy(),
        process::id()
    ));

    let write = (|| {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&temporary);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_body_is_rendered_with_its_hint() {
        let body = r#"{"error":"incident grouping disabled","hint":"configure a group stage"}"#;
        assert_eq!(
            describe_error(body),
            "incident grouping disabled\n(configure a group stage)"
        );
    }

    #[test]
    fn a_body_that_is_not_the_usual_shape_is_shown_verbatim() {
        assert_eq!(describe_error("upstream said no\n"), "upstream said no");
        assert_eq!(
            describe_error(r#"{"detail":"nope"}"#),
            r#"{"detail":"nope"}"#
        );
    }

    #[test]
    fn a_blank_token_variable_sends_no_header() {
        // SAFETY: single-threaded test with no other reader of this variable.
        unsafe { std::env::set_var("RSIGMA_TEST_BLANK_TOKEN", "   ") };
        assert!(token_from_env("RSIGMA_TEST_BLANK_TOKEN").is_none());
        assert!(token_from_env("RSIGMA_TEST_UNSET_TOKEN").is_none());
        unsafe { std::env::remove_var("RSIGMA_TEST_BLANK_TOKEN") };
    }

    #[test]
    fn a_failed_write_leaves_the_previous_export_intact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bundle.json");
        write_atomically(&path, "first").unwrap();
        write_atomically(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");

        // The temporary file is a sibling, so nothing is left behind either.
        let leftovers: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }
}
