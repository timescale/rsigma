//! `rsigma mcp serve` — run the Model Context Protocol server.
//!
//! Exposes the rsigma toolchain to MCP-aware agents. stdio is the default
//! transport; `--http <addr>` opts into the Streamable HTTP transport with
//! optional bearer-token auth and TLS. The tool surface lives in the
//! [`rsigma_mcp`] crate; this module owns the CLI flags and the tokio runtime,
//! mirroring how `engine daemon` is wired.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use rsigma_parser::LintConfig;

use crate::exit_code;

/// `rsigma mcp <command>` subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum McpCommands {
    /// Run the MCP server (stdio by default; `--http` for Streamable HTTP).
    Serve(McpServeArgs),
}

/// Arguments for `rsigma mcp serve`.
#[derive(Args, Debug)]
pub(crate) struct McpServeArgs {
    /// Path to a YAML config file. Overrides config-file discovery
    /// (./rsigma.yaml, .rsigmarc, ~/.config/rsigma/config.yaml,
    /// /etc/rsigma/config.yaml). Unlike a discovered project file, it may set
    /// the security-sensitive `mcp.*` keys. CLI flags still take precedence
    /// over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Lint config file (`.rsigma-lint.yml`) applied by the `lint_rules` tool.
    /// When omitted, lint defaults are used.
    #[arg(long = "lint-config", value_name = "PATH")]
    pub lint_config: Option<PathBuf>,

    /// Default root directory for relative `path` arguments in tool calls. Lets
    /// an agent reference rules by a path relative to a rules tree.
    #[arg(long = "rules-dir", value_name = "PATH")]
    pub rules_dir: Option<PathBuf>,

    /// Run without `--rules-dir`, letting tool calls read any file the server
    /// user can read. Required to serve `--http` without a root; on stdio it
    /// silences the startup warning. Off by default. Config key:
    /// `mcp.allow_unconfined_paths`.
    #[arg(long = "allow-unconfined-paths")]
    pub allow_unconfined_paths: bool,

    /// Allow the `convert_rules` tool to delegate targets without a native
    /// backend to an installed sigma-cli (off by default). Delegated calls
    /// spawn a subprocess; path inputs stay confined to `--rules-dir`.
    #[arg(long = "allow-sigma-cli")]
    pub allow_sigma_cli: bool,

    /// Base URL of a running rsigma daemon (`http://127.0.0.1:9090`). When
    /// set, the operate-cycle tools (incidents, risk, silences, dispositions)
    /// register and call this API. Unix-socket URLs are unsupported; use TCP
    /// loopback. Config key: `mcp.daemon_url`.
    #[arg(long = "daemon-url", value_name = "URL")]
    pub daemon_url: Option<String>,

    /// Extra root CA (PEM) for a self-signed daemon TLS listener. Config key:
    /// `mcp.daemon_ca`.
    #[arg(long = "daemon-ca", value_name = "PATH")]
    pub daemon_ca: Option<PathBuf>,

    /// Bearer token sent to the daemon as `Authorization: Bearer <token>`.
    /// Also read from `RSIGMA_MCP_DAEMON_TOKEN`. Flag/env only: secrets stay
    /// out of config files.
    #[arg(
        long = "daemon-token",
        env = "RSIGMA_MCP_DAEMON_TOKEN",
        value_name = "TOKEN"
    )]
    pub daemon_token: Option<String>,

    /// Register the mutating operate tools (`create_silence`,
    /// `post_disposition`). Off by default; requires `--daemon-url`. Config
    /// key: `mcp.allow_operate_writes`.
    #[arg(long = "allow-operate-writes")]
    pub allow_operate_writes: bool,

    /// Serve over Streamable HTTP on this address (e.g. `127.0.0.1:9100`)
    /// instead of stdio. The MCP endpoint is mounted at `/mcp`.
    #[arg(long = "http", value_name = "ADDR")]
    pub http: Option<SocketAddr>,

    /// Require this bearer token on every HTTP request (sent as
    /// `Authorization: Bearer <token>`). Also read from `RSIGMA_MCP_AUTH_TOKEN`.
    /// Secrets stay flag/env-only and are never read from config files.
    #[arg(
        long = "auth-token",
        env = "RSIGMA_MCP_AUTH_TOKEN",
        value_name = "TOKEN"
    )]
    pub auth_token: Option<String>,

    /// Allow binding plaintext HTTP on a non-loopback address without TLS.
    #[arg(long = "allow-plaintext")]
    pub allow_plaintext: bool,

    /// TLS certificate (PEM) for the HTTP transport. Requires `--tls-key` and a
    /// build with the `daemon-tls` feature.
    #[arg(long = "tls-cert", value_name = "PATH", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key (PEM) for the HTTP transport. Requires `--tls-cert`.
    #[arg(long = "tls-key", value_name = "PATH", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
}

/// Dispatch `rsigma mcp <command>`.
pub(crate) fn dispatch_mcp(cmd: McpCommands, ctx: crate::output::OutputCtx) {
    if ctx.explicit_format {
        ctx.warn_unsupported("mcp serve", "MCP protocol stream");
    }
    match cmd {
        McpCommands::Serve(args) => cmd_mcp_serve(args),
    }
}

/// Overlay the `mcp` config section (defaults < file < env) onto any flag the
/// operator did not set explicitly. The MCP HTTP auth token and the daemon
/// token are intentionally excluded: secrets stay flag/env-only.
fn apply_mcp_config(args: &mut McpServeArgs) {
    let base = crate::config::load_and_merge(args.config.as_deref());
    let Some(mcp) = base.mcp else {
        return;
    };
    if args.http.is_none()
        && let Some(addr) = mcp.http_addr
    {
        match addr.parse::<SocketAddr>() {
            Ok(parsed) => args.http = Some(parsed),
            Err(e) => {
                eprintln!("Invalid mcp.http_addr '{addr}' in config: {e}");
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
    }
    if args.lint_config.is_none() {
        args.lint_config = mcp.lint_config;
    }
    if args.rules_dir.is_none() {
        args.rules_dir = mcp.rules_dir;
    }
    if !args.allow_unconfined_paths
        && let Some(allow) = mcp.allow_unconfined_paths
    {
        args.allow_unconfined_paths = allow;
    }
    // A bool flag cannot distinguish "absent" from "false", so the config only
    // ever turns delegation on; an explicit --allow-sigma-cli already wins.
    if !args.allow_sigma_cli
        && let Some(allow) = mcp.allow_sigma_cli
    {
        args.allow_sigma_cli = allow;
    }
    if args.daemon_url.is_none() {
        args.daemon_url = mcp.daemon_url;
    }
    if args.daemon_ca.is_none() {
        args.daemon_ca = mcp.daemon_ca;
    }
    if !args.allow_operate_writes
        && let Some(allow) = mcp.allow_operate_writes
    {
        args.allow_operate_writes = allow;
    }
}

/// Run the MCP server. Builds a multi-thread tokio runtime (same pattern as the
/// daemon) and serves over stdio or, when `--http` is set, Streamable HTTP.
pub(crate) fn cmd_mcp_serve(mut args: McpServeArgs) {
    apply_mcp_config(&mut args);

    match path_confinement(&args) {
        Confinement::Confined | Confinement::UnconfinedAllowed => {}
        Confinement::UnconfinedStdio => eprintln!(
            "warning: --rules-dir is not set, so MCP tools can read any file this user can \
             read and fix_rules cannot write; set --rules-dir to confine path arguments"
        ),
        Confinement::UnconfinedHttpRefused => {
            eprintln!(
                "refusing to serve --http without --rules-dir: tool calls could read any file \
                 this user can read; set --rules-dir, or pass --allow-unconfined-paths to opt out"
            );
            process::exit(exit_code::CONFIG_ERROR);
        }
    }

    let lint_config = match &args.lint_config {
        Some(path) => match LintConfig::load(path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading lint config {}: {e}", path.display());
                process::exit(exit_code::CONFIG_ERROR);
            }
        },
        None => LintConfig::default(),
    };

    let handler = match build_handler(&args, lint_config) {
        Ok(handler) => handler,
        Err(e) => {
            eprintln!("{e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create async runtime for the MCP server: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let result = match args.http {
        None => runtime.block_on(rsigma_mcp::serve_stdio(handler)),
        Some(addr) => runtime.block_on(serve_http_transport(handler, addr, &args)),
    };

    if let Err(e) = result {
        eprintln!("MCP server error: {e}");
        process::exit(exit_code::RULE_ERROR);
    }
}

/// How tool path arguments are bounded for this invocation.
#[derive(Debug, PartialEq, Eq)]
enum Confinement {
    /// `--rules-dir` is set.
    Confined,
    /// No root, stdio transport, no opt-out: allowed with a startup warning.
    UnconfinedStdio,
    /// No root, `--http`, no opt-out: refuse to start.
    UnconfinedHttpRefused,
    /// No root, with `--allow-unconfined-paths`.
    UnconfinedAllowed,
}

fn path_confinement(args: &McpServeArgs) -> Confinement {
    match (&args.rules_dir, args.allow_unconfined_paths, args.http) {
        (Some(_), _, _) => Confinement::Confined,
        (None, true, _) => Confinement::UnconfinedAllowed,
        (None, false, None) => Confinement::UnconfinedStdio,
        (None, false, Some(_)) => Confinement::UnconfinedHttpRefused,
    }
}

/// Build the MCP handler, attaching a daemon client when `--daemon-url` is set.
fn build_handler(
    args: &McpServeArgs,
    lint_config: LintConfig,
) -> Result<rsigma_mcp::RsigmaMcp, String> {
    let Some(url) = args.daemon_url.clone() else {
        return Ok(rsigma_mcp::RsigmaMcp::new(
            args.rules_dir.clone(),
            lint_config,
            args.allow_sigma_cli,
        ));
    };
    let ca_pem = match &args.daemon_ca {
        Some(path) => Some(
            std::fs::read(path)
                .map_err(|e| format!("failed to read daemon CA {}: {e}", path.display()))?,
        ),
        None => None,
    };
    rsigma_mcp::RsigmaMcp::with_daemon(
        args.rules_dir.clone(),
        lint_config,
        args.allow_sigma_cli,
        rsigma_mcp::DaemonConnect {
            url,
            ca_pem,
            token: args.daemon_token.clone(),
        },
        args.allow_operate_writes,
    )
    .map_err(|e| format!("invalid daemon client configuration: {e}"))
}

/// Serve the Streamable HTTP transport (plaintext, or TLS when `daemon-tls` is
/// compiled and cert/key are supplied).
async fn serve_http_transport(
    handler: rsigma_mcp::RsigmaMcp,
    addr: SocketAddr,
    args: &McpServeArgs,
) -> anyhow::Result<()> {
    let tls_requested = args.tls_cert.is_some();

    if !tls_requested && !addr.ip().is_loopback() && !args.allow_plaintext {
        anyhow::bail!(
            "refusing to bind plaintext on non-loopback address {addr}; \
             pass --tls-cert/--tls-key to enable TLS or --allow-plaintext to opt out \
             (e.g. when terminating TLS at a sidecar proxy)"
        );
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let auth = args.auth_token.clone();

    if tls_requested {
        return serve_http_tls(handler, listener, auth, addr, args).await;
    }

    eprintln!("MCP Streamable HTTP server listening on http://{addr}/mcp");
    rsigma_mcp::serve_http(handler, listener, auth).await
}

/// TLS path: only available when the `daemon-tls` feature is compiled. Reuses
/// the daemon's rustls loader and TLS-terminating axum listener.
#[cfg(feature = "daemon-tls")]
async fn serve_http_tls(
    handler: rsigma_mcp::RsigmaMcp,
    listener: tokio::net::TcpListener,
    auth: Option<String>,
    addr: SocketAddr,
    args: &McpServeArgs,
) -> anyhow::Result<()> {
    use std::sync::Arc;

    use crate::daemon::tls::{RustlsListener, TlsCliConfig, TlsState};

    let cli = TlsCliConfig {
        cert_path: args.tls_cert.clone().expect("tls_cert present"),
        key_path: args.tls_key.clone().expect("tls_key present"),
        key_password: None,
        client_ca_path: None,
        min_version: Default::default(),
    };
    let tls_state = TlsState::from_paths(cli).map_err(|e| anyhow::anyhow!("{e}"))?;

    let gauge = Arc::new(
        prometheus::IntGauge::new(
            "rsigma_mcp_tls_active_connections",
            "Active TLS connections to the MCP HTTP server",
        )
        .expect("valid gauge"),
    );
    let tls_listener = RustlsListener::new(listener, tls_state.config, gauge);

    eprintln!("MCP Streamable HTTP server listening on https://{addr}/mcp");

    let router = rsigma_mcp::http_router(handler, auth);
    axum::serve(tls_listener, router).await?;
    Ok(())
}

/// Stub used when the binary is built without `daemon-tls`: TLS flags require
/// that feature, so surface a clear error rather than silently falling back to
/// plaintext.
#[cfg(not(feature = "daemon-tls"))]
async fn serve_http_tls(
    _handler: rsigma_mcp::RsigmaMcp,
    _listener: tokio::net::TcpListener,
    _auth: Option<String>,
    _addr: SocketAddr,
    _args: &McpServeArgs,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "--tls-cert/--tls-key require a build with the `daemon-tls` feature; \
         rebuild with `--features daemon-tls` or terminate TLS at a sidecar proxy \
         and use --allow-plaintext"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: McpServeArgs,
    }

    fn confinement(argv: &[&str]) -> Confinement {
        let cli = Cli::try_parse_from(std::iter::once("serve").chain(argv.iter().copied()))
            .expect("valid args");
        path_confinement(&cli.args)
    }

    #[test]
    fn rules_dir_confines_every_transport() {
        assert_eq!(confinement(&["--rules-dir", "r"]), Confinement::Confined);
        assert_eq!(
            confinement(&["--rules-dir", "r", "--http", "127.0.0.1:9100"]),
            Confinement::Confined
        );
    }

    #[test]
    fn stdio_without_root_warns() {
        assert_eq!(confinement(&[]), Confinement::UnconfinedStdio);
    }

    #[test]
    fn http_without_root_is_refused() {
        assert_eq!(
            confinement(&["--http", "127.0.0.1:9100"]),
            Confinement::UnconfinedHttpRefused
        );
    }

    #[test]
    fn opt_out_allows_unconfined_paths() {
        assert_eq!(
            confinement(&["--http", "127.0.0.1:9100", "--allow-unconfined-paths"]),
            Confinement::UnconfinedAllowed
        );
        assert_eq!(
            confinement(&["--allow-unconfined-paths"]),
            Confinement::UnconfinedAllowed
        );
    }
}
