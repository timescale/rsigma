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
    /// Lint config file (`.rsigma-lint.yml`) applied by the `lint_rules` tool.
    /// When omitted, lint defaults are used.
    #[arg(long = "lint-config", value_name = "PATH")]
    pub lint_config: Option<PathBuf>,

    /// Default root directory for relative `path` arguments in tool calls. Lets
    /// an agent reference rules by a path relative to a rules tree.
    #[arg(long = "rules-dir", value_name = "PATH")]
    pub rules_dir: Option<PathBuf>,

    /// Allow the `convert_rules` tool to delegate targets without a native
    /// backend to an installed sigma-cli (off by default). Delegated calls
    /// spawn a subprocess; path inputs stay confined to `--rules-dir`.
    #[arg(long = "allow-sigma-cli")]
    pub allow_sigma_cli: bool,

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
pub(crate) fn dispatch_mcp(cmd: McpCommands) {
    match cmd {
        McpCommands::Serve(args) => cmd_mcp_serve(args),
    }
}

/// Overlay the `mcp` config section (defaults < file < env) onto any flag the
/// operator did not set explicitly. The auth token is intentionally excluded:
/// secrets stay flag/env-only.
fn apply_mcp_config(args: &mut McpServeArgs) {
    let base = crate::config::load_and_merge(None);
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
    // A bool flag cannot distinguish "absent" from "false", so the config only
    // ever turns delegation on; an explicit --allow-sigma-cli already wins.
    if !args.allow_sigma_cli
        && let Some(allow) = mcp.allow_sigma_cli
    {
        args.allow_sigma_cli = allow;
    }
}

/// Run the MCP server. Builds a multi-thread tokio runtime (same pattern as the
/// daemon) and serves over stdio or, when `--http` is set, Streamable HTTP.
pub(crate) fn cmd_mcp_serve(mut args: McpServeArgs) {
    apply_mcp_config(&mut args);

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

    let handler =
        rsigma_mcp::RsigmaMcp::new(args.rules_dir.clone(), lint_config, args.allow_sigma_cli);

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
