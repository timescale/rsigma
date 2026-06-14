//! `rsigma mcp serve` — run the Model Context Protocol server.
//!
//! Exposes the rsigma toolchain to MCP-aware agents over stdio. The tool
//! surface lives in the [`rsigma_mcp`] crate; this module owns the CLI flags
//! and the tokio runtime, mirroring how `engine daemon` is wired.

use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use rsigma_parser::LintConfig;

use crate::exit_code;

/// `rsigma mcp <command>` subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum McpCommands {
    /// Run the MCP server over stdio.
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
}

/// Dispatch `rsigma mcp <command>`.
pub(crate) fn dispatch_mcp(cmd: McpCommands) {
    match cmd {
        McpCommands::Serve(args) => cmd_mcp_serve(args),
    }
}

/// Run the MCP server over stdio. Builds a multi-thread tokio runtime (same
/// pattern as the daemon).
pub(crate) fn cmd_mcp_serve(args: McpServeArgs) {
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

    let handler = rsigma_mcp::RsigmaMcp::new(args.rules_dir.clone(), lint_config);

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

    if let Err(e) = runtime.block_on(rsigma_mcp::serve_stdio(handler)) {
        eprintln!("MCP server error: {e}");
        process::exit(exit_code::RULE_ERROR);
    }
}
