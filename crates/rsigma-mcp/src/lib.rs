//! # rsigma-mcp
//!
//! A [Model Context Protocol](https://modelcontextprotocol.io) server that
//! exposes the rsigma Sigma toolchain (parser, linter, evaluator, converter,
//! field extraction, pipeline resolution) as MCP tools and resources, so any
//! MCP-aware agent can author, lint, fix, validate, evaluate, and convert Sigma
//! detection rules with structured, machine-readable results.
//!
//! The server is transport-agnostic; the [`RsigmaMcp`] handler is driven over
//! stdio by `rsigma mcp serve` (and, behind a feature, Streamable HTTP). The
//! handlers are thin synchronous wrappers over the underlying rsigma crates,
//! which keeps stdout reserved for the transport (all diagnostics go to stderr).

#[cfg(feature = "http")]
mod http;
mod input;
mod tools;

#[cfg(feature = "http")]
pub use http::{http_router, serve_http};
pub use tools::RsigmaMcp;

use rmcp::ServiceExt;

/// Serve the MCP handler over stdio (stdin/stdout), blocking until the client
/// disconnects. The caller owns the tokio runtime.
pub async fn serve_stdio(handler: RsigmaMcp) -> anyhow::Result<()> {
    let service = handler.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
