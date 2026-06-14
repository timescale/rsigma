# `rsigma-mcp`

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the rsigma toolchain (parse, lint, validate, evaluate, convert, fields, pipelines) as MCP tools for AI agents. Built on [`rmcp`](https://crates.io/crates/rmcp), the official Rust MCP SDK.

- [docs.rs/rsigma-mcp](https://docs.rs/rsigma-mcp)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-mcp/README.md)
- [crates.io/crates/rsigma-mcp](https://crates.io/crates/rsigma-mcp)

## When to use

- You are wiring rsigma into an MCP client (Cursor, Claude Code) — use the [`rsigma mcp serve`](../cli/mcp/serve.md) command, which embeds this crate.
- You are building your own agent host and want to serve the rsigma tool surface from your binary — depend on this crate and call `serve_stdio`.

For the end-to-end workflow, client setup, and the tool reference with example calls, see the [MCP server guide](../guide/mcp-server.md).

## Install

```toml
[dependencies]
rsigma-mcp = "{{ rsigma.version }}"
```

## Public surface

| Item | Purpose |
|------|---------|
| `RsigmaMcp::new(root, lint_config)` | Build the handler with an optional default root for relative path-based tool calls and a lint configuration. |
| `RsigmaMcp::default()` | A handler with no root and default lint configuration. |
| `serve_stdio(handler)` | Serve the handler over stdio, blocking until the client disconnects. The caller owns the tokio runtime. |

The handler implements `rmcp::ServerHandler`, so it can also be served over any rmcp transport.

## Minimum example

```rust,no_run
use rsigma_mcp::RsigmaMcp;
use rsigma_parser::LintConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = RsigmaMcp::new(None, LintConfig::default());
    rsigma_mcp::serve_stdio(handler).await
}
```

## See also

- [MCP server guide](../guide/mcp-server.md) for the full tool reference and client setup.
- [`rsigma mcp serve`](../cli/mcp/serve.md) for the CLI command.
- [`rsigma-parser`](parser.md), [`rsigma-eval`](eval.md), [`rsigma-convert`](convert.md), [`rsigma-runtime`](runtime.md) for the crates it wraps.
