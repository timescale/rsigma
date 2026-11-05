# `rsigma-mcp`

{{ added "0.16.0" }}

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the RSigma toolchain (parse, lint, validate, evaluate, convert, reverse-convert, tune, fields, pipelines, ADS authoring) as MCP tools for AI agents. Built on [`rmcp`](https://crates.io/crates/rmcp), the official Rust MCP SDK.

- [docs.rs/rsigma-mcp](https://docs.rs/rsigma-mcp)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-mcp/README.md)
- [crates.io/crates/rsigma-mcp](https://crates.io/crates/rsigma-mcp)

## When to use

- You are wiring RSigma into an MCP client (Cursor, Claude Code): use the [`rsigma mcp serve`](../cli/mcp/serve.md) command, which embeds this crate.
- You are building your own agent host and want to serve the RSigma tool surface from your binary: depend on this crate and call `serve_stdio` (or `serve_http` with the `http` feature).

For the end-to-end workflow, client setup, and the tool reference with example calls, see the [MCP server guide](../guide/mcp-server.md).

## Install

```toml
[dependencies]
rsigma-mcp = "{{ rsigma.version }}"
# Optional Streamable HTTP transport:
# rsigma-mcp = { version = "{{ rsigma.version }}", features = ["http"] }
```

| Feature | Effect |
|---------|--------|
| `http` | Exposes `serve_http`, `http_router`, and their `HttpOptions` variants for the Streamable HTTP transport. |

## Public surface

| Item | Purpose |
|------|---------|
| `RsigmaMcp::new(root, lint_config, allow_sigma_cli)` | Build the handler with an optional default root for relative path-based tool calls, a lint configuration, and the sigma-cli delegation switch for `convert_rules` (pass `false` to keep conversion native-only). |
| `RsigmaMcp::with_daemon(..., connect, allow_operate_writes)` | Same as `new`, plus a [`DaemonConnect`](https://docs.rs/rsigma-mcp) so Operate-cycle tools register against a running daemon. Write tools register only when `allow_operate_writes` is true. |
| `DaemonClient` / `DaemonConnect` / `DaemonError` | HTTP client pointed at the daemon control-plane API. |
| `RsigmaMcp::default()` | A handler with no root, default lint configuration, and delegation disabled. |
| `serve_stdio(handler)` | Serve the handler over stdio, blocking until the client disconnects. The caller owns the tokio runtime. |
| `serve_http` / `http_router` (`http` feature) | Serve over Streamable HTTP (`/mcp`), or obtain the axum router for embedding. The optional bearer token is the only setting, and only loopback `Host` headers are accepted. |
| `serve_http_with` / `http_router_with(handler, HttpOptions)` (`http` feature) | Same, with `HttpOptions { auth_token, allowed_hosts }`. `AllowedHosts` is `Loopback` (`LOOPBACK_HOSTS`, the default), `List(hosts)`, or `Any`; requests with any other `Host` get `403`. Use `Any` only when a bearer token guards the endpoint. {{ added "unreleased" }} |

The handler implements `rmcp::ServerHandler`, so it can also be served over any rmcp transport.

## Minimum example

```rust,no_run
use rsigma_mcp::RsigmaMcp;
use rsigma_parser::LintConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = RsigmaMcp::new(None, LintConfig::default(), false);
    rsigma_mcp::serve_stdio(handler).await
}
```

## See also

- [MCP server guide](../guide/mcp-server.md) for the full tool reference and client setup.
- [`rsigma mcp serve`](../cli/mcp/serve.md) for the CLI command.
- [`rsigma-parser`](parser.md), [`rsigma-eval`](eval.md), [`rsigma-convert`](convert.md), [`rsigma-runtime`](runtime.md) for the crates it wraps.
