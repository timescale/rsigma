# `rsigma mcp serve`

Run the [Model Context Protocol](https://modelcontextprotocol.io) server, exposing the rsigma Sigma toolchain (parse, lint, validate, evaluate, convert, fields, pipelines) as MCP tools to AI agents such as Cursor and Claude Code.

## Synopsis

```text
rsigma mcp serve [OPTIONS]
```

The server speaks JSON-RPC over stdio: stdin and stdout are the transport, so all human-readable diagnostics go to stderr. Run it under an MCP client rather than interactively.

## Description

`mcp serve` starts a stdio MCP server backed by the same crates the CLI uses. An agent connects, calls `tools/list` to discover the tool surface, and calls tools with either inline content (e.g. `yaml`) or a file `path`. Tool outputs are structured JSON: ASTs, lint findings with spans and fix availability, evaluation matches, backend queries, and field inventories.

For the full tool reference, client setup, and the agentic write-lint-evaluate loop, see the [MCP server guide](../../guide/mcp-server.md).

The command is gated behind the opt-in `mcp` Cargo feature: build from source with `--features mcp`. The prebuilt binaries and Docker image (built with `--all-features`) include it. See [Feature Flags](../../reference/feature-flags.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--lint-config <PATH>` | lint defaults | A lint config file (`.rsigma-lint.yml`) applied by the `lint_rules` tool (disabled rules, severity overrides, extra tag namespaces). Config key: `mcp.lint_config`. |
| `--rules-dir <PATH>` | none | Default root directory for relative `path` arguments in tool calls, so an agent can reference rules by a path relative to a rules tree. Config key: `mcp.rules_dir`. |
| `--http <ADDR>` | stdio | Serve over the Streamable HTTP transport on this address (e.g. `127.0.0.1:9100`) instead of stdio. The MCP endpoint is mounted at `/mcp`. Config key: `mcp.http_addr`. |
| `--auth-token <TOKEN>` | none | Require this static bearer token on every HTTP request (`Authorization: Bearer <token>`); requests without it get `401`. Also read from `RSIGMA_MCP_AUTH_TOKEN`. Flag/env only: secrets are never read from config files. |
| `--allow-plaintext` | off | Allow binding plaintext HTTP on a non-loopback address without TLS. Loopback binds never need it. |
| `--tls-cert <PATH>` | none | TLS certificate (PEM) for the HTTP transport. Requires `--tls-key` and a build with the `daemon-tls` feature. |
| `--tls-key <PATH>` | none | TLS private key (PEM) for the HTTP transport. Requires `--tls-cert`. |

`--http`, `--lint-config`, and `--rules-dir` also resolve from the layered config (`mcp` section) and the `RSIGMA_MCP__*` environment layer; the auth token stays flag/env-only.

The global flags (`--log-format`, `--quiet`, …) are accepted but stdout stays reserved for the MCP transport; use `--log-format` to send structured diagnostics to stderr.

## Tools

| Tool | Purpose |
|------|---------|
| `parse_rule` | Parse Sigma YAML (rules, correlations, filters) to AST JSON. |
| `parse_condition` | Parse a condition expression to a parse-tree. |
| `lint_rules` | Lint rules; findings carry rule id, severity, line, and fix availability. |
| `validate_rules` | Parse + compile + correlation checks, optional pipelines and source resolution. |
| `evaluate_events` | Run events against rules (detections and correlations). |
| `convert_rules` | Convert rules to a backend query (`postgres`/`lynxdb`/`fibratus`). |
| `list_backends` | List conversion targets and their formats. |
| `list_fields` | List the event fields rules reference, with provenance. |
| `resolve_pipeline` | Inspect a builtin or file pipeline; optionally resolve dynamic sources. |
| `list_builtin_pipelines` | List the builtin pipelines. |
| `fix_rules` | Apply safe auto-fixes; optionally persist with `write: true`. |

Plus three read-only resources: `rsigma://lint/catalogue`, `rsigma://reference/modifiers`, and `rsigma://reference/mitre-tactics`.

## Example: register with Cursor

Add to your `mcp.json`:

```json
{
  "mcpServers": {
    "rsigma": {
      "command": "rsigma",
      "args": ["mcp", "serve", "--rules-dir", "/path/to/rules"]
    }
  }
}
```

## Streamable HTTP

For remote agents, serve over HTTP instead of stdio:

```bash
# Local, loopback (no TLS required)
rsigma mcp serve --http 127.0.0.1:9100

# Authenticated (bearer token), behind a TLS-terminating proxy
RSIGMA_MCP_AUTH_TOKEN=$(openssl rand -hex 32) \
  rsigma mcp serve --http 0.0.0.0:9100 --allow-plaintext

# Native TLS (requires the `daemon-tls` feature)
rsigma mcp serve --http 0.0.0.0:9100 \
  --auth-token "$TOKEN" \
  --tls-cert /etc/rsigma/tls/cert.pem --tls-key /etc/rsigma/tls/key.pem
```

The endpoint is `https?://<addr>/mcp`. Plaintext binds on non-loopback addresses are refused unless `--allow-plaintext` is set (use it when a sidecar proxy terminates TLS). Native TLS reuses the daemon's rustls loader and is only available when the binary is built with `daemon-tls`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The server ran and the client disconnected cleanly. |
| `2` | The server failed (transport error). |
| `3` | The `--lint-config` file could not be loaded, or an invalid config value (e.g. `mcp.http_addr`). |

## See also

- [MCP server guide](../../guide/mcp-server.md) for the full workflow, tool reference, and client setup.
- [Feature Flags](../../reference/feature-flags.md) for the `mcp` feature.
