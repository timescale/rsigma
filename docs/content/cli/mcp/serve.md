# `rsigma mcp serve`

{{ added "0.16.0" }}

Run the [Model Context Protocol](https://modelcontextprotocol.io) server, exposing the RSigma Sigma toolchain (parse, lint, validate, evaluate, convert, reverse-convert, tune, test exemplars, fields, pipelines) as MCP tools to AI agents such as Cursor and Claude Code.

## Synopsis

```text
rsigma mcp serve [OPTIONS]
```

The server speaks JSON-RPC over stdio: stdin and stdout are the transport, so all human-readable diagnostics go to stderr. Run it under an MCP client rather than interactively.

## Description

`mcp serve` starts a stdio MCP server backed by the same crates the CLI uses. An agent connects, calls `tools/list` to discover the tool surface, and calls tools with either inline content (e.g. `yaml` or `query`) or a file `path`. Tool outputs are structured JSON: ASTs, lint findings with spans and fix availability, evaluation matches, backend queries, reverse-converted drafts, and field inventories.

For the full tool reference, client setup, and the agentic write-lint-evaluate loop, see the [MCP server guide](../../guide/mcp-server.md).

The command is gated behind the opt-in `mcp` Cargo feature: build from source with `--features mcp`. The prebuilt binaries and Docker image (built with `--all-features`) include it. See [Feature Flags](../../reference/feature-flags.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--lint-config <PATH>` | lint defaults | A lint config file (`.rsigma-lint.yml`) applied by the `lint_rules` tool (disabled rules, severity overrides, extra tag namespaces). Config key: `mcp.lint_config`. |
| `--rules-dir <PATH>` | none | Root directory for path arguments in tool calls. Relative paths resolve against it, and any path that leaves it (absolute, `../`, or through a symlink) is refused. Without it, tools can read any file the server's OS user can read, `fix_rules` cannot write, `--http` refuses to start, and stdio prints a startup warning. Config key: `mcp.rules_dir`. |
| `--allow-unconfined-paths` | off | Run without `--rules-dir`, leaving path arguments unconfined. Required to serve `--http` without a root; on stdio it silences the startup warning. `fix_rules` still cannot write without a root. Config key: `mcp.allow_unconfined_paths`. {{ added "0.25.0" }} |
| `--allow-sigma-cli` | off | Allow the `convert_rules` tool to delegate targets without a native backend to an installed [sigma-cli](../../reference/backends/sigma-cli.md), reaching the full pySigma backend set. Delegated calls spawn a subprocess (60s timeout, at most 2 concurrent); `path` and file-based `pipelines` inputs stay confined to `--rules-dir` when it is set. Config key: `mcp.allow_sigma_cli`. |
| `--daemon-url <URL>` | none | Base URL of a running rsigma daemon (`http://127.0.0.1:9090`). Registers the Operate-cycle read tools against that API. Unix-socket URLs are unsupported; use TCP loopback. Config key: `mcp.daemon_url`. {{ added "0.22.0" }} |
| `--daemon-ca <PATH>` | none | Extra root CA (PEM) for a self-signed daemon TLS listener. Config key: `mcp.daemon_ca`. {{ added "0.22.0" }} |
| `--daemon-token <TOKEN>` | none | Bearer token sent to the daemon as `Authorization: Bearer <token>`. Also read from `RSIGMA_MCP_DAEMON_TOKEN`. Flag/env only: secrets are never read from config files. {{ added "0.22.0" }} |
| `--allow-operate-writes` | off | Register `create_silence` and `post_disposition`. Requires `--daemon-url`. Config key: `mcp.allow_operate_writes`. {{ added "0.22.0" }} |
| `--http <ADDR>` | stdio | Serve over the Streamable HTTP transport on this address (e.g. `127.0.0.1:9100`) instead of stdio. The MCP endpoint is mounted at `/mcp`. Config key: `mcp.http_addr`. |
| `--auth-token <TOKEN>` | none | Require this static bearer token on every HTTP request (`Authorization: Bearer <token>`); requests without it get `401`. Also read from `RSIGMA_MCP_AUTH_TOKEN`. Flag/env only: secrets are never read from config files. |
| `--allow-plaintext` | off | Allow binding plaintext HTTP on a non-loopback address without TLS. Loopback binds never need it. |
| `--tls-cert <PATH>` | none | TLS certificate (PEM) for the HTTP transport. Requires `--tls-key` and a build with the `daemon-tls` feature. |
| `--tls-key <PATH>` | none | TLS private key (PEM) for the HTTP transport. Requires `--tls-cert`. |

`--http`, `--lint-config`, `--rules-dir`, `--allow-unconfined-paths`, `--allow-sigma-cli`, `--daemon-url`, `--daemon-ca`, and `--allow-operate-writes` also resolve from the layered config (`mcp` section) and the `RSIGMA_MCP__*` environment layer; the MCP HTTP auth token and the daemon token stay flag/env-only.

The global flags (`--log-format`, `--quiet`, …) are accepted but stdout stays reserved for the MCP transport; use `--log-format` to send structured diagnostics to stderr.

## Tools

| Tool | Purpose |
|------|---------|
| `parse_rule` | Parse Sigma YAML (rules, correlations, filters) to AST JSON. |
| `parse_condition` | Parse a condition expression to a parse-tree. |
| `lint_rules` | Lint rules; findings carry rule id, severity, line, and fix availability. |
| `validate_rules` | Parse + compile + correlation checks, optional pipelines, source resolution, and `fail_level`. |
| `evaluate_events` | Run events against rules (detections and correlations). |
| `convert_rules` | Convert rules to a backend query (`postgres`/`lynxdb`/`fibratus` natively; other targets via sigma-cli with `--allow-sigma-cli`). |
| `reverse_convert` | Reverse-convert a SIEM query (`dialect: lucene`) into a draft Sigma rule (YAML). |
| `list_backends` | List conversion targets and their formats (plus installed sigma-cli targets with `--allow-sigma-cli`). |
| `list_fields` | List the event fields rules reference, with provenance. |
| `resolve_pipeline` | Inspect a builtin or file pipeline; optionally resolve dynamic sources. |
| `list_builtin_pipelines` | List the builtin pipelines (`ecs_windows`, `fibratus_windows`, `sysmon`). |
| `fix_rules` | Apply safe auto-fixes; optionally persist with `write: true` (requires `--rules-dir`). |
| `author_ads` | Scaffold or render ADS detection metadata for a rule. |
| `tune_rules` | Propose a verified Sigma filter from false-positive and true-positive event arrays. |
| `test_exemplars` | Replay embedded `rsigma.exemplars` and return the pass/fail report. {{ added "0.22.0" }} |
| `list_incidents` | List open incidents (`--daemon-url`). {{ added "0.22.0" }} |
| `get_incident` | Fetch one open incident by id. {{ added "0.22.0" }} |
| `get_incident_bundle` | Fetch the evidence bundle for one incident (`json` or `markdown`). {{ added "0.22.0" }} |
| `list_risk_entities` | List open risk entities. {{ added "0.22.0" }} |
| `get_rule_quality` | Fetch the per-rule quality view. {{ added "0.22.0" }} |
| `list_silences` | List operator silences. {{ added "0.22.0" }} |
| `create_silence` | Create a TTL-bounded silence (`--allow-operate-writes`). {{ added "0.22.0" }} |
| `post_disposition` | Record an analyst verdict (`--allow-operate-writes`). {{ added "0.22.0" }} |

Plus four read-only resources: `rsigma://lint/catalogue`, `rsigma://ads/schema`, `rsigma://reference/modifiers`, and `rsigma://reference/mitre-tactics`. See the [MCP server guide](../../guide/mcp-server.md#operate-cycle) for the three-tier registration model.

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
rsigma mcp serve --http 127.0.0.1:9100 --rules-dir /path/to/rules

# Authenticated (bearer token), behind a TLS-terminating proxy
RSIGMA_MCP_AUTH_TOKEN=$(openssl rand -hex 32) \
  rsigma mcp serve --http 0.0.0.0:9100 --rules-dir /path/to/rules --allow-plaintext

# Native TLS (requires the `daemon-tls` feature)
rsigma mcp serve --http 0.0.0.0:9100 --rules-dir /path/to/rules \
  --auth-token "$TOKEN" \
  --tls-cert /etc/rsigma/tls/cert.pem --tls-key /etc/rsigma/tls/key.pem
```

The endpoint is `https?://<addr>/mcp`. Plaintext binds on non-loopback addresses are refused unless `--allow-plaintext` is set (use it when a sidecar proxy terminates TLS). Native TLS reuses the daemon's rustls loader and is only available when the binary is built with `daemon-tls`.

`--http` refuses to start without `--rules-dir` unless `--allow-unconfined-paths` is set, because any client that reaches the endpoint could otherwise read files outside a rules tree. {{ added "0.25.0" }}

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The server ran and the client disconnected cleanly. |
| `2` | The server failed (transport error). |
| `3` | The `--lint-config` file could not be loaded, an invalid config value (e.g. `mcp.http_addr`), or `--http` without `--rules-dir` or `--allow-unconfined-paths`. |

## See also

- [MCP server guide](../../guide/mcp-server.md) for the full workflow, tool reference, and client setup.
- [Feature Flags](../../reference/feature-flags.md) for the `mcp` feature.
