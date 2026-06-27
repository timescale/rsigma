# MCP Server

`rsigma mcp serve` runs a [Model Context Protocol](https://modelcontextprotocol.io) server that gives any MCP-aware agent (Cursor, Claude Code, and others) a structured tool surface over the rsigma Sigma toolchain. Instead of shelling out to the CLI and scraping text, an agent calls typed tools and gets back machine-readable JSON: ASTs, lint findings with spans and fix availability, evaluation matches, backend queries, and field inventories.

The server is gated behind the opt-in `mcp` Cargo feature. Build from source with `--features mcp`; the prebuilt binaries and Docker image (built with `--all-features`) include it.

## Why an MCP server

A detection engineer working with an agent wants a grounded write-lint-evaluate loop: the agent drafts a rule, the linter tells it exactly what is wrong (with the spec rule id and whether a safe fix exists), it evaluates the rule against sample events to confirm it fires, and it converts the rule to the target backend. Every step returns structured data the agent can reason over, and nothing requires the agent to parse human-formatted CLI output.

## Transport

The server speaks JSON-RPC over **stdio**: stdin and stdout are the transport, so the server keeps stdout clean and sends any diagnostics to stderr. You normally run it under an MCP client, not interactively.

```bash
rsigma mcp serve --rules-dir /path/to/rules
```

`--rules-dir` sets a default root so an agent can pass `path` arguments relative to a rules tree. `--lint-config` points the `lint_rules` tool at a `.rsigma-lint.yml` (disabled rules, severity overrides, extra tag namespaces).

## Client setup

### Cursor

Add an entry to your `mcp.json` (project `.cursor/mcp.json` or the global one):

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

### Claude Code

```bash
claude mcp add rsigma -- rsigma mcp serve --rules-dir /path/to/rules
```

Either way the client launches `rsigma mcp serve` as a subprocess and talks to it over stdio.

## Tool reference

Every tool accepts **either** inline content (`yaml`, `condition`, `events`) **or** a file `path`, never both. Path arguments resolve against `--rules-dir` when relative. Outputs are JSON with an `ok` flag plus tool-specific fields. Content errors (a rule that fails to parse, a backend that cannot represent a rule) come back inside a successful response as `{ "ok": false, ... }` so the agent can read and act on them; only malformed requests return MCP errors.

| Tool | Input | Output |
|------|-------|--------|
| `parse_rule` | `yaml` or `path` | AST as JSON, plus rule/correlation/filter counts and parse errors. |
| `parse_condition` | `condition` | The parsed condition expression tree. |
| `lint_rules` | `yaml` or file/dir `path` | Findings per file: lint rule id, severity, message, 1-indexed line, `fixable`, and the fix title. |
| `validate_rules` | `yaml` or file/dir `path`, `pipelines`, `resolve_sources` | Parse + compile + correlation-reference results, with per-rule compile errors. |
| `evaluate_events` | rules (`yaml`/`path`), events (`events` array or `events_path` NDJSON), `pipelines`, `match_detail`, `enrichers`/`enrichers_path` | Matches with `event_index`, a summary of detection/correlation counts. With `enrichers` the matches are run through an enrichment pipeline first. |
| `convert_rules` | rules, `target`, `format`, `pipelines`, `options`, `skip_unsupported` | Backend queries per rule, plus errors and warnings. |
| `list_backends` | (none) | Conversion targets with their formats and correlation methods. |
| `list_fields` | rules, `pipelines`, `include_filters` | Each referenced field with the rules and source kinds that use it. |
| `resolve_pipeline` | `pipeline` (builtin name or path), `resolve_sources` | Pipeline name, priority, transformation count, dynamic sources. |
| `list_builtin_pipelines` | (none) | The builtin pipelines (`ecs_windows`, `fibratus_windows`, `sysmon`). |
| `fix_rules` | `yaml` or file `path`, `lint_rules`, `write` | Applies safe auto-fixes; returns the fixed YAML and applied/failed/skipped-unsafe counts. `write: true` (path only) persists to disk. |
| `author_ads` | `yaml` or file/dir `path` | Per rule: the current ADS sections, the required sections missing under the active config, and a `rsigma.ads.*` scaffold to complete. |

## Resources

The server exposes read-only MCP resources so an agent can ground itself on the exact vocabulary without spending tool calls:

| URI | Contents |
|-----|----------|
| `rsigma://lint/catalogue` | The full lint catalogue ({{ rsigma.lint.total }} rules) as JSON: id, default severity, fix disposition, one-line description. |
| `rsigma://ads/schema` | The ADS section catalogue as JSON: section id, carrier field, default-required, description. |
| `rsigma://reference/modifiers` | Sigma field modifiers with descriptions. |
| `rsigma://reference/mitre-tactics` | MITRE ATT&CK tactics with descriptions. |

## Enrichment

`evaluate_events` accepts an optional `enrichers` (inline YAML/JSON) or `enrichers_path`. The config follows the daemon's enrichers schema (`template`, `http`, `command` primitives with kind-aware template namespaces); the matches are enriched before being returned. Because the loader validates the config (including template-namespace checks) and surfaces failures as structured errors, the tool doubles as an enricher-config validator. `lookup` enrichers are not available here because they need the daemon's dynamic-source cache.

### Example calls

Parse a rule:

```json
{ "name": "parse_rule", "arguments": { "yaml": "title: Whoami\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains: whoami\n  condition: sel\n" } }
```

Evaluate it against an event:

```json
{
  "name": "evaluate_events",
  "arguments": {
    "yaml": "title: Whoami\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains: whoami\n  condition: sel\nlevel: medium\n",
    "events": [ { "CommandLine": "cmd /c whoami" } ],
    "match_detail": "summary"
  }
}
```

Convert it to PostgreSQL:

```json
{ "name": "convert_rules", "arguments": { "path": "windows/proc.yml", "target": "postgres", "format": "view" } }
```

## The agentic loop

A productive pattern an agent can run end to end:

1. **Draft** a rule and call `parse_rule` to confirm it is structurally valid.
2. **Lint** with `lint_rules`; for each finding, the `rule` id and `fixable` flag tell the agent whether to apply a known-safe correction or rewrite by hand.
3. **Evaluate** with `evaluate_events` against a handful of positive and negative sample events to confirm the rule fires where expected and stays quiet otherwise. `match_detail: "summary"` (or `"full"`) explains *why* each event matched.
4. **Validate** the whole set with `validate_rules` (optionally with `pipelines`) before shipping.
5. **Convert** with `convert_rules` to the deployment backend.

## HTTP deployment

For remote agents, serve over the Streamable HTTP transport instead of stdio with `--http <addr>` (the MCP endpoint is mounted at `/mcp`):

```bash
rsigma mcp serve --http 127.0.0.1:9100
```

- **Auth.** `--auth-token <token>` (or `RSIGMA_MCP_AUTH_TOKEN`) requires a static bearer token on every request; requests without `Authorization: Bearer <token>` get `401`. The token is compared in constant time and is flag/env-only (never read from config files).
- **TLS.** `--tls-cert`/`--tls-key` terminate TLS in-process using the same rustls loader as the daemon (requires a build with the `daemon-tls` feature). Alternatively terminate TLS at a sidecar proxy and bind plaintext with `--allow-plaintext`.
- **Plaintext safety.** Binding plaintext on a non-loopback address is refused unless `--allow-plaintext` is set.

The `--http`, `--lint-config`, and `--rules-dir` settings also resolve from the layered config (`mcp` section) and the `RSIGMA_MCP__*` environment layer (for example `RSIGMA_MCP__HTTP_ADDR=127.0.0.1:9100`); the auth token stays flag/env-only.

## See also

- [`rsigma mcp serve`](../cli/mcp/serve.md) for the flag reference.
- [Configuration](../reference/configuration.md) for the `mcp.*` config keys.
- [Linting Rules](linting-rules.md) for the lint vocabulary the `lint_rules` tool reports.
- [Rule Conversion](rule-conversion.md) for what `convert_rules` produces.
- [Feature Flags](../reference/feature-flags.md) for the `mcp` feature.
