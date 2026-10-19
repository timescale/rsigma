# MCP Server

{{ added "0.16.0" }}

`rsigma mcp serve` runs a [Model Context Protocol](https://modelcontextprotocol.io) server that gives any MCP-aware agent (Cursor, Claude Code, and others) a structured tool surface over the RSigma Sigma toolchain. Instead of shelling out to the CLI and scraping text, an agent calls typed tools and gets back machine-readable JSON: ASTs, lint findings with spans and fix availability, evaluation matches, backend queries, reverse-converted drafts, and field inventories.

The server is gated behind the opt-in `mcp` Cargo feature. Build from source with `--features mcp`; the prebuilt binaries and Docker image (built with `--all-features`) include it.

## Why an MCP server

A detection engineer working with an agent wants a grounded write-lint-evaluate loop: the agent drafts a rule, the linter tells it exactly what is wrong (with the spec rule id and whether a safe fix exists), it evaluates the rule against sample events to confirm it fires, and it converts the rule to the target backend. Every step returns structured data the agent can reason over, and nothing requires the agent to parse human-formatted CLI output.

## Transport

The server speaks JSON-RPC over **stdio**: stdin and stdout are the transport, so the server keeps stdout clean and sends any diagnostics to stderr. You normally run it under an MCP client, not interactively.

```bash
rsigma mcp serve --rules-dir /path/to/rules
```

`--rules-dir` sets a root so an agent can pass `path` arguments relative to a rules tree, and confines every path argument to it: absolute paths, `../`, and symlinks that leave the root are refused, and so are directory inputs that contain symlinks. Set it whenever the agent processes untrusted content; without it, tools can read any file the server's OS user can read. Without a root, stdio prints a startup warning, `fix_rules` cannot write, and `--http` refuses to start unless `--allow-unconfined-paths` is set. {{ added "0.25.0" }} See [Security Hardening](../reference/security.md#mcp-server-tool-surface). `--lint-config` points the `lint_rules` tool at a `.rsigma-lint.yml` (disabled rules, severity overrides, extra tag namespaces).

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

Fifteen Engineer-cycle tools always register. When `--daemon-url` (or `mcp.daemon_url`) points at a running daemon, six Operate-cycle read tools join `tools/list`; `--allow-operate-writes` adds the two mutating tools. Content-bearing Engineer tools accept **either** inline content (`yaml`, `condition`, `events`, `query`) **or** a file `path`, never both. Path arguments resolve against `--rules-dir` when relative (and `tune_rules` / `test_exemplars` path inputs stay confined to that root when it is set). Outputs are JSON with an `ok` flag plus tool-specific fields. Content errors (a rule that fails to parse, a backend that cannot represent a rule, or a daemon that returns non-2xx) come back inside a successful response as `{ "ok": false, ... }` so the agent can read and act on them; only malformed requests return MCP errors.

| Tool | Input | Output |
|------|-------|--------|
| `parse_rule` | `yaml` or `path` | AST as JSON, plus rule/correlation/filter counts, `parse_errors`, and `parse_warnings`. `ok` is false only when a document fails to parse; an ignored invalid value such as `status: draft` is reported in `parse_warnings` instead. {{ added "0.25.0" }} |
| `parse_condition` | `condition` | The parsed condition expression tree. |
| `lint_rules` | `yaml` or file/dir `path` | Findings per file: lint rule id, severity, message, 1-indexed line, `fixable`, and the fix title. |
| `validate_rules` | `yaml` or file/dir `path`, `pipelines`, `resolve_sources`, `fail_level` | Parse + compile + correlation-reference results, with per-rule compile errors and separate `parse_errors` and `parse_warnings`. `fail_level` is `error` (default) or `warning`; at `warning`, a parse warning also sets `ok` to false. {{ added "0.25.0" }} |
| `evaluate_events` | rules (`yaml`/`path`), events (`events` array or `events_path` NDJSON), `pipelines`, `match_detail`, `emit_detections`, `enrichers`/`enrichers_path` | Matches with `event_index`, a summary of detection/correlation counts. With `enrichers` the matches are run through an enrichment pipeline first. Rules referenced only by correlations without `generate: true`, detections and correlations alike, produce no matches unless `emit_detections` is `true`. {{ added "0.24.0" }} |
| `convert_rules` | rules, `target`, `format`, `pipelines`, `options`, `skip_unsupported` | Backend queries per rule, plus errors and warnings. Native targets (`postgres`/`lynxdb`/`fibratus`) convert in-process; with `--allow-sigma-cli`, any other target is delegated to an installed [sigma-cli](../reference/backends/sigma-cli.md) and the result carries `engine: "sigma-cli"`, a per-line `queries` split, the verbatim `raw` output (authoritative for multi-line formats), and sigma-cli's diagnostics as `warnings`. |
| `reverse_convert` | `query`, optional `dialect` (`lucene`), plus metadata the query cannot carry (`title`, `id`, `level`, `status`, `logsource_product`/`category`/`service`). At least one logsource key is required. | Draft Sigma YAML (or `{ "ok": false, ... }` for constructs with no Sigma equivalent or a missing logsource). Same surface as [`rsigma rule reverse`](../cli/rule/reverse.md). {{ added "0.24.0" }} |
| `list_backends` | (none) | Conversion targets with their formats and correlation methods; with `--allow-sigma-cli`, installed sigma-cli targets are appended with `engine: "sigma-cli"`. |
| `list_fields` | rules, `pipelines`, `include_filters` | Each referenced field with the rules and source kinds that use it. |
| `resolve_pipeline` | `pipeline` (builtin name or path), `resolve_sources` | Pipeline name, priority, transformation count, dynamic sources. |
| `list_builtin_pipelines` | (none) | The builtin pipelines (`ecs_windows`, `fibratus_windows`, `sysmon`). |
| `fix_rules` | `yaml` or file `path`, `lint_rules`, `write` | Applies safe auto-fixes; returns the fixed YAML and applied/failed/skipped-unsafe counts. `write: true` (path only, and only with `--rules-dir`) persists to disk. |
| `author_ads` | `yaml` or file/dir `path` | Per rule: the current ADS sections, the required sections missing under the active config, and a `rsigma.ads.*` scaffold to complete. |
| `tune_rules` | rules (`yaml` or confined file/dir `path`), target `rule`, inline `false_positives` and `true_positives`, optional `pipelines` and tuning bounds | A verified `TuneReport` containing filter YAML, field rationale, clusters, FP coverage, warnings, and before/after counts. |
| `test_exemplars` | rules (`yaml` or confined file/dir `path`), optional `pipelines` | The shared exemplar report: per-entry expect/actual/pass plus rules with no exemplars. {{ added "0.22.0" }} |
| `list_incidents` | optional `min_level`, `limit` | Open incidents from `GET /api/v1/incidents`. Registers when a daemon URL is set. {{ added "0.22.0" }} |
| `get_incident` | `id` | One open incident from `GET /api/v1/incidents/{id}`. 404 and grouping-disabled 503 come back as content errors. {{ added "0.22.0" }} |
| `get_incident_bundle` | `id`, optional `format` (`json` or `markdown`) | Evidence bundle from `GET /api/v1/incidents/{id}/bundle`. {{ added "0.22.0" }} |
| `list_risk_entities` | (none) | Open risk entities from `GET /api/v1/risk`. Empty responses include a note so a disabled accumulator is not mistaken for a clean estate. {{ added "0.22.0" }} |
| `get_rule_quality` | optional `rule_id` | Per-rule quality view from `GET /api/v1/dispositions`. {{ added "0.22.0" }} |
| `list_silences` | (none) | Operator silences from `GET /api/v1/silences`, with `origin` and `state`. {{ added "0.22.0" }} |
| `create_silence` | `matchers`, exactly one of `ends_at` or `duration`, optional `id`/`starts_at`/`comment`/`created_by` | Write-gated. Creates a TTL-bounded silence; a retried client `id` returns the existing entry. {{ added "0.22.0" }} |
| `post_disposition` | `verdict` plus `fingerprint` or `incident_id`, optional `rule_id`/`scope`/`timestamp`/`analyst`/`note` | Write-gated. Returns the ingest summary; a redelivered identity is `duplicate`, not an error. {{ added "0.22.0" }} |

## Operate cycle

{{ added "0.22.0" }}

The operate tools are thin wrappers over the daemon control-plane API. They register only when the MCP server is pointed at a daemon, and the two mutating tools take a second explicit gate. An agent discovers what it is allowed to do from `tools/list`.

```bash
# Read-only triage against a loopback daemon
rsigma mcp serve --rules-dir /path/to/rules --daemon-url http://127.0.0.1:9090

# Same, plus silences and dispositions
rsigma mcp serve --rules-dir /path/to/rules \
  --daemon-url http://127.0.0.1:9090 \
  --allow-operate-writes
```

Three registration tiers:

| Configuration | Tools in `tools/list` |
|---------------|----------------------|
| No daemon URL | The 15 Engineer-cycle tools. |
| `--daemon-url` set | Those 15 plus the six read tools. |
| `--daemon-url` and `--allow-operate-writes` | Those 21 plus `create_silence` and `post_disposition`. |

`--allow-operate-writes` mirrors `--allow-sigma-cli`: default off, flag beats config (`mcp.allow_operate_writes`). A daemon running API authentication needs `--daemon-token` (or `RSIGMA_MCP_DAEMON_TOKEN`); the token is flag/env-only. A `reader` token covers the six read tools; an `operator` token adds `silences:write` and `dispositions:write` (and `capture:write` when capture is enabled). 401/403 come back as `{ "ok": false }` with a hint naming the flag and the required permission.

`--daemon-ca <PATH>` adds a PEM root CA for a self-signed daemon TLS listener. Unix-socket daemon URLs are unsupported; use TCP loopback.

`create_silence` refuses an unbounded window: supply `ends_at` (RFC 3339) or `duration` (humantime, converted at call time). An optional client `id` is checked against `GET /api/v1/silences` first so a retried create is a no-op. `post_disposition` requires `fingerprint` or `incident_id` so the disposition store's redelivery key engages; without an identity a retry would double-count.

A typical triage loop: `list_incidents` (optionally `min_level` / `limit`) → `get_incident` / `get_incident_bundle` → `list_risk_entities` and `get_rule_quality` → `create_silence` with a TTL → `post_disposition` → `tune_rules` if the verdict is a false positive.

## Resources

The server exposes read-only MCP resources so an agent can ground itself on the exact vocabulary without spending tool calls:

| URI | Contents |
|-----|----------|
| `rsigma://lint/catalogue` | The full lint catalogue ({{ rsigma.lint.total }} rules) as JSON: id, default severity, fix disposition, one-line description. |
| `rsigma://ads/schema` | The ADS section catalogue as JSON: section id, carrier field, default-required, description. |
| `rsigma://reference/modifiers` | Sigma field modifiers with descriptions. |
| `rsigma://reference/mitre-tactics` | MITRE ATT&CK tactics with descriptions. |

## Enrichment

`evaluate_events` accepts an optional `enrichers` (inline YAML/JSON) or `enrichers_path`. The config follows the daemon's enrichers schema, restricted to `template` enrichers (with kind-aware template namespaces); the matches are enriched before being returned. Because the loader validates the config (including template-namespace checks) and surfaces failures as structured errors, the tool doubles as a template-enricher validator. `command` and `http` enrichers are refused so a tool call cannot run local programs or reach network endpoints, and `lookup` and `stix` enrichers need resources only the daemon has; configure all four on the daemon.

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

Draft a rule from a Lucene query:

```json
{
  "name": "reverse_convert",
  "arguments": {
    "query": "CommandLine:*whoami* AND NOT User:SYSTEM",
    "dialect": "lucene",
    "title": "Whoami",
    "logsource_product": "windows",
    "logsource_category": "process_creation"
  }
}
```

Propose a filter while protecting a known true positive:

```json
{
  "name": "tune_rules",
  "arguments": {
    "path": "windows/backup-tool.yml",
    "rule": "929a690e-bef0-4204-a928-ef5e620d6fcc",
    "false_positives": [
      { "Image": "C:\\Program Files\\Veeam\\backup.exe", "User": "svc_backup" },
      { "Image": "C:\\Program Files\\Veeam\\backup.exe", "User": "svc_backup" }
    ],
    "true_positives": [
      { "Image": "C:\\Temp\\backup.exe", "User": "attacker" }
    ],
    "filter_id": "3f7b1c2e-9a44-4d1e-8f61-2b0c5d9e7a10"
  }
}
```

## sigma-cli delegation

By default the server is pure in-process Rust and `convert_rules` only accepts the native targets. Starting it with `--allow-sigma-cli` (config key `mcp.allow_sigma_cli`) lets `convert_rules` delegate any other target to an installed [sigma-cli](../reference/backends/sigma-cli.md), reaching the full pySigma backend set (`splunk`, `elasticsearch`, `kusto`, `qradar`, `loki`, and more):

```json
{ "name": "convert_rules", "arguments": { "path": "windows/proc.yml", "target": "splunk" } }
```

The delegated result carries `engine: "sigma-cli"`, a per-line `queries` split, the verbatim `raw` output (read this for multi-line formats like Loki `ruler`), and sigma-cli's diagnostics as `warnings`. When sigma-cli is not installed, the result is `{ "ok": false, ... }` with install guidance.

Delegation is off by default because it spawns a subprocess, a category change from the server's in-process posture. When enabled it stays bounded: `path` and file-based `pipelines` arguments are confined to `--rules-dir` when one is configured (a path that escapes it is refused), inline `yaml` is staged through a private temporary file, each invocation is killed after 60 seconds, and at most two delegations run concurrently. RSigma builtin pipeline names (`ecs_windows`, `fibratus_windows`, `sysmon`) are not translated for delegated targets; pass sigma-cli pipeline names or YAML paths. Discovery honors the `RSIGMA_SIGMA_CLI` override and otherwise resolves `sigma` on `PATH`; note that the prebuilt Docker image bundles no Python, so delegation is effectively a local-stdio feature.

## The agentic loop

A productive pattern an agent can run end to end:

1. **Draft** a rule (hand-authored YAML, or `reverse_convert` from a Lucene query) and call `parse_rule` to confirm it is structurally valid.
2. **Lint** with `lint_rules`; for each finding, the `rule` id and `fixable` flag tell the agent whether to apply a known-safe correction or rewrite by hand.
3. **Evaluate** with `evaluate_events` against a handful of positive and negative sample events to confirm the rule fires where expected and stays quiet otherwise. `match_detail: "summary"` (or `"full"`) explains *why* each event matched. When the events live on the rule as `rsigma.exemplars`, `test_exemplars` is the closed runner.
4. **Tune** a noisy rule with `tune_rules`, supplying classified false positives and a protected true-positive set, then review the returned filter and evidence.
5. **Validate** the whole set with `validate_rules` (optionally with `pipelines`) before shipping.
6. **Convert** with `convert_rules` to the deployment backend.

## HTTP deployment

For remote agents, serve over the Streamable HTTP transport instead of stdio with `--http <addr>` (the MCP endpoint is mounted at `/mcp`):

```bash
rsigma mcp serve --http 127.0.0.1:9100 --rules-dir /path/to/rules
```

- **Auth.** `--auth-token <token>` (or `RSIGMA_MCP_AUTH_TOKEN`) requires a static bearer token on every request; requests without `Authorization: Bearer <token>` get `401`. The token is compared in constant time and is flag/env-only (never read from config files).
- **TLS.** `--tls-cert`/`--tls-key` terminate TLS in-process using the same rustls loader as the daemon (requires a build with the `daemon-tls` feature). Alternatively terminate TLS at a sidecar proxy and bind plaintext with `--allow-plaintext`.
- **Plaintext safety.** Binding plaintext on a non-loopback address is refused unless `--allow-plaintext` is set.
- **Path confinement.** `--http` refuses to start without `--rules-dir` unless `--allow-unconfined-paths` is set. {{ added "0.25.0" }}

The `--http`, `--lint-config`, `--rules-dir`, `--allow-unconfined-paths`, `--daemon-url`, `--daemon-ca`, and `--allow-operate-writes` settings also resolve from the layered config (`mcp` section) and the `RSIGMA_MCP__*` environment layer (for example `RSIGMA_MCP__HTTP_ADDR=127.0.0.1:9100`); the MCP HTTP auth token and the daemon token stay flag/env-only.

## See also

- [`rsigma mcp serve`](../cli/mcp/serve.md) for the flag reference.
- [Configuration](../reference/configuration.md) for the `mcp.*` config keys.
- [Linting Rules](linting-rules.md) for the lint vocabulary the `lint_rules` tool reports.
- [Rule Conversion](rule-conversion.md) for what `convert_rules` produces.
- [`rsigma rule reverse`](../cli/rule/reverse.md) for the CLI sibling of `reverse_convert`.
- [Feature Flags](../reference/feature-flags.md) for the `mcp` feature.
