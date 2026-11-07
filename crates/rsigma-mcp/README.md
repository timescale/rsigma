# rsigma-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the [rsigma](https://github.com/timescale/rsigma) Sigma detection-rule toolchain (parser, linter, evaluator, converter, field extraction, pipeline resolution) as MCP tools, so any MCP-aware agent (Cursor, Claude Code, …) can author, lint, validate, evaluate, and convert Sigma rules with structured, machine-readable results.

The server is transport-agnostic. The CLI drives it over stdio via `rsigma mcp serve`.

## Usage

The crate is consumed by `rsigma-cli`; you normally run the server through the CLI:

```bash
rsigma mcp serve --rules-dir /path/to/rules
```

To embed the handler in your own binary:

```rust,no_run
use rsigma_mcp::{DaemonConnect, RsigmaMcp};
use rsigma_parser::LintConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // root, lint config, allow sigma-cli delegation in convert_rules
    let handler = RsigmaMcp::new(None, LintConfig::default(), false);
    // Or attach a daemon so operate tools register:
    let _operate = RsigmaMcp::with_daemon(
        None,
        LintConfig::default(),
        false,
        DaemonConnect {
            url: "http://127.0.0.1:9090".into(),
            ca_pem: None,
            token: None,
        },
        false,
    )?;
    rsigma_mcp::serve_stdio(handler).await
}
```

## Tools

| Tool | Purpose |
|------|---------|
| `parse_rule` | Parse Sigma YAML (rules, correlations, filters) to AST JSON. |
| `parse_condition` | Parse a Sigma condition expression to a parse-tree. |
| `lint_rules` | Lint rules; findings carry lint rule id, severity, line, and fix availability. |
| `validate_rules` | Parse + compile + correlation checks, optional pipelines, source resolution, and `fail_level`. |
| `evaluate_events` | Evaluate JSON events against rules (detections and correlations). Matches of rules referenced by a correlation, detections and correlations alike, are suppressed unless `emit_detections` is true. |
| `convert_rules` | Convert rules to backend queries (`postgres`/`lynxdb`/`fibratus` natively; any other target via an installed sigma-cli when the server runs with `--allow-sigma-cli`). |
| `list_backends` | List conversion targets and their formats (plus installed sigma-cli targets when delegation is enabled). |
| `list_fields` | List the event fields rules reference, with provenance. |
| `resolve_pipeline` | Inspect a builtin or file pipeline; optionally resolve dynamic sources. |
| `list_builtin_pipelines` | List the builtin pipelines. |
| `fix_rules` | Apply safe auto-fixes to Sigma YAML; `write: true` (path only, and only with a rules root) persists to disk. |
| `format_rules` | Rewrite Sigma YAML into the canonical layout; `write: true` (path only, and only with a rules root) persists to disk. |
| `author_ads` | Report each rule's ADS sections, the required sections missing under the active config, and a `rsigma.ads.*` scaffold to complete. |
| `reverse_convert` | Reverse-convert a SIEM query (`dialect: lucene` today) into a draft Sigma rule (YAML); takes the metadata and logsource a query cannot carry as parameters. |
| `tune_rules` | Propose a verified Sigma filter from inline false-positive and true-positive event arrays; path inputs and pipeline files are confined to `--rules-dir`. |
| `test_exemplars` | Replay embedded `rsigma.exemplars` and return the shared pass/fail report; `path` is confined to `--rules-dir`. |
| `list_incidents` | List open incidents from a configured daemon (`--daemon-url`). |
| `get_incident` | Fetch one open incident by id. |
| `get_incident_bundle` | Fetch the evidence bundle for one incident. |
| `list_risk_entities` | List open risk entities. |
| `get_rule_quality` | Fetch the per-rule quality view. |
| `list_silences` | List operator silences. |
| `create_silence` | Create a TTL-bounded silence (`--allow-operate-writes`). |
| `post_disposition` | Record an analyst verdict (`--allow-operate-writes`). |

Engineer-cycle tools always register. Operate-cycle tools appear in `tools/list` only when a daemon URL is configured; the two mutating tools also require `--allow-operate-writes`. Every Engineer tool accepts inline content (`yaml`/`condition`/`events`) xor a file `path`, and returns structured JSON. Stdout is reserved for the MCP transport; diagnostics go to stderr.

## Resources

Four read-only resources expose reference data: `rsigma://lint/catalogue` (92 entries: 91 emitted lint rules plus the reserved `empty_filter_rules` rule), `rsigma://ads/schema` (the ADS section catalogue), `rsigma://reference/modifiers`, and `rsigma://reference/mitre-tactics`.

## Design

- Built on [`rmcp`](https://crates.io/crates/rmcp) 3.0 (the official Rust MCP SDK).
- `RsigmaMcp` is the cloneable handler; the tool methods are thin wrappers over the underlying rsigma crates.
- The CLI owns the tokio runtime entry point (`serve_stdio`), mirroring how the daemon is wired.
- With the `http` feature, `http_router_with` and `serve_http_with` take `HttpOptions` (bearer token and `AllowedHosts` for `Host` and `Origin` validation). `http_router` and `serve_http` keep the loopback host list. The CLI refuses a non-loopback bind without a token unless `--allow-unauthenticated` is set.
- `--rules-dir` confines every path argument (`path`, `events_path`, `enrichers_path`, file-based `pipelines`): paths that leave it through an absolute path, `../`, or a symlink are refused, as are directory inputs containing symlinks. `evaluate_events` only builds `template` enrichers, and refuses templates that reference `${ENV_VAR}` so a caller cannot read the server's environment; `command`, `http`, `lookup`, and `stix` are refused.
- sigma-cli delegation is opt-in (`--allow-sigma-cli`) and hardened: `path` and file-based pipeline inputs are confined to `--rules-dir` when set, inline YAML is staged to a temp file, the subprocess is killed after 60s, and at most two delegations run concurrently.
- Operate-cycle tools are opt-in (`--daemon-url`, plus `--allow-operate-writes` for mutations). The daemon token is flag/env-only (`--daemon-token` / `RSIGMA_MCP_DAEMON_TOKEN`).

## Smoke test

[`scripts/mcp-smoke.py`](../../scripts/mcp-smoke.py) drives a built binary end to end over both transports and exercises every tool and resource. The `mcp` feature is opt-in, so build with it first:

```bash
cargo build --release -p rsigma --features mcp
python3 scripts/mcp-smoke.py            # stdio
python3 scripts/mcp-smoke.py --http     # Streamable HTTP + bearer auth
```

It is a post-build sanity check; CI correctness is covered by this crate's Rust tests.

## See also

- [MCP server guide](https://rsigma.io/guide/mcp-server/) for client setup and the full workflow.
- [`rsigma mcp serve`](https://rsigma.io/cli/mcp/serve/) for the flag reference.
