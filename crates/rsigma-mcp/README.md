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
use rsigma_mcp::RsigmaMcp;
use rsigma_parser::LintConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let handler = RsigmaMcp::new(None, LintConfig::default());
    rsigma_mcp::serve_stdio(handler).await
}
```

## Tools

| Tool | Purpose |
|------|---------|
| `parse_rule` | Parse Sigma YAML (rules, correlations, filters) to AST JSON. |
| `parse_condition` | Parse a Sigma condition expression to a parse-tree. |
| `lint_rules` | Lint rules; findings carry lint rule id, severity, line, and fix availability. |
| `validate_rules` | Parse + compile + correlation checks, optional pipelines and source resolution. |
| `evaluate_events` | Evaluate JSON events against rules (detections and correlations). |
| `convert_rules` | Convert rules to backend queries (`postgres`/`lynxdb`/`fibratus`). |
| `list_backends` | List conversion targets and their formats. |
| `list_fields` | List the event fields rules reference, with provenance. |
| `resolve_pipeline` | Inspect a builtin or file pipeline; optionally resolve dynamic sources. |
| `list_builtin_pipelines` | List the builtin pipelines. |
| `fix_rules` | Apply safe auto-fixes to Sigma YAML; `write: true` (path only) persists to disk. |

Every tool accepts inline content (`yaml`/`condition`/`events`) xor a file `path`, and returns structured JSON. Stdout is reserved for the MCP transport; diagnostics go to stderr.

## Resources

Three read-only resources expose reference data: `rsigma://lint/catalogue` (the 75-rule lint catalogue), `rsigma://reference/modifiers`, and `rsigma://reference/mitre-tactics`.

## Design

- Built on [`rmcp`](https://crates.io/crates/rmcp) 1.7 (the official Rust MCP SDK).
- `RsigmaMcp` is the cloneable handler; the tool methods are thin wrappers over the underlying rsigma crates.
- The CLI owns the tokio runtime entry point (`serve_stdio`), mirroring how the daemon is wired.

## See also

- [MCP server guide](https://timescale.github.io/rsigma/guide/mcp-server/) for client setup and the full workflow.
- [`rsigma mcp serve`](https://timescale.github.io/rsigma/cli/mcp/serve/) for the flag reference.
