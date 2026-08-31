# CLI Reference

`rsigma` is a single binary that exposes every operation through noun-led command groups: `engine`, `rule`, `backend`, `pipeline`, `mcp`, and `config`. Each subcommand is independent and self-contained; there is no global state. A YAML config file is optional but supported, with strict flag > env > file > default precedence. See the [Configuration Reference](../reference/configuration.md).

`engine daemon` and `pipeline resolve` require the `daemon` Cargo feature; `mcp` requires the `mcp` feature. Prebuilt release archives and the GHCR Docker image are built with `--all-features`, so those commands are present there. Source builds need the matching features enabled.

This reference documents every subcommand with its flag table, verified examples, and exit-code semantics. For narrative walkthroughs see the [User Guide](../guide/evaluating-rules.md).

## Quick navigation

| Group | Subcommands | What it does |
|-------|-------------|--------------|
| [`engine`](engine/eval.md) | `eval`, `explain`, `classify`, `discover-schemas`, `status`, `incidents export`, `tap`, `tail`, `daemon` | Run and inspect Sigma rules against events: one-shot, explain, classify, or long-running |
| [`rule`](rule/parse.md) | `parse`, `validate`, `lint`, `fields`, `draft`, `tune`, `reverse`, `doc`, `backtest`, `coverage`, `scorecard`, `visibility`, `hygiene`, `condition`, `stdin`, `migrate-sources` | Inspect, draft, lint, tune, reverse-convert, backtest, score, and ATT&CK-map Sigma rule files |
| [`backend`](backend/convert.md) | `convert`, `targets`, `formats` | Convert Sigma rules into backend-native queries (PostgreSQL, LynxDB, Fibratus, and delegated sigma-cli targets) |
| [`pipeline`](pipeline/diff.md) | `diff`, `resolve` | Diff pipeline rewrites and test dynamic sources |
| [`mcp`](mcp/serve.md) | `serve` | Run the Model Context Protocol server for agent tooling (`mcp` feature) |
| [`config`](config/init.md) | `init`, `validate`, `show`, `schema`, `path`, `reload` | Scaffold, validate, introspect, and reload the YAML config file |

## Global flags

Every subcommand accepts five global flags. They share the same layered precedence as the rest of the configuration: **flag > `RSIGMA_GLOBAL__*` env > `global.*` in the YAML config > built-in default**. The `--output-format` and `--color` defaults are TTY-aware where a command emits structured or tabular data; see the [Output reference](../reference/output.md) for per-command defaults.

| Flag | Default | Values | Effect |
|------|---------|--------|--------|
| `--log-format` | unset | `json`, `text` | Emit structured diagnostic logs to stderr via `tracing-subscriber`. Verbosity controlled by `RUST_LOG` (default `info`). Has no effect on `engine daemon`, which always logs JSON. |
| `--output-format` | TTY-aware | `json`, `ndjson`, `table`, `csv`, `tsv` | Selects the wire format for any tabular data the subcommand emits. Many structured commands default to pretty `json` on a TTY and `ndjson` when piped; human-oriented commands often default to `table`. |
| `--color` | `auto` | `auto`, `always`, `never` | Controls ANSI color on human-readable paths (lint findings, summaries). Honors [`NO_COLOR`](https://no-color.org/) when `auto`. |
| `--quiet` / `-q` | off | flag | Suppress every non-data line (progress, summary, fallback warnings). Errors still go to stderr. |
| `--no-stats` | off | flag | Suppress only the trailing summary / stats line. Progress messages still appear. |

`--log-format` adds the diagnostic-log stream alongside the existing stdout/stderr output; it never replaces them. See [Observability](../guide/observability.md) for the full RUST_LOG target catalog. For the output formats and color resolution model see the [Output reference](../reference/output.md).

`--version` and `--features` are top-level introspection flags, not per-command globals. `--features` prints the Cargo features compiled into this binary, one name per line. `--version` and the `--help` footer carry the same list. See [Feature Flags](../reference/feature-flags.md#detecting-features-at-runtime).

## Command tree

```text
rsigma
├── engine
│   ├── eval                   one-shot evaluation against fixed input
│   ├── explain                explain why a rule matched or missed an event
│   ├── classify               report which schema each event matches
│   ├── discover-schemas       mine unrecognized events into candidate schemas
│   ├── status                 query a running daemon's /api/v1/status snapshot
│   ├── incidents
│   │   └── export             export open incidents from a running daemon
│   ├── tap                    capture a bounded window of the live event stream
│   ├── tail                   stream a running daemon's live detections
│   └── daemon                 long-running streaming detection (`daemon` feature)
├── rule
│   ├── parse                  parse a single rule file, dump AST as JSON
│   ├── validate               parse + compile a directory of rules
│   ├── lint                   run the {{ rsigma.lint.rules }} lint checks
│   ├── fields                 list every field referenced by the rules
│   ├── draft                  draft a rule from exemplar events (optional baseline)
│   ├── tune                   propose a verified filter from FP/TP exemplars
│   ├── reverse                reverse-convert a SIEM query into a draft Sigma rule
│   ├── doc                    report or scaffold ADS detection-strategy documents
│   ├── backtest               replay a corpus and diff per-rule fires vs expectations
│   ├── coverage               map rules onto ATT&CK; Navigator export + gap analysis
│   ├── scorecard              fuse backtest/coverage into keep/tune/retire verdicts
│   ├── visibility             score telemetry visibility (DeTT&CT + Navigator layer)
│   ├── hygiene                flag hygiene and retirement candidates
│   ├── condition              parse a condition expression, dump AST
│   ├── stdin                  parse a rule from stdin
│   └── migrate-sources        extract pipeline-embedded sources into standalone files
├── backend
│   ├── convert                emit backend-native queries from rules
│   ├── targets                list compiled-in backends
│   └── formats                list output formats for one backend
├── pipeline
│   ├── diff                   show how pipelines rewrite a rule before evaluation
│   └── resolve                offline source resolution + dry-run (`daemon` feature)
├── mcp                        (`mcp` feature)
│   └── serve                  run the Model Context Protocol server
└── config
    ├── init                   scaffold a commented rsigma.yaml
    ├── validate               check files for unknown keys and inactive sections
    ├── show                   print the effective config with per-leaf sources
    ├── schema                 emit the JSON Schema
    ├── path                   list the config files that would be loaded
    └── reload                 hot-reload a running daemon (POST /api/v1/reload)
```

## Exit codes

Every subcommand uses the same four-code scheme. Full table and CI patterns are in the [Exit Codes](../reference/exit-codes.md) reference and the [CI/CD guide](../guide/ci-cd.md#exit-codes).

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Findings: `eval --fail-on-detection`, `lint --fail-level`, `hygiene`/`scorecard --fail-on`, or per-source failures from `pipeline resolve` |
| `2` | Rule error: rules could not be parsed, compiled, or converted |
| `3` | Configuration error: bad pipeline file, malformed argument, unreachable daemon client call |

## Environment variables

| Variable | Effect | Applies to |
|----------|--------|------------|
| `RUST_LOG` | `tracing-subscriber` filter directive. Default `info`. | Any subcommand running with `--log-format`, or always for `engine daemon`. |
| `NO_COLOR` | Disable ANSI colors in human-readable output. Honored by `rule lint` and other commands that emit colored stderr. | All. |
| `NATS_CREDS`, `NATS_TOKEN`, `NATS_USER`, `NATS_PASSWORD`, `NATS_NKEY` | NATS authentication, mutually exclusive. | `engine daemon` with `--input nats://` or `--output nats://`. |
| `RSIGMA_CONSUMER_GROUP` | NATS JetStream consumer group name for horizontal scaling. | `engine daemon`. |
| `RSIGMA_API_TOKEN` | Bearer token for daemon-client calls that send auth (for example `engine incidents export`). | Selected daemon clients. |
| `RSIGMA_MCP_AUTH_TOKEN` | Bearer token for `mcp serve --http`. | `mcp serve`. |

See [Environment Variables reference](../reference/environment-variables.md) for the complete list, including the layered `RSIGMA_<SECTION>__*` config overrides.

## See also

- [Installation](../getting-started/installation.md) for how to obtain the binary.
- [Quick Start](../getting-started/quick-start.md) for the three-minute "run your first rule" path.
- [User Guide](../guide/evaluating-rules.md) for narrative walkthroughs of each command.
- [Feature Flags](../reference/feature-flags.md) for the `daemon`, `mcp`, and related Cargo features.
