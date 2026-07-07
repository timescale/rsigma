# CLI Reference

`rsigma` is a single binary that exposes every operation through five noun-led command groups: `engine`, `rule`, `backend`, `pipeline`, and `config`. Each subcommand is independent and self-contained; there is no global state. A YAML config file is optional but supported, with strict CLI > env > file > default precedence — see the [Configuration Reference](../reference/configuration.md).

This reference documents every subcommand with its flag table, verified examples, and exit-code semantics. For narrative walkthroughs see the [User Guide](../guide/evaluating-rules.md).

## Quick navigation

| Group | Subcommands | What it does |
|-------|-------------|--------------|
| [`engine`](engine/eval.md) | `eval`, `daemon` | Run Sigma rules against events: one-shot or long-running. |
| [`rule`](rule/parse.md) | `parse`, `validate`, `lint`, `fields`, `backtest`, `coverage`, `condition`, `stdin` | Inspect, validate, lint, backtest, and ATT&CK-map Sigma rule files. |
| [`backend`](backend/convert.md) | `convert`, `targets`, `formats` | Convert Sigma rules into backend-native queries (PostgreSQL, LynxDB, …). |
| [`pipeline`](pipeline/resolve.md) | `resolve` | Inspect and test processing pipelines, including dynamic sources. |
| [`config`](config/init.md) | `init`, `validate`, `show`, `schema`, `path`, `reload` | Scaffold, validate, introspect, and reload the YAML config file. |

## Global flags

Every subcommand accepts five global flags. They share the same layered precedence as the rest of the configuration: **flag > `RSIGMA_GLOBAL__*` env > `global.*` in the YAML config > built-in default**. The `--output-format` and `--color` defaults are TTY-aware, so `rsigma … | jq` and `rsigma …` in a terminal both do the right thing without an explicit override.

| Flag | Default | Values | Effect |
|------|---------|--------|--------|
| `--log-format` | unset | `json`, `text` | Emit structured diagnostic logs to stderr via `tracing-subscriber`. Verbosity controlled by `RUST_LOG` (default `info`). Has no effect on `engine daemon`, which always logs JSON. |
| `--output-format` | TTY-aware | `json`, `ndjson`, `table`, `csv`, `tsv` | Selects the wire format for any tabular data the subcommand emits. Default is pretty `json` on a TTY and `ndjson` when piped. |
| `--color` | `auto` | `auto`, `always`, `never` | Controls ANSI color on human-readable paths (lint findings, summaries). Honours [`NO_COLOR`](https://no-color.org/) when `auto`. |
| `--quiet` / `-q` | off | flag | Suppress every non-data line (progress, summary, fallback warnings). Errors still go to stderr. |
| `--no-stats` | off | flag | Suppress only the trailing summary / stats line. Progress messages still appear. |

`--log-format` adds the diagnostic-log stream alongside the existing stdout/stderr output; it never replaces them. See [Observability](../guide/observability.md) for the full RUST_LOG target catalog. For the output formats and color resolution model see the [Output reference](../reference/output.md).

## Command tree

```text
rsigma
├── engine
│   ├── eval                   one-shot evaluation against fixed input
│   └── daemon                 long-running streaming detection
├── rule
│   ├── parse                  parse a single rule file, dump AST as JSON
│   ├── validate               parse + compile a directory of rules
│   ├── lint                   run the {{ rsigma.lint.rules }} lint checks
│   ├── migrate-sources        extract pipeline-embedded sources into standalone files
│   ├── fields                 list every field referenced by the rules
│   ├── backtest               replay a corpus and diff per-rule fires vs expectations
│   ├── coverage               map rules onto ATT&CK; Navigator export + gap analysis
│   ├── condition              parse a condition expression, dump AST
│   └── stdin                  parse a rule from stdin
├── backend
│   ├── convert                emit backend-native queries from rules
│   ├── targets                list compiled-in backends
│   └── formats                list output formats for one backend
├── pipeline
│   └── resolve                offline source resolution + dry-run for dynamic pipelines
└── config
    ├── init                   scaffold a commented rsigma.yaml
    ├── validate               check files for unknown keys and inactive sections
    ├── show                   print the effective config with per-leaf sources
    ├── schema                 emit the JSON Schema
    ├── path                   list the config files that would be loaded
    └── reload                 hot-reload a running daemon (POST /api/v1/reload)
```

## Exit codes

Every subcommand uses the same four-code scheme. Full table and CI patterns are in the [CI/CD guide](../guide/ci-cd.md#exit-codes).

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Findings. `eval --fail-on-detection` matched, or `lint` produced findings at or above `--fail-level`. |
| `2` | Rule error: rules could not be parsed, compiled, or converted. |
| `3` | Configuration error: bad pipeline file, malformed argument. |

## Environment variables

| Variable | Effect | Applies to |
|----------|--------|------------|
| `RUST_LOG` | `tracing-subscriber` filter directive. Default `info`. | Any subcommand running with `--log-format`, or always for `engine daemon`. |
| `NO_COLOR` | Disable ANSI colors in human-readable output. Honoured by `rule lint` and other commands that emit colored stderr. | All. |
| `NATS_CREDS`, `NATS_TOKEN`, `NATS_USER`, `NATS_PASSWORD`, `NATS_NKEY` | NATS authentication, mutually exclusive. | `engine daemon` with `--input nats://` or `--output nats://`. |
| `RSIGMA_CONSUMER_GROUP` | NATS JetStream consumer group name for horizontal scaling. | `engine daemon`. |

See [Environment Variables reference](../reference/environment-variables.md) for the complete list.

## See also

- [Installation](../getting-started/installation.md) for how to obtain the binary.
- [Quick Start](../getting-started/quick-start.md) for the three-minute "run your first rule" path.
- [User Guide](../guide/evaluating-rules.md) for narrative walkthroughs of each command.
