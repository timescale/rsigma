# CLI Reference

`rsigma` is a single binary that exposes every operation through five noun-led command groups: `engine`, `rule`, `backend`, `pipeline`, and `config`. Each subcommand is independent and self-contained; there is no global state. A YAML config file is optional but supported, with strict CLI > env > file > default precedence — see the [Configuration Reference](../reference/configuration.md).

This reference documents every subcommand with its flag table, verified examples, and exit-code semantics. For narrative walkthroughs see the [User Guide](../guide/evaluating-rules.md).

## Quick navigation

| Group | Subcommands | What it does |
|-------|-------------|--------------|
| [`engine`](engine/eval.md) | `eval`, `daemon` | Run Sigma rules against events: one-shot or long-running. |
| [`rule`](rule/parse.md) | `parse`, `validate`, `lint`, `fields`, `condition`, `stdin` | Inspect, validate, and lint Sigma rule files. |
| [`backend`](backend/convert.md) | `convert`, `targets`, `formats` | Convert Sigma rules into backend-native queries (PostgreSQL, LynxDB, …). |
| [`pipeline`](pipeline/resolve.md) | `resolve` | Inspect and test processing pipelines, including dynamic sources. |
| [`config`](config/init.md) | `init`, `validate`, `show`, `schema`, `path`, `reload` | Scaffold, validate, introspect, and reload the YAML config file. |

## Global flags

Every subcommand accepts one global flag:

| Flag | Default | Values | Effect |
|------|---------|--------|--------|
| `--log-format` | unset | `json`, `text` | Emit structured diagnostic logs to stderr via `tracing-subscriber`. Verbosity controlled by `RUST_LOG` (default `info`). Has no effect on `engine daemon`, which always logs JSON. |

`--log-format` adds the diagnostic-log stream alongside the existing stdout/stderr output; it never replaces them. See [Observability](../guide/observability.md) for the full RUST_LOG target catalog.

## Command tree

```text
rsigma
├── engine
│   ├── eval                   one-shot evaluation against fixed input
│   └── daemon                 long-running streaming detection
├── rule
│   ├── parse                  parse a single rule file, dump AST as JSON
│   ├── validate               parse + compile a directory of rules
│   ├── lint                   run the 66 lint checks
│   ├── fields                 list every field referenced by the rules
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

## Migration from flat subcommands

Twelve flat top-level subcommands were moved into the four groups above. The flat aliases are hidden from `rsigma --help` but kept as functional forwarders: each call still runs and prints a stderr migration warning pointing at the new path. `rsigma <alias> --help` is still routable so scripts that introspect a subcommand keep working through the deprecation window.

| Old | New | Will be removed in |
|-----|-----|------------|
| `rsigma eval` | `rsigma engine eval` | v1.0 ([#126](https://github.com/timescale/rsigma/issues/126)) |
| `rsigma daemon` | `rsigma engine daemon` | v1.0 |
| `rsigma parse` | `rsigma rule parse` | v1.0 |
| `rsigma validate` | `rsigma rule validate` | v1.0 |
| `rsigma lint` | `rsigma rule lint` | v1.0 |
| `rsigma fields` | `rsigma rule fields` | v1.0 |
| `rsigma condition` | `rsigma rule condition` | v1.0 |
| `rsigma stdin` | `rsigma rule stdin` | v1.0 |
| `rsigma convert` | `rsigma backend convert` | v1.0 |
| `rsigma list-targets` | `rsigma backend targets` | v1.0 |
| `rsigma list-formats` | `rsigma backend formats` | v1.0 |
| `rsigma resolve` | `rsigma pipeline resolve` | v1.0 |

A scripted migration is one `sed`:

```bash
# Replace every flat invocation in a tree of CI/shell scripts.
git ls-files '*.sh' '*.yml' '*.yaml' Makefile | xargs sed -i.bak -E '
    s/rsigma (eval|daemon)/rsigma engine \1/g
    s/rsigma (parse|validate|lint|fields|condition|stdin)/rsigma rule \1/g
    s/rsigma convert/rsigma backend convert/g
    s/rsigma list-targets/rsigma backend targets/g
    s/rsigma list-formats/rsigma backend formats/g
    s/rsigma resolve/rsigma pipeline resolve/g
'
```

Test the resulting changes locally before committing; the script preserves a `.bak` for each modified file.

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
