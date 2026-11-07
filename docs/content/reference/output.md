# Output Formats

Structured rsigma commands can emit results in one of five formats. Artifact producers (Sigma YAML, backend query text, replay fixtures) and protocol streams keep their fixed wire format. The selector, color policy, and noise controls are global flags that resolve through the same precedence model as the rest of the [configuration](configuration.md).

## Selector

```text
--output-format <FORMAT>   # json | ndjson | table | csv | tsv
```

| Format | When to use it |
|--------|----------------|
| `json` | Default on a TTY for structured commands; a single pretty-printed JSON document (envelope or array). |
| `ndjson` | Default when piped for structured commands; one compact JSON object per logical record. Stream-friendly. |
| `table` | Width-aligned text table. Numeric columns are right-aligned. |
| `csv` | RFC 4180-style comma-separated values. Header row first, then one row per record. |
| `tsv` | Tab-separated equivalent of `csv`. Friendlier for `cut` and `awk`. |

## Resolution

Highest precedence first:

1. `--output-format` flag on the command line.
2. `RSIGMA_GLOBAL__OUTPUT_FORMAT` environment variable.
3. `global.output_format` in the discovered config file (or the file behind `--config`).
4. TTY-aware default for structured commands:
   - `json` when stdout is a terminal (pretty-printed for human reading).
   - `ndjson` when stdout is piped or redirected (so `| jq`, `| fluent-bit`, and `>file.ndjson` do the right thing without an extra flag).

Some commands keep a legacy human default when the selector is unset (for example `rule fields`, `rule lint`, `rule validate`, `backend targets`). Passing `--output-format` always overrides that default.

## Color

```text
--color <CHOICE>   # auto (default) | always | never
```

Resolved with the same precedence as `--output-format`:

1. `--color` flag.
2. `RSIGMA_GLOBAL__COLOR` env.
3. `global.color` in the config file.
4. `auto`: ANSI escapes are emitted only when stdout is a TTY and the [`NO_COLOR`](https://no-color.org/) environment variable is unset.

Use `--color always` in CI to keep colour in build logs; `--color never` to strip colour without overriding the TTY check.

## Noise control

| Flag | Effect |
|------|--------|
| `--quiet`, `-q` | Suppress every non-data line: progress (`Loaded N rules…`), stat summaries (`Processed N events, M matches.`), and unsupported-format warnings. Errors still go to stderr; exit codes are unchanged. |
| `--no-stats` | Suppress the trailing summary line only. Progress messages still appear, so you can watch a long-running stream but skip the footer when piping into a tool that does not expect one. |

`--quiet` implies `--no-stats`.

## Where output lands

The contract is the same across every subcommand:

* **Stdout** carries the data (matches, fields, lint findings, queries, YAML, fixtures).
* **Stderr** carries diagnostics, progress, the optional stats summary, and any warnings.

This is what lets `rsigma engine eval … | jq '.rule_title'` work cleanly: `jq` only sees the detection objects.

## Not the same as a daemon sink format

`--output-format` selects how a **command** renders its product. The streaming daemon's sinks have their own, separate wire-format selector: `?format=ndjson|ocsf` on a sink spec, which chooses between rsigma's native NDJSON and [OCSF Detection Finding](../guide/ocsf-findings.md) JSON per sink. `--output-format` does not apply to daemon sinks, and `?format=` does not apply to batch commands.

## Unsupported formats

When a command cannot honor an explicit `--output-format`, it prints one stderr warning and keeps its documented product:

```text
warning: `--output-format csv` is not supported by `rule reverse`; falling back to Sigma YAML.
```

`--quiet` suppresses that warning. The command never silently pretends the requested format was produced.

## Per-command behavior

### Structured (all five formats)

| Command | Implicit default | Notes |
|---------|------------------|-------|
| `engine eval` | Pretty JSON on TTY; NDJSON when piped | `table`/`csv`/`tsv` project `LEVEL | RULE | TYPE | DETAIL`. `--pretty` still forces pretty JSON for backwards compatibility. |
| `engine explain` | Human table/tree | Explicit selector overrides. |
| `engine classify` | TTY-aware json/ndjson | Full five-format support. |
| `engine discover-schemas` | TTY-aware json/ndjson | Full five-format support. |
| `engine status` | TTY-aware json/ndjson | Table/csv/tsv project metric rows. |
| `engine tail` | TTY-aware json/ndjson | Streaming detections. |
| `rule lint` | Coloured human view | Explicit `json` emits `{summary, findings}`; `ndjson` one finding per line; `csv`/`tsv` use `PATH,SEVERITY,RULE,LINE,MESSAGE`. |
| `rule fields` | Table (even when piped) | Hidden `--json` aliases `--output-format json`. |
| `rule backtest`/`coverage`/`scorecard`/`visibility`/`hygiene` | TTY-aware or table | Full five-format support. |
| `rule draft --emit report` | TTY-aware | Full five-format support. |
| `rule validate` | Human summary | Explicit selector emits `{summary, …}` for `json` and `PATH,STATUS,ERRORS` rows for table/csv/tsv/ndjson. |
| `backend targets`/`backend formats` | Human listing | Explicit selector emits `PROVIDER,NAME,DESCRIPTION` or `TARGET,KIND,NAME,DESCRIPTION` rows. |
| `pipeline resolve` | Compact JSON (`--pretty` optional) | Explicit selector emits `PIPELINE,SOURCE_ID,SOURCE_TYPE,STATUS,DATA_OR_ERROR` rows. |
| `pipeline diff` | Human unified diff | `json`/`ndjson` keep the AST envelope; `csv`/`tsv` emit per-rule rows with compact JSON in `BEFORE`/`AFTER`. |
| `config validate`/`show`/`path` | Text/path lines | Local `--format` (when set) wins over global `--output-format` and prints a precedence warning. Global `json`/`ndjson`/`table`/`csv`/`tsv` are honored when local `--format` is unset. `show --format yaml` remains available. |

### Query artifacts

| Command | Default | Explicit formats |
|---------|---------|------------------|
| `backend convert` | Raw backend query text | `json` wraps `{target, format, queries:[…]}`; `ndjson` emits one query record per line; `table`/`csv`/`tsv` warn and keep raw text. `--output` always writes raw text. |

### AST (json/ndjson only)

| Command | Behaviour |
|---------|-----------|
| `rule parse`/`rule condition`/`rule stdin` | Pretty JSON on a TTY; compact NDJSON when piped or redirected. `table`/`csv`/`tsv` warn and fall back to JSON. |

### Fixed artifacts and protocols

| Command | Product | Explicit incompatible formats |
|---------|---------|-------------------------------|
| `rule reverse` | Sigma YAML | Warn; keep YAML. |
| `rule draft` (default `--emit yaml`) | Sigma YAML | Warn; keep YAML. |
| `rule migrate-sources` | Source YAML + pipeline rewrites | Warn; keep file/YAML product. |
| `rule fmt` | File report, unified diff, or formatted YAML | Warn; keep text. |
| `engine tap` | Replayable NDJSON fixture | Warn unless `ndjson`; never array-wrap or pretty-print. |
| `engine daemon` | Configured sink wire format | Warn; sinks unchanged. |
| `mcp serve` | MCP protocol stream | Warn; protocol unchanged. |
| `config init`/`config reload` | File write/HTTP status | Warn; no stdout data product. |
| `config schema` | JSON Schema document | `json`/`ndjson` supported; `table`/`csv`/`tsv` warn and fall back to JSON. |

`rule fmt` writes its data product to stdout: `Would reformat:` report lines, unified diffs, or the formatted text from `--stdout`. Progress lines, `Reformatted:` lines, `skipped:` lines, errors, and the trailing summary go to stderr.

## Examples

Stream detections into jq, getting compact NDJSON automatically because stdout is piped:

```bash
rsigma engine eval -r rules/ -e @events.ndjson \
  | jq '{rule: .rule_title, level: .level}'
```

Force a table on a TTY for at-a-glance triage:

```bash
rsigma engine eval -r rules/ -e @events.ndjson --output-format table
```

Export a coverage report as CSV for a spreadsheet:

```bash
rsigma rule fields -r rules/ --output-format csv > coverage.csv
```

Fail a CI job on any lint finding and dump JSON for the GitHub Actions summary:

```bash
rsigma rule lint rules/ \
  --fail-level warning \
  --output-format json \
  --quiet \
  > lint.json
```

Pin a project-wide default in `.rsigmarc`:

```yaml
global:
  output_format: ndjson
  color: auto
```

CLI flags still override the file, so a developer can flip back to a TTY view with `rsigma rule fields -r rules/ --output-format table`.
