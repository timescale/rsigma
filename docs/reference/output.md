# Output Formats

Every rsigma subcommand can emit its structured output in one of five formats. The selector, color policy, and noise controls are global flags that resolve through the same precedence model as the rest of the [configuration](configuration.md).

## Selector

```text
--output-format <FORMAT>   # json | ndjson | table | csv | tsv
```

| Format | When to use it |
|--------|----------------|
| `json` | Default on a TTY; a single pretty-printed JSON object per record. |
| `ndjson` | Default when piped; one compact JSON object per line. Stream-friendly. |
| `table` | Width-aligned text table for `engine eval` (`LEVEL | RULE | TYPE | DETAIL`), `rule fields`, `rule lint`, and `rule validate`. Numeric columns are right-aligned. |
| `csv` | RFC 4180-style comma-separated values. Header row first, then one row per record. |
| `tsv` | Tab-separated equivalent of `csv`. Friendlier for `cut` and `awk`. |

## Resolution

Highest precedence first:

1. `--output-format` flag on the command line.
2. `RSIGMA_GLOBAL__OUTPUT_FORMAT` environment variable.
3. `global.output_format` in the discovered config file (or the file behind `--config`).
4. TTY-aware default:
   - `json` when stdout is a terminal (pretty-printed for human reading).
   - `ndjson` when stdout is piped or redirected (so `| jq` / `| fluent-bit` / `>file.ndjson` do the right thing without an extra flag).

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
| `--quiet`, `-q` | Suppress every non-data line: progress (`Loaded N rules…`), stat summaries (`Processed N events, M matches.`), and the warning printed when `backend convert` falls back to raw text for non-tabular formats. Errors still go to stderr; exit codes are unchanged. |
| `--no-stats` | Suppress the trailing summary line only. Progress messages still appear, so you can watch a long-running stream but skip the footer when piping into a tool that does not expect one. |

`--quiet` implies `--no-stats`.

## Where output lands

The contract is the same across every subcommand:

* **Stdout** carries the data (matches, fields, lint findings, queries).
* **Stderr** carries diagnostics, progress, the optional stats summary, and any warnings.

This is what lets `rsigma engine eval … | jq '.rule_title'` work cleanly: `jq` only sees the detection objects.

## Per-command behaviour

| Command | TTY default | When piped | Notes |
|---------|------------|-----------|-------|
| `engine eval` | Pretty JSON | NDJSON | `table` renders one row per match (`LEVEL | RULE | TYPE | DETAIL`). `csv` / `tsv` write a header line then one row per match (streaming). `--pretty` still forces pretty JSON for backwards compatibility. |
| `engine daemon` | Daemon output stays NDJSON on its configured sinks. `--output-format` does not change the sink wire format. |
| `rule parse`, `rule condition`, `rule stdin` | Pretty JSON | Pretty JSON | These commands emit a parsed AST; pretty-printing stays the default. `--output-format ndjson` switches to compact. |
| `rule fields` | Table | Table | Default is the legacy table view even when piped, so existing pipelines do not change. Explicit `--output-format json|ndjson|csv|tsv` overrides. The hidden `--json` flag still works and is equivalent to `--output-format json`. |
| `rule lint` | Coloured human view | Coloured human view (without ANSI when piped) | Same default-as-before behaviour. `--output-format json` emits `{summary, findings}`. `--output-format ndjson` emits one `Finding` per line. `--output-format csv|tsv` emits a `PATH,SEVERITY,RULE,LINE,MESSAGE` view. |
| `rule validate` | Human summary | Human summary | The format selector is reserved here; the existing summary is unchanged. |
| `backend convert` | Raw query text | Raw query text | The backend keeps its own `-f, --format` for the query format (SQL view, sliding_window, …). `--output-format json` wraps the queries in `{target, format, queries: [{rule_title, rule_id, query}, …]}`. The non-JSON tabular formats are not meaningful for free-form query text; the command prints a stderr warning and falls back to raw text. |

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
