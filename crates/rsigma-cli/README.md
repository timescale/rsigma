# rsigma

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma` is a command-line interface for parsing, validating, linting, and evaluating [Sigma](https://github.com/SigmaHQ/sigma) detection rules.

This binary is part of the [rsigma workspace].

## Installation

```bash
cargo install rsigma
```

## Quick Start

```bash
# Single event (inline JSON)
rsigma eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Read events from a file (@file syntax)
rsigma eval -r path/to/rules/ -e @events.ndjson

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'
```

## Subcommands

### `parse` — Parse a single rule

Parse a Sigma YAML file and output the AST as JSON.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a Sigma YAML file |
| `--pretty` / `-p` | flag | **true** | Pretty-print JSON output |

```bash
rsigma parse rule.yml            # print AST as pretty-printed JSON
rsigma parse rule.yml --pretty   # same (default)
```

Note: pretty-print is on by default and cannot be disabled.

### `validate` — Validate rules in a directory

Parse and compile all rules in a directory, reporting errors.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a directory of Sigma YAML files |
| `--verbose` / `-v` | flag | `false` | Show details for each file (parse errors, compile errors) |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s) to apply before compilation |

```bash
rsigma validate path/to/rules/ -v              # verbose output
rsigma validate rules/ -p pipelines/ecs.yml    # validate with pipeline
```

### `lint` — Lint rules against the Sigma specification

Run 65 built-in lint rules with optional JSON schema validation.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a Sigma rule file or directory |
| `--schema` / `-s` | string | none | `"default"` to download the official schema (cached 7 days), or a path to a local JSON schema file |
| `--verbose` / `-v` | flag | `false` | Show details for all files, including those that pass |
| `--color` | string | `"auto"` | `auto`, `always`, or `never` |
| `--disable` | string | `""` | Comma-separated lint rule IDs to suppress |
| `--config` | path | none | Explicit path to `.rsigma-lint.yml` (otherwise auto-discovered by walking ancestor directories) |

```bash
rsigma lint path/to/rules/                     # lint all rules
rsigma lint path/to/rules/ -v                  # verbose (show passing files + info-only)
rsigma lint path/to/rules/ --schema default    # + JSON schema validation (downloads + caches)
rsigma lint rule.yml --schema my-schema.json   # local JSON schema
rsigma lint path/to/rules/ --color always      # force color
rsigma lint rules/ --disable missing_description,missing_author  # suppress specific rules
rsigma lint rules/ --config my-lint.yml        # explicit config file
```

**Lint output summary format:**

```
Checked N file(s): X passed, Y failed (A error(s), B warning(s), C info(s))
```

**Schema validation skips** documents with `action: global`, `action: reset`, or `action: repeat` (action fragments).

### `eval` — Evaluate events against rules

Evaluate JSON events against Sigma detection and correlation rules.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--rules` / `-r` | path | required | Path to Sigma rule file or directory |
| `--event` / `-e` | string | none | A single event as a JSON string, or `@path` to read NDJSON from a file. If omitted, reads NDJSON from stdin |
| `--pretty` | flag | **false** | Pretty-print JSON output |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s), applied in priority order |
| `--jq` | string | none | jq filter to extract event payload (conflicts with `--jsonpath`) |
| `--jsonpath` | string | none | JSONPath (RFC 9535) query (conflicts with `--jq`) |
| `--suppress` | string | none | Suppression window for correlation alerts (e.g. `5m`, `1h`, `30s`) |
| `--action` | string | none | `alert` or `reset` — action after correlation fires |
| `--no-detections` | flag | `false` | Suppress detection-level output (only show correlation alerts) |
| `--include-event` | flag | `false` | Include full event JSON in each detection match |
| `--correlation-event-mode` | string | `"none"` | `none`, `full`, or `refs` |
| `--max-correlation-events` | integer | **10** | Max events stored per correlation window |
| `--timestamp-field` | repeatable | `[]` | Event field(s) for timestamp extraction (prepended to the default list) |

**Basic evaluation:**

```bash
# Single event (inline JSON)
rsigma eval -r path/to/rules/ -e '{"CommandLine": "whoami"}'

# Read events from a file (@file syntax — streams as NDJSON, one event per line)
rsigma eval -r path/to/rules/ -e @events.ndjson

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With processing pipeline(s) — applied in priority order
rsigma eval -r rules/ -p sysmon.yml -p custom.yml -e '...'
```

The `@file` syntax is equivalent to piping the file via stdin but avoids the pipe:

```bash
# These are equivalent:
rsigma eval -r rules/ -e @events.ndjson
cat events.ndjson | rsigma eval -r rules/
```

**Event extraction (jq / JSONPath):**

`--jq` and `--jsonpath` are mutually exclusive. Both can return multiple values (e.g. `.records[]`, `$.records[*]`), and each returned value is evaluated as a separate event.

```bash
# Unwrap nested payloads with jq syntax
rsigma eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# JSONPath (RFC 9535)
rsigma eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Array unwrapping — yields one event per element
rsigma eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'

# Stream with extraction
hel run | rsigma eval -r rules/ -p ecs.yml --jq '.event'
```

**Detection output:**

```bash
# Include the full matched event JSON in detection output
rsigma eval -r rules/ --include-event -e '{"CommandLine": "whoami"}'
```

**Correlation options:**

```bash
# Suppression — deduplicate correlation alerts within a time window
rsigma eval -r rules/ --suppress 5m < events.ndjson

# Action on fire — reset state after alert (default: alert)
rsigma eval -r rules/ --suppress 5m --action reset < events.ndjson

# Include full contributing events in correlation output (compressed in memory)
rsigma eval -r rules/ --correlation-event-mode full < events.ndjson

# Include lightweight event references (timestamp + ID) instead
rsigma eval -r rules/ --correlation-event-mode refs < events.ndjson

# Cap stored events per correlation window (default: 10)
rsigma eval -r rules/ --correlation-event-mode full --max-correlation-events 20 < events.ndjson

# Suppress detection output (only show correlation alerts)
rsigma eval -r rules/ --no-detections < events.ndjson

# Custom timestamp field for correlation windowing
rsigma eval -r rules/ --timestamp-field time < events.ndjson
```

### `condition` — Parse a condition expression

Parse a Sigma condition expression and output the AST as pretty-printed JSON. Output is always pretty-printed.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `expr` | positional | required | The condition expression to parse |

```bash
rsigma condition 'selection and not filter'
```

### `stdin` — Parse YAML from stdin

Read a single Sigma YAML document from stdin and output the AST as JSON.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--pretty` / `-p` | flag | **true** | Pretty-print JSON output |

```bash
cat rule.yml | rsigma stdin
```

## File Discovery

All subcommands that accept a directory path scan recursively for `.yml` and `.yaml` files only.

- **Rule loading:** Files are parsed individually; parse errors are accumulated (not fatal). Rules, correlations, and filters from all files are merged into a single collection.
- **Lint config discovery:** Walks ancestor directories from the target path upward, looking for `.rsigma-lint.yml` or `.rsigma-lint.yaml`. The `--config` flag overrides auto-discovery.

## Event Input Modes

| Mode | Input format | Behavior |
|------|-------------|----------|
| `rsigma eval -e '...'` | Inline JSON string | Parses the string as a single JSON object and evaluates it |
| `rsigma eval -e @path` | NDJSON file | Reads the file line-by-line as NDJSON (same behavior as stdin) |
| `rsigma eval` (no `--event`) | NDJSON from stdin | Each non-blank line is parsed as JSON. Blank lines are skipped |
| `rsigma stdin` | Single YAML document | Parses as Sigma YAML → outputs AST as JSON |

Event filters (`--jq`/`--jsonpath`) are applied to every event regardless of input mode.

## Output Format

### Detection match (JSON)

```json
{
  "rule_title": "Detect Whoami",
  "rule_id": "abc-123-...",
  "level": "medium",
  "tags": ["attack.execution"],
  "matched_selections": ["selection"],
  "matched_fields": [
    { "field": "CommandLine", "value": "cmd /c whoami" }
  ],
  "event": null
}
```

The `event` field is present only when `--include-event` is set.

### Correlation match (JSON)

```json
{
  "rule_title": "Brute Force",
  "rule_id": null,
  "level": "high",
  "tags": [],
  "correlation_type": "event_count",
  "group_key": [["User", "admin"]],
  "aggregated_value": 3.0,
  "timespan_secs": 300,
  "events": null,
  "event_refs": null
}
```

`events` is populated when `--correlation-event-mode full`; `event_refs` when `--correlation-event-mode refs`.

### Stderr messages

- `Loaded N rules from PATH` (detection-only) or `Loaded N detection rules + M correlation rules from PATH`
- `Loaded pipeline: NAME (priority N)` per pipeline
- `Event filter: jq 'EXPR'` or `Event filter: jsonpath 'EXPR'` when using `--jq`/`--jsonpath`
- `No matches.` when a single event yields no matches
- `Invalid JSON event: ...` on parse error (single event)
- `Invalid JSON on line N` for NDJSON parse errors (continues processing)
- `Processed N events, M matches.` (detection-only) or `Processed N events, M detection matches, K correlation matches.` (with correlations)

## Pipeline Loading

- Each `-p PATH` loads one pipeline file.
- Pipelines are sorted by `priority` (ascending); lower priority runs first.
- All pipelines are applied in sequence to each rule before compilation.
- `merge_pipelines` is not used by the CLI; each pipeline remains separate with its own state.

## Environment Variables

| Variable | Scope | Behavior |
|----------|-------|----------|
| `NO_COLOR` | `lint` only | When set, disables color output regardless of `--color` setting |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (no errors found for lint; matches may or may not exist for eval) |
| `1` | Error: parse failure, validation error, lint errors found, missing required argument, invalid argument value |

## License

MIT License.

[rsigma workspace]: https://github.com/timescale/rsigma
