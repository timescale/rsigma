# `rsigma engine eval`

One-shot evaluation of Sigma rules against events from a file, stdin, or an inline argument.

## Synopsis

```text
rsigma engine eval [OPTIONS] --rules <RULES>
```

## Description

Loads rules from a file or directory, optionally applies one or more processing pipelines, reads events from `--event` (or stdin), and writes matched `MatchResult` JSON to stdout. Exits when the event source is exhausted.

This is the right tool for ad-hoc threat hunting, forensic replay over `.evtx` and NDJSON files, and any "run rules against this data, then exit" workflow. For a long-running daemon with hot-reload and metrics, use [`engine daemon`](daemon.md). For per-rule assertions over a corpus (a CI fixture harness with expected-vs-actual fire counts and a JUnit report), use [`rule backtest`](../rule/backtest.md).

For a narrative tutorial see [Evaluating Rules](../../guide/evaluating-rules.md).

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-r, --rules <RULES>` | Path to a Sigma rule file or directory of rules (recursive). May also be supplied via `eval.rules` in a config file. |

### Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the [discovery chain](../../reference/configuration.md#discovery). CLI flags still take precedence over file values. |
| `--dry-run` | off | Print the effective `eval` section (defaults < file < env) and exit `0` without evaluating anything. |

### Input selection

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --event <EVENT>` | stdin | Single event as a JSON string, or `@path` to read NDJSON or `.evtx`. Without this flag, reads NDJSON from stdin. |
| `--jq <JQ>` | unset | `jq` filter to extract the event payload from each input object. Example: `--jq '.event'`, `--jq '.records[]'`. Mutually exclusive with `--jsonpath`. |
| `--jsonpath <JSONPATH>` | unset | JSONPath ([RFC 9535](https://www.rfc-editor.org/rfc/rfc9535)) query to extract the event payload. Example: `--jsonpath '$.event'`, `--jsonpath '$.records[*]'`. |
| `--input-format <FORMAT>` | `auto` | Input log format: `auto`, `json`, `syslog`, `plain`. With the `logfmt` and `cef` features: also `logfmt`, `cef`. |
| `--syslog-tz <OFFSET>` | `+00:00` | Timezone offset for RFC 3164 syslog parsing. Format: `+HH:MM` or `-HH:MM`. |
| `--syslog-strip-bom <BOOL>` | `true` | Strip a leading UTF-8 BOM (`U+FEFF`) from RFC 5424 syslog messages. RFC 5424 treats the BOM as an encoding marker, not content. Pass `--syslog-strip-bom false` to keep it byte-for-byte. |

### Pipeline

| Flag | Description |
|------|-------------|
| `-p, --pipeline <PIPELINES>` | Processing pipeline(s) to apply. Accepts the builtin names (`ecs_windows`, `sysmon`) or YAML file paths. Repeatable; applied in priority order. |

### Output

The global `--output-format` / `--color` / `--quiet` / `--no-stats` flags apply here too; see [Output Formats](../../reference/output.md). The flags below are eval-specific.

| Flag | Default | Description |
|------|---------|-------------|
| `--pretty` | off | Pretty-print JSON output. Kept for backwards compatibility; equivalent to `--output-format json` with pretty-printing on. |
| `--no-detections` | off | Suppress detection output for rules that exist only to feed correlations (`generate: false`). |
| `--include-event` | off | Embed the full event JSON in every `MatchResult`. Equivalent to setting `rsigma.include_event: "true"` per-rule. |
| `--match-detail <LEVEL>` | `off` | Match-detail verbosity: `off` (field + value only), `summary` (adds matcher kind, selection, case sensitivity, and reports keyword/absence matches), or `full` (also records the matched pattern). See [Evaluating Rules](../../guide/evaluating-rules.md#match-detail). |

### Correlation behavior

| Flag | Default | Description |
|------|---------|-------------|
| `--suppress <DURATION>` | unset | Suppress duplicate correlation alerts within the window (`5m`, `1h`, `30s`). |
| `--action <ACTION>` | `alert` | Post-fire action for correlations: `alert` (keep state, re-alert on next match) or `reset` (clear window state). |
| `--correlation-event-mode <MODE>` | `none` | Whether to embed contributing events in correlation output: `none`, `full` (deflate-compressed full bodies), `refs` (timestamp + ID only). |
| `--max-correlation-events <N>` | `10` | Cap on stored events per correlation window when `--correlation-event-mode` is not `none`. Oldest evicted. |
| `--max-state-entries <N>` | `100000` | Hard cap on correlation state entries across all correlations and group keys. When reached, the stalest entries are evicted to 90% capacity and a warning is logged. |
| `--max-group-entries <N>` | unset | Cap on retained entries within a single correlation group's window state. Bounds within-window growth of chatty groups; oldest entries are dropped (session windows keep their span anchor). Unset = unbounded. Equivalent to the `rsigma.max_group_entries` custom attribute. |
| `--timestamp-field <FIELD>` | unset | Field name to prepend to the timestamp extraction priority list. Default list: `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`. Repeatable. |

### Performance (advanced)

| Flag | Default | Description |
|------|---------|-------------|
| `--bloom-prefilter` | off | Enable per-field bloom filter over positive substring needles. Useful for IOC-heavy rule sets against mostly-non-matching telemetry. See [Performance Tuning](../../guide/performance-tuning.md#bloom-pre-filter-for-substring-heavy-rule-sets). |
| `--bloom-max-bytes <BYTES>` | `1048576` | Memory budget for the bloom index (1 MiB default). No effect without `--bloom-prefilter`. |
| `--cross-rule-ac` | off | Enable the cross-rule Aho-Corasick pre-filter. Available when compiled with the `daachorse-index` Cargo feature. See [Performance Tuning](../../guide/performance-tuning.md#cross-rule-aho-corasick-pre-filter). |

### Field observability (offline coverage report)

The same gap / broken-coverage signals exposed by the daemon's `/api/v1/fields*` endpoints are available offline as a one-shot report:

| Flag | Default | Description |
|------|---------|-------------|
| `--observe-fields` | off | Record the field keys of every evaluated event and emit a coverage report at end-of-run. The report has the same JSON shape as `GET /api/v1/fields`, so the same `jq` queries work against either runtime (suited for CI gap analysis). |
| `--observe-fields-max-keys <N>` | `10000` | Hard ceiling on distinct field names tracked. New keys are dropped after the cap (and counted via `overflow_dropped` in the report). |
| `--observe-fields-report <PATH>` | unset | Write the report to a file. When omitted (and `--observe-fields` is set), the report goes to stderr so detections on stdout stay machine-consumable. |

```bash
# CI: keep stdout for detection NDJSON, stderr for logs, report in its own file
rsigma engine eval -r rules/ -e @events.ndjson \
    --observe-fields \
    --observe-fields-report coverage.json

# Quick interactive run: the report shows up on stderr alongside the
# "Processed N events, M matches." line
rsigma engine eval -r rules/ -e @events.ndjson --observe-fields
```

See [Observability: detection coverage](../../guide/observability.md#detection-coverage-with-observe-fields) for the operator workflow shared with the daemon path.

### Schema routing

Recognize each event's schema and evaluate it against the pipeline-set bound to that schema (instead of applying one pipeline set to every event). See the [Schema Routing](../../guide/schema-routing.md) guide.

| Flag | Default | Description |
|------|---------|-------------|
| `--schema-routing` | off | Classify each event and route it to its schema's bound pipeline-set; detections feed one shared correlation store. |
| `--schema-config <PATH>` | unset | YAML with the `schemas:` signatures and `routing:` bindings (`bindings`, `default_pipelines`, `on_unknown`). |
| `--on-unknown <POLICY>` | `warn` | Policy for events that match no schema: `warn`, `drop`, `passthrough`, or `error`. Overrides the config value. |

These flags may also be supplied via the `eval.schema` block in a [config file](../../reference/configuration.md) (`routing`, `config`, `on_unknown`); a flag always wins over the file.

### Logsource-aware evaluation

Skip rules whose `product`/`service`/`category` conflicts with the event's declared logsource. Conflict-based and fail-open. See the [Logsource-Aware Evaluation](../../guide/logsource-routing.md) guide.

| Flag | Default | Description |
|------|---------|-------------|
| `--logsource-routing` | off | Enable conflict-based logsource pruning. |
| `--logsource-field-map <MAP>` | `product=product,service=service,category=category` | Event field names each dimension is read from, as `product=...,service=...,category=...`. |
| `--event-logsource <LOGSOURCE>` | unset | Static event logsource applied when the field is absent, as `product=windows,...`. An `-e @file.evtx` input implies `product: windows` when unset. |

These flags may also be supplied via the `eval.logsource_routing` block in a [config file](../../reference/configuration.md) (`enabled`, `field_map`, `event_logsource`); a flag always wins over the file.

### CI gating

| Flag | Description |
|------|-------------|
| `--fail-on-detection` | Exit with code `1` when any detection or correlation fires. |

## Examples

### Single inline event

```bash
rsigma engine eval -r rules/ -e '{"CommandLine":"cmd /c whoami"}'
```

### NDJSON file with pretty output

```bash
rsigma engine eval -r rules/ --pretty -e @events.ndjson
```

### Table view for interactive triage

```bash
rsigma engine eval -r rules/ -e @events.ndjson --output-format table
```

A width-aligned `LEVEL | RULE | TYPE | DETAIL` table appears on stdout. Use `--output-format csv` or `--output-format tsv` to pipe into a spreadsheet instead. See [Output Formats](../../reference/output.md).

### EVTX file with the bundled Windows-mapping pipeline

```bash
rsigma engine eval -r rules/ -e @Security.evtx
```

EVTX records are nested under `Event.System.*` and `Event.EventData.*`; rules must reference fields by their full dotted path. See [Input Formats](../../guide/input-formats.md#evtx-windows-event-log-feature-gated).

### Tail a JSON log file into the engine

```bash
tail -F /var/log/app.json | rsigma engine eval -r rules/
```

### Extract events from a wrapper envelope

```bash
rsigma engine eval -r rules/ --jq '.records[]' < otlp-batch.ndjson
```

### CI fixture: assert nothing matches

```bash
rsigma engine eval -r rules/ --fail-on-detection -e @ci/negative.ndjson
```

Exits `1` if any rule fires. Exits `0` if the fixture stays quiet.

### Apply a builtin pipeline

```bash
rsigma engine eval -r rules/ -p ecs_windows -e '{"process.command_line": "whoami"}'
```

### Correlation with suppression

```bash
rsigma engine eval -r rules/ --suppress 5m --action reset \
    --correlation-event-mode refs --max-correlation-events 50 \
    < security-events.ndjson
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Events processed cleanly. With `--fail-on-detection`, no rule fired. Per-rule parse errors are logged as warnings but do not change the exit code. |
| `1` | With `--fail-on-detection`, at least one detection or correlation fired. |
| `2` | The rules path itself could not be read. Use [`rule validate`](../rule/validate.md) for a strict per-rule gate that fails on parse or compile errors. |
| `3` | Configuration error: bad `-p`, malformed `--suppress`, invalid `--jq` filter, etc. |

## See also

- [Evaluating Rules](../../guide/evaluating-rules.md) for the narrative version with event-extraction patterns and correlation walkthroughs.
- [Input Formats](../../guide/input-formats.md) for JSON, syslog, logfmt, CEF, EVTX, OTLP, plain text, and auto-detect.
- [Processing Pipelines](../../guide/processing-pipelines.md) for `-p` semantics and the builtin pipelines.
- [Performance Tuning](../../guide/performance-tuning.md) for `--bloom-prefilter` and `--cross-rule-ac`.
- [CI/CD](../../guide/ci-cd.md) for `--fail-on-detection` patterns.
- [`rule backtest`](../rule/backtest.md) for per-rule corpus assertions and CI reports.
- [`engine daemon`](daemon.md) for the long-running streaming counterpart.
