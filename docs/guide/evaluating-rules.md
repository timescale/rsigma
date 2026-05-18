# Evaluating Rules

`rsigma engine eval` runs Sigma rules against events that you provide as a one-shot command. It is the right tool for ad-hoc hunting, forensic investigations, replaying historical data, and gating CI pipelines on rule matches. For a long-running daemon with hot-reload and metrics, see [Streaming Detection](streaming-detection.md).

This page covers the five input modes, event extraction with jq and JSONPath, correlation behaviour during eval, and the differences between eval and daemon mode.

## Modes of input

`engine eval` reads events from one of five places. The mode is chosen by which flags you pass:

| Mode | How to invoke | Behaviour |
|------|---------------|-----------|
| Inline JSON | `--event '{"...": "..."}'` | Parse the argument as a single JSON object and evaluate it. |
| NDJSON file | `--event @path/to/events.ndjson` | Read the file line by line, one event per line. Blank lines are skipped. |
| EVTX file | `--event @path/to/log.evtx` | Parse the Windows Event Log binary file and evaluate each record. Requires the `evtx` feature. |
| stdin NDJSON | omit `--event`, pipe via `\|` | Same as the NDJSON file mode but from stdin. Exits after EOF. |
| Inline YAML rule from stdin | `rsigma rule stdin` | Different command, used for parsing rules, not events. |

Every mode produces the same `MatchResult` JSON output on stdout, one object per matched event. Stderr carries status lines.

### Inline events

```bash
rsigma engine eval -r rules/ -e '{"CommandLine": "cmd /c whoami"}'
```

Useful for spot-checks and CI fixtures. For multiple inline events, prefer the NDJSON file form.

### Event files with the `@file` syntax

```bash
rsigma engine eval -r rules/ -e @events.ndjson
```

The `@` prefix tells RSigma to read from a file instead of treating the argument as inline JSON. The file is streamed line by line, so it can be larger than memory. A few practical points:

- One JSON object per line (no pretty-printed multiline JSON).
- Blank lines and lines starting with `//` are silently skipped, matching how detection engineers tend to keep test fixtures.
- Parse errors on individual lines are written to stderr but do not abort the run.
- A summary `Processed N events, M matches.` is written to stderr at the end.

### EVTX (Windows Event Log) files

```bash
rsigma engine eval -r rules/ -e @Security.evtx
rsigma engine eval -r rules/ -p sysmon -e @Microsoft-Windows-Sysmon%4Operational.evtx
```

EVTX files are detected automatically by the `.evtx` extension (case-insensitive). The adapter walks the binary file, converts each record to JSON, and feeds it into the engine. Pair this with the bundled `sysmon` pipeline to add the `EventID` conditions that route to per-event-id selections. Available when the `evtx` feature is compiled in.

### stdin

```bash
cat events.ndjson | rsigma engine eval -r rules/
tail -f -n +0 /var/log/audit.json | rsigma engine eval -r rules/
hel run | rsigma engine eval -r rules/ -p ecs.yml
```

The default mode when no `--event` is given. Equivalent to `--event @-`. Useful for unix pipelines and for feeding RSigma from collectors like [Helr](../ecosystem/helr.md), [Vector](otlp-integration.md), or `tail`.

## Pipelines and field mapping

Real event schemas almost never match Sigma field names directly. Processing pipelines bridge that gap. Pass any number of `--pipeline NAME_OR_PATH` (or `-p`) flags; they are applied to each rule in priority order before compilation:

```bash
rsigma engine eval -r rules/ -p ecs_windows -e '{"process.command_line": "whoami"}'
rsigma engine eval -r rules/ -p sysmon -p custom.yml -e @events.ndjson
```

`ecs_windows` and `sysmon` are [builtin pipelines](../reference/builtin-pipelines.md) embedded in the binary. Anything else is treated as a file path. The full pipeline system is covered in [Processing Pipelines](processing-pipelines.md).

## Event extraction with jq and JSONPath

When your events are wrapped inside an envelope (`.records[]`, `.events[]`, an OTLP-style nested layout), use `--jq` or `--jsonpath` to point RSigma at the part of each line that contains the actual event. The two flags are mutually exclusive.

```bash
rsigma engine eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

rsigma engine eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'
```

Both forms can return multiple values from a single input line. RSigma treats each returned value as its own event:

```bash
rsigma engine eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'
```

This is a common pattern when you ingest a batch envelope (`{"records": [...]}`) and want to evaluate each record individually.

## Correlation in eval mode

Correlation rules (`event_count`, `temporal`, `value_count`, and the five other types) build state in memory while RSigma processes events. In eval mode that state lives only for the duration of the run:

```bash
rsigma engine eval -r rules/ --suppress 5m < events.ndjson
rsigma engine eval -r rules/ --suppress 5m --action reset < events.ndjson
rsigma engine eval -r rules/ --no-detections < events.ndjson
rsigma engine eval -r rules/ --correlation-event-mode full --max-correlation-events 20 < events.ndjson
```

| Flag | Purpose |
|------|---------|
| `--suppress 5m` | Suppress duplicate correlation alerts within the window. |
| `--action alert\|reset` | What to do after a correlation fires: keep state (re-fire on next match) or clear it. |
| `--no-detections` | Drop detection-level output, only emit correlation results. |
| `--correlation-event-mode none\|full\|refs` | Whether to include contributing events in correlation output (and how). |
| `--max-correlation-events N` | Cap the number of events stored per correlation window. Default 10. |
| `--timestamp-field FIELD` | Add a field name to the front of the timestamp extraction list (default `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`). |

For continuous correlation that survives restarts, switch to [streaming detection](streaming-detection.md) where state is persisted to SQLite.

## Detection output and the `event` field

Each match prints one JSON `MatchResult` on stdout:

```json
{
  "rule_title": "Suspicious whoami invocation",
  "rule_id": "8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a",
  "level": "medium",
  "tags": ["attack.discovery", "attack.t1033"],
  "matched_selections": ["selection"],
  "matched_fields": [
    {"field": "CommandLine", "value": "cmd /c whoami"}
  ]
}
```

Use `--include-event` to embed the full event JSON in every match (useful for forensic timelines but it bloats output):

```bash
rsigma engine eval -r rules/ --include-event -e @events.ndjson
```

For per-rule control, set the `rsigma.include_event` custom attribute on the rule (`"true"`/`"false"`). See [Custom Attributes](../reference/custom-attributes.md).

## Input formats other than JSON

`--input-format` accepts `auto` (the default), `json`, `syslog`, `plain`, and the feature-gated `logfmt`, `cef`. Auto-detect tries JSON, then syslog, then plain text:

```bash
tail -f /var/log/syslog | rsigma engine eval -r rules/ --input-format syslog --syslog-tz +05:30
rsigma engine eval -r rules/ --input-format logfmt < app.log
rsigma engine eval -r rules/ --input-format cef < arcsight.log
```

See [Input Formats](input-formats.md) for the full reference.

## Exit codes for CI

By default, `engine eval` exits 0 whether or not any rule fires. To make a CI step fail when a detection or correlation triggers, add `--fail-on-detection`:

```bash
rsigma engine eval -r rules/ --fail-on-detection -e @test-events.ndjson
echo $?
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success. Events were processed cleanly. With `--fail-on-detection`, no rule fired. Per-rule parse errors are logged as warnings and do not change the exit code. |
| 1 | Findings. With `--fail-on-detection`, at least one detection or correlation fired. |
| 2 | The rules path itself could not be read (missing directory, permission denied). Use `rule validate` for a strict gate that fails on per-rule parse or compile errors. |
| 3 | Configuration error. A pipeline file could not be loaded, a CLI argument was invalid, or a `--suppress` duration was malformed. |

The [CI/CD guide](ci-cd.md) shows how to plug this into GitHub Actions, GitLab CI, and similar systems.

## eval vs daemon: when to use which

| Question | Answer |
|----------|--------|
| Do I want a one-shot run that exits after EOF? | `engine eval` |
| Do I need correlation state to survive between runs? | `engine daemon` with `--state-db` |
| Do I want hot-reload of rule files? | `engine daemon` |
| Do I need a Prometheus `/metrics` endpoint? | `engine daemon` |
| Do I need HTTP, NATS, or OTLP input? | `engine daemon` |
| Am I writing a fixture or CI test? | `engine eval` |
| Am I doing forensic replay of EVTX or NDJSON? | `engine eval` |

The same rules, pipelines, and engine internals power both, so a rule that passes a CI eval will behave the same when promoted to the daemon.

## See also

- [CLI reference: `engine eval`](../cli/engine/eval.md) for the full flag table.
- [Streaming Detection](streaming-detection.md) for the daemon.
- [Input Formats](input-formats.md) for JSON, syslog, logfmt, CEF, EVTX, plain text, and auto-detect.
- [Processing Pipelines](processing-pipelines.md) for field mapping.
- [Custom Attributes](../reference/custom-attributes.md) for per-rule overrides of CLI flags.
