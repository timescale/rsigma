# Evaluating Rules

`rsigma engine eval` runs Sigma rules against events as a one-shot command. Use it for ad-hoc hunting, forensic replay, and CI gates. For a long-running daemon with hot-reload and metrics, see [Streaming Detection](streaming-detection.md).

This page covers the four event input modes, envelopes and non-JSON formats, correlation flags in eval, stdout shape (`--include-event`, `--match-detail`), debugging misses with `engine explain`, and exit codes for CI.

## Modes of input

`engine eval` reads events from one of four places. The mode is chosen by which flags you pass:

| Mode | How to invoke | Behavior |
|------|---------------|----------|
| Inline JSON | `--event '{"...": "..."}'` | Parse the argument as a single JSON object and evaluate it. |
| NDJSON file | `--event @path/to/events.ndjson` | Read the file line by line, one event per line. Blank lines are skipped. |
| EVTX file | `--event @path/to/log.evtx` | Parse the Windows Event Log binary file and evaluate each record. Requires the `evtx` feature. |
| stdin NDJSON | omit `--event`, or `--event @-` | Same streaming semantics as the NDJSON file mode, but from stdin. Exits after EOF. |

Every mode produces the same `EvaluationResult` JSON on stdout, one object per match (a single event can fire many rules). Stderr carries status lines.

### Inline events

```bash
rsigma engine eval -r rules/ -e '{"CommandLine": "cmd /c whoami"}'
```

Best for spot-checks and tiny CI fixtures. For more than one event, prefer `@file` or stdin so you do not fight shell quoting.

### Event files with the `@file` syntax

```bash
rsigma engine eval -r rules/ -e @events.ndjson
```

The `@` prefix reads from a file instead of treating the argument as inline JSON. The file is streamed line by line, so it can be larger than memory:

- One JSON object per line (no pretty-printed multiline JSON).
- Blank lines and lines starting with `//` are silently skipped, matching how detection engineers tend to keep test fixtures.
- Parse errors on individual lines go to stderr but do not abort the run.
- Stderr closes with `Processed N events, M matches.`

To reproduce a miss locally, capture a window from a running daemon with [`rsigma engine tap`](../cli/engine/tap.md) (optionally redacting fields), then replay it:

```bash
rsigma engine tap -o fixture.ndjson
rsigma engine eval -r candidate-rules/ -e @fixture.ndjson
```

### EVTX (Windows Event Log) files

```bash
rsigma engine eval -r rules/ -e @Security.evtx
rsigma engine eval -r rules/ -p sysmon -e @Microsoft-Windows-Sysmon%4Operational.evtx
```

EVTX is detected by the `.evtx` extension (case-insensitive). The adapter walks the binary file, converts each record to JSON, and feeds it into the engine. Pair with the bundled `sysmon` pipeline when you need `EventID` routing into per-event-id selections. Available when the `evtx` feature is compiled in.

### stdin

Omit `--event` (or pass `--event @-`) to read NDJSON from stdin. That is the default for unix pipelines: collectors and `tail` feed events until EOF, then eval exits.

```bash
cat events.ndjson | rsigma engine eval -r rules/
tail -f -n +0 /var/log/audit.json | rsigma engine eval -r rules/
helr run | rsigma engine eval -r rules/ -p ecs.yml
```

Use eval for one-shot pipes and batch replay. For a long-lived service, start [`engine daemon`](streaming-detection.md#start-the-daemon) with `--input http` (or NATS/unix) and post events with curl or a collector; a finite stdin pipe into the daemon also ends the process once the writer closes. Collectors such as [Helr](../ecosystem/helr.md) and [Vector](otlp-integration.md) fit either path depending on whether you want a one-shot run or a service.

## Pipelines and field mapping

Real event schemas almost never match Sigma field names directly. Pass any number of `--pipeline NAME_OR_PATH` (or `-p`) flags; they apply to each rule in priority order before compilation:

```bash
rsigma engine eval -r rules/ -p ecs_windows -e '{"process.command_line": "whoami"}'
rsigma engine eval -r rules/ -p sysmon -p custom.yml -e @events.ndjson
```

`ecs_windows` and `sysmon` are [builtin pipelines](../reference/builtin-pipelines.md). Anything else is a file path. Full detail: [Processing Pipelines](processing-pipelines.md).

## Event extraction with jq and JSONPath

When events sit inside an envelope (`.records[]`, `.events[]`, nested OTLP-style layouts), use `--jq` or `--jsonpath` to select the object that should be evaluated. The flags are mutually exclusive.

```bash
rsigma engine eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'
rsigma engine eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'
```

Both can return multiple values from one input line; each returned value is evaluated as its own event:

```bash
rsigma engine eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'
```

That pattern is common for batch envelopes (`{"records": [...]}`) where you want each record evaluated individually.

## Input formats other than JSON

`--input-format` accepts `auto` (default), `json`, `syslog`, `plain`, and the feature-gated `logfmt` and `cef`. Auto-detect tries JSON, then syslog, then plain text:

```bash
tail -f /var/log/syslog | rsigma engine eval -r rules/ --input-format syslog --syslog-tz +05:30
rsigma engine eval -r rules/ --input-format logfmt < app.log
rsigma engine eval -r rules/ --input-format cef < arcsight.log
```

See [Input Formats](input-formats.md) for the full matrix and flags.

## Correlation in eval mode

Correlation rules build state in memory for the duration of the run. That state is discarded when eval exits; use the daemon with `--state-db` when windows must survive restarts.

```bash
rsigma engine eval -r rules/ --suppress 5m < events.ndjson
rsigma engine eval -r rules/ --correlation-event-mode full --max-correlation-events 20 < events.ndjson
```

By default, a detection referenced by a correlation contributes to correlation state but does not produce a standalone result. Set top-level `generate: true` on a correlation when its referenced detections should also be standalone output, or pass `--emit-detections` to emit every detection match for that invocation. {{ added "0.24.0" }}

The same applies to a correlation referenced by another correlation. In a chain where a detection feeds a child correlation that feeds a parent correlation, only the parent produces a result; the child still updates the parent's state. `generate: true` on the parent also emits the child, and `--emit-detections` emits every detection and correlation match in the chain. {{ added "0.24.0" }}

| Flag | Purpose |
|------|---------|
| `--suppress 5m` | Suppress duplicate correlation alerts within the window. |
| `--action <alert,reset>` | After a correlation fires: `alert` keeps state and can re-fire; `reset` clears the window. |
| `--emit-detections` | Emit detection and correlation matches even when they only feed correlations. |
| `--no-detections` | Deprecated compatibility flag. Correlation-only detections are already suppressed by default. |
| `--correlation-event-mode <none,full,refs>` | Include contributing events: `none` (zero overhead), `full` (deflate-compressed bodies), `refs` (timestamp + ID only). |
| `--max-correlation-events N` | Cap events stored per correlation window. Default 10. |
| `--max-state-entries N` | Hard cap on correlation state entries across all correlations and group keys. Default 100,000. |
| `--max-group-entries N` | Cap retained entries within a single group's window. Unset = unbounded. |
| `--timestamp-field FIELD` | Prepend a field name to the timestamp extraction list (default `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`). |

For continuous correlation, see [streaming detection](streaming-detection.md).

## Detection output

Each match prints one JSON `EvaluationResult` on stdout. Detection and correlation share a flat object shape; consumers tell them apart by `matched_fields` vs `correlation_type` (see [Core Concepts](../getting-started/concepts.md#output)).

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

`matched_selections` lists, once each, the selections whose match decides the condition, and `matched_fields` comes from those selections only. A selection that matched but did not make the rule fire is left out: `(s1 and s2) or s3` firing on `s3` reports only `s3` even when `s1` matched, and `a and not b` never reports `b`. {{ added "0.25.0" }}

### Including the event body

`--include-event` embeds the full event JSON in every match. Useful for forensic timelines; it also bloats output:

```bash
rsigma engine eval -r rules/ --include-event -e @events.ndjson
```

For per-rule control, set `rsigma.include_event` on the rule (`"true"` / `"false"`). See [Custom Attributes](../reference/custom-attributes.md).

### Match detail

By default each `matched_fields` entry is `{field, value}`. `--match-detail` records why each field matched, which helps when triaging a noisy rule or building a downstream UI:

```bash
rsigma engine eval -r rules/ --match-detail full -e '{"CommandLine": "cmd /c whoami"}'
```

| Level | What you get |
|-------|--------------|
| `off` (default) | `{field, value}` only. Byte-for-byte the historical shape. |
| `summary` | Adds `selection`, `matcher` (for example `contains` or `endswith`), and `case_sensitive`. Also reports keyword matches (field `"keyword"`) and absence matches (`value: null`) that `off` drops. |
| `full` | Everything in `summary` plus `pattern` (truncated for very long pattern sets). |

A `full` entry looks like:

```json
{
  "field": "CommandLine",
  "value": "cmd /c whoami",
  "selection": "selection",
  "matcher": "contains",
  "pattern": "whoami",
  "case_sensitive": false
}
```

Negated matchers add `"negated": true`. Higher levels enlarge each detection line and only run when a rule matches, so they cost nothing on the non-matching hot path. The daemon exposes the same control via `--match-detail` or `daemon.engine.match_detail`.

For array object-scope matches (`field[any]` / `[all]` / `[all_or_empty]` / `[none]`), `matched_fields` records the binding members with indexed paths (`connections[0].protocol`, `connections[0]` for an element-self item) instead of the whole array container. `[any]` emits the members that satisfied the body; `[all]` emits every member up to a cap of 32 (index order); `[none]` and a vacuous `[all_or_empty]` keep the container entry. A scalar treated as one member uses the un-indexed path (`connections.protocol`) so it still resolves through field lookup. One caveat for dotted container fields: when the field itself is a dot path that crosses an array (`a.b[any]` where `a` is an array of objects), field lookup flattens the intermediate arrays into one synthesized member list, so the emitted indices refer to that flattened view and may not resolve positionally against the original document. Recorded paths are best-effort detail, never a verdict surface.

## Debugging why a rule did not match

`--match-detail` explains a match. The harder question is why a rule did not match the event you wrote it for. The answer is usually a single field: a renamed key, a wrong value, or a casing difference. [`engine explain`](../cli/engine/explain.md) runs a non-short-circuiting evaluator over one rule and one event and prints, for every condition node and field, whether it passed and why not:

```bash
rsigma engine explain -r rules/ -e '{"Image":"C:\\Windows\\cmd.exe"}'
```

```text
Suspicious PowerShell (ps-1): NO MATCH
  FAIL all of:
    FAIL selection
      FAIL Image|endswith "\powershell.exe"  actual="C:\Windows\cmd.exe" (value mismatch)
      PASS CommandLine|contains "-enc" (matched)
    FAIL not:
      PASS filter
        PASS User|exact "system" (matched)
```

Each failed leaf carries a reason: `field absent`, `value mismatch` (with the actual value), `case mismatch`, an existence-check failure, or no keyword match. The verdict always agrees with `engine eval`, since it runs the same matchers. Add `--output-format json` for a machine-readable trace, `--rule-id` to focus one rule, and `-p` to explain through a pipeline (with `--show-pipeline` to print the rewrite first).

Array object-scope traces include the member index, each predicate, and nested scopes (`rules[any]` containing `ip[all]`). See [Array Matching](array-matching.md) for a worked `engine explain` tree.

When the field name itself is in doubt, [`pipeline diff`](../cli/pipeline/diff.md) shows how a pipeline rewrites the rule before evaluation:

```bash
rsigma pipeline diff -r rules/ -p ecs_windows --rule-id ps-1
```

For correlations, [`engine eval --dump-correlation-state`](../cli/engine/eval.md) prints the final window state after a replay. The daemon exposes the same view live at `GET /api/v1/correlations/state`.

## Exit codes for CI

By default, `engine eval` exits 0 whether or not any rule fires. To fail a CI step when a detection or correlation triggers, add `--fail-on-detection`:

```bash
rsigma engine eval -r rules/ --fail-on-detection -e @test-events.ndjson
echo $?
```

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

The same rules, pipelines, and engine internals power both, so a rule that passes a CI eval behaves the same when promoted to the daemon.

## See also

- [CLI reference: `engine eval`](../cli/engine/eval.md) for the full flag table.
- [Streaming Detection](streaming-detection.md) for the daemon.
- [Input Formats](input-formats.md) for JSON, syslog, logfmt, CEF, EVTX, plain text, and auto-detect.
- [Processing Pipelines](processing-pipelines.md) for field mapping.
- [Custom Attributes](../reference/custom-attributes.md) for per-rule overrides of CLI flags.
