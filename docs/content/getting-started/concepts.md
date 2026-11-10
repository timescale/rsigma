---
description: "Core RSigma concepts: what Sigma rules are, processing pipelines, the eval and daemon split, rule conversion, correlation, and the noun-led CLI."
---

# Core Concepts

A short tour of the ideas you run into when working with RSigma. If you already know Sigma, skim for RSigma-specific details: eval vs daemon, pipelines, conversion, and the noun-led CLI. If you are new to Sigma, the primer below is enough to follow the rest of these docs; authoring depth lives on SigmaHQ.

## What is Sigma?

[Sigma](https://sigmahq.io/) is a vendor-agnostic YAML format for describing log-event detection rules. A rule declares:

- A **[logsource](https://sigmahq.io/docs/basics/log-sources.html)** that names where the events come from (`category: process_creation`, `product: windows`, ...).
- One or more **selections** that match field values, like `CommandLine|contains: 'whoami'`.
- A **[condition](https://sigmahq.io/docs/basics/conditions.html)** expression combining selections with `and`, `or`, `not`, and quantifiers (`1 of selection_*`, `all of them`).
- Metadata: title, id, level, tags, references, false positives, and so on.

[SigmaHQ](https://github.com/SigmaHQ/sigma) maintains a large community rule repository. RSigma implements the [Sigma v2.1.0 specification](https://sigmahq.io/sigma-specification/) and is tested against that corpus on every CI run. Authoring questions belong on [SigmaHQ's docs](https://sigmahq.io/docs/guide/getting-started.html); runtime, conversion, and operational questions belong here.

## The three kinds of rules

RSigma understands the full Sigma v2 family:

| Kind | Purpose | Example |
|------|---------|---------|
| **Detection** | Match individual events | "Flag any command line containing `whoami`" |
| **Correlation** | Aggregate across events over time (`event_count`, `value_count`, `temporal`, and related types) | "Five failed logins from the same user within five minutes" |
| **Filter** | Inject `AND NOT` conditions into other rules for centralized tuning | "Exclude actions by service accounts whose name starts with `svc_`" |

Loading a directory of YAML files yields one in-memory collection of all three. Evaluation and conversion operate on that collection as a whole.

## Selections, modifiers, and conditions

A detection block looks like this:

```yaml
detection:
    selection:
        EventID: 4625
        TargetUserName|endswith: '$'
    filter_ip:
        SourceAddress|cidr: '10.0.0.0/8'
    condition: selection and not filter_ip
```

The keys under `detection` are named selections. The `condition` line is a boolean expression over those names. Field modifiers such as `endswith`, `cidr`, `contains`, and `re` change how a field value is matched. RSigma implements the full Sigma modifier set; see the [parser library reference](../library/parser.md) for the complete list.

## Two modes: eval vs daemon

RSigma offers two evaluation modes that share the same engine:

| | `rsigma engine eval` | `rsigma engine daemon` |
|---|---|---|
| Lifetime | One-shot; exits after EOF | Long-running; stays alive after stdin EOF |
| Inputs | Inline event, `@file`, stdin NDJSON, EVTX files | stdin, HTTP POST, NATS JetStream, OTLP HTTP/gRPC |
| Correlation state | In-memory only, lost on exit | Persisted to SQLite, survives restarts |
| Hot-reload | No | File watcher + `SIGHUP` + `POST /api/v1/reload` |
| Health checks | None | `/healthz`, `/readyz`, `/metrics` |
| Output | stdout (NDJSON or pretty JSON) | Fan-out to stdout, file, NATS |
| Use cases | CI rule validation, forensic replay, ad-hoc hunting | Production streaming detection |

Rule of thumb: anything that runs in a terminal and exits is `engine eval`; anything that runs as a service is `engine daemon`.

See [evaluating rules](../guide/evaluating-rules.md) and [streaming detection](../guide/streaming-detection.md) for full tutorials.

## Processing pipelines

Pipelines rewrite rules before compilation so Sigma field names match your event schema. For example, `CommandLine` may become `process.command_line` (ECS) or a JSONB path in PostgreSQL.

```yaml
name: My ECS Mapping
priority: 20
transformations:
  - id: ecs_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      Image: process.executable
    rule_conditions:
      - type: logsource
        product: windows
```

RSigma supports the pySigma-compatible transformation set and ships builtin pipelines (`ecs_windows`, `sysmon`) you can pass by name with `-p`. Multiple pipelines chain by `priority`. Dynamic pipelines can also fetch values from HTTP, files, commands, or NATS at load time; see [processing pipelines](../guide/processing-pipelines.md).

## Conversion backends

Instead of evaluating rules in process, `rsigma backend convert` emits backend-native queries for historical hunting:

| Backend | Target names | Output |
|---------|--------------|--------|
| PostgreSQL/TimescaleDB | `postgres`, `postgresql`, `pg` | SQL (default, view, timescaledb, continuous_aggregate, sliding_window) |
| LynxDB | `lynxdb` | SPL2-compatible search |
| Fibratus | `fibratus` | Fibratus rule YAML |
| Test | `test` | Backend-neutral text (for testing pipelines) |

New backends plug in via the `Backend` trait; see [adding backends](../developers/adding-backends.md) and the [rule conversion guide](../guide/rule-conversion.md).

## Input formats

Events are accepted as JSON/NDJSON by default, with auto-detection across syslog, logfmt, CEF, EVTX, OTLP, and plain text. Several formats are feature-gated. See [input formats](../guide/input-formats.md) for the full matrix and flags.

## The command groups

The CLI is noun-led: every group is a noun, every leaf is a verb.

| Group | Purpose |
|-------|---------|
| `engine` | Run and inspect rules against events (`eval`, `daemon`, and related tools) |
| `rule` | Operate on rule files (parse, lint, draft, backtest, coverage, and more) |
| `backend` | Generate backend-native queries |
| `pipeline` | Diff pipeline rewrites and resolve dynamic sources |
| `config` | Scaffold, validate, and reload layered YAML configuration |
| `mcp` | Run the Model Context Protocol server (feature-gated) |

See the [CLI reference](../cli/index.md) for every subcommand.

## Output

Detection and correlation both serialize as a flat `EvaluationResult` JSON object on stdout (NDJSON when streaming). Downstream consumers tell them apart by field presence: detections carry `matched_fields`, correlations carry `correlation_type`.

A detection match looks like this (default match detail):

```json
{"rule_title":"...","rule_id":"...","level":"medium","tags":["..."],"matched_selections":["selection"],"matched_fields":[{"field":"...","value":"..."}]}
```

The `event` field is omitted unless `--include-event` is set or the rule enables `rsigma.include_event`. Optional header fields such as `rule_id` and `level` serialize as `null` when absent; empty `custom_attributes` and unset `enrichments` are omitted.

A correlation firing looks like this:

```json
{
  "rule_title": "Brute Force",
  "rule_id": "...",
  "level": "high",
  "tags": ["..."],
  "correlation_type": "event_count",
  "group_key": [["User", "admin"]],
  "aggregated_value": 5.0,
  "timespan_secs": 300
}
```

`events` and `event_refs` appear only when correlation event mode is `Full` or `Refs`. The [HTTP API reference](../reference/http-api.md) and [eval library docs](../library/eval.md) cover the full field set.

## Where to go next

- **Tutorial path:** [quick start](quick-start.md) -> [evaluating rules](../guide/evaluating-rules.md) -> [streaming detection](../guide/streaming-detection.md).
- **Reference path:** [CLI](../cli/index.md), [linting rules](../reference/lint-rules.md), [Prometheus metrics](../reference/metrics.md), [feature flags](../reference/feature-flags.md).
- **Architecture path:** [crate map and data flow](../reference/architecture.md), [library API](../library/index.md), [contributing](../contributing.md).
