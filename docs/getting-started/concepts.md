# Core Concepts

A short, opinionated tour of the ideas you will run into when working with RSigma. If you already know Sigma, skim this for RSigma-specific details (eval vs daemon modes, pipelines, and the noun-led CLI). If you are new to Sigma, this page links to the canonical specification so you can dive deeper.

## What is Sigma?

[Sigma](https://sigmahq.io/) is a generic, vendor-agnostic format for describing log-event detection rules in YAML. A rule declares:

- A **[logsource](https://sigmahq.io/docs/basics/log-sources.html)** that names where the events come from (`category: process_creation`, `product: windows`, ...).
- One or more **selections** that match field values, like `CommandLine|contains: 'whoami'`. See the [rules guide](https://sigmahq.io/docs/basics/rules.html) and [field modifiers](https://sigmahq.io/docs/basics/modifiers.html).
- A **[condition](https://sigmahq.io/docs/basics/conditions.html)** expression combining selections with `and`, `or`, `not`, and quantifiers (`1 of selection_*`, `all of them`).
- Metadata: title, id, level, tags, references, false positives, etc.

[SigmaHQ](https://github.com/SigmaHQ/sigma) maintains a community rule repository of several thousand rules covering Windows, Linux, macOS, cloud, SaaS, and network telemetry. RSigma can run against the entire SigmaHQ corpus without modification.

RSigma implements the [Sigma v2.1.0 specification](https://sigmahq.io/sigma-specification/) and is tested against the SigmaHQ corpus on every CI run. Authoring questions almost always belong on SigmaHQ; runtime, conversion, and operational questions belong here.

### SigmaHQ reading list

For deeper dives into rule authoring, the official Sigma docs are the canonical source:

| Topic | Where |
|-------|-------|
| Getting started writing rules | [sigmahq.io/docs/guide/getting-started.html](https://sigmahq.io/docs/guide/getting-started.html) |
| Rule structure and metadata | [sigmahq.io/docs/basics/rules.html](https://sigmahq.io/docs/basics/rules.html) |
| Field modifiers (`contains`, `re`, `cidr`, ...) | [sigmahq.io/docs/basics/modifiers.html](https://sigmahq.io/docs/basics/modifiers.html) |
| Condition expressions (`and`, `or`, `1 of`, ...) | [sigmahq.io/docs/basics/conditions.html](https://sigmahq.io/docs/basics/conditions.html) |
| Log sources and taxonomy | [sigmahq.io/docs/basics/log-sources.html](https://sigmahq.io/docs/basics/log-sources.html) |
| Correlation rules | [sigmahq.io/docs/meta/correlations.html](https://sigmahq.io/docs/meta/correlations.html) |
| Filter rules | [sigmahq.io/docs/meta/filters.html](https://sigmahq.io/docs/meta/filters.html) |
| Pipelines (pySigma convention) | [sigmahq.io/docs/digging-deeper/pipelines.html](https://sigmahq.io/docs/digging-deeper/pipelines.html) |
| Formal specification | [sigmahq.io/sigma-specification](https://sigmahq.io/sigma-specification/) |
| Community rule repository | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |

## The three kinds of rules

RSigma understands the full Sigma v2 family, not just simple detection rules.

| Kind | Purpose | Example |
|------|---------|---------|
| **Detection** | Match individual events. Most common kind of rule. | "Flag any command line containing `whoami`." |
| **Correlation** | Aggregate across events over time. Eight types: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, `value_median`. | "Five failed logins from the same user within five minutes." |
| **Filter** | Inject `AND NOT` conditions into other rules. Used for centralized tuning without editing the original rules. | "Exclude actions performed by service accounts whose name starts with `svc_`." |

A `SigmaCollection` is the in-memory bundle of all three. Loading a directory of YAML files yields one collection, and conversion or evaluation operates on the collection as a whole.

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

The keys under `detection` (`selection`, `filter_ip`) are named selections. The `condition` line is a boolean expression over those names.

**Field modifiers** transform how a field value is matched. RSigma implements all 30+ modifiers defined by the Sigma spec, including:

- **String matching:** `contains`, `startswith`, `endswith`, `cased`, `re`, `wide`, `utf16`, `windash`, `base64`, `base64offset`
- **Pattern matching:** `cidr`, `expand`
- **Numeric comparison:** `gt`, `gte`, `lt`, `lte`, `neq`
- **Field references:** `fieldref`, `exists`
- **Linking:** `all` (AND across values), `i`, `m`, `s` (regex flags)

See the [linter and parser reference](../library/parser.md) for the full list and a complete description of each modifier.

## Two modes: eval vs daemon

RSigma offers two evaluation modes that share the same engine:

| | `rsigma engine eval` | `rsigma engine daemon` |
|---|---|---|
| Lifetime | One-shot. Exits after EOF. | Long-running. Stays alive after stdin EOF. |
| Inputs | Inline event, `@file`, stdin NDJSON, EVTX files. | stdin, HTTP POST, NATS JetStream, OTLP HTTP/gRPC. |
| Correlation state | In-memory only, lost on exit. | Persisted to SQLite, survives restarts. |
| Hot-reload | No. | File watcher + `SIGHUP` + `POST /api/v1/reload`. |
| Health checks | None. | `/healthz`, `/readyz`, `/metrics`. |
| Output | stdout (NDJSON or pretty JSON). | Fan-out to stdout, file, NATS. |
| Use cases | CI rule validation, forensic replay, ad-hoc hunting. | Production streaming detection. |

Rule of thumb: anything that runs in a terminal and exits is `engine eval`; anything that runs as a service is `engine daemon`. The flags overlap heavily because the underlying engine is the same.

See [evaluating rules](../guide/evaluating-rules.md) and [streaming detection](../guide/streaming-detection.md) for full tutorials.

## Processing pipelines

Pipelines are a pySigma-compatible system for rewriting rules before they are compiled. They handle the impedance mismatch between how Sigma rules name fields (e.g. `CommandLine`) and how your events actually name fields (e.g. `process.command_line` if you ship through Elastic, or `data.event.process.commandLine` if you use a JSONB column in PostgreSQL).

A pipeline YAML defines a list of transformations to apply, optionally gated by rule conditions:

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

RSigma supports 26 transformation types covering field renames, value transforms, logsource rewriting, condition injection, drop rules, and backend-specific configuration. Multiple pipelines can be chained with `priority` controlling order.

RSigma also ships two **builtin pipelines** (`ecs_windows`, `sysmon`) that can be referenced by name without external files. Use them with `-p ecs_windows` instead of `-p pipelines/my-ecs.yml`.

### Dynamic pipelines

Pipelines can also fetch values from external sources (HTTP, files, commands, NATS) and inject them into transformations at load time. This is a capability unique to RSigma and is described in detail in [the processing pipelines guide](../guide/processing-pipelines.md#dynamic-pipelines).

## Conversion backends

Instead of evaluating rules in process, RSigma can convert them to backend-native queries for historical threat hunting. The `rsigma backend convert` command walks each rule's AST and emits a query string for the chosen backend.

Currently shipped backends:

| Backend | Target name | Output |
|---------|-------------|--------|
| Test | `test` | Backend-neutral text queries (for testing pipelines) |
| PostgreSQL/TimescaleDB | `postgres`, `postgresql`, `pg` | SQL with five output formats (default, view, timescaledb, continuous_aggregate, sliding_window) |
| LynxDB | `lynxdb` | SPL2-compatible `FROM <index> \| search ...` |

The conversion framework is pluggable via the `Backend` trait, so new backends can be added with a few hundred lines of Rust. See [adding backends](../developers/adding-backends.md).

## Input formats

RSigma reads events in seven formats with auto-detection by default:

| Format | Example use case |
|--------|------------------|
| JSON/NDJSON | API logs, Sysmon-as-JSON, the universal default |
| Syslog (RFC 3164/5424) | Network appliances, traditional Unix logs |
| logfmt (feature-gated) | Application logs from Go services |
| CEF (feature-gated) | ArcSight, McAfee, vendor SIEM-friendly format |
| EVTX (feature-gated) | Windows Event Log binary files, for offline forensics |
| OTLP (feature-gated) | OpenTelemetry-compatible agents (Alloy, Vector, Fluent Bit) |
| Plain text | Fallback for unstructured lines, keyword-only matching |

See [input formats](../guide/input-formats.md) for the full reference, including the format-specific flags.

## The five command groups

The RSigma CLI has been reorganized into noun-led command groups so it can scale as more subcommands arrive. Every group is a noun, every leaf is a verb:

| Group | Subcommands | Purpose |
|-------|-------------|---------|
| `engine` | `eval`, `daemon` | Run rules against events. |
| `rule` | `parse`, `validate`, `lint`, `fields`, `condition`, `stdin` | Operate on rule files. |
| `backend` | `convert`, `targets`, `formats` | Generate backend-native queries. |
| `pipeline` | `resolve` | Test dynamic pipeline source resolution. |
| `attack` | (reserved) | MITRE ATT&CK tooling (planned). |

The previous flat commands (`rsigma eval`, `rsigma daemon`, ...) still work for one release as deprecated aliases. See the [CLI reference](../cli/index.md) for the full migration table.

## Output

A successful detection produces a `MatchResult` (one JSON object per match, NDJSON when streaming) on stdout:

```json
{"rule_title":"...","rule_id":"...","level":"medium","tags":["..."],"matched_selections":["selection"],"matched_fields":[{"field":"...","value":"..."}]}
```

The `event` field is only present when `--include-event` is set or when `rsigma.include_event` is enabled via custom attributes. All other fields are always present (`null` for missing values where applicable).

A correlation that fires produces a `CorrelationResult`:

```json
{
  "rule_title": "Brute Force",
  "correlation_type": "event_count",
  "group_key": [["User", "admin"]],
  "aggregated_value": 5.0,
  "timespan_secs": 300,
  "events": null,
  "event_refs": null
}
```

Both types are stable JSON suitable for downstream consumers (Loki, Slack webhooks, SOAR playbooks, Fenrir response engines, custom alerting). The [output formats reference](../reference/http-api.md#output-payloads) defines every field.

## Where to go next

- **Tutorial path:** [quick start](quick-start.md) -> [evaluating rules](../guide/evaluating-rules.md) -> [streaming detection](../guide/streaming-detection.md).
- **Reference path:** [CLI](../cli/index.md), [linting rules](../reference/lint-rules.md), [Prometheus metrics](../reference/metrics.md), [feature flags](../reference/feature-flags.md).
- **Architecture path:** [crate map and data flow](../reference/architecture.md), [library API](../library/index.md), [contributing](../developers/contributing.md).
