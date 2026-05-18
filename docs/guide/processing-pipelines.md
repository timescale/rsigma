# Processing Pipelines

Processing pipelines are RSigma's mechanism for transforming Sigma rules before they reach the engine or a backend. They handle the impedance mismatch between how Sigma rules name fields (`CommandLine`, `EventID`, `User`) and how your events actually name fields (`process.command_line`, `winlog.event_id`, `actor.user.name`). Pipelines are pySigma-compatible, so anything you write for pySigma works in RSigma, and most pipelines from the SigmaHQ pySigma backends work as well.

This page covers static pipelines (the bread and butter), builtin pipelines (`ecs_windows`, `sysmon`), and dynamic pipelines (an RSigma-only capability that pulls values from external sources at runtime).

## What pipelines do

A pipeline is a list of **transformations** applied to each rule in priority order before the rule is compiled or converted. Common transformations:

- Map field names: `CommandLine` becomes `process.command_line`.
- Inject conditions: every `process_creation` rule gets `EventID: 1` added.
- Set logsource: rewrite `product: windows` to `product: windows_sysmon`.
- Drop rules that target a different schema.
- Set backend-specific options like `postgres.table` or `index`.

All of this happens in memory, once, at engine load time (or whenever rules hot-reload). The compiled or converted output looks as if the rules had been written against your schema directly.

A pipeline YAML file looks like this:

```yaml
name: My ECS Mapping
priority: 20
transformations:
  - id: ecs_process_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      Image: process.executable
      ProcessId: process.pid
      ParentImage: process.parent.executable
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
  - id: ecs_user_fields
    type: field_name_mapping
    mapping:
      User: user.name
      TargetUserName: user.target.name
    rule_conditions:
      - type: logsource
        product: windows
```

`priority: 20` controls ordering when multiple pipelines are chained (lower numbers run first). `rule_conditions` gates each transformation so it only runs against matching rules.

## Loading pipelines

Pass `-p NAME_OR_PATH` to any subcommand that accepts pipelines (`engine eval`, `engine daemon`, `backend convert`, `rule validate`, `rule fields`, `pipeline resolve`). The flag is repeatable:

```bash
rsigma engine eval -r rules/ -p ecs_windows -e @events.ndjson
rsigma engine daemon -r rules/ -p ecs_windows -p custom-mappings.yml
rsigma backend convert rules/ -t postgres -p pipelines/ocsf_postgres.yml
rsigma rule validate rules/ -p sysmon
```

The argument is first checked against [builtin pipelines](#builtin-pipelines). If no match, it is treated as a file path. Multiple pipelines are sorted by `priority` and applied in sequence.

## Builtin pipelines

RSigma embeds two ready-to-use pipelines in the binary, so common cases need no external file:

| Name | What it does |
|------|--------------|
| `ecs_windows` | Maps Sigma/Sysmon field names to Elastic Common Schema (ECS). Use with Winlogbeat, Elastic Agent, or any pipeline that produces ECS-shaped events. |
| `sysmon` | Adds `EventID` conditions to route by Sysmon event type. Use when evaluating against raw Sysmon JSON. |

```bash
rsigma engine eval -r rules/ -p ecs_windows -e '{"process.command_line": "whoami"}'
rsigma engine daemon -r rules/ -p sysmon
```

Builtin pipelines are not file-watched (they are embedded at compile time). Updating them means upgrading RSigma.

See [Builtin Pipelines reference](../reference/builtin-pipelines.md) for the complete field maps and conditions inside each one.

## Transformations: the 26 types

Pipelines compose 26 transformation types. The most common ones in practice are:

| Transformation | What it does |
|----------------|--------------|
| `field_name_mapping` | Rename fields one-to-one or one-to-many (`CommandLine: [process.command_line, process.args]`). |
| `field_name_prefix_mapping` | Rename fields by prefix. |
| `field_name_prefix` / `field_name_suffix` | Add a static prefix or suffix to every field name. |
| `field_name_transform` | Case conversion (`lower`, `upper`, `snake_case`, `title`). |
| `add_condition` | Inject extra detection conditions (e.g. add `EventID: 1`). |
| `drop_detection_item` | Remove matching detection items. |
| `change_logsource` | Modify `category`, `product`, `service`. |
| `replace_string` | Regex string replacement in values. |
| `map_string` | Map specific values to replacements. |
| `set_value` | Replace detection item values. |
| `set_state` | Store backend-relevant key/value pairs (`table`, `schema`, `index`). |
| `set_custom_attribute` | Set per-rule attributes that engines and backends read (`rsigma.*`, `postgres.*`). |
| `query_expression_placeholders` | Backend query template envelope (used by `rsigma-convert`). |
| `nest` | Apply a group of transformations conditionally. |

The full list with every field is in the [rsigma-eval Library reference](../library/eval.md#transformations-26-types). All transformations support the same three-tier condition system below.

## Conditions: when does a transformation run?

Every transformation can be gated by one or more conditions at three levels:

### Rule conditions

Apply at the rule level. Common types:

| Type | Fields |
|------|--------|
| `logsource` | `category`, `product`, `service` |
| `contains_detection_item` | `field`, optional `value` |
| `processing_item_applied` | `processing_item_id` (chain to prior steps) |
| `processing_state` | `key`, `val` |
| `is_sigma_rule` / `is_sigma_correlation_rule` | (no args) |
| `rule_attribute` | `attribute`, `value` |
| `tag` | `tag` |

```yaml
transformations:
  - id: drop_aws
    type: rule_failure
    message: "AWS rules not supported in this deployment"
    rule_conditions:
      - type: logsource
        product: aws
```

### Detection item conditions

Apply per detection item:

| Type | Fields |
|------|--------|
| `match_string` | `pattern`, `negate` |
| `is_null` | `negate` |
| `processing_item_applied` | `processing_item_id` |

### Field name conditions

Filter by field name:

| Type | Fields |
|------|--------|
| `include_fields` | `fields`, `match_type` (`plain` or `regex`) |
| `exclude_fields` | `fields`, `match_type` |

```yaml
transformations:
  - id: prefix_security_fields
    type: field_name_prefix
    prefix: "security."
    field_name_conditions:
      - type: include_fields
        fields: ["TargetUserName", "SourceIp"]
```

## Chaining pipelines

Multiple pipelines compose by `priority`. Lower runs first. Each pipeline carries its own internal state (`PipelineState`), so values set with `set_state` in one pipeline are visible only to subsequent transformations within the same pipeline. The CLI does not merge pipelines: each remains separate.

```bash
rsigma engine eval -r rules/ \
    -p pipelines/01-windows-base.yml \
    -p pipelines/02-ecs-mapping.yml \
    -p pipelines/03-org-overrides.yml
```

If two pipelines set the same custom attribute on the same rule, the last one wins.

## Custom attributes (`rsigma.*` and `postgres.*`)

Transformations can write per-rule attributes that the engine and backends read. The most useful:

| Attribute | Read by | Effect |
|-----------|---------|--------|
| `rsigma.timestamp_field` | `engine daemon`, `engine eval` | Prepend a field name to the timestamp extraction priority list. |
| `rsigma.suppress` | correlation engine | Per-rule suppression window override. |
| `rsigma.action` | correlation engine | `alert` or `reset` after a correlation fires. |
| `rsigma.include_event` | detection engine | Embed the full event JSON in detection output for this rule. |
| `rsigma.correlation_event_mode` | correlation engine | `none`, `full`, `refs` for one rule. |
| `rsigma.max_correlation_events` | correlation engine | Per-window event cap for one rule. |
| `postgres.table` | PostgreSQL backend | Override the target table for one rule. |
| `postgres.schema` | PostgreSQL backend | Override the schema. |
| `postgres.database` | PostgreSQL backend | Override the database. |

Use `set_custom_attribute` to write them:

```yaml
transformations:
  - id: keep_full_events_for_brute_force
    type: set_custom_attribute
    attribute: rsigma.include_event
    value: "true"
    rule_conditions:
      - type: rule_attribute
        attribute: id
        value: "brute-force-detection"
```

See [Custom Attributes reference](../reference/custom-attributes.md) for the full list.

## Dynamic pipelines

Static pipelines hardcode every value in YAML. Dynamic pipelines let those values come from external sources at runtime: HTTP APIs, local commands, files, or NATS subjects. This is a capability unique to RSigma. Nothing in pySigma or the SigmaHQ ecosystem matches it.

The use cases are concrete:

- A threat-intel feed publishes IOC lists. Reference them inside an `add_condition` so detection rules update without rule edits.
- A central config service hands out field mappings per environment. Reference them inside `field_name_mapping`.
- An on-prem catalog publishes which tables hold which event categories. Reference it inside `set_state` to route rules to the right `postgres.table` per logsource.
- A bus broadcasts pipeline updates. Subscribe over NATS and re-resolve on push.

### Source declaration

Add a `sources` section to your pipeline YAML. Each source has a type, a configuration, an extraction expression, and a refresh policy. Substitution into the pipeline is wired through `vars:`, which the runtime expands with the resolved data; rules then reference the resulting values via standard `%placeholder%` syntax handled by the `value_placeholders` transformation:

```yaml
name: dynamic_threat_intel
priority: 50
sources:
  - id: ip_blocklist
    type: http
    url: https://feeds.example.com/blocklist.json
    format: json
    extract: ".ips"
    refresh: 300s
    timeout: 10s
    on_error: use_cached
    required: true

  - id: enrichment_rules
    type: command
    command: ["generate-transformations", "--format", "json"]
    format: json
    refresh: once

vars:
  blocklist: "${source.ip_blocklist}"

transformations:
  - id: expand_placeholders
    type: value_placeholders

  - include: ${source.enrichment_rules}
```

In rules, reference the var with the standard Sigma `%name%` placeholder:

```yaml
title: Connection to known-bad IP
logsource:
    category: network_connection
detection:
    selection:
        Action: 'allow'
        DestinationIp: '%blocklist%'
    condition: selection
```

`${source.<id>}` substitution applies to `vars:` entries and to `include:` directives. Transformation field values such as `add_condition.conditions.<field>` are parsed as typed structures and do **not** substitute dynamic sources directly; route lists of values through `vars` plus `value_placeholders` as shown above. Single scalar substitutions inside transformation fields (such as `set_state.value`) follow the same pattern through `vars`.

### Source types

| Type | Fetches | Notes |
|------|---------|-------|
| `file` | Local file content | Supports `refresh: watch` (re-reads on filesystem change). |
| `http` | HTTP GET/POST response | Supports `method`, `headers`, custom `timeout`. |
| `command` | Local command stdout | Killed after 30 s, stdout capped at 10 MB, stderr capped at 64 KB. |
| `nats` | NATS subject messages | Requires `daemon-nats` feature. Subscribes for push updates. |

### Data formats

| Format | Parsed with |
|--------|-------------|
| `json` | `serde_json` |
| `yaml` | `yaml_serde` |
| `lines` | One value per line (produces a JSON array of strings) |
| `csv` | Comma-separated values |

### Extraction languages

After parsing, an optional `extract` expression selects a subset of the data. Three languages are supported. The plain-string shorthand is jq:

```yaml
# jq (default for plain strings)
extract: ".indicators[].ip"

# JSONPath
extract:
  type: jsonpath
  expr: "$.indicators[*].ip"

# CEL (Common Expression Language)
extract:
  type: cel
  expr: "data.indicators.filter(i, i.severity > 7).map(i, i.ip)"
```

| Language | Library | Best for |
|----------|---------|----------|
| `jq` | jaq | Complex transformations, array iteration, filtering. |
| `jsonpath` | jsonpath-rust | Simple path queries into nested JSON. Fastest of the three. |
| `cel` | cel-interpreter | Typed expressions with filtering and aggregation. Slower; best for small datasets. |

See the [Dynamic Sources reference](../reference/dynamic-sources.md) for benchmarks and tradeoffs.

### Refresh policies

| Policy | Behaviour |
|--------|-----------|
| `once` | Fetch at startup only. |
| `<duration>` (`300s`, `5m`, `1h`) | Re-fetch on a fixed interval. |
| `watch` | File-system watch (file sources only). |
| `push` | NATS push delivery (NATS sources only). |
| `on_demand` | Fetch at startup, then only when triggered via SIGHUP, `POST /api/v1/sources/resolve`, or a NATS control message. |

### Error handling

| Policy | Behaviour |
|--------|-----------|
| `use_cached` | Serve the last successfully fetched value on failure. The default if the source has been resolved before. |
| `fail` | For required sources: block startup. For optional sources: log and use null. |
| `use_default` | Fall back to the `default` value declared in the source config. |

Required sources block the daemon's startup until they resolve. Optional sources (`required: false`) let the daemon start with a null fallback and retry in the background.

### Include directives

A whole block of transformations can be injected from a resolved source:

```yaml
transformations:
  - include: ${source.dynamic_transforms}
```

The source must resolve to a JSON array of transformation objects. Nested includes are rejected (max depth 1). Remote sources (HTTP/NATS) require `--allow-remote-include` on the daemon for security.

### Testing dynamic sources offline

`rsigma pipeline resolve` resolves all sources in a pipeline and prints the result without running the engine. Useful for testing config:

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --pretty
rsigma pipeline resolve -p pipelines/dynamic.yml --source threat_intel
rsigma pipeline resolve -p pipelines/dynamic.yml --dry-run
```

`--dry-run` lists each source's type, refresh policy, and `required` flag without performing the actual fetch. Good for catching config typos before they hit production.

`rsigma rule validate --resolve-sources -p pipeline.yml` extends validation to also exercise source resolution. Sources must be reachable for validation to pass, so this is the right gate to wire into CI for dynamic pipelines.

### Hot-reload and dynamic sources

The daemon's hot-reload mechanism extends to dynamic sources. The triggers:

| Trigger | What it re-resolves |
|---------|---------------------|
| Filesystem change to a `.yml`/`.yaml` rules or pipeline file | Rules + pipelines + all dynamic sources (push, watch, and interval still tick independently). |
| `SIGHUP` | Same as above. |
| `POST /api/v1/reload` | Same as above. |
| `POST /api/v1/sources/resolve` | All dynamic sources only (rules not reloaded). |
| `POST /api/v1/sources/resolve` with `{"source_id": "..."}` | One source. |
| `DELETE /api/v1/sources/cache/{source_id}` | Invalidate one source's cache so the next read fetches fresh. |
| NATS message on `rsigma.control.resolve` | Same as `POST /api/v1/sources/resolve`. |

### Security model

Dynamic pipelines can run external commands and reach out over HTTP, so the daemon enforces hard limits:

| Limit | Default | Configurable |
|-------|---------|--------------|
| HTTP body size cap | 10 MB | Per source via `max_body_size`. |
| Command stdout size cap | 10 MB | Per source via `max_stdout`. |
| Command stderr size cap | 64 KB | Per source. |
| Command execution timeout | 30 s | Per source via `timeout`. |
| HTTP fetch timeout | 30 s | Per source via `timeout`. |
| Refresh interval minimum | 1 s (clamped silently with a warning) | Cannot be lowered. |
| NATS message size cap | 10 MB | Cannot be raised. |
| Remote `include` directives | Disabled by default | `--allow-remote-include` on the daemon. |

See [Security Hardening reference](../reference/security.md) for the full picture.

## OCSF pipelines

Two OCSF (Open Cybersecurity Schema Framework) pipelines are included with the rsigma-convert crate and useful as starting points for PostgreSQL-backed deployments:

| Pipeline | What it does |
|----------|--------------|
| `pipelines/ocsf_postgres.yml` | Single-table: every event class routes to `security_events`. |
| `pipelines/ocsf_postgres_multi_table.yml` | Per-logsource routing: process events to `process_events`, network events to `network_events`, etc. |

Use them as templates and copy/customise for your schema. They're typical examples of `field_name_mapping` plus `set_state` plus `set_custom_attribute` working together.

## See also

- [Builtin Pipelines reference](../reference/builtin-pipelines.md) for the contents of `ecs_windows` and `sysmon`.
- [Dynamic Sources reference](../reference/dynamic-sources.md) for the full source spec, extract language details, and benchmarks.
- [Custom Attributes reference](../reference/custom-attributes.md) for every `rsigma.*` and `postgres.*` knob.
- [Security Hardening reference](../reference/security.md) for the resource limits enforced on dynamic sources.
- [CLI reference: `pipeline resolve`](../cli/pipeline/resolve.md) for the offline source-testing command.
- [Library API: rsigma-eval pipelines](../library/eval.md#processing-pipelines) for embedding the pipeline engine in your own code.
