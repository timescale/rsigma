---
description: "Reference for reusable RSigma dynamic sources: file, command, HTTP, and NATS types, extraction, refresh, errors, and limits."
---

# Dynamic Sources

{{ added "0.10.0" }}

Dynamic sources let the daemon fetch reusable values from files, local commands, HTTP endpoints, and NATS subjects. Source declarations are loaded independently through `--source`, resolved into a shared cache, and consumed by either [dynamic pipelines](dynamic-pipelines.md) or [`lookup` enrichers](../guide/enrichers.md#lookup-read-from-the-dynamic-source-cache). One source can be reused by any number of pipelines and enrichers.

Dynamic pipelines and `lookup` enrichers are currently the only consumers of dynamic sources. This page documents the consumer-independent source specification: every source type, the four data formats, the three extract languages, the five refresh policies, the three error policies, and every resource limit the runtime enforces.

For pipeline-specific `${source.<id>}` and `include:` syntax, see [Dynamic Pipelines](dynamic-pipelines.md). For post-evaluation lookups, see [Enrichers: dynamic sources](../guide/enrichers.md#using-dynamic-sources-with-lookup-enrichers). For source testing, see [`pipeline resolve`](../cli/pipeline/resolve.md). For runtime metrics, see [Prometheus metrics: dynamic sources](metrics.md#dynamic-sources-5-metrics).

## Source declaration

Dynamic sources are declared in standalone YAML files and loaded into the daemon with the repeatable `--source` flag. Each file has a top-level `sources:` block; every entry is a YAML mapping with the schema documented below.

```yaml
# sources.yml
sources:
  - id: employee_directory
    type: file
    path: ./data/employees.json
    format: json
  - id: kev_catalog
    type: http
    url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    format: json
    extract: ".vulnerabilities"
    refresh: 1h
```

Pass it to the daemon alongside whichever consumers need it:

```bash
rsigma engine daemon -r rules/ \
    --source sources.yml \
    -p pipeline.yml \
    --enrichers enrichers.yml
```

The pipeline and enricher flags are independent. Omit either one when that consumer is not needed.

A directory path loads all `*.yml`/`*.yaml` files in it, sorted alphabetically:

```bash
rsigma engine daemon -r rules/ -p pipeline.yml --source sources.d/
```

Offline resolution uses the same declaration files through [`pipeline resolve --source-file`](../cli/pipeline/resolve.md):

```bash
rsigma pipeline resolve -p pipeline.yml --source-file sources.yml --pretty
```

The flag is repeatable, so you can load from multiple files and directories:

```bash
rsigma engine daemon -r rules/ -p pipeline.yml \
    --source infra-sources.yml \
    --source threat-intel-sources.yml
```

### Schema

Every entry in the `sources:` list takes the same shape:

```yaml
sources:
  - id: <source-id>           # required, used in ${source.<id>} refs
    type: <file|http|command|nats>
    # type-specific fields…
    format: <json|yaml|lines|csv>
    extract: <expression>     # optional
    refresh: <once|<duration>|watch|push|on_demand>
    required: <true|false>    # default true
    timeout: <duration>       # default 30s for http/command
    on_error: <use_cached|fail|use_default>
    default: <value>          # required if on_error=use_default
    max_body_size: <bytes>    # default 10485760 (10 MiB)
    max_stdout: <bytes>       # command type only
```

The full Rust type lives at [`rsigma_eval::pipeline::sources::DynamicSource`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/pipeline/sources.rs). The parser is at [`rsigma_eval::pipeline::parsing`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/pipeline/parsing.rs).

A source ID is one or more ASCII letters, digits, `_`, or `-` (for example `ip_blocklist`, `threat-intel`, or `1st_feed`). Pipelines reference it as `${source.<id>}` and `lookup` enrichers use it in their `source:` field. A declaration with any other character, such as a dot or a space, fails to load with an error naming the ID. {{ added "0.25.0" }}

### Collision semantics

Source IDs must be unique across every `--source` file (and across every directory the flag expands into). If the same ID appears in two different declaration sites the daemon exits at startup with an error naming both file paths, so there is exactly one canonical declaration site per source ID.

::: callout warning "Pipeline-embedded `sources:` was removed in v0.19.0"
Declaring `sources:` inside a pipeline file is no longer accepted (tracked in [#137](https://github.com/timescale/rsigma/issues/137)). The parser rejects such a pipeline with a hard error pointing at the migration tool. Source declarations live only in standalone `--source` files, which also lets enrichers reuse them.

If you still have a pipeline with an inline `sources:` block, run `rsigma rule migrate-sources -p <pipelines-dir-or-file> -o sources.yml` to extract it into a standalone file, then load it via `--source sources.yml`. See the [`rule migrate-sources` reference](../cli/rule/migrate-sources.md) for flags and the `--strategy per-pipeline` mode.
:::

## Source types

### `file`

Reads a local file, parses it according to `format`, applies `extract` if set, and returns the result.

```yaml
- id: field_config
  type: file
  path: /etc/rsigma/fields.json
  format: json
  refresh: watch
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | yes | Absolute or pipeline-relative path. |
| `format` | enum | yes | `json`, `yaml`, `lines`, or `csv`. |
| `extract` | string or object | no | Filter applied after parsing. |

`refresh: watch` is only valid for file sources (uses `notify`). For other refresh policies, file behaves like the others.

### `http`

GET (or other method) request, response body parsed and optionally extracted. Uses `reqwest`. A request may carry a `body` for query APIs that require one (GraphQL, `_search`, TheHive 5's `/api/v1/query`).

```yaml
- id: ip_blocklist
  type: http
  url: https://feeds.example.com/blocklist.json
  format: json
  extract: ".ips"
  method: GET                  # default (POST when a body is set)
  headers:                     # optional
    Authorization: "Bearer ${FEED_TOKEN}"
  timeout: 10s                 # default 30s
  refresh: 300s
  on_error: use_cached
```

A POST query with a request body:

```yaml
- id: thehive_cases
  type: http
  url: https://thehive.example.com/api/v1/query
  headers:
    Authorization: "Bearer ${THEHIVE_API_KEY}"
    Content-Type: application/json
  body: |
    {"query": [{"_name": "listCase"}, {"_name": "filter", "_field": "status", "_value": "Resolved"}]}
  format: json
  extract: ".[]"
  refresh: 300s
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | Full HTTP(S) URL. |
| `method` | string | no | `GET` (default), `POST`, `PUT`, etc. Defaults to `POST` when `body` is set. |
| `headers` | mapping | no | Request headers. `${VAR}` references are expanded from the environment at fetch time, so tokens stay out of the committed YAML. |
| `body` | string | no | Request body sent verbatim after `${VAR}` expansion. Set `Content-Type` in `headers`; the engine does not infer it. |
| `format` | enum | yes | `json`, `yaml`, `lines`, or `csv`. |
| `extract` | string or object | no | Filter applied after parsing. |
| `timeout` | duration | no | Request timeout. Default `30s`. |
| `max_body_size` | bytes | no | Per-source override for the 10 MiB default. |

### `command`

Runs a local executable, captures stdout, parses it according to `format`. Useful for shelling out to an inventory tool, a script that queries an internal API with credentials only the host has access to, or a generator that produces transformation YAML on demand.

```yaml
- id: enrichment_rules
  type: command
  command: ["/usr/local/bin/generate-transformations", "--format", "json"]
  format: json
  refresh: once
  timeout: 5s
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | array of strings | yes | argv array. First element is the executable. |
| `format` | enum | yes | `json`, `yaml`, `lines`, or `csv`. |
| `extract` | string or object | no | Filter applied after parsing. |
| `timeout` | duration | no | Execution wall-clock cap. Default `30s`. |
| `max_stdout` | bytes | no | Per-source override for the 10 MiB stdout cap. |

The runtime additionally caps stderr at 64 KiB regardless of `max_stdout`. Stderr is logged on failure but not parsed.

### `nats`

Subscribes to a NATS subject and updates the source value with each message. Requires the `daemon-nats` build feature.

```yaml
- id: live_iocs
  type: nats
  url: nats://nats.internal:4222
  subject: rsigma.iocs.current
  format: json
  refresh: push
  required: false
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | `nats://host:port`. Auth comes from the daemon-level `--nats-*` flags. |
| `subject` | string | yes | NATS subject (no wildcards for dynamic-source use). |
| `format` | enum | yes | `json`, `yaml`, `lines`, or `csv`. |
| `extract` | string or object | no | Filter applied after parsing. |

`refresh: push` is only valid for NATS sources. Each subject message replaces the source value.

## Data formats

| Format | Library | Notes |
|--------|---------|-------|
| `json` | `serde_json` | Standard JSON. |
| `yaml` | `yaml_serde` 0.10 | Multi-document files concatenate into an array. |
| `lines` | (internal) | One value per non-blank line; the resolved value is a JSON array of strings. |
| `csv` | `csv` crate | Header row required; each subsequent row becomes an object keyed by the header. |

## Extract languages

The optional `extract:` filter slices the parsed data after `format` parsing. Three languages are supported:

| Language | Library | Best for |
|----------|---------|----------|
| `jq` | [`jaq`](https://github.com/01mf02/jaq) | Complex transformations, array iteration, filtering. Familiar to operators. |
| `jsonpath` | [`serde_json_path`](https://docs.rs/serde_json_path) (RFC 9535) | Simple path queries. Fastest of the three. |
| `cel` | [`cel`](https://docs.rs/cel) | Typed expressions with filtering and aggregation. Slower; use for small datasets. |

Plain-string `extract:` defaults to jq. Use the object form for explicit selection:

```yaml
# Shorthand: jq
extract: ".indicators[].ip"

# Explicit jq
extract:
  type: jq
  expr: ".indicators[].ip"

# JSONPath
extract:
  type: jsonpath
  expr: "$.indicators[*].ip"

# CEL
extract:
  type: cel
  expr: "data.indicators.filter(i, i.severity > 7).map(i, i.ip)"
```

## Refresh policies

`refresh:` controls how often the source re-fetches.

| Policy | Behaviour | Valid for |
|--------|-----------|-----------|
| `once` | Fetch at startup only. | All source types. |
| `<duration>` (`30s`, `5m`, `1h`) | Re-fetch on a fixed interval. Minimum 1 s; values below clamp to 1 s with a `WARN` log. | All source types. |
| `watch` | File-system change notification via `notify`. | `file` only. |
| `push` | New value on each NATS message. | `nats` only. |
| `on_demand` | Fetch at startup, then only when explicitly triggered (`SIGHUP`, `POST /api/v1/sources/resolve`, NATS control subject `rsigma.control.resolve`). | All source types. |

A `<duration>` refresh below `MIN_REFRESH_INTERVAL` (1 second) clamps silently with a runtime warning. Operators wishing to refresh more aggressively than that should use NATS push, on-demand triggers, or rethink the architecture.

## Error policies

`on_error:` controls what happens when a fetch fails (network down, command exits non-zero, parse error, extract returns empty):

| Policy | Behaviour |
|--------|-----------|
| `use_cached` | Serve the last successfully fetched value. The default when the source has been resolved at least once. |
| `fail` | For `required: true` (default): the pipeline load fails. For `required: false`: log and substitute null. |
| `use_default` | Substitute the literal `default:` value declared inline. Requires `default:` to be set. |

The `required` flag interacts with `on_error`:

- `required: true` + `on_error: fail` -> startup fails; the daemon exits.
- `required: true` + `on_error: use_cached` -> startup succeeds if a cached value exists from a prior run (with `--state-db`); fails otherwise.
- `required: false` + `on_error: fail` -> source resolves to null; pipeline continues.

## Consumers

### Dynamic pipelines

A pipeline reads a source through `${source.<id>}` in `vars:` or an `include:` directive. Pipeline-specific substitution rules, examples, limits, and validation commands are documented in [Dynamic Pipelines](dynamic-pipelines.md).

### Lookup enrichers

A `type: lookup` enricher names a cached source with `source: <id>`, then optionally applies a per-result jq, JSONPath, or CEL expression before injecting the value:

```yaml
enrichers:
  - id: asset_context
    kind: detection
    type: lookup
    inject_field: asset
    source: asset_inventory
    extract: '."${detection.fields.HostName}"'
    extract_type: jq
    default: "unknown"
```

The source is declared once in a standalone `--source` file. It does not need to be referenced by a pipeline, and the daemon does not require `-p` merely because an enricher uses it. See [Using dynamic sources with `lookup` enrichers](../guide/enrichers.md#using-dynamic-sources-with-lookup-enrichers) for the complete configuration and lookup behavior.

## Triggers and hot-reload

| Trigger | Re-resolves |
|---------|-------------|
| Filesystem change to a `.yml`/`.yaml` rules or pipeline file | Rules + pipelines + all dynamic sources. |
| `SIGHUP` | Same as above. |
| `POST /api/v1/reload` | Same as above. |
| `POST /api/v1/sources/resolve` (no body) | All dynamic sources only; rules are not reloaded. |
| `POST /api/v1/sources/resolve` with `{"source_id":"..."}` | One source. |
| `DELETE /api/v1/sources/cache/{source_id}` | Invalidates the cache. The next read fetches fresh. Always returns `200 OK`, even for nonexistent IDs. |
| NATS message on `rsigma.control.resolve` | All dynamic sources only. |
| Interval timer | The single source whose `refresh:` interval just elapsed. |

The `push` policy (NATS) updates the source value continuously on each incoming message, without going through the reload pipeline.

## Resource limits

Every dynamic source path enforces hard limits to bound resource consumption. Per-source overrides are noted in the table.

| Limit | Constant | Default | Per-source override |
|-------|----------|---------|---------------------|
| HTTP response body size | `MAX_SOURCE_RESPONSE_BYTES` | 10 MiB | `max_body_size` |
| Command stdout size | `MAX_SOURCE_RESPONSE_BYTES` | 10 MiB | `max_stdout` |
| Command stderr size | (hard-coded) | 64 KiB | not configurable |
| Command execution timeout | `DEFAULT_COMMAND_TIMEOUT` | 30 s | `timeout` |
| HTTP request timeout | (hard-coded default) | 30 s | `timeout` |
| Refresh interval minimum | `MIN_REFRESH_INTERVAL` | 1 s | not configurable (lower values clamp with a warning) |
| NATS message size cap | `MAX_SOURCE_RESPONSE_BYTES` | 10 MiB | not configurable |
| Include nesting depth | `MAX_INCLUDE_DEPTH` | 1 | not configurable |
| Remote include resolution | none | off | `--allow-remote-include` daemon flag |

Exceeding any limit produces a `SourceErrorKind::ResourceLimit` failure with a descriptive message. See [Security Hardening](security.md) for the broader catalogue.

## See also

- [Dynamic Pipelines](dynamic-pipelines.md) for pipeline-specific `${source.<id>}`, `vars:`, and `include:` behavior.
- [Enrichers](../guide/enrichers.md#using-dynamic-sources-with-lookup-enrichers) for consuming source values after a detection or correlation fires.
- [Disposition Source Recipes](../guide/disposition-recipes.md) for worked HTTP sources (env-header auth, POST `body`, jq `extract`) that pull case-system verdicts into the triage loop.
- [`pipeline resolve`](../cli/pipeline/resolve.md) for offline source testing.
- [`rule validate --resolve-sources`](../cli/rule/validate.md) for the strict CI gate.
- [Prometheus metrics: dynamic sources](metrics.md#dynamic-sources-5-metrics) for what every successful and failing resolve exposes.
- [HTTP API: sources](http-api.md#dynamic-sources) for the daemon control endpoints.
- [Security Hardening](security.md) for every other resource limit the runtime enforces.
- [`rsigma_runtime::sources` source](https://github.com/timescale/rsigma/tree/main/crates/rsigma-runtime/src/sources) for the implementation.
