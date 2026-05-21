# Dynamic Pipeline Sources

Dynamic pipeline sources let a [processing pipeline](../guide/processing-pipelines.md#dynamic-pipelines) pull values from external systems (files, local commands, HTTP, NATS) at load time and inject them through the standard Sigma `vars` + `value_placeholders` mechanism. This page documents the full source specification, every source type, the four data formats, the three extract languages, the five refresh policies, the three error policies, and every resource limit the runtime enforces.

For an introduction to the feature see [Processing Pipelines: dynamic pipelines](../guide/processing-pipelines.md#dynamic-pipelines). For end-to-end testing see [`pipeline resolve`](../cli/pipeline/resolve.md). For runtime metrics see [Prometheus metrics: dynamic pipeline sources](metrics.md#dynamic-pipeline-sources-5-metrics).

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

Pass it to the daemon:

```bash
rsigma engine daemon -r rules/ -p pipeline.yml --source sources.yml
```

A directory path loads all `*.yml`/`*.yaml` files in it, sorted alphabetically:

```bash
rsigma engine daemon -r rules/ -p pipeline.yml --source sources.d/
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

### Collision semantics

Source IDs must be unique across every `--source` file (and across every directory the flag expands into). If the same ID appears in two different declaration sites the daemon exits at startup with an error naming both file paths, so there is exactly one canonical declaration site per source ID.

!!! warning "Pipeline-embedded `sources:` is deprecated"
    Declaring `sources:` inside a pipeline file is deprecated and will be
    removed in v1.0 (tracked in [#137](https://github.com/timescale/rsigma/issues/137)).
    The parser still accepts it today, but emits a loud `warning:` on stderr
    and a structured `tracing::warn!` event pointing at the pipeline path.

    Run `rsigma rule migrate-sources -p <pipelines-dir-or-file> -o sources.yml`
    to extract every inline `sources:` block into a standalone file, then
    load it via `--source sources.yml`. See the
    [`rule migrate-sources` reference](../cli/rule/migrate-sources.md) for
    flags and the `--strategy per-pipeline` mode.

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

GET (or other method) request, response body parsed and optionally extracted. Uses `reqwest`.

```yaml
- id: ip_blocklist
  type: http
  url: https://feeds.example.com/blocklist.json
  format: json
  extract: ".ips"
  method: GET                  # default
  headers:                     # optional
    Authorization: "Bearer ${env:FEED_TOKEN}"
  timeout: 10s                 # default 30s
  refresh: 300s
  on_error: use_cached
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | Full HTTP(S) URL. |
| `method` | string | no | `GET` (default), `POST`, `PUT`, etc. |
| `headers` | mapping | no | Request headers. Static values only; env-variable interpolation is not implemented. |
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
| `cel` | [`cel-interpreter`](https://docs.rs/cel-interpreter) | Typed expressions with filtering and aggregation. Slower; use for small datasets. |

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

## Template substitution

The `${source.<id>}` syntax expands ONLY in the `vars:` block. The expander does NOT substitute references inside typed transformation fields (e.g. `add_condition.conditions.X`). The supported pattern is to put the resolved value into a `vars:` entry and reference it from rules via the standard Sigma `%name%` placeholder, expanded by the `value_placeholders` transformation:

```yaml
# sources.yml -- loaded via `--source sources.yml`
sources:
  - id: ip_blocklist
    type: http
    url: …
    extract: ".ips"
```

```yaml
# pipeline.yml -- loaded via `-p pipeline.yml`
vars:
  blocklist: "${source.ip_blocklist}"

transformations:
  - type: value_placeholders
```

```yaml
# rule
detection:
    selection:
        DestinationIp: '%blocklist%'
    condition: selection
```

Dot-path indexing into a nested structure works in `vars:`:

```yaml
vars:
  admin_emails: "${source.env_config.admin_emails}"
  log_index:    "${source.env_config.log_index}"
```

Inline templates work too (`${source.X}` as part of a larger string), but they substitute the source's stringified representation, which is rarely what you want for array sources. Whole-value substitution (where `${source.X}` is the entire `vars:` entry) is the safe form: it expands an array source to multiple `vars` entries that `value_placeholders` can map onto rule values. For scalar sources, inline templates compose cleanly:

```yaml
vars:
  greeting: "Hello, ${source.env_config.org_name}!"
```

## Include directives

A source resolving to a JSON array of transformation objects can be inlined via `include:`:

```yaml
transformations:
  - include: ${source.dynamic_transforms}
```

Constraints:

- The resolved value must be a JSON array of transformation objects, not a single object.
- Nested includes are rejected (`MAX_INCLUDE_DEPTH = 1`). If an included fragment itself contains `include:` directives, expansion fails at startup with a clear error message.
- Remote sources (HTTP, NATS) require `--allow-remote-include` on the daemon. The default policy restricts include resolution to local sources (`file`, `command`) to limit the blast radius of a compromised CDN or NATS broker.

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
| Remote include resolution | — | off | `--allow-remote-include` daemon flag |

Exceeding any limit produces a `SourceErrorKind::ResourceLimit` failure with a descriptive message. See [Security Hardening](security.md) for the broader catalogue.

## See also

- [Processing Pipelines: dynamic pipelines](../guide/processing-pipelines.md#dynamic-pipelines) for the narrative version.
- [`pipeline resolve`](../cli/pipeline/resolve.md) for offline source testing.
- [`rule validate --resolve-sources`](../cli/rule/validate.md) for the strict CI gate.
- [Prometheus metrics: dynamic pipeline sources](metrics.md#dynamic-pipeline-sources-5-metrics) for what every successful and failing resolve exposes.
- [HTTP API: sources](http-api.md#dynamic-pipeline-sources) for the daemon control endpoints.
- [Security Hardening](security.md) for every other resource limit the runtime enforces.
- [`rsigma_runtime::sources` source](https://github.com/timescale/rsigma/tree/main/crates/rsigma-runtime/src/sources) for the implementation.
