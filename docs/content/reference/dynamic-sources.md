---
description: "Reference for reusable RSigma dynamic sources: file, command, HTTP, NATS, watchlist, and TAXII types, extraction, refresh, errors, and limits."
---

# Dynamic Sources

{{ added "0.10.0" }}

Dynamic sources let the daemon fetch reusable values from files, local commands, HTTP endpoints, NATS subjects, and TAXII collections. Source declarations are loaded independently through `--source`, resolved into a shared cache, and consumed by either [dynamic pipelines](dynamic-pipelines.md) or [`lookup` enrichers](../guide/enrichers.md#lookup-read-from-the-dynamic-source-cache). One source can be reused by any number of pipelines and enrichers.

Dynamic pipelines and `lookup` enrichers are currently the only consumers of dynamic sources. This page documents the consumer-independent source specification: every source type, the data formats, the three extract languages, the five refresh policies, the three error policies, and every resource limit the runtime enforces.

For pipeline-specific `${source.<id>}` and `include:` syntax, see [Dynamic Pipelines](dynamic-pipelines.md). For post-evaluation lookups, see [Enrichers: dynamic sources](../guide/enrichers.md#using-dynamic-sources-with-lookup-enrichers). For source testing, see [`pipeline resolve`](../cli/pipeline/resolve.md). For runtime metrics, see [Prometheus metrics: dynamic sources](metrics.md#dynamic-sources-11-metrics).

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
    type: <file|http|command|nats|watchlist|taxii>
    # type-specific fields…
    format: <json|yaml|lines|csv|stix>
    extract: <expression>     # optional
    refresh: <once|<duration>|watch|push|on_demand>
    required: <true|false>    # default true
    timeout: <duration>       # default 30s for http/command
    on_error: <use_cached|fail|use_default>
    default: <value>          # required if on_error=use_default
    max_body_size: <bytes>    # http type only; default 10485760 (10 MiB)
    max_stdout: <bytes>       # command type only
```

The full Rust type lives at [`rsigma_eval::pipeline::sources::DynamicSource`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/pipeline/sources.rs). The parser is at [`rsigma_eval::pipeline::parsing`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/src/pipeline/parsing.rs).

A declaration fails to load, with an error naming the source and the key, when it sets a key that is unknown or that does not apply to its `type:` (for example `path` on an `http` source, or `refresh` on a `watchlist`), when a `stix:`, `auth:`, or `extract:` mapping has an unknown key, or when `format`, `on_error`, `refresh`, `timeout`, or `required` has a value outside its supported set. A sources file whose top level has any key other than `sources` fails the same way. {{ added "0.28.0" }}

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
| `format` | enum | yes | `json`, `yaml`, `lines`, `csv`, or `stix`. |
| `extract` | string or object | no | Filter applied after parsing. Rejected when `format` is `stix`. |
| `stix` | object | no | Options for `format: stix`. See [format: stix](#format-stix). |

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
| `format` | enum | yes | `json`, `yaml`, `lines`, `csv`, or `stix`. |
| `extract` | string or object | no | Filter applied after parsing. Rejected when `format` is `stix`. |
| `stix` | object | no | Options for `format: stix`. See [format: stix](#format-stix). |
| `timeout` | duration | no | Request timeout. Default `30s`. |
| `max_body_size` | bytes | no | Per-source override for the 10 MiB response body cap. A positive integer. {{ added "0.28.0" }} |

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
| `max_stdout` | bytes | no | Per-source override for the 10 MiB stdout cap. A positive integer. {{ added "0.28.0" }} |

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

`refresh: push` is only valid for NATS sources. Each subject message replaces the source value and is stored in the source cache, so a later cache-first rebuild and a lookup enricher see it.

### `watchlist`

{{ added "0.28.0" }}

Indicators pushed over the HTTP API. The source has nothing to fetch. Resolution returns the unexpired values as a JSON array of strings, sorted by bytes. Outside the daemon, where no registry is attached, it resolves to `[]`.

```yaml
- id: c2_ips
  type: watchlist
  max_indicators: 100000
  max_value_length: 2048
  default_ttl: 30d
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_indicators` | integer | no | Most unexpired values the set may hold. Default `100000`. `0` is a configuration error. When a pipeline references the source, the effective cap is the smaller of this value and 4096. |
| `max_value_length` | integer | no | Longest accepted value, in bytes. Default `2048`. `0` is a configuration error. |
| `default_ttl` | duration | no | Lifetime used when a push names no expiry. Absent means indicators stay until deleted. `30d` is 30 days. |

`refresh`, `format`, `extract`, and `timeout` are rejected. The ids `resolve` and `cache` are reserved, because they would be ambiguous with `/api/v1/sources/resolve` and `/api/v1/sources/cache`. `required` and `on_error` are accepted and ignored.

Push, replace, delete, and list go through `/api/v1/sources/{source_id}/indicators`. See [HTTP API](http-api.md#watchlist-indicators) and [Threat intel watchlists](../guide/threat-intel-watchlists.md).

A pipeline that expands `%c2_ips%` rebuilds when the set changes. An empty watchlist expands to a condition that matches nothing. A watchlist that a pipeline references is capped at 4096 indicators, and a push past that cap returns 422 and changes nothing. A watchlist that no pipeline references keeps `max_indicators`, which is how a lookup enricher holds a larger set. A successful reload computes the cap again: a pipeline edit that starts referencing the watchlist lowers it, and one that stops referencing it restores `max_indicators`.

### `taxii`

{{ added "0.28.0" }}

Polls a TAXII 2.1 collection and turns its indicators into the value described under [`format: stix`](#format-stix). Requires the `stix-source` feature. `url` is the API root. The daemon does not run discovery. `collection` is the collection id, a UUID. `refresh` may be a duration, `once`, or `on_demand`. Omitted means `once`. With `once`, a collection larger than one poll loads only the first poll's objects and the daemon logs a warning, so give a large collection a duration. `watch` and `push` are rejected, and so are `extract` and `format`.

```yaml
- id: ti
  type: taxii
  url: https://taxii.example/api1/
  collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
  refresh: 15m
  page_size: 500
  auth:
    bearer_token_env: TAXII_TOKEN
  stix:
    min_confidence: 50
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | yes | TAXII API root. Checked against the daemon egress policy before the first poll. |
| `collection` | string | yes | Collection id. Must be a UUID (`8-4-4-4-12` hex). |
| `page_size` | integer | no | Objects requested per page. Default `500`. Must be greater than 0. |
| `auth` | object | no | Omit it when the collection needs no credentials. When present, exactly one of bearer, basic, or API key. Each secret is an environment variable name, read when the resolver is built. A missing variable is a startup error that names it. |
| `auth.bearer_token_env` | string | no | Variable holding a bearer token. Sent as `Authorization: Bearer`. |
| `auth.basic_user_env` | string | no | Variable holding the basic-auth user. Requires `basic_password_env`. |
| `auth.basic_password_env` | string | no | Variable holding the basic-auth password. Requires `basic_user_env`. |
| `auth.api_key_env` | string | no | Variable holding an API key. |
| `auth.api_key_header` | string | no | Header for `api_key_env`. Default `X-API-Key`. |
| `stix` | object | no | Same block as [`format: stix`](#format-stix). Omitted means every observable kind, no confidence floor, and a cap of 100000 active indicators. |
| `timeout` | duration | no | Per-request timeout. Default 30s. |

The first resolve reads the collection. Later resolves send `added_after` set to the previous poll's last `X-TAXII-Date-Added-Last` and merge what comes back. One poll reads at most `max_indicators` plus one page of objects, and at most the page budget that comes from that. When the server still has more, the poll keeps the pages it applied, logs a warning, and sets the cursor one microsecond before the last page's `X-TAXII-Date-Added-Last`. `added_after` is exclusive and objects on the next page can share that date, so the next refresh reads them again instead of skipping them. A collection larger than one poll therefore loads across refreshes. A poll fails when a budget stop cannot move the cursor (the last page has no added-date, or one added-date covers more objects than the budget), when a page repeats the cursor, or when HTTP 416 recovery would send the same filter again. A failed poll returns the error, keeps the pages it applied, and leaves the cached value and the cursor unchanged, so `on_error: use_cached` keeps serving the last good value and the next poll reads those pages again. The cursor lives in the process. After a restart the next poll is a full read.

The process keeps the indicators that are in the value. Indicators that lose the cap stay while the retained set is under twice `max_indicators`, so a freed slot can be filled from them without re-reading the collection. Past that bound they are dropped until a restart. Revoked and expired ids are kept only as a `modified` time, and that list is capped at `max_indicators`, so an older version cannot replace them and memory does not grow with every id the feed has ever sent. Not-yet-valid indicators use the room left under that bound. `rsigma_stix_source_skipped_total` counts an indicator when that resolve leaves it out. An id that stays out is not counted on later polls.

The client follows the daemon egress policy. It does not follow redirects and it does not use a proxy, including when the server returns an absolute URL. Each objects page is capped at 64 MiB. The page is parsed with a depth limit, a string limit, and an object-count limit of twice `page_size`. Objects that are not indicators, including custom objects, are accepted by the parser and then ignored.

## Data formats

| Format | Library | Notes |
|--------|---------|-------|
| `json` | `serde_json` | Standard JSON. |
| `yaml` | `yaml_serde` 0.10 | Multi-document files concatenate into an array. |
| `lines` | (internal) | One value per non-blank line; the resolved value is a JSON array of strings. |
| `csv` | `csv` crate | Header row required; each subsequent row becomes an object keyed by the header. |
| `stix` | `rstix` | A STIX 2.1 bundle. File and HTTP only. Requires `stix-source`. `extract` is rejected. See [format: stix](#format-stix). {{ added "0.28.0" }} |

### `format: stix`

{{ added "0.28.0" }}

`format: stix` on a file or HTTP source parses the body as a STIX bundle and builds the same value a TAXII source builds. The file or HTTP fetch is otherwise unchanged: a file may use `refresh: watch`, and HTTP keeps the egress policy and the 10 MiB body cap. Each resolve is stateless. There is no cursor.

```yaml
- id: ti_file
  type: file
  path: ./intel/indicators.json
  format: stix
  refresh: watch
  stix:
    min_confidence: 70
    observables: [ipv4, domain]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `stix.min_confidence` | integer | no | Drop indicators whose confidence is set and below this value. Range 0..=100. Unset confidence is kept. |
| `stix.observables` | list of strings | no | Kinds to emit. Omitted means every kind in the table below. An unknown name is a configuration error that lists the valid names. `[]` emits no kinds. |
| `stix.max_indicators` | integer | no | Most active indicators kept. Default `100000`. `0` is a configuration error. Past the cap, the highest confidence wins and equal confidence keeps the smaller id. The rest count as `over_limit`. An indicator that emits no configured observable does not take a slot. On a TAXII source, indicators that lose the cap stay in memory while the retained set is under twice this number, and a later resolve can fill a freed slot from them. Past that bound they are dropped until a restart reads the collection again. |

An indicator is kept when all of these hold: `pattern_type` is `stix`, `revoked` is not true, `valid_from` is at or before the resolve time, `valid_until` is unset or after that time, confidence is unset or at least `min_confidence`, the pattern is a simple comparison, and at least one comparison is a configured kind. A simple pattern is one observation, or several joined only by `OR`, with no qualifier (`WITHIN`, `REPEATS`, `START`, `STOP`), no `AND`, no `FOLLOWEDBY`, and no negated comparison. Each comparison is `=` or `IN` against a string or integer. Anything else is `unsupported_pattern` and the indicator is dropped. A comparison whose path is not one of the kinds below increments `unmapped_observable` and is left out of the arrays. When every comparison is unmapped, the indicator is left out and does not count as active.

Each array value escapes `\`, `*`, and `?`. A Sigma `|expand` comparison then stays exact: a URL query string does not become a single-character wildcard, and a value of `*` does not match every event. The `indicators` object uses the raw value as its key, so a lookup still compares the event text.

Objects that are not indicators are ignored. Two versions of the same id keep the one with the greater `modified`. A newer version with `revoked: true` removes it. Expiry is applied at resolve time, so an indicator stays in the value until the next refresh after `valid_until`.

Every configured kind is always present. Arrays are sorted and deduplicated. `indicators` maps a value to at most 16 metadata objects, sorted by confidence descending and then by id. Metadata fields are `id`, `name` (omitted when unset), `confidence` (omitted when unset), `valid_until` (omitted when unset, RFC3339), `labels` (the indicator types, always present, possibly empty), and `kill_chain_phases` (always present, each with `kill_chain_name` and `phase_name`).

| Key | Taken from |
|-----|------------|
| `ipv4` | `ipv4-addr:value` with no `/` |
| `ipv4_cidr` | `ipv4-addr:value` containing `/` |
| `ipv6` | `ipv6-addr:value` with no `/`. The text is not lowercased. |
| `ipv6_cidr` | `ipv6-addr:value` containing `/` |
| `domain` | `domain-name:value`, lowercased |
| `url` | `url:value` |
| `email` | `email-addr:value` |
| `file_name` | `file:name` |
| `md5` | `file:hashes.MD5`, lowercased |
| `sha1` | `file:hashes.'SHA-1'`, lowercased |
| `sha256` | `file:hashes.'SHA-256'`, lowercased |
| `sha512` | `file:hashes.'SHA-512'`, lowercased |
| `registry_key` | `windows-registry-key:key` |
| `mutex` | `mutex:name` |
| `mac` | `mac-addr:value`, lowercased |
| `asn` | `autonomous-system:number`, printed as a decimal |

A resolved value looks like this when `observables` names `ipv4`, `ipv4_cidr`, `domain`, `url`, and `sha256`:

```json
{
  "domain": ["bad.example.com"],
  "indicators": {
    "198.51.100.7": [
      {
        "confidence": 80,
        "id": "indicator--01234567-89ab-4cde-8fab-0123456789ab",
        "kill_chain_phases": [
          {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
        ],
        "labels": ["malicious-activity"],
        "name": "c2",
        "valid_until": "2026-12-01T00:00:00Z"
      }
    ]
  },
  "ipv4": ["198.51.100.7"],
  "ipv4_cidr": ["203.0.113.0/24"],
  "sha256": ["abcdef"],
  "url": []
}
```

`command` and `nats` cannot use `format: stix`. A `stix:` block on any other format is a configuration error. See [Threat intel watchlists](../guide/threat-intel-watchlists.md#stix-indicator-sources) for how this sits next to a watchlist and next to `taxii sync`.

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

| Trigger | What runs |
|---------|-----------|
| A referenced source value changes (file watch, interval, NATS message, watchlist push, or a resolve that returns a new value) | Rules are rebuilt from cached source values. Sources that are already cached are not fetched again. A failed rebuild keeps the previous rules. |
| Filesystem change to a `.yml`/`.yaml` rules or pipeline file | Full reload: rules, pipelines, and a fresh fetch of dynamic sources. |
| `SIGHUP` | Same as a full reload. |
| `POST /api/v1/reload` | Same as a full reload. |
| `POST /api/v1/sources/resolve` | Re-resolves every dynamic source. The request body is ignored. Rules reload only if a referenced value changes. |
| `POST /api/v1/sources/resolve/{source_id}` | Re-resolves that source. No request body. |
| `DELETE /api/v1/sources/cache/{source_id}` | Invalidates the cache. The next read fetches fresh. Always returns `200 OK`, even for nonexistent IDs. |
| NATS message on `rsigma.control.resolve` | Re-resolves every dynamic source. |
| Interval timer | Re-resolves the one source whose `refresh:` interval elapsed. |

A full reload and a pending rebuild collapse into the full reload. The rebuild itself does not fetch sources that already have a cached value, and it does not schedule another rebuild.

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
- [Prometheus metrics: dynamic sources](metrics.md#dynamic-sources-11-metrics) for what every successful and failing resolve exposes.
- [HTTP API: sources](http-api.md#dynamic-sources) for the daemon control endpoints.
- [Security Hardening](security.md) for every other resource limit the runtime enforces.
- [`rsigma_runtime::sources` source](https://github.com/timescale/rsigma/tree/main/crates/rsigma-runtime/src/sources) for the implementation.
