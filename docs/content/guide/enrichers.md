---
description: "Enrich Sigma detections with asset, identity, IP reputation, GeoIP, and runbook context using template, lookup, HTTP, command, STIX, or MMDB steps."
---

# Enrichers

{{ added "0.13.0" }}

Post-evaluation enrichers run after `engine.evaluate()` produces each `EvaluationResult` and before that result is serialized to a sink. They inject contextual data (asset info, IP reputation, identity, GeoIP, runbook URLs) into the `enrichments.<field>` map on each detection or correlation, so every downstream consumer (RSoar, Grafana, Loki, custom scripts) sees the same structured context without re-fetching it.

This page covers what to put in `--enrichers <path>`, how the seven primitives compose into the `enrich_<keyfield>_<target>` recipe catalog, and how to promote a recipe to a Rust-coded named enricher when one of the seven primitives is not enough. The CLI flag itself is documented under [`engine daemon`](../cli/engine/daemon.md#post-evaluation-enrichment); per-call Prometheus metrics live in [Prometheus metrics](../reference/metrics.md#enrichment-13-metrics).

## Why post-evaluation, not in-pipeline

Processing pipelines (`-p`) run *before* the engine evaluates a rule: they map field names, filter events, and inject literal values. Enrichers run *after* the engine has already decided that a detection or correlation fired. The two surfaces are complementary:
- Use a pipeline when you want to normalize field names, drop noisy events, or inject a fixed list (threat-intel IOCs, allow-list users) into rule conditions. The pipeline runs once per event.
- Use an enricher when you want to attach context to a *firing* detection (asset owner, IP reputation, runbook URL). The enricher runs once per match, not once per event, and its work never re-affects rule evaluation.

This split keeps the evaluation hot path independent of any external system: a downstream HTTP outage cannot stop the engine from emitting detections, only from enriching them.

## Config schema

Pass a YAML file to `--enrichers <path>` on `engine daemon`. The file is hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; a reload that fails validation logs the error and keeps the previous pipeline active, so a typo never silently degrades production to "no enrichment".

```yaml
# Bound on concurrent enrichment chains. Defaults to 16.
max_concurrent_enrichments: 16

enrichers:
  - id: <unique-string>            # required, used as a Prometheus label
    kind: detection | correlation  # required, see "Kind and template namespaces"
    type: template | lookup | http | command | stix | mmdb | dns  # required, the primitive
    inject_field: <field-name>     # required, key under enrichments.<...>
    timeout: 5s                    # optional, humantime; default 5s
    on_error: skip | null | drop   # optional; default skip
    on_miss: skip | null | drop    # optional; lookup, http, stix, mmdb, dns; default on_error
    scope:                         # optional; see "Scope filtering"
      rules: [<rule-id-or-glob>, ...]
      tags:  [<tag-or-prefix.*>, ...]
      levels: [low, medium, high, critical, informational]
    # ... primitive-specific fields below ...
```

Keys that are unknown, or that do not apply to the entry's `type:`, are rejected at load with an error that names the key and lists the supported ones. The same holds for keys under `scope` and at the top level of the file. A key set to an empty value (`headers: {}`, `attack_technique: false`, `miss_status: []`, `mmap: false`) counts as absent. `default` counts whenever it is written, `default: null` included. Bespoke types registered with `register_builtin` receive unknown keys and validate them themselves. {{ added "0.28.0" }}

## Misses and errors

{{ added "0.28.0" }}

A miss is a lookup that ran and found no data for its key: a `lookup` source cache miss or an extract that matched nothing, a `stix` query with no objects or an extract that returned `null`, an `mmdb` address with no record or an empty projection, a `dns` NXDOMAIN or NODATA answer, and an `http` response whose status is listed in `miss_status`. An `http` result that is `null` after the optional `extract` is not a miss: it injects `default` when one is configured, and `null` otherwise. Everything else that stops an enricher (a timeout, a non-2xx status that is not listed, an invalid key, a store or resolver error, an extract evaluation error) is a failure. `template` and `command` have no misses.

Three keys decide what a miss does:

- `default`: the value injected on a miss. Writing `default: null` injects `null`. A miss covered by `default` counts as a success.
- `on_miss: skip | null | drop`: what to do with a miss when `default` is not set. It applies to `lookup`, `http`, `stix`, `mmdb`, and `dns`. When it is absent, a miss follows `on_error`.
- `on_error: skip | null | drop`: what to do with a failure, and with a miss when neither `default` nor `on_miss` is set.

`default` always handles a miss, so setting `on_miss` together with `default` (including `default: null`) fails at load. `on_miss` on a `template` or `command` entry also fails at load, because those types have no misses. `default: null` and `on_miss: null` both inject `null` on a miss. The first reports `status="success"` and the second `status="miss"` in `rsigma_enrichment_total`, so pick `on_miss: null` when dashboards should tell misses apart.

To fail closed on errors but keep detections whose lookup found nothing, drop on errors and skip on misses:

```yaml
- id: geo_src
  kind: detection
  type: mmdb
  inject_field: geo
  db_path: /var/lib/geoip/GeoLite2-City.mmdb
  key: "${detection.fields.SourceIp}"
  on_error: drop                   # an invalid IP or a decode failure drops the detection
  on_miss: skip                    # an address with no record keeps it, without a geo field
```

## Using dynamic sources with `lookup` enrichers

{{ added "0.13.0" }}

Dynamic sources are not owned by processing pipelines. The daemon loads standalone `--source` declarations into a shared cache before it builds the enrichment pipeline. A `type: lookup` enricher reads that cache directly, so it can use a dynamic source without any `-p` pipeline:

```yaml
# sources.yml
sources:
  - id: asset_inventory
    type: file
    path: /etc/rsigma/assets.json
    format: json
    refresh: watch
```

```yaml
# enrichers.yml
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

```bash
rsigma engine daemon -r rules/ \
    --source sources.yml \
    --enrichers enrichers.yml
```

The same source can also be referenced by dynamic pipelines or by additional `lookup` enrichers. It is resolved and refreshed once, and every consumer reads the shared cached value. Among enricher primitives, only `lookup` consumes dynamic sources by ID. `template`, `stix`, `http`, and `command` use their own configuration and do not read the dynamic-source cache.

Source declarations, fetch types, refresh policies, and error handling are documented in [Dynamic Sources](../reference/dynamic-sources.md). Pipeline-specific `${source.<id>}` syntax is documented separately in [Dynamic Pipelines](../reference/dynamic-pipelines.md).

## Kind and template namespaces

Every enricher declares a `kind: detection | correlation`. The kind drives two checks:

1. **Config-load-time template validation.** A `kind: detection` enricher may only reference `${detection.*}` variables in its templated fields; a `kind: correlation` enricher may only reference `${correlation.*}`. Cross-namespace references are rejected at startup with a clear error pointing at the offending field. `${ENV_VAR}` is allowed in both namespaces, except in enrichers passed to the MCP server's `evaluate_events` tool, which refuses them so a caller cannot read the server's environment (see [MCP server](mcp-server.md)). {{ added "0.27.0" }}
2. **Runtime body matching.** The pipeline skips enrichers whose declared kind does not match the current `EvaluationResult` body variant before invoking `enrich()`, so a detection-kind enricher pays no cost on correlation results and vice versa.

Detection variables (`${detection.*}`):

| Variable | Resolves to |
|---|---|
| `${detection.rule.title}`/`.id`/`.level` | Rule metadata from `RuleHeader` |
| `${detection.tags}` | Comma-joined `tags` |
| `${detection.fields.<name>}` | The matched value of `<name>` from `matched_fields`; when the rule did not match on `<name>`, the value of `<name>` in the event {{ added "0.28.0" }} |
| `${detection.event.<dotted.path>}` | JSON path into the original event |

`${detection.fields.<name>}` reads a matched field first, even when its value is null or empty. When no matched field has that name, it reads `<name>` from the event: the whole name as a top-level key first, then as a dotted path (`process.parent.name`, `addresses.0`). If neither exists, it renders empty. A rule therefore does not have to select on `SourceIp` for an enricher keyed on `${detection.fields.SourceIp}` to see it. {{ added "0.28.0" }}

The daemon retains each detection's event automatically whenever a loaded enricher reads `${detection.fields.*}` or `${detection.event.*}`, so these templates resolve without `--include-event`. Without `--include-event` or capture, the event is stripped right after enrichment, before the risk layer, the alert pipeline, and the sinks; with capture on, it is stripped after capture admission as before. A rule that sets `rsigma.include_event: "true"` keeps its event either way, and `--include-event` delivers every event. Retention follows enricher reloads: it turns on when a reloaded file starts reading the event and off when it stops. Only the fields each type renders count: the `template` text, `lookup` and `stix` `extract`, `stix_id`, `text_search`, the `http` `url`, `body`, and header values, `command` arguments and `env` values, and the `mmdb` and `dns` `key`. The `http` and `dns` `extract`, which are not templates, do not turn it on. The MCP server's `evaluate_events` tool retains and strips events the same way for the enrichers passed to it. {{ added "0.28.0" }}

Retention serializes the event into every detection only while a loaded enricher reads the payload, the same work `--include-event` does. {{ added "0.28.0" }}

Correlation variables (`${correlation.*}`):

| Variable | Resolves to |
|---|---|
| `${correlation.rule.title}`/`.id`/`.level` | Rule metadata from `RuleHeader` |
| `${correlation.tags}` | Comma-joined `tags` |
| `${correlation.type}` | `event_count`, `temporal`, `value_sum`, ... |
| `${correlation.aggregated_value}` | The value that crossed the condition threshold |
| `${correlation.timespan_secs}` | Window size in seconds |
| `${correlation.group_key.<field>}` | Look up a group-by field by name |
| `${correlation.group_key}` | Joined `field=value,field=value` string |

For enrichers that conceptually apply to both kinds (identity lookups, runbook URLs, any tag-based enricher), declare two YAML entries with the same `type` and `inject_field` but different `kind` and template namespaces.

## Scope filtering

`scope` limits when an enricher fires within its declared `kind`:

- `scope.rules`: list of rule IDs (exact match) or rule-title globs (`Suspicious *`)
- `scope.tags`: tag-set intersection with prefix wildcards (`attack.*` matches `attack.t1059.001`)
- `scope.levels`: severity membership against `RuleHeader::level`
- No scope = fires for every result of the enricher's declared kind (use for cheap enrichers like `template`)

There is no `scope.kinds` axis: the top-level `kind` already gates which result variant the enricher sees. Axes are AND-ed; an empty axis is not a filter.

## Tenancy

`scope.tenants` restricts an enricher to listed tenants. Dynamic sources, watchlists, STIX sources, MMDB databases, and DNS caches stay operator-global and shared. For per-tenant data, declare per-tenant source ids and reference them only from that tenant's ruleset. See [Multi-tenancy](multi-tenancy.md). {{ added "0.28.0" }}

## The seven primitives

### `template`: pure string interpolation

The cheapest primitive: it does no I/O and cannot fail past config-load-time template parse errors.

```yaml
- id: runbook_det
  kind: detection
  type: template
  inject_field: runbook_url
  template: "https://wiki.internal/runbooks/${detection.rule.id}"
```

### `lookup`: read from the dynamic source cache

Reads a value from the shared dynamic [source cache](../reference/dynamic-sources.md) by source ID and applies an `extract` expression (jq/JSONPath/CEL) with template-expanded variables to slice it. The source can be shared with pipelines and other lookup enrichers without another fetch.

```yaml
- id: asset_context_corr
  kind: correlation
  type: lookup
  inject_field: asset_context
  source: asset_inventory          # id of a dynamic source configured on the daemon
  extract: '.assets[] | select(.hostname == "${correlation.group_key.HostName}")'
  extract_type: jq                 # jq | jsonpath | cel; defaults to jq
  default: "unknown"               # injected on cache miss / no extract match
  on_error: skip                   # applied to errors, and to misses when default is not configured
```

The decision matrix:

- **Cache hit + extract matches** → inject the extracted value
- **Cache hit + no extract match** → if `default` is configured, inject it; otherwise apply `on_miss`, or `on_error` when `on_miss` is absent {{ added "0.28.0" }}
- **Cache miss** → if `default` is configured, inject it; otherwise apply `on_miss`, or `on_error` when `on_miss` is absent {{ added "0.28.0" }}
- **Extract evaluation error** (invalid jq, type mismatch) → always applies `on_error`, even with `default` set

Writing `default: null` injects `null` on a miss; omitting `default` leaves the miss to `on_miss` or `on_error`. See [Misses and errors](#misses-and-errors). {{ added "0.28.0" }}

`lookup` requires at least one dynamic source to be configured on the daemon via `--source <file>`. The loader surfaces a clear error at startup if a `lookup` enricher is configured without a source cache. Source declarations live only in standalone `--source` files. A pipeline is not required. See [Using dynamic sources with `lookup` enrichers](#using-dynamic-sources-with-lookup-enrichers).

### `stix`: local STIX store lookup

{{ added "0.23.0" }}

Query a local [`FsStore`](../library/rstix.md#rstix-graph-marking-store) opened by the daemon via `--stix-store <dir>` (same on-disk layout as [`taxii sync`](../cli/taxii/sync.md) and [`taxii store`](../cli/taxii/store.md)). Requires the `stix-enrich` feature (included in prebuilt `--all-features` binaries). Zero-network-cost for anything already imported into the store.

```yaml
- id: hash_intel
  kind: detection
  type: stix
  inject_field: stix_indicators
  text_search: "${detection.fields.SHA256}"
  type_filter: [indicator]
  max_results: 3
  extract: ".[0]"
  extract_type: jq
  default: []
  on_error: skip
```

Query modes (at least one required):

| Field | Behavior |
|-------|----------|
| `stix_id` | Template-expanded STIX id → direct store `get`. |
| `text_search` | Template-expanded substring → [`StixQuery::text_search`](../library/rstix.md#rstix-graph-marking-store). |
| `attack_technique: true` | Uses the first `attack.t*` technique tag on the firing rule (for example `attack.t1059.001` → search `1059.001`). |

Optional `type_filter` restricts to known STIX 2.1 type names (`indicator`, `attack-pattern`, …). Custom `x_*` MITRE types are matched via `text_search` without a filter. `max_results` defaults to `1`. On a miss (no objects, or an extract that returns `null`), `default` is injected when configured; otherwise `on_miss` applies, or `on_error` when `on_miss` is absent (same contract as `lookup`). {{ added "0.28.0" }}

Operational loop:

1. `rsigma taxii sync --store ./attck-store …` (batch or cron).
2. `rsigma engine daemon --stix-store ./attck-store --enrichers enrichers.yml …`. A store synced with `--allow-custom` (MITRE ATT&CK `x-mitre-*` objects) also needs `--stix-store-allow-custom` on the daemon.
3. Enricher hot-reload re-reads the store from disk so a re-sync is visible without restarting the daemon.

### `mmdb`: local MMDB lookup

{{ added "0.28.0" }}

Look up an IP address in an operator-supplied MaxMind DB (MMDB) file and inject the decoded record. The lookup is vendor-neutral: any MMDB layout works, including GeoLite2 and GeoIP2 City or ASN, IP2Location, IP2Proxy, and databases you build yourself, because records are decoded generically into JSON. Requires the `mmdb-enrich` feature, which is included in the prebuilt binaries. Databases are not bundled; point `db_path` at a file you downloaded or generated.

```yaml
- id: geo_src
  kind: detection
  type: mmdb
  inject_field: geo
  db_path: /var/lib/geoip/GeoLite2-City.mmdb
  key: "${detection.fields.SourceIp}"
  fields:                          # optional; omit to inject the full decoded record
    country_code: country.iso_code
    country_name: country.names.en
    region: subdivisions.0.iso_code
    lat: location.latitude
  default: { country_code: "unknown" }   # optional; used on miss
  on_error: skip
```

A correlation-kind entry reads the same database from the group key. Entries that name the same `db_path` share one loaded reader, so a reload happens once per file.

```yaml
- id: geo_corr
  kind: correlation
  type: mmdb
  inject_field: geo
  db_path: /var/lib/geoip/GeoLite2-City.mmdb
  key: "${correlation.group_key.SourceIp}"
```

Field-path syntax: each value in `fields` is a dotted path into the record. A segment made only of ASCII digits is always an array index, so `subdivisions.0.iso_code` reads the first subdivision's code and `usage_types.1` reads the second array element. Every other segment is a map key. An empty path, an empty segment, or an empty field name is rejected at config load. A path that does not exist is omitted from the injected object; a type mismatch (for example an index into a map) fails the lookup.

Miss and error handling:

| Situation | Result |
|---|---|
| Record found and, with `fields`, at least one path present | Inject the object (hit) |
| No record for the IP | Inject `default` when configured, otherwise apply `on_miss` (logged at debug) {{ added "0.28.0" }} |
| `fields` configured but no path present | Inject `default` when configured, otherwise apply `on_miss` (logged at debug) {{ added "0.28.0" }} |
| `key` renders empty | Fetch error, then `on_error` |
| `key` is not an IP address | Parse error, then `on_error` |
| Record decode or path type mismatch | Parse error, then `on_error` |
| IPv6 key against an IPv4-only database, or another lookup failure | Fetch error, then `on_error` |

The database is checked for replacement about once a minute. A changed file is reopened and swapped in off the hot path, and the previous reader stays active if the reopen fails. An unchanged file is not reloaded. Replace databases atomically: write the new file next to the old one, then `mv` it over the old path. `geoipupdate` already does this. A single-file bind mount pins the original inode, so mount the containing directory instead.

Set `mmap: true` to memory-map the database instead of reading it into memory (see the sizing notes below). It needs the `mmdb-mmap` feature, which the prebuilt binaries and the Docker image include; without the feature, `mmap: true` fails at load. Entries that share a `db_path` must agree on `mmap`. A mapped file must be replaced, never rewritten: writing to it in place or truncating it while the daemon has it mapped can crash the daemon with `SIGBUS`. The atomic replacement above is safe, because the daemon keeps reading the old file until it maps the new one on the next check. {{ added "0.28.0" }}

```yaml
- id: geo_src
  kind: detection
  type: mmdb
  inject_field: geo
  db_path: /var/lib/geoip/GeoLite2-City.mmdb
  key: "${detection.fields.SourceIp}"
  mmap: true                       # requires the mmdb-mmap feature
```

GeoLite2-City example with a field projection:

```yaml
- id: geo_city
  kind: detection
  type: mmdb
  inject_field: geo
  db_path: /var/lib/geoip/GeoLite2-City.mmdb
  key: "${detection.fields.SourceIp}"
  fields:
    country: country.iso_code
    region: subdivisions.0.iso_code
    city: city.names.en
    latitude: location.latitude
    longitude: location.longitude
```

ASN example against a GeoLite2-ASN database:

```yaml
- id: geo_asn
  kind: detection
  type: mmdb
  inject_field: asn
  db_path: /var/lib/geoip/GeoLite2-ASN.mmdb
  key: "${detection.fields.SourceIp}"
  fields:
    number: autonomous_system_number
    organization: autonomous_system_organization
```

IP2Proxy example against a proxy database:

```yaml
- id: geo_proxy
  kind: detection
  type: mmdb
  inject_field: proxy
  db_path: /var/lib/geoip/IP2PROXY-LITE-PX11.MMDB
  key: "${detection.fields.SourceIp}"
  fields:
    is_proxy: is_proxy
    proxy_type: proxy_type
    country_code: country_code
```

Operational metrics for this primitive:

- Alert on staleness with `(time() - rsigma_enrichment_mmdb_build_epoch_seconds{database="/var/lib/geoip/GeoLite2-City.mmdb"}) > 86400 * 7`.
- Catch a wrong `key` field with the misses-to-hits ratio: `sum(rate(rsigma_enrichment_mmdb_misses_total[5m])) / clamp_min(sum(rate(rsigma_enrichment_mmdb_hits_total[5m])), 1) > 0.5`.

Sizing: by default each database is read fully into memory once, however many entries name its `db_path`. With `mmap: true` the file is memory-mapped instead: its pages live in the operating system's page cache, which every process that maps or reads the file shares and the kernel can evict under memory pressure, and the first lookup that touches a page loads it, from disk when it is not already cached. With a 93 MB database that merges geo, ASN, and anonymity data, the daemon's idle resident memory was 113 MB with the file read into memory and 21.5 MB with it mapped (18.5 MB without enrichers), and 174 MB and 141 MB after 100,000 lookups of random IPv4 addresses. Once its pages are resident, a mapped lookup costs the same as an owned one. A lookup costs a few microseconds per enricher per result. Each path in `fields` is decoded separately, so a projection of a few paths costs less than the full record, while a projection of many paths can cost more than the full record. Each entry repeats the key render and the tree lookup, so one entry with several fields is cheaper than several entries on the same file: in the crate's benchmarks, one entry with 17 paths cost about 13% less than three entries with the same paths. {{ added "0.28.0" }}

### `dns`: DNS lookup

{{ added "0.28.0" }}

Resolve a template-expanded name through DNS and inject the answers as presentation-format strings. Requires the `dns-enrich` feature, which is included in the prebuilt binaries. The lookup uses the system resolver unless `nameservers` lists explicit servers.

```yaml
- id: resolve_domain
  kind: detection
  type: dns
  inject_field: resolved
  record_type: IP
  key: "${detection.fields.Domain}"
  cache_ttl: 5m                    # default 5m; cap on positive TTLs
  negative_cache_ttl: 1m           # default 1m; cap on negative TTLs
  cache_max_entries: 10000         # default 10000; must be greater than 0
  nameservers: ["10.0.0.53", "[2001:db8::53]:5353"]   # optional; empty uses the system resolver
  default: []                      # optional; used on miss
  on_error: skip
```

`record_type` accepts `IP` plus `A`, `AAAA`, `ANAME`, `CAA`, `CERT`, `CNAME`, `CSYNC`, `HINFO`, `HTTPS`, `MX`, `NAPTR`, `NS`, `OPENPGPKEY`, `PTR`, `SMIMEA`, `SOA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, and `TXT`. `IP` is a shorthand that queries A and AAAA concurrently and merges the answers. Any other value, including the query-only and meta types (`ANY`, `AXFR`, `IXFR`, `OPT`, `TSIG`, `NULL`, `ZERO`) and the DNSSEC types (`DNSKEY`, `DS`, `RRSIG`, `NSEC`, and so on), is rejected at config load with a message that lists the supported values.

Each answer is a string in the record's presentation format, and the injected value is a JSON array filtered to the queried type. A CNAME chain is not included unless `record_type` is `CNAME`. For `PTR`, `CNAME`, `NS`, `ANAME`, `MX`, and `SRV`, one trailing root dot is stripped from the rendered string. TXT character-strings are joined into one lossy string. Duplicate strings are removed while preserving order, and `IP` lists A answers before AAAA answers.

The key is rendered from its template and trimmed. An empty key is a fetch error. `PTR` requires an IP address and converts it to the reverse name; an IPv4-mapped IPv6 address is canonicalized to IPv4. Every other record type rejects an IP literal and asks for `record_type: PTR` instead. Domain names are lowercased, IDNA-encoded, and fully qualified, so the resolver never applies its search list.

Each enricher owns its own response cache. Positive answers are cached for at most `cache_ttl`, and negative answers (NXDOMAIN and NODATA) are cached for at most the SOA-derived negative TTL capped by `negative_cache_ttl`. A negative answer whose response carries no SOA has no TTL to derive, so it is not cached. Timeouts, SERVFAIL, refused, and I/O errors are never cached. Setting both TTLs to `0s` disables the cache; setting one to `0s` disables only that kind of caching. A `cache_max_entries` of `0` is a config error.

`nameservers` entries must be IP literals with an optional port. Hostnames are rejected. An empty list uses the system resolver.

Miss and error handling:

| Situation | Result |
|---|---|
| At least one answer of the queried type | Inject the array (hit) |
| NXDOMAIN or NODATA | Inject `default` when configured, otherwise apply `on_miss` (logged at debug) {{ added "0.28.0" }} |
| `IP` where one of A or AAAA answers | Inject the answers from the side that answered |
| `IP` where both sides miss | Inject `default` when configured, otherwise apply `on_miss` (logged at debug) {{ added "0.28.0" }} |
| `key` renders empty | Fetch error, then `on_error` |
| `key` has the wrong form for the record type | Parse error, then `on_error` |
| Resolver timeout | Timeout error, then `on_error` |
| SERVFAIL, refused, I/O failure, or another resolver error | Fetch error, then `on_error` |

Operational metrics for this primitive:

- Catch a wrong `key` field with the misses-to-hits ratio: `sum(rate(rsigma_enrichment_dns_cache_misses_total[5m])) / clamp_min(sum(rate(rsigma_enrichment_dns_cache_hits_total[5m])), 1) > 0.5`.
- Alert on resolver health with `sum(rate(rsigma_enrichment_dns_queries_total{result="error"}[5m])) > 0.1`.

### `http`: per-result HTTP fetch with optional response cache

Per-result `reqwest` request with template-expanded URL, headers, and optional body. Parses the response as JSON, optionally sliced by an `extract` expression. The optional response cache is keyed on the method, the rendered URL, the body, and the rendered headers, with a configurable TTL; mandatory in practice for any rate-limited API. Because the rendered headers are part of the key, a header that carries `${detection.tenant}` or an event field never shares a cached response with another value.

```yaml
- id: hash_virustotal
  kind: detection
  type: http
  inject_field: file_reputation
  url: "https://www.virustotal.com/api/v3/files/${detection.fields.SHA256}"
  method: GET                      # default GET
  headers:
    x-apikey: "${VIRUSTOTAL_API_KEY}"
  cache_ttl: 1h                    # mandatory for the 4 req/min free tier
  extract: ".data.attributes.last_analysis_stats"
  extract_type: jq
  miss_status: [404]               # VirusTotal answers an unknown hash with 404
  default: null                    # injected for an unknown hash
  on_error: skip
  scope:
    tags: ["attack.execution", "attack.defense_evasion"]
```

`default` is the value injected for a `null` result and for a listed status. `miss_status` lists response statuses, each in `300..=599`, that mean "no data for this key" rather than a failure, for APIs that answer an unknown indicator with a status such as 404. It is empty by default, so every non-2xx status is a failure. A listed status is a miss: the body is not read and `extract` does not run. An entry outside `300..=599` fails at load. {{ added "0.28.0" }}

Miss and error handling: {{ added "0.28.0" }}

| Situation | Result |
|---|---|
| 2xx response whose value, after the optional `extract`, is not `null` | Inject the value (hit) |
| 2xx response whose value, after the optional `extract`, is `null` | Inject `default` when configured, otherwise inject `null` |
| Status listed in `miss_status` | Inject `default` when configured, otherwise apply `on_miss` (logged at debug); the body is not read |
| `extract` evaluation error | Extract error, then `on_error` |
| Any other non-2xx status, a timeout, a transport error, a body over the cap, or invalid JSON | `on_error`, even when `default` is set |

Both 2xx bodies and `miss_status` responses are cached for `cache_ttl`, and `extract` and `default` are applied again on each cache hit. {{ added "0.28.0" }}

Event and correlation values are escaped for where they land. In `url`, each `${detection.*}` or `${correlation.*}` value is percent-encoded as one URL component (everything except letters, digits, `-`, `_`, `.`, and `~`), so a field value cannot add path segments, start a query, or reach another path on the host; a value that is exactly `.` or `..` has its dots encoded twice so it cannot act as a dot segment. In `body`, values are JSON-string-escaped, so a value inside a JSON string literal cannot add keys; a placeholder outside a string literal is inserted as raw text. `${ENV_VAR}` values in `url` are inserted verbatim, and header values are not escaped (CR and LF are rejected). {{ added "0.25.0" }}

Each enricher instance owns its own response cache: two enrichers hitting the same URL with different `Authorization` headers do not share entries. Response bodies are capped at 10 MiB (same default as HTTP dynamic sources). Outbound URLs follow the daemon [`--egress-policy`](../reference/security.md#http-egress-policy-ssrf-defense) (SSRF / cloud-metadata defense at DNS resolution time, on IP-literal URLs, and on every redirect hop). {{ added "0.27.0" }}

### `command`: per-result local-process execution

Per-result `tokio::process::Command` invocation with template-expanded argv and environment. Stdout is captured (capped at 10 MB) and parsed as JSON or as a raw string. Non-zero exit codes map to a fetch error with a snippet of stderr attached.

```yaml
- id: ip_reputation
  kind: detection
  type: command
  inject_field: ip_reputation
  command:
    - "/usr/local/bin/check-ip-rep"
    - "${detection.fields.SourceIp}"
  env:
    REP_LOCAL_DB: "/var/lib/iprep.db"
  output: json                     # json (default) | raw
  timeout: 3s
  on_error: skip
```

## Composing enrichers (recipes)

The seven primitives cover almost every operational use case via composition. Recipes are *field-parametric*: substitute the field names your pipeline actually produces (`SourceIp`, `cip`, `client.ip`, `ClientIp`, ...) for the placeholders below.

### `enrich_ip_employee`: identity lookup by source IP

```yaml
# sources.yml -- loaded via `rsigma engine daemon --source sources.yml`
sources:
  - id: employee_directory
    type: file
    path: /etc/rsigma/employees.json
    format: json
    extract:
      expr: 'with_entries(.value |= {user: .user, team: .team})'
      type: jq
```

```yaml
# enrichers.yml -- loaded via `--enrichers enrichers.yml`
enrichers:
  - id: enrich_ip_employee
    kind: detection
    type: lookup
    inject_field: employee
    source: employee_directory
    extract: '."${detection.fields.SourceIp}"'
    extract_type: jq
    default: "unknown"
    scope:
      levels: [high, critical]
```

Expected `enrichments.employee` shape: `{"user": "alice", "team": "Platform"}` or `"unknown"` on miss.

### `enrich_username_employee`: identity lookup by username

Same pattern as above, keyed by username. The source file is an object keyed by user name (or rebuild the extract to match your directory shape):

```yaml
# sources.yml
sources:
  - id: employee_directory_by_user
    type: file
    path: /etc/rsigma/employees-by-user.json
    format: json
    refresh: 1h
```

```yaml
# enrichers.yml
enrichers:
  - id: enrich_username_employee
    kind: detection
    type: lookup
    inject_field: employee
    source: employee_directory_by_user
    extract: '."${detection.fields.User}"'
    extract_type: jq
    default: null
```

### `enrich_ip_geoip`: country/city/ASN by IP

Use `type: mmdb` with a local GeoLite2 or GeoIP2 database. This is the native path: the lookup stays local and no per-result network call is made.

```yaml
# enrichers.yml
enrichers:
  - id: enrich_ip_geoip
    kind: detection
    type: mmdb
    inject_field: geoip
    db_path: /var/lib/geoip/GeoLite2-City.mmdb
    key: "${detection.fields.SourceIp}"
    fields:
      country: country.iso_code
      region: subdivisions.0.iso_code
      city: city.names.en
    default: { country: "unknown" }
```

If the GeoIP data is already exported as JSON, use `lookup` against a dynamic source instead:

```yaml
# sources.yml
sources:
  - id: geoip_db
    type: file
    path: /var/lib/geoip/cidr-to-country.json
    format: json
    refresh: 24h
```

```yaml
# enrichers.yml
enrichers:
  - id: enrich_ip_geoip
    kind: detection
    type: lookup
    inject_field: geoip
    source: geoip_db
    extract: '.[] | select(.cidr | test("${detection.fields.SourceIp}"))'
    extract_type: jq
    default: { country: "unknown" }
```

For a hosted GeoIP API, use `http` with a `cache_ttl`, so repeated detections from one address cost one request per `cache_ttl`:

```yaml
# enrichers.yml
enrichers:
  - id: enrich_ip_geoip
    kind: detection
    type: http
    inject_field: geoip
    url: "https://geoip.example.com/v1/${detection.fields.SourceIp}"
    headers:
      Authorization: "Bearer ${GEOIP_API_KEY}"
    cache_ttl: 24h
    extract: 'select(.country_code) | {country: .country_code, region: .region_code, city: .city}'
    extract_type: jq
    default: { country: "unknown" }
    on_error: skip
```

To use it with a provider, adapt three fields:

- `url`: the provider's lookup endpoint. The IP is percent-encoded as one URL component, which works for IPv4 and IPv6 alike.
- `headers`: how the provider takes its key. Send the key in a header rather than a query parameter, because `${ENV_VAR}` values in `url` are inserted verbatim and a failed request logs the full URL. For a keyless tier, remove `headers`; a provider can reject an empty key instead of treating it as keyless.
- `extract`: the response paths on the right of each key.

The `extract` injects the same shape as the `mmdb` recipe, and `default` injects `{country: "unknown"}` when the provider has no record for the address, so moving between a hosted API and a local database does not change what downstream consumers read. Providers commonly answer private and reserved addresses with HTTP 200 and a body that says there is no record, and each says it differently; `select(.country_code)` yields `null` for every body without the field you need, and `default` covers that `null`. If the provider answers an unknown address with a status such as 404 instead, add it to `miss_status`. A rejected key or an exhausted quota typically returns another non-2xx status, which goes through `on_error`. {{ added "0.28.0" }}

Every lookup sends the address to the provider, internal addresses included. Use `mmdb` when addresses must stay inside your network.

### `enrich_ip_rdns`: reverse DNS name by IP

{{ added "0.28.0" }}

Use `type: dns` with `record_type: PTR`. The injected value is the first name the reverse zone returns, without its trailing root dot.

```yaml
# enrichers.yml
enrichers:
  - id: enrich_ip_rdns
    kind: detection
    type: dns
    inject_field: rdns
    record_type: PTR
    key: "${detection.fields.SourceIp}"
    extract: ".[0]"
    extract_type: jq
    default: null
```

Expected `enrichments.rdns` shape: a hostname string such as `host.example.com`, or `null` on miss.

### `enrich_hash_virustotal`: hash reputation with cache

`cache_ttl` is mandatory for the 4 req/min free tier and saves repeat requests during duplicate-detection bursts on any tier:

```yaml
# enrichers.yml
enrichers:
  - id: enrich_hash_virustotal
    kind: detection
    type: http
    inject_field: file_reputation
    url: "https://www.virustotal.com/api/v3/files/${detection.fields.SHA256}"
    method: GET
    headers:
      x-apikey: "${VIRUSTOTAL_API_KEY}"
    cache_ttl: 1h
    extract: ".data.attributes.last_analysis_stats"
    extract_type: jq
    miss_status: [404]
    default: null
    on_error: skip
    scope:
      tags: ["attack.execution", "attack.defense_evasion"]
```

Expected `enrichments.file_reputation` shape: the `last_analysis_stats` object, or `null` when VirusTotal has no report for the hash (HTTP 404). A `null` rather than a placeholder string keeps the field an object wherever it has a value, so a sink with a typed schema does not reject either form. A 404 is cached for `cache_ttl` like a report. {{ added "0.28.0" }}

### `enrich_cve_kev`: known-exploited-vulnerability flag

Pulls the CISA KEV catalog as a dynamic source, then flags CVEs that appear in it.

```yaml
# sources.yml
sources:
  - id: kev_catalog
    type: http
    url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    format: json
    refresh: 1h
```

```yaml
# enrichers.yml
enrichers:
  - id: enrich_cve_kev
    kind: detection
    type: lookup
    inject_field: kev
    source: kev_catalog
    extract: '.vulnerabilities[] | select(.cveID == "${detection.fields.CveId}")'
    extract_type: jq
    default: null
```

### `enrich_url_runbook`: synthesized runbook URL

Pure string interpolation, no I/O. Use this any time a downstream consumer (Slack, PagerDuty, RSoar) needs a per-detection link.

```yaml
# enrichers.yml
enrichers:
  - id: enrich_url_runbook
    kind: detection
    type: template
    inject_field: runbook_url
    template: "https://wiki.internal/runbooks/${detection.rule.id}"
```

### When to pick which primitive

- Prefer `mmdb` for GeoIP, ASN, and proxy data that ships as a MaxMind DB file.
- Prefer `dns` for forward and reverse name resolution, including MX, TXT, and SRV records.
- Prefer `lookup` if the data is bounded and refreshes infrequently (employee directory, KEV catalog, a JSON GeoIP dump).
- Prefer `http` only when the data is genuinely per-result or too large to cache. Always set `cache_ttl` for rate-limited APIs.
- Prefer `command` only when no other primitive will do (a binary parser, a vendored CLI tool, an existing script).
- Never use `template` for anything that could be a YAML literal.

## Promoting a recipe to a bespoke enricher

The seven primitives cover almost every use case via composition. A bespoke Rust-coded enricher is justified only when at least one of these holds:

1. **It bundles non-trivial data** (a dataset committed to the repo and `include_bytes!`-ed at compile time). Recipes can't express vendored data.
2. **It needs a parser the YAML primitives don't expose** (e.g. a proprietary binary format such as a PCAP-derived flow table, the STIX 2.1 graph with parent/child resolution). Adding the parser as a generic source might cost more than just shipping the enricher.
3. **It provides a stable named contract**: downstream consumers reference a specific `enrichments.<field>` shape directly. A recipe-driven approach lets every operator pick their own `inject_field`, which is fine for ad-hoc enrichment but bad for a contract that crosses team or organizational boundaries.
4. **It implements a non-obvious algorithm** (e.g. coalescing per-result hash lookups into one batched-GET request). This is implementable as a recipe but the implementation is fragile.

External crates wire a bespoke type via `register_builtin(name, factory)`:

```rust
use rsigma_runtime::{Enricher, register_builtin};

register_builtin(
    "enrich_my_thing",
    std::sync::Arc::new(|raw_config: &serde_json::Value| -> Result<Box<dyn Enricher>, String> {
        let cfg: MyConfig = serde_json::from_value(raw_config.clone()).map_err(|e| e.to_string())?;
        Ok(Box::new(MyEnricher::new(cfg)))
    }),
).unwrap();
```

Reserved names (`template`, `lookup`, `http`, `command`, `stix`, `mmdb`, `dns`) are rejected at registration time; duplicate registrations of the same name are rejected to keep the global registry append-only. Bespoke types follow the same `kind`, `scope`, and template rules as the seven primitives; promotion does not change the YAML shape, only the `type:` value.

## Output shape

The pipeline writes into `RuleHeader::enrichments` lazily, so detections and correlations that no enricher touched still serialize without an empty `enrichments` object. A typical NDJSON line looks like:

```json
{"rule_title":"Suspicious PowerShell encoded command","rule_id":"rule-pwsh-enc","level":"high","tags":["attack.t1059.001"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"powershell -enc ..."}],"enrichments":{"asset_info":{"hostname":"dc01","owner":"IT-Ops"},"runbook_url":"https://wiki.internal/runbooks/rule-pwsh-enc"}}
```

## Logging

{{ added "0.28.0" }}

A miss without `default` logs at debug level (`Enricher found no data`), so routine misses do not flood the log. A miss covered by `default` is a success and is not logged. Every other failure logs a warning (`Enricher failed, skipping`, `... injecting null`, or `... dropping result`) at most once per 10 seconds per enricher id. Every warning carries a `suppressed` field: the number of failures of that enricher since the previous warning that were not logged. When the enrichers are reloaded, failures not yet reported are logged once per enricher id as `Enricher failures suppressed since the last warning`, with the same field.

## Metrics

| Metric | Labels | Description |
|---|---|---|
| `rsigma_enrichment_total` | `enricher_id`, `kind`, `status` | Per-call outcome counter; `status` is `success`/`skip`/`error`/`timeout`/`miss`/`drop`. A miss that is skipped or injected as `null` reports `miss` {{ added "0.28.0" }} |
| `rsigma_enrichment_duration_seconds` | `enricher_id`, `kind` | Per-enricher latency histogram |
| `rsigma_enrichment_queue_depth` | none | Pending enrichment calls (sum across both kinds) |
| `rsigma_enrichment_http_cache_hits_total` | `enricher_id` | HTTP enricher response-cache hits |
| `rsigma_enrichment_http_cache_misses_total` | `enricher_id` | HTTP enricher response-cache misses |
| `rsigma_enrichment_http_cache_expirations_total` | `enricher_id` | HTTP enricher response-cache entries evicted on expiry |
| `rsigma_enrichment_mmdb_hits_total` | `enricher_id` | MMDB lookups that found a record and a non-empty projection |
| `rsigma_enrichment_mmdb_misses_total` | `enricher_id` | MMDB lookups with no record or an empty projection, including misses where `default` was injected |
| `rsigma_enrichment_mmdb_reloads_total` | `database`, `result` (`success`, `failure`) | MMDB reload attempts that reopened a changed file, or failed and kept the old reader |
| `rsigma_enrichment_mmdb_build_epoch_seconds` | `database` | Build epoch of the loaded MMDB database; alert on `time() - rsigma_enrichment_mmdb_build_epoch_seconds` |
| `rsigma_enrichment_dns_cache_hits_total` | `enricher_id` | DNS queries answered from the response cache, including cached negative answers |
| `rsigma_enrichment_dns_cache_misses_total` | `enricher_id` | DNS queries that went to a nameserver, including every query when caching is disabled |
| `rsigma_enrichment_dns_queries_total` | `enricher_id`, `result` (`answer`, `no_records`, `error`) | Upstream DNS query results |

DNS counters are per query, not per enrichment call: an `IP` lookup counts two queries. A query cut off by the pipeline's outer enricher timeout never completes, so it is not counted in `queries_total`; it shows up in `rsigma_enrichment_total{status="timeout"}` instead. Key errors send no query and are not counted here.

Every `(enricher_id, kind, status)` triple, every HTTP-cache `enricher_id` row, every MMDB hit and miss `enricher_id` row, both MMDB reload `result` values, every DNS cache hit and miss `enricher_id` row, and all three DNS query `result` values are pre-registered at startup, so all thirteen families render at zero on the first `/metrics` scrape, before any event has fired. Filtered (kind- or scope-mismatched) calls do not increment any counters.

## See also

- [`engine daemon` reference](../cli/engine/daemon.md#post-evaluation-enrichment) for the `--enrichers` flag.
- [Dynamic Sources](../reference/dynamic-sources.md) for the shared source cache that `lookup` reads from.
- [Dynamic Pipelines](../reference/dynamic-pipelines.md) for consuming the same sources before rule evaluation.
- [Security Hardening](../reference/security.md#http-egress-policy-ssrf-defense) for egress policy on HTTP enrichers and body size caps.
- [Prometheus metrics](../reference/metrics.md#enrichment-13-metrics) for the full metric definitions.
- [Adding enrichers](../developers/adding-enrichers.md) for shipping a bespoke `register_builtin` type.
- [`rsigma-runtime`](../library/runtime.md) for the `Enricher` trait, `EnrichmentPipeline`, and `register_builtin` API.
