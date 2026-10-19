# Enrichers

{{ added "0.13.0" }}

Post-evaluation enrichers run after `engine.evaluate()` produces each `EvaluationResult` and before that result is serialized to a sink. They inject contextual data (asset info, IP reputation, identity, GeoIP, runbook URLs) into the `enrichments.<field>` map on each detection or correlation, so every downstream consumer (RSoar, Grafana, Loki, custom scripts) sees the same structured context without re-fetching it.

This page covers what to put in `--enrichers <path>`, how the five primitives compose into the `enrich_<keyfield>_<target>` recipe catalog, and how to promote a recipe to a Rust-coded named enricher when one of the five primitives is not enough. The CLI flag itself is documented under [`engine daemon`](../cli/engine/daemon.md#post-evaluation-enrichment); per-call Prometheus metrics live in [Prometheus metrics](../reference/metrics.md#enrichment-6-metrics).

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
    type: template | lookup | http | command  # required, the primitive
    inject_field: <field-name>     # required, key under enrichments.<...>
    timeout: 5s                    # optional, humantime; default 5s
    on_error: skip | null | drop   # optional; default skip
    scope:                         # optional; see "Scope filtering"
      rules: [<rule-id-or-glob>, ...]
      tags:  [<tag-or-prefix.*>, ...]
      levels: [low, medium, high, critical, informational]
    # ... primitive-specific fields below ...
```

## Kind and template namespaces

Every enricher declares a `kind: detection | correlation`. The kind drives two checks:

1. **Config-load-time template validation.** A `kind: detection` enricher may only reference `${detection.*}` variables in its templated fields; a `kind: correlation` enricher may only reference `${correlation.*}`. Cross-namespace references are rejected at startup with a clear error pointing at the offending field. `${ENV_VAR}` is allowed in both namespaces.
2. **Runtime body matching.** The pipeline skips enrichers whose declared kind does not match the current `EvaluationResult` body variant before invoking `enrich()`, so a detection-kind enricher pays no cost on correlation results and vice versa.

Detection variables (`${detection.*}`):

| Variable | Resolves to |
|---|---|
| `${detection.rule.title}` / `.id` / `.level` | Rule metadata from `RuleHeader` |
| `${detection.tags}` | Comma-joined `tags` |
| `${detection.fields.<name>}` | The matched value of `<name>` from `matched_fields` |
| `${detection.event.<dotted.path>}` | JSON path into the original event (when `rsigma.include_event: "true"` on the rule) |

Correlation variables (`${correlation.*}`):

| Variable | Resolves to |
|---|---|
| `${correlation.rule.title}` / `.id` / `.level` | Rule metadata from `RuleHeader` |
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

## The five primitives

### `template`: pure string interpolation

Cheapest primitive. No I/O. Cannot fail past config-load-time template parse errors.

```yaml
- id: runbook_det
  kind: detection
  type: template
  inject_field: runbook_url
  template: "https://wiki.internal/runbooks/${detection.rule.id}"
```

### `lookup`: read from the dynamic-pipelines source cache

Reads a value from the dynamic-pipelines [source cache](../reference/dynamic-sources.md) by `source_id` and applies an `extract` expression (jq / JSONPath / CEL) with template-expanded variables to slice it. Zero-network-cost for anything already loaded as a dynamic source.

```yaml
- id: asset_context_corr
  kind: correlation
  type: lookup
  inject_field: asset_context
  source: asset_inventory          # id of a dynamic source configured on the daemon
  extract: '.assets[] | select(.hostname == "${correlation.group_key.HostName}")'
  extract_type: jq                 # jq | jsonpath | cel; defaults to jq
  default: "unknown"               # injected on cache miss / no extract match
  on_error: skip                   # applied only when default is not configured
```

The decision matrix:

- **Cache hit + extract matches** → inject the extracted value
- **Cache hit + no extract match** → if `default` is configured, inject it; otherwise apply `on_error`
- **Cache miss** → if `default` is configured, inject it; otherwise apply `on_error`
- **Extract evaluation error** (invalid jq, type mismatch) → always applies `on_error`, even with `default` set

`lookup` requires at least one dynamic source to be configured on the daemon via `--source <file>`. The loader surfaces a clear error at startup if a `lookup` enricher is configured without a source cache. (Source declarations live only in `--source` files; pipeline-embedded `sources:` is removed. See the [Dynamic Sources reference](../reference/dynamic-sources.md#source-declaration).)

### `stix`: local STIX store lookup

{{ added "0.23.0" }}

Query a local [`FsStore`](../library/rstix.md#rstix-graph-marking-store) opened by the daemon via `--stix-store <dir>` (same on-disk layout as [`taxii sync`](../cli/taxii/sync.md) and [`taxii store`](../cli/taxii/store.md)). Requires the **`stix-enrich`** feature (included in prebuilt `--all-features` binaries). Zero-network-cost for anything already imported into the store.

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

Optional `type_filter` restricts to known STIX 2.1 type names (`indicator`, `attack-pattern`, …). Custom `x_*` MITRE types are matched via `text_search` without a filter. `max_results` defaults to **1**. On miss, `default` overrides `on_error` (same contract as `lookup`).

Operational loop:

1. `rsigma taxii sync --store ./attck-store …` (batch or cron).
2. `rsigma engine daemon --stix-store ./attck-store --enrichers enrichers.yml …`. A store synced with `--allow-custom` (MITRE ATT&CK `x-mitre-*` objects) also needs `--stix-store-allow-custom` on the daemon.
3. Enricher hot-reload re-reads the store from disk so a re-sync is visible without restarting the daemon.

### `http`: per-result HTTP fetch with optional response cache

Per-result `reqwest` request with template-expanded URL, headers, and optional body. Parses the response as JSON, optionally sliced by an `extract` expression. The optional response cache is keyed on `(method, url, body_hash)` with a configurable TTL; mandatory in practice for any rate-limited API.

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
  on_error: skip
  scope:
    tags: ["attack.execution", "attack.defense_evasion"]
```

Event and correlation values are escaped for where they land. In `url`, each `${detection.*}` or `${correlation.*}` value is percent-encoded as one URL component (everything except letters, digits, `-`, `_`, `.`, and `~`), so a field value cannot add path segments, start a query, or reach another path on the host; a value that is exactly `.` or `..` has its dots encoded twice so it cannot act as a dot segment. In `body`, values are JSON-string-escaped, so a value inside a JSON string literal cannot add keys; a placeholder outside a string literal is inserted as raw text. `${ENV_VAR}` values in `url` are inserted verbatim, and header values are not escaped (CR and LF are rejected). {{ added "0.25.0" }}

Each enricher instance owns its own response cache: two enrichers hitting the same URL with different `Authorization` headers do not share entries. Response bodies are capped at 10 MiB (same default as HTTP dynamic sources). Outbound URLs follow the daemon [`--egress-policy`](../reference/security.md#http-egress-policy-ssrf-defense) (SSRF / cloud-metadata defense at DNS resolution time).

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

The four primitives cover almost every operational use case via composition. Recipes are *field-parametric*: substitute the field names your pipeline actually produces (`SourceIp`, `cip`, `client.ip`, `ClientIp`, ...) for the placeholders below.

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

Prefer `lookup` if a GeoIP dump fits in memory:

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

For vendor APIs, use `http` with a `cache_ttl` instead of shipping a dump (same shape as the VirusTotal recipe below).

### `enrich_hash_virustotal`: hash reputation with cache

`cache_ttl` is mandatory for the 4 req/min free tier and a major win for duplicate-detection bursts on any tier:

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
    on_error: skip
    scope:
      tags: ["attack.execution", "attack.defense_evasion"]
```

### `enrich_cve_kev`: known-exploited-vulnerability flag

Pulls the CISA KEV catalog as a dynamic-pipelines source, then flags CVEs that appear in it.

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

- Prefer `lookup` if the data is bounded and refreshes infrequently (employee directory, KEV catalog, GeoIP dump).
- Prefer `http` only when the data is genuinely per-result or too large to cache. Always set `cache_ttl` for rate-limited APIs.
- Prefer `command` only when no other primitive will do (a binary parser, a vendored CLI tool, an existing script).
- Never use `template` for anything that could be a YAML literal.

## Promoting a recipe to a bespoke enricher

The four primitives cover almost every use case via composition. A bespoke Rust-coded enricher is justified only when at least one of these holds:

1. **It bundles non-trivial data** (a dataset committed to the repo and `include_bytes!`-ed at compile time). Recipes can't express vendored data.
2. **It needs a parser the YAML primitives don't expose** (e.g. MaxMind's binary GeoLite2 format, the STIX 2.1 graph with parent/child resolution). Adding the parser as a generic source might cost more than just shipping the enricher.
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

Reserved names (`template`, `lookup`, `http`, `command`) are rejected at registration time; duplicate registrations of the same name are rejected to keep the global registry append-only. Bespoke types follow the same `kind` / `scope` / template rules as the four primitives; promotion does not change the YAML shape, only the `type:` value.

## Output shape

The pipeline writes into `RuleHeader::enrichments` lazily, so detections and correlations that no enricher touched still serialize without an empty `enrichments` object. A typical NDJSON line looks like:

```json
{"rule_title":"Suspicious PowerShell encoded command","rule_id":"rule-pwsh-enc","level":"high","tags":["attack.t1059.001"],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"powershell -enc ..."}],"enrichments":{"asset_info":{"hostname":"dc01","owner":"IT-Ops"},"runbook_url":"https://wiki.internal/runbooks/rule-pwsh-enc"}}
```

## Metrics

| Metric | Labels | Description |
|---|---|---|
| `rsigma_enrichment_total` | `enricher_id`, `kind`, `status` | Per-call outcome counter; `status` is `success` / `skip` / `error` / `timeout` / `drop` |
| `rsigma_enrichment_duration_seconds` | `enricher_id`, `kind` | Per-enricher latency histogram |
| `rsigma_enrichment_queue_depth` | none | Pending enrichment calls (sum across both kinds) |
| `rsigma_enrichment_http_cache_hits_total` | `enricher_id` | HTTP enricher response-cache hits |
| `rsigma_enrichment_http_cache_misses_total` | `enricher_id` | HTTP enricher response-cache misses |
| `rsigma_enrichment_http_cache_expirations_total` | `enricher_id` | HTTP enricher response-cache entries evicted on expiry |

Every `(enricher_id, kind, status)` triple and every HTTP-cache `enricher_id` row is pre-registered at startup, so all six families render at zero on the first `/metrics` scrape, before any event has fired. Filtered (kind- or scope-mismatched) calls do not increment any counters.

## See also

- [`engine daemon` reference](../cli/engine/daemon.md#post-evaluation-enrichment) for the `--enrichers` flag.
- [Dynamic Pipeline Sources](../reference/dynamic-sources.md) for the source cache that `lookup` reads from.
- [Security Hardening](../reference/security.md#http-egress-policy-ssrf-defense) for egress policy on HTTP enrichers and body size caps.
- [Prometheus metrics](../reference/metrics.md#enrichment-6-metrics) for the full metric definitions.
- [Adding enrichers](../developers/adding-enrichers.md) for shipping a bespoke `register_builtin` type.
- [`rsigma-runtime`](../library/runtime.md) for the `Enricher` trait, `EnrichmentPipeline`, and `register_builtin` API.
