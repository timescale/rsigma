# HTTP API

The `engine daemon` binds a single Axum HTTP server on `--api-addr` (default `0.0.0.0:9090`) that handles probes, metrics, REST control endpoints, an HTTP event ingest endpoint, and (with the `daemon-otlp` feature) OTLP log ingestion.

All bodies are JSON unless otherwise noted. All responses include a `Content-Type` header. Error responses are JSON objects with an `error` key.

## Endpoint summary

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/healthz` | GET | none | Liveness probe. Always 200 once the listener is up. |
| `/readyz` | GET | none | Readiness probe. 200 when rules and pipelines are loaded; 503 during startup or after a failed reload. |
| `/metrics` | GET | none | Prometheus text format. See [Prometheus metrics](metrics.md). |
| `/api/v1/status` | GET | none | Counters, state-entry counts, uptime, and (when configured) dynamic-source summary. |
| `/api/v1/incidents` | GET | none | Open incidents from the alert-pipeline grouping stage. |
| `/api/v1/silences` | GET, POST | none | List silences, or create one (returns its id). |
| `/api/v1/silences/{id}` | DELETE | none | Remove a silence by id. |
| `/api/v1/rules` | GET | none | Rule counts and rules-directory path. |
| `/api/v1/reload` | POST | none | Trigger an immediate rules + pipelines reload. |
| `/api/v1/events` | POST | none | NDJSON event ingest. Only enabled with `--input http`. |
| `/api/v1/sources` | GET | none | Dynamic pipeline sources currently registered. |
| `/api/v1/sources/resolve` | POST | none | Force re-resolution of all dynamic sources (with no body) or one specific source (with `{"source_id":"..."}`). |
| `/api/v1/sources/resolve/{source_id}` | POST | none | Force re-resolution of a single source by path parameter (no body). Equivalent to the body variant above; useful when the caller has to fit inside an HTTP client that does not send a JSON body on `POST`. |
| `/api/v1/sources/cache/{source_id}` | DELETE | none | Invalidate one source's cache so the next read fetches fresh. |
| `/api/v1/fields` | GET | none | Combined gap + broken-coverage report. Requires `--observe-fields`. |
| `/api/v1/fields/unknown` | GET | none | Fields seen in events that no rule references. Requires `--observe-fields`. |
| `/api/v1/fields/missing` | GET | none | Fields referenced by rules that have never appeared in an event. Requires `--observe-fields`. |
| `/api/v1/fields/observer` | DELETE | none | Reset the field observer's counters. Requires `--observe-fields`. |
| `/api/v1/schemas` | GET | none | Per-schema event breakdown and unknown rate. Requires `--observe-schemas`. |
| `/api/v1/tap` | GET | none | Stream a bounded, optionally-redacted window of the live event stream as chunked NDJSON. Disabled by default; enable with `daemon.tap.enabled: true`. |
| `/api/v1/detections/stream` | GET | none | Stream live detections as chunked NDJSON, with optional `level` / `rule` filters. Disabled by default; enable with `daemon.tail.enabled: true`. |
| `/v1/logs` | POST | none | OTLP/HTTP log ingestion (`application/x-protobuf` or `application/json`, optionally gzip-encoded). Requires `daemon-otlp`. |
| OTLP/gRPC `LogsService/Export` | gRPC | none | OTLP over gRPC on the same `--api-addr`. Requires `daemon-otlp`. |

The daemon does not implement authentication today; deploy it behind a reverse proxy or restrict the bind address to a trusted network. In-process TLS termination is available via the optional `daemon-tls` build feature: pass `--tls-cert` / `--tls-key` to terminate TLS for the HTTP REST, OTLP/HTTP, and OTLP/gRPC surfaces on the same `--api-addr`, and `--tls-client-ca` to require mTLS. See [TLS termination for the API listener](security.md#tls-termination-for-the-api-listener) for the full flag set.

## Probes

### `GET /healthz`

Liveness probe. Returns 200 once the listener has accepted at least one accept; never returns 5xx unless the process is being killed.

```bash
curl -sS http://127.0.0.1:9090/healthz
```

```json
{"status":"ok"}
```

### `GET /readyz`

Readiness probe. 200 when rules and pipelines are loaded; 503 during startup or after a reload failure. Drain traffic when 503.

```bash
curl -sS http://127.0.0.1:9090/readyz
```

```json
{"status":"ready","rules_loaded":true}
```

503 body:

```json
{"status":"starting","rules_loaded":false}
```

## Status and counters

### `GET /api/v1/status`

Snapshot of engine counters plus uptime. The `dynamic_sources` block is present only when a pipeline declares sources.

```bash
curl -sS http://127.0.0.1:9090/api/v1/status
```

```json
{
  "status": "running",
  "detection_rules": 1,
  "correlation_rules": 0,
  "correlation_state_entries": 0,
  "events_processed": 2,
  "detection_matches": 1,
  "correlation_matches": 0,
  "uptime_seconds": 19.07,
  "dynamic_sources": {
    "total": 2,
    "resolves_total": 4,
    "errors_total": 0,
    "cache_hits": 0
  }
}
```

The same counters are exposed in Prometheus form on `/metrics`. Use `/api/v1/status` for a quick one-shot snapshot; use `/metrics` for monitoring. For a formatted view from the command line, [`rsigma engine status`](../cli/engine/status.md) fetches this endpoint and renders it as a table (or `json`/`ndjson`/`csv`/`tsv`).

### `GET /api/v1/incidents`

Open incidents from the alert-pipeline grouping stage (present when `--alert-pipeline` configures a `group` block). Each entry has the same shape as an emitted `IncidentResult`, with `state: open` and `trigger: snapshot`.

```bash
curl -sS http://127.0.0.1:9090/api/v1/incidents
```

```json
{
  "count": 1,
  "incidents": [
    {
      "incident_id": "f8bcd62a829b1126",
      "state": "open",
      "trigger": "snapshot",
      "first_seen": 1719412800,
      "last_seen": 1719412860,
      "max_level": "high",
      "result_count": 2,
      "rule_counts": {"rule-1": 2},
      "group_by": {"match.CommandLine": "malware x"},
      "refs": [{"rule": "rule-1", "level": "high"}]
    }
  ]
}
```

The `include` mode configured on the `group` block decides whether each incident carries lightweight `refs` or full `results`. See the [Alert Pipeline](../guide/alert-pipeline.md) guide.

### `GET /api/v1/silences`

List operator silences (static config silences and API-created ones) with their derived state.

```bash
curl -sS http://127.0.0.1:9090/api/v1/silences
```

```json
{
  "count": 1,
  "silences": [
    {
      "id": "0b6c...",
      "matchers": [{"selector": "match.CommandLine", "op": "=~", "value": "malware.*"}],
      "created_by": "ops",
      "comment": "test maintenance",
      "origin": "api",
      "state": "active"
    }
  ]
}
```

### `POST /api/v1/silences`

Create a silence. The body is a JSON object with `matchers` (required; each `{selector, op, value}` where `op` is `=`, `!=`, `=~`, or `!~`), optional `starts_at` / `ends_at` (RFC 3339), `created_by`, and `comment`. Returns `201` with the assigned `id`. A missing matcher list or a bad regex returns `400`. Once the dynamic-silence cap (`max_silences`, default 1000) is reached it returns `429`; delete silences or raise the cap.

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/silences \
  -d '{"matchers":[{"selector":"rule","op":"=","value":"noisy-rule"}],"comment":"muted"}'
```

```json
{ "status": "created", "id": "0b6c..." }
```

### `DELETE /api/v1/silences/{id}`

Remove a silence by id. Returns `200` when removed, `404` when no such silence exists.

```bash
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/silences/0b6c...
```

### `GET /api/v1/rules`

Returns rule counts and the configured rules path. Useful for quickly confirming a reload picked up the expected number of rules.

```bash
curl -sS http://127.0.0.1:9090/api/v1/rules
```

```json
{
  "detection_rules": 22,
  "correlation_rules": 2,
  "rules_path": "/etc/rsigma/rules"
}
```

## Reload

### `POST /api/v1/reload`

Trigger a full reload: rules, pipelines, and dynamic source state. Equivalent to `SIGHUP` or to a file change inside the watched rules directory. The body is ignored.

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/reload
```

```json
{"status":"reload_triggered"}
```

The actual reload runs asynchronously; check `/readyz` and `rsigma_reloads_total` to confirm it completed. On a failure (parse error in a new rule), the daemon keeps serving the previously-loaded rules and increments `rsigma_reloads_failed_total`.

## Event ingest (HTTP mode)

### `POST /api/v1/events`

Active only when the daemon was started with `--input http`. Accepts NDJSON in the request body. Each line is parsed as a JSON object and queued for evaluation. Returns the number of accepted events.

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/events \
  -H 'Content-Type: application/x-ndjson' \
  --data '{"CommandLine":"whoami /priv"}
{"CommandLine":"echo hello"}'
```

```json
{"accepted":2}
```

Lines that fail to parse increment `rsigma_events_parse_errors_total` and are dropped silently. To inspect parse errors, scrape `/metrics` or watch the daemon's stderr log.

## Dynamic pipeline sources

### `GET /api/v1/sources`

Lists every dynamic source registered by the loaded pipelines, with its type, refresh policy, and `required` flag.

```bash
curl -sS http://127.0.0.1:9090/api/v1/sources
```

```json
{
  "sources": [
    {
      "source_id": "ip_blocklist",
      "pipeline": "dynamic_test",
      "type": "Http",
      "refresh": "Interval(300s)",
      "required": true
    },
    {
      "source_id": "field_config",
      "pipeline": "dynamic_test",
      "type": "File",
      "refresh": "Once",
      "required": true
    }
  ]
}
```

When no pipelines declare sources:

```json
{"sources":[]}
```

### `POST /api/v1/sources/resolve`

Force re-resolution of every dynamic source (with no body) or one named source (with a JSON body):

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/sources/resolve
```

```json
{"status":"resolve_triggered"}
```

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/sources/resolve \
  -H 'Content-Type: application/json' \
  --data '{"source_id":"ip_blocklist"}'
```

If no dynamic sources are configured:

```json
{"error":"no dynamic sources configured"}
```

### `POST /api/v1/sources/resolve/{source_id}`

Force re-resolution of one named source via a path parameter, with no request body. Equivalent to the body variant of `POST /api/v1/sources/resolve` and useful for clients that cannot send a JSON body on `POST` (some load balancers, the simplest `curl --data ''` recipes, etc.).

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/sources/resolve/ip_blocklist
```

```json
{"status":"resolve_triggered","source_id":"ip_blocklist"}
```

Returns `404 {"error":"no dynamic sources configured"}` when no sources are registered, and `429 {"status":"resolve_already_pending"}` if a refresh for the same `source_id` is still in flight.

### `DELETE /api/v1/sources/cache/{source_id}`

Invalidate the cached value for one source so the next refresh fetches fresh. Useful when an upstream feed regenerates content out-of-band of its declared TTL.

```bash
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/sources/cache/ip_blocklist
```

```json
{"status":"invalidated","source_id":"ip_blocklist"}
```

The endpoint returns `200 OK` for any source ID regardless of whether that ID is currently configured; nonexistent IDs are a no-op. If you need a strict check, list `/api/v1/sources` first and confirm the source is registered before invalidating.

## Field observability

The daemon can record the field keys of every event it evaluates and join that against the field names referenced by loaded rules. This surfaces two halves of detection coverage from inside the process:

- **Gap signal:** fields in events that no rule references. Likely candidates for new detections, or a sign that an enricher should drop the field before ingestion.
- **Broken-coverage signal:** fields referenced by rules that have never appeared in an event. Either the rule is dead-lettered (wrong pipeline mapping, wrong logsource) or the event source has stopped emitting that field.

Field observation is **off by default**. Start the daemon with `--observe-fields` (and optionally `--observe-fields-max-keys <N>`, default `10000`) to enable the surface. When disabled, all four endpoints below return `503 Service Unavailable` with `{"error":"field observation disabled","hint":"..."}`.

Three Prometheus surfaces refresh on every `/metrics` scrape (and after every successful `/api/v1/fields/*` call): `rsigma_fields_observed_total`, `rsigma_fields_observer_unique_keys`, and `rsigma_fields_observer_overflow_dropped_total`. See [Prometheus metrics](metrics.md) for the catalog entries.

### `GET /api/v1/fields`

One-shot snapshot bundling `summary`, `unknown`, and `missing` sections. Useful for dashboards that want all three views in a single round-trip. Each list section is paginated via `?limit=N&offset=M`.

```bash
curl -sS 'http://127.0.0.1:9090/api/v1/fields?limit=10'
```

```json
{
  "summary": {
    "events_observed": 1248,
    "unique_keys_observed": 18,
    "rule_fields_loaded": 22,
    "overflow_dropped": 0,
    "max_keys": 10000,
    "uptime_seconds": 312.4,
    "intersection_count": 12,
    "unknown_count": 6,
    "missing_count": 10
  },
  "unknown": {
    "items": [{"field": "src_ip", "count": 1187}],
    "total": 6,
    "offset": 0,
    "limit": 10,
    "next_offset": null
  },
  "missing": {
    "items": [{
      "field": "ProcessGuid",
      "rule_count": 3,
      "sources": ["detection"],
      "rule_titles": ["Sysmon Process Tampering", "..."],
      "truncated": false
    }],
    "total": 10,
    "offset": 0,
    "limit": 10,
    "next_offset": null
  }
}
```

### `GET /api/v1/fields/unknown`

Event field paths that the observer has seen but no loaded rule references. Sorted by descending count, then ascending name. Paginated with `?limit=N&offset=M`.

```bash
curl -sS 'http://127.0.0.1:9090/api/v1/fields/unknown?limit=5'
```

```json
{
  "items": [
    {"field": "src_ip", "count": 1187},
    {"field": "User", "count": 1183}
  ],
  "total": 6,
  "offset": 0,
  "limit": 5,
  "next_offset": null
}
```

### `GET /api/v1/fields/missing`

Field names referenced by loaded rules that have never appeared in an event since the observer was started (or last reset). Each entry includes `rule_count` (total rules touching the field), `sources` (the kinds the field originated in: `detection`, `correlation`, `filter`, `metadata`), and `rule_titles` (up to 10 sample titles, with `truncated: true` when more exist).

```bash
curl -sS 'http://127.0.0.1:9090/api/v1/fields/missing?limit=5'
```

```json
{
  "items": [
    {
      "field": "ProcessGuid",
      "rule_count": 3,
      "sources": ["detection"],
      "rule_titles": ["Sysmon Process Tampering"],
      "truncated": false
    }
  ],
  "total": 10,
  "offset": 0,
  "limit": 5,
  "next_offset": null
}
```

### `DELETE /api/v1/fields/observer`

Clear the observer's counters and overflow tally, and reset the per-observer uptime clock. Returns what was cleared so dashboards can subtract baselines.

```bash
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/fields/observer
```

```json
{"status":"reset","previous_keys":18,"previous_events":1248}
```

A `DELETE` does not affect rule loading or any other daemon state. Use it after a rule reload to start a clean coverage window against the updated rule set.

## Schema observability

Available when the daemon is started with `--observe-schemas`. Every event is classified by schema (content-based recognition: ECS, Sysmon, rendered Windows Event Log, CEF, OCSF, a `generic_json` fallback, plus any `--schema-config` signatures), so a mixed stream's composition and its unknown rate are visible at a glance. See [`engine classify`](../cli/engine/classify.md) for the one-shot equivalent and the signature format.

### `GET /api/v1/schemas`

Returns the per-schema counts and the classified/unknown totals since daemon start. Returns `503` when `--observe-schemas` is off.

```bash
curl -sS http://127.0.0.1:9090/api/v1/schemas
```

```json
{
  "summary": {
    "events_observed": 1248,
    "classified": 1203,
    "unknown": 45,
    "uptime_seconds": 612.4
  },
  "by_schema": [
    {"schema": "ecs", "count": 900},
    {"schema": "sysmon", "count": 250},
    {"schema": "generic_json", "count": 53}
  ]
}
```

The same signal is exposed as the `rsigma_events_by_schema_total{schema}` and `rsigma_events_unknown_schema_total` Prometheus counters. A rising unknown rate flags a source whose schema RSigma does not recognize; add a signature with `--schema-config`.

## Live event tap

### `GET /api/v1/tap`

Stream a bounded window of the live event stream as chunked NDJSON, one event per line, followed by a summary record. The capture ends at `duration` or `limit`, whichever comes first, and a dropped client connection tears the session down automatically. The capture is lossy by design: a full per-session buffer drops events (counted in the summary) rather than ever applying backpressure to the engine. This is the endpoint behind [`rsigma engine tap`](../cli/engine/tap.md).

Disabled by default (the tap exfiltrates raw events). Enable it with `daemon.tap.enabled: true` or the `--enable-tap` flag; otherwise the endpoint returns `503 Service Unavailable` with `{"error":"event tap disabled","hint":"..."}`.

| Query param | Default | Description |
|-------------|---------|-------------|
| `duration` | `30s` | Capture window (humantime). Rejected with `400` above `daemon.tap.max_duration` (default `5m`). |
| `limit` | unset | Stop after N events, before the duration if reached first. |
| `stage` | `decoded` | `decoded` (post-parse, post-filter) or `raw` (the input line as received). |
| `redact` | unset | Comma-separated dotted field paths, redacted server-side before the data leaves the daemon. |

```bash
curl -sS -N 'http://127.0.0.1:9090/api/v1/tap?duration=10s&redact=user.email,src_ip'
```

```text
{"CommandLine":"whoami","src_ip":"rsigma:redacted:cfea2addbf5c8284","user":{"email":"rsigma:redacted:509efebfb0e7ac1e"}}
{"CommandLine":"id","src_ip":"rsigma:redacted:8e1b...","user":{"email":"rsigma:redacted:1f9c..."}}
{"rsigma_tap_summary":{"captured":2,"dropped":0,"duration_ms":10000,"stage":"decoded"}}
```

**Redaction is server-side.** Raw values for redacted fields never cross the wire. Each value is replaced with a deterministic per-session token (`rsigma:redacted:<16 hex>`), so equal values map to equal tokens within one capture (preserving correlation cardinality on replay) while a random per-session salt blocks dictionary reversal and cross-fixture linkage. Paths use the same object-key / numeric-index navigation as the [enrichment template engine](../guide/enrichers.md), except a non-numeric segment meeting an array fans out to every element (fail-closed).

Error semantics:

| Status | When |
|--------|------|
| `400 Bad Request` | Malformed params, an invalid `stage`, or a `duration` over `daemon.tap.max_duration`. |
| `409 Conflict` | The concurrent-session cap (`daemon.tap.max_sessions`, default `2`) is reached. |
| `503 Service Unavailable` | The tap is disabled (the default; not enabled via `daemon.tap.enabled: true` or `--enable-tap`). |

!!! warning "The tap exfiltrates raw events"
    Anyone who can reach this endpoint can read live event traffic. It is off by default; enable it only behind mTLS and redact sensitive fields. See [Security](security.md#live-event-tap).

Four Prometheus metrics track the tap: `rsigma_tap_sessions_total`, `rsigma_tap_active_sessions`, `rsigma_tap_events_streamed_total`, and `rsigma_tap_events_dropped_total`. See [Prometheus metrics](metrics.md).

## Live detection tail

### `GET /api/v1/detections/stream`

Stream live detections as chunked NDJSON, one result per line, followed by a summary record. The capture ends at `duration` or `limit`, whichever comes first; with neither it streams until the client disconnects. Each line is the same `EvaluationResult` shape the sinks emit (so `engine tail` and a saved sink file are the same format), captured after post-evaluation enrichment and before dispatch, regardless of which sinks are configured. The stream is lossy by design: a full per-session buffer drops detections (counted in the summary) rather than ever backpressuring the sink task. This is the endpoint behind [`rsigma engine tail`](../cli/engine/tail.md).

Disabled by default. Enable it with `daemon.tail.enabled: true` or the `--enable-tail` flag; otherwise the endpoint returns `503 Service Unavailable` with `{"error":"detection tail disabled","hint":"..."}`.

| Query param | Default | Description |
|-------------|---------|-------------|
| `duration` | unset | Capture window (humantime). Unset streams until the client disconnects. |
| `limit` | unset | Stop after N detections, before the duration if reached first. |
| `level` | unset | Minimum severity (`informational`, `low`, `medium`, `high`, `critical`); lower or unleveled results are excluded. |
| `rule` | unset | Case-insensitive substring matched against the rule title or id. |

```bash
curl -sS -N 'http://127.0.0.1:9090/api/v1/detections/stream?level=high&rule=whoami'
```

```text
{"rule_title":"Whoami Detector","rule_id":"...","level":"high","tags":[],"matched_selections":["selection"],"matched_fields":[{"field":"CommandLine","value":"whoami"}]}
{"rsigma_tail_summary":{"streamed":1,"dropped":0}}
```

Error semantics:

| Status | When |
|--------|------|
| `400 Bad Request` | Malformed params or an invalid `level`. |
| `409 Conflict` | The concurrent-session cap (`daemon.tail.max_sessions`, default `2`) is reached. |
| `503 Service Unavailable` | The tail is disabled (the default; not enabled via `daemon.tail.enabled: true` or `--enable-tail`). |

Two Prometheus metrics track the tail: `rsigma_tail_active_sessions` and `rsigma_tail_detections_dropped_total`. See [Prometheus metrics](metrics.md).

## OTLP ingest

### `POST /v1/logs` (HTTP)

OTLP log ingestion over HTTP. Accepts `application/x-protobuf` or `application/json`, optionally gzip-encoded. Returns `application/x-protobuf` (or `application/json` matching the request) with the standard OTLP `ExportLogsServiceResponse`. Requires the daemon to be built with `daemon-otlp`.

### gRPC `LogsService/Export`

The same OTLP gRPC service binds on the same `--api-addr`. Use `grpcurl` or any OTLP client to publish:

```bash
grpcurl -plaintext -d @ rsigma.internal:9090 \
    opentelemetry.proto.collector.logs.v1.LogsService/Export \
    < logs.json
```

See [OTLP Integration](../guide/otlp-integration.md) for full agent recipes (Grafana Alloy, Vector, Fluent Bit, OpenTelemetry Collector) and the LogRecord-to-rsigma field mapping.

## See also

- [Streaming Detection](../guide/streaming-detection.md) for the daemon overview and hot-reload semantics.
- [OTLP Integration](../guide/otlp-integration.md) for `/v1/logs` agent recipes.
- [Prometheus Metrics](metrics.md) for `/metrics` definitions and alert recipes.
- [Observability](../guide/observability.md) for the broader `tracing` and metrics story.
- [Processing Pipelines: dynamic pipelines](../guide/processing-pipelines.md#dynamic-pipelines) for the source declarations exposed by `/api/v1/sources`.
- [Security: TLS termination for the API listener](security.md#tls-termination-for-the-api-listener) for the optional `daemon-tls` build feature and the `--tls-*` flag set.
