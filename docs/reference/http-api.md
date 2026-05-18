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
| `/api/v1/rules` | GET | none | Rule counts and rules-directory path. |
| `/api/v1/reload` | POST | none | Trigger an immediate rules + pipelines reload. |
| `/api/v1/events` | POST | none | NDJSON event ingest. Only enabled with `--input http`. |
| `/api/v1/sources` | GET | none | Dynamic pipeline sources currently registered. |
| `/api/v1/sources/resolve` | POST | none | Force re-resolution of all dynamic sources (with no body) or one specific source (with `{"source_id":"..."}`). |
| `/api/v1/sources/cache/{source_id}` | DELETE | none | Invalidate one source's cache so the next read fetches fresh. |
| `/v1/logs` | POST | none | OTLP/HTTP log ingestion (`application/x-protobuf` or `application/json`, optionally gzip-encoded). Requires `daemon-otlp`. |
| OTLP/gRPC `LogsService/Export` | gRPC | none | OTLP over gRPC on the same `--api-addr`. Requires `daemon-otlp`. |

The daemon does not implement authentication today; deploy it behind a reverse proxy or restrict the bind address to a trusted network. TLS termination is on the [roadmap](https://github.com/timescale/rsigma/issues/128).

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

The same counters are exposed in Prometheus form on `/metrics`. Use `/api/v1/status` for a quick one-shot snapshot; use `/metrics` for monitoring.

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

### `DELETE /api/v1/sources/cache/{source_id}`

Invalidate the cached value for one source so the next refresh fetches fresh. Useful when an upstream feed regenerates content out-of-band of its declared TTL.

```bash
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/sources/cache/ip_blocklist
```

```json
{"status":"invalidated","source_id":"ip_blocklist"}
```

The endpoint returns `200 OK` for any source ID regardless of whether that ID is currently configured; nonexistent IDs are a no-op. If you need a strict check, list `/api/v1/sources` first and confirm the source is registered before invalidating.

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
- [Issue #128 (TLS for daemon API + OTLP)](https://github.com/timescale/rsigma/issues/128) for the planned TLS termination.
