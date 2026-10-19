# HTTP API

The `engine daemon` binds a single Axum HTTP server on `--api-addr` (default `0.0.0.0:9090`) that handles probes, metrics, REST control endpoints, an HTTP event ingest endpoint, and (with the `daemon-otlp` feature) OTLP log ingestion.

All bodies are JSON unless otherwise noted. All responses include a `Content-Type` header. Error responses are JSON objects with an `error` key.

## Endpoint summary

| Path | Method | Permission | Description |
|------|--------|------------|-------------|
| `/healthz` | GET | always open | Liveness probe. Always 200 once the listener is up. |
| `/readyz` | GET | always open | Readiness probe. 200 when rules and pipelines are loaded; 503 during startup or after a failed reload. |
| `/metrics` | GET | `metrics:read` | Prometheus text format. See [Prometheus metrics](metrics.md). |
| `/api/v1/status` | GET | `status:read` | Counters, state-entry counts, uptime, and (when configured) dynamic-source summary. |
| `/api/v1/correlations` | GET | `correlations:read` | Compiled correlation list with per-group counts. Empty when the engine has no correlation rules. |
| `/api/v1/correlations/state` | GET | `correlations:read` | Live per-group correlation window snapshot (current aggregate vs threshold, window entries, last alert, seconds to eviction). Filter with `?id=` and `?group=`. |
| `/api/v1/incidents` | GET | `incidents:read` | Open incidents from the alert-pipeline grouping stage. |
| `/api/v1/incidents/{id}` | GET | `incidents:read` | One open incident, in the same shape as a list entry. |
| `/api/v1/incidents/{id}/bundle` | GET | `incident-bundles:read` | One incident joined to its rules' ADS documentation and the risk entities it overlaps, as JSON or Markdown. |
| `/api/v1/risk` | GET | `risk:read` | Open entities tracked by the risk accumulator, with their window score, tactic count, source count, and window bounds. |
| `/api/v1/silences` | GET, POST | `silences:read`, `silences:write` | List silences, or create one (returns its id). |
| `/api/v1/silences/{id}` | DELETE | `silences:write` | Remove a silence by id. |
| `/api/v1/dispositions` | GET, POST | `dispositions:read`, `dispositions:write` | Ingest analyst dispositions, or read the per-rule false-positive ratio. Disabled by default; enable with `daemon.dispositions.enabled: true` or `--enable-dispositions`. When capture is enabled, POST also requires `capture:write`. There is no read endpoint for the capture ring or spool. |
| `/api/v1/rules` | GET | `rules:read` | Rule counts and rules-directory path. |
| `/api/v1/reload` | POST | `reload:execute` | Trigger an immediate rules + pipelines reload. |
| `/api/v1/events` | POST | `events:ingest` | NDJSON event ingest. Only enabled with `--input http`. |
| `/api/v1/sources` | GET | `sources:read` | Dynamic pipeline sources currently registered. |
| `/api/v1/sources/resolve` | POST | `sources:write` | Force re-resolution of all dynamic sources (with no body) or one specific source (with `{"source_id":"..."}`). |
| `/api/v1/sources/resolve/{source_id}` | POST | `sources:write` | Force re-resolution of a single source by path parameter (no body). Equivalent to the body variant above; useful when the caller has to fit inside an HTTP client that does not send a JSON body on `POST`. |
| `/api/v1/sources/cache/{source_id}` | DELETE | `sources:write` | Invalidate one source's cache so the next read fetches fresh. |
| `/api/v1/fields` | GET | `fields:read` | Combined gap + broken-coverage report. Requires `--observe-fields`. |
| `/api/v1/fields/unknown` | GET | `fields:read` | Fields seen in events that no rule references. Requires `--observe-fields`. |
| `/api/v1/fields/missing` | GET | `fields:read` | Fields referenced by rules that have never appeared in an event. Requires `--observe-fields`. |
| `/api/v1/fields/observer` | DELETE | `fields:write` | Reset the field observer's counters. Requires `--observe-fields`. |
| `/api/v1/schemas` | GET | `schemas:read` | Per-schema event breakdown and unknown rate. Requires `--observe-schemas`. |
| `/api/v1/schemas` | DELETE | `schemas:write` | Reset the schema observer's counters and samples (including the discovery sample). Requires `--observe-schemas`. |
| `/api/v1/schemas/suggestions` | GET | `schemas:read` | Candidate schema signatures mined from the unrecognized-event sample. Requires `--discover-schemas`. |
| `/api/v1/tap` | GET | `tap:read` | Stream a bounded, optionally-redacted window of the live event stream as chunked NDJSON. Disabled by default; enable with `daemon.tap.enabled: true`. |
| `/api/v1/detections/stream` | GET | `detections:read` | Stream live detections as chunked NDJSON, with optional `level` / `rule` filters. Disabled by default; enable with `daemon.tail.enabled: true`. |
| `/api/v1/audit` | GET | `audit:read` | Paginated control-plane mutation audit log (who, what, when, outcome). Requires `--state-db`; auto-enabled when a state database is configured. |
| `/v1/logs` | POST | `events:ingest` | OTLP/HTTP log ingestion (`application/x-protobuf` or `application/json`, optionally gzip-encoded). Requires `daemon-otlp`. |
| OTLP/gRPC `LogsService/Export` | gRPC | `events:ingest` | OTLP over gRPC on the same `--api-addr`. Requires `daemon-otlp`. |

The Permission column applies only when authentication is enabled; without it every route is open, which the daemon accepts only on loopback, a `unix://` socket, a listener that requires client certificates, or with `--allow-unauthenticated`. In-process TLS termination is available via the optional `daemon-tls` build feature: pass `--tls-cert` / `--tls-key` to terminate TLS for the HTTP REST, OTLP/HTTP, and OTLP/gRPC surfaces on the same `--api-addr`, and `--tls-client-ca` to require mTLS. See [TLS termination for the API listener](security.md#tls-termination-for-the-api-listener) for the full flag set.

Endpoint details are split across three pages:

- This page: probes, authentication, reload, event ingest, dynamic pipeline sources, and OTLP ingest.
- [HTTP API: Detection State](http-api-state.md): status and counters, correlations, incidents and incident bundles, risk, silences, the audit trail, dispositions, and rules.
- [HTTP API: Live Observability](http-api-observability.md): field and schema observability, the live event tap, and the live detection tail.

## Authentication

Bearer-token authentication is off by default, so loopback and `unix://` deployments are untouched. {{ added "0.25.0" }} A non-loopback TCP `--api-addr` refuses to start without it unless the listener requires client certificates (`--tls-client-ca`) or `--allow-unauthenticated` is passed (see [Daemon network exposure](security.md#daemon-network-exposure)). Enable it either with the `--api-token-env <ENV_VAR>` flag (a single token with full `admin` permissions, read from the named environment variable) or with the `daemon.api.auth` config block for per-token roles:

```yaml
daemon:
  api:
    auth:
      anonymous_permissions: ["metrics:read"]
      roles:
        triage-bot: ["*:read", "silences:write", "dispositions:write"]
      tokens:
        - name: grafana
          role: reader
          token_env: RSIGMA_API_TOKEN_GRAFANA
        - name: shipper
          role: ingest
          token_env: RSIGMA_API_TOKEN_SHIPPER
        - name: ci
          role: triage-bot
          token_env: RSIGMA_API_TOKEN_CI
```

Clients send `Authorization: Bearer <token>`. Each route requires the `resource:action` permission in the summary table above; a token's permission set comes from its role. The built-in roles are `reader` (`*:read`), `operator` (`*:read` plus every control-plane write except reload, including `capture:write`), `ingest` (`events:ingest` only, so a log shipper's token cannot create silences), and `admin` (`*`). Custom roles are permission lists with `*` wildcards (`"*:read"`, `"silences:*"`); a token can also carry an inline `permissions` list instead of a `role`.

Token secrets never live in YAML: `token_env` names an environment variable, resolved once at startup, and a missing or empty variable fails startup. Token comparison is constant time. `GET /healthz` and `GET /readyz` are always unauthenticated so liveness probes need no secrets; `anonymous_permissions` grants a permission set to requests without an `Authorization` header (for example `["metrics:read"]` keeps Prometheus scraping token-free, and `["*:read"]` protects only the mutating endpoints).

Failure semantics: a missing or unrecognized token gets `401 Unauthorized` (with a `WWW-Authenticate: Bearer` header); a recognized token without the required permission gets `403 Forbidden` naming the missing permission. A presented-but-invalid token is always 401, never a fallback to the anonymous grants. OTLP/gRPC clients pass the same `authorization` metadata and receive `UNAUTHENTICATED` / `PERMISSION_DENIED` gRPC status codes. Rejections are counted in `rsigma_api_auth_failures_total{reason}` and logged at warn level with the token name (never the secret). See [Security](security.md#daemon-api-authentication) for the threat-model discussion.

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
{"status":"not_ready","rules_loaded":false}
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

## OTLP ingest

### `POST /v1/logs` (HTTP)

OTLP log ingestion over HTTP. Accepts `application/x-protobuf` or `application/json`, optionally gzip-encoded. Returns `application/x-protobuf` (or `application/json` matching the request) with the standard OTLP `ExportLogsServiceResponse`. Requires the daemon to be built with `daemon-otlp`.

The request body is limited to 2 MiB as sent. A gzip-encoded body is also limited to 4 MiB after decompression, the same limit the gRPC transport applies, and a larger body is rejected with `413 Payload Too Large`. {{ added "0.25.0" }}

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
