# Observability

RSigma is built on `tracing` plus the `prometheus` crate. Every meaningful event in the daemon and CLI lands on one of:

- A `tracing` event (info, warning, error, debug, or trace) on stderr.
- A Prometheus counter, gauge, or histogram exposed on `/metrics` (daemon only).

This page covers the four observability surfaces you actually operate on: the log subscriber and its format, the `RUST_LOG` filter targets that surface specific concerns (NATS lifecycle, dynamic sources, hot-reload, HTTP requests, correlation memory pressure), what to scrape with Prometheus, and how to recognize the most useful tracing spans.

## Log format and verbosity

The daemon always emits structured JSON to stderr. The other commands (`engine eval`, `rule lint`, `rule validate`, `backend convert`, `pipeline resolve`) default to human-readable stdout/stderr output with no structured logs. Opt into a tracing subscriber for them with `--log-format`:

```bash
rsigma --log-format json rule validate rules/ -p pipelines/ecs.yml
rsigma --log-format text engine eval -r rules/ -e @events.ndjson
```

| Value | What it does |
|-------|--------------|
| `json` | Structured JSON, one object per line. Same shape the daemon always emits. |
| `text` | Human-readable text with ANSI colors when stderr is a TTY. |

`--log-format` adds the diagnostic-log stream alongside the existing stdout/stderr output; it never replaces them. So `rsigma --log-format json engine eval ...` still prints the `MatchResult` lines to stdout exactly as before; the JSON log lines arrive on stderr.

Verbosity is controlled by the standard `RUST_LOG` environment variable (`tracing_subscriber::EnvFilter`). The default is `info`. The flag has no effect on `engine daemon`, which is always JSON.

## RUST_LOG filter targets

Every emitted event carries a `target` field naming the module that produced it. Use that to narrow `RUST_LOG` to the area you care about:

| Target | What it surfaces | When to enable above `info` |
|--------|------------------|-----------------------------|
| `rsigma::daemon::server` | Daemon lifecycle: rule load, API server bind, source start, sink start, shutdown drain. | Always at `info`. Drop to `debug` only when chasing startup ordering bugs. |
| `rsigma::daemon::reload` | File watcher for rules and pipelines, reload triggers, atomic engine swap. | `debug` when investigating "my rule change is not picked up". |
| `rsigma::daemon::health` | Readiness state transitions (`/readyz` flipping 200 ↔ 503). | `debug` if liveness probes flap. |
| `rsigma_runtime::engine` | Rules + pipeline load, swap, recompile timing. | `debug` to confirm the engine swap path during hot-reload. |
| `rsigma_runtime::sources` | Per-source fetches (HTTP, file, command, NATS), cache hits and misses, parse failures. | `debug` when a dynamic source is misbehaving. |
| `rsigma_runtime::sources::refresh` | Scheduled refresh ticks for interval-based sources. | `debug` to see refresh cadence; usually noisy. |
| `rsigma_eval::correlation_engine` | Correlation state pressure (`max_state_entries` evictions), correlation matches. | `warn` is enough in practice; the eviction message is what you actually want to alert on. |
| `rsigma_eval::engine` | Cross-rule AC index limits, bloom-filter sizing. Static one-shot warnings. | `warn`. |
| `async_nats::connector` | NATS connect/disconnect/reconnect lifecycle. Appears with `daemon-nats` enabled. | `debug` to trace transient connection drops; `info` is enough for steady-state. |
| `async_nats` | NATS event-stream messages (`event: connected`, `event: closed`). | Same. |
| `tower_http::trace::on_request` and `tower_http::trace::on_response` | Per-request HTTP access logs for the `/api/v1/*`, `/metrics`, `/v1/logs` endpoints. | `debug` for an access log; off in production unless debugging. |

A few combinations that come up often in practice:

```bash
# Quiet production daemon: only warnings and above, but keep INFO for the
# daemon's own lifecycle messages so the boot sequence stays readable.
RUST_LOG="warn,rsigma::daemon=info" \
    rsigma engine daemon -r rules/

# Trace a hot-reload that is not picking up a rule change.
RUST_LOG="info,rsigma::daemon::reload=debug,rsigma_runtime::engine=debug" \
    rsigma engine daemon -r rules/

# Investigate a dynamic source that is timing out.
RUST_LOG="info,rsigma_runtime::sources=debug" \
    rsigma engine daemon -r rules/ -p pipelines/dynamic.yml

# HTTP access log on the daemon API.
RUST_LOG="info,tower_http=debug" \
    rsigma engine daemon -r rules/ --input http
```

## Spans

A `tracing` span is a structured scope around a unit of work. When the daemon resolves dynamic sources during a rule load, the span tree looks like this in the JSON output:

```json
{
  "timestamp": "...",
  "level": "DEBUG",
  "fields": {"message": "Source fetched successfully", "source_id": "ips"},
  "target": "rsigma_runtime::sources",
  "span": {"rules_path": "/tmp/obs-test/rules", "name": "load_rules"},
  "spans": [{"rules_path": "/tmp/obs-test/rules", "name": "load_rules"}]
}
```

The `span` and `spans` fields tell you the call stack that produced the event without needing distributed tracing infrastructure. The named spans currently emitted:

| Span | Where | Useful for |
|------|-------|------------|
| `load_rules` | Engine swap path during startup and hot-reload. | Correlating per-source fetches with the engine reload that triggered them. |
| `evaluate_batch` (debug only) | Per-batch processing in `LogProcessor`. Includes `batch_size`, `matches`, `elapsed_ms`. | Profiling batch latency vs throughput. Off at `info`. |
| `otlp_logs_request` | One per OTLP `/v1/logs` POST or gRPC `Export`. Includes content encoding and record count. | Detecting agents that send malformed OTLP or overly-large batches. Off at `info`. |

Spans are emitted alongside events. To capture them in a structured aggregator (Loki, Datadog Logs, ClickHouse, etc.), index on the `span.name` field as well as `target` and `level`.

## Prometheus metrics

The daemon binds `/metrics` on the same `--api-addr` as the REST API. It exposes 38 metric definitions across seven concerns under `--all-features` (33 always-present plus 3 OTLP + 2 TLS gated on the matching build features):

| Concern | Metrics | What they answer |
|---------|---------|------------------|
| **Engine throughput** | `rsigma_events_processed_total`, `rsigma_events_parse_errors_total`, `rsigma_detection_matches_total`, `rsigma_correlation_matches_total`, `rsigma_event_processing_seconds`, `rsigma_pipeline_latency_seconds`, `rsigma_batch_size`, `rsigma_uptime_seconds` | How fast are we ingesting, how often are rules firing, how long does each batch take? |
| **Queue and back-pressure** | `rsigma_input_queue_depth`, `rsigma_output_queue_depth`, `rsigma_back_pressure_events_total` | Is the engine keeping up with the source? Is the source faster than the sink? |
| **Rule and state load** | `rsigma_detection_rules_loaded`, `rsigma_correlation_rules_loaded`, `rsigma_correlation_state_entries`, `rsigma_reloads_total`, `rsigma_reloads_failed_total`, `rsigma_dlq_events_total` | How many rules are loaded, how full is the correlation state, are reloads succeeding? |
| **Per-rule labels** (appear after first match) | `rsigma_detection_matches_by_rule_total{rule_id="..."}`, `rsigma_correlation_matches_by_rule_total{rule_id="..."}` | Which specific rules are firing? |
| **Dynamic sources** (with `-p` pipelines that declare sources) | `rsigma_source_resolves_total`, `rsigma_source_resolve_errors_total`, `rsigma_source_resolve_seconds`, `rsigma_source_cache_hits_total`, `rsigma_source_last_resolved_timestamp` | Are HTTP/file/command sources reachable and timely? |
| **Enrichment** | `rsigma_enrichment_total`, `rsigma_enrichment_duration_seconds`, `rsigma_enrichment_queue_depth`, `rsigma_enrichment_http_cache_hits_total`, `rsigma_enrichment_http_cache_misses_total`, `rsigma_enrichment_http_cache_expirations_total` | How is the enricher chain performing and how often does the HTTP cache pay off? |
| **OTLP** (with `daemon-otlp` feature) | `rsigma_otlp_requests_total`, `rsigma_otlp_log_records_total`, `rsigma_otlp_errors_total` | How are upstream OTLP agents behaving? |
| **TLS** (with `daemon-tls` feature) | `rsigma_tls_certificate_expiry_seconds`, `rsigma_tls_active_connections` | When does the server cert expire (alert on `< 7d`) and how many TLS clients are connected? |

Some metrics only appear after their first relevant event (per-rule labels, enrichment counters, OTLP counters, TLS handshake failures). A startup `/metrics` scrape shows about 20 distinct metric names; the full 38 emerge as the daemon does real work and as the feature-gated surfaces are exercised.

Scrape `/metrics` at 15-30 s intervals. The histograms (`event_processing_seconds`, `pipeline_latency_seconds`, `batch_size`) use the default Prometheus bucket boundaries; alert on the `_bucket{le="..."}` quantiles you care about rather than on the raw average.

A minimal scrape config:

```yaml
scrape_configs:
  - job_name: rsigma
    scrape_interval: 15s
    static_configs:
      - targets: ['rsigma.internal:9090']
```

The full table with every label and source-of-truth pointer lives in the [Prometheus metrics reference](../reference/metrics.md).

## Useful alerting recipes

These four alerts catch most operational regressions for free.

```yaml
groups:
  - name: rsigma
    rules:
      # Engine is unable to keep up with the source.
      - alert: RsigmaBackPressure
        expr: rate(rsigma_back_pressure_events_total[5m]) > 0
        for: 10m
        labels: {severity: warning}
        annotations:
          summary: rsigma is back-pressuring the input

      # Correlation state heading toward the hard cap (default 100k).
      - alert: RsigmaCorrelationStatePressure
        expr: rsigma_correlation_state_entries > 80000
        for: 10m
        labels: {severity: warning}
        annotations:
          summary: rsigma correlation state above 80% of the hard cap

      # DLQ getting events means upstream is sending unparseable data.
      - alert: RsigmaDlqVolume
        expr: rate(rsigma_dlq_events_total[5m]) > 1
        for: 15m
        labels: {severity: warning}
        annotations:
          summary: rsigma is routing events to the dead-letter queue

      # Reload-failure rate. Rules path issues, pipeline parse errors.
      - alert: RsigmaReloadsFailing
        expr: rate(rsigma_reloads_failed_total[5m]) > 0
        for: 10m
        labels: {severity: critical}
        annotations:
          summary: rsigma rule reload is failing
```

## Detection coverage with `--observe-fields`

The daemon can answer two coverage questions live from inside the process:

- **Gap signal:** "which event fields am I receiving that no loaded rule references?" An answer of "src_ip is the most-frequent unknown field" is a strong hint that an enricher should drop the field before ingestion, or that a new rule should consume it.
- **Broken-coverage signal:** "which rule fields have never appeared in an event since the daemon started?" An answer of "ProcessGuid is referenced by 3 rules and was never seen" usually means a pipeline mapping is wrong or the upstream agent dropped the field.

Field observation is **off by default** because it adds a per-event field iteration that operators should opt into. Enable it with `--observe-fields` and (optionally) cap memory with `--observe-fields-max-keys <N>` (default `10000`).

```bash
rsigma engine daemon -r /etc/rsigma/rules/ \
  --pipeline ecs_windows \
  --observe-fields \
  --observe-fields-max-keys 10000
```

Once enabled, four endpoints are live on `--api-addr`:

```bash
# Compact one-shot view bundled with summary, unknown, missing.
curl -sS http://127.0.0.1:9090/api/v1/fields | jq

# Just the gap signal, sorted by hottest unknown first.
curl -sS http://127.0.0.1:9090/api/v1/fields/unknown | jq '.items[:5]'

# Just the broken-coverage signal, with sample rule titles.
curl -sS http://127.0.0.1:9090/api/v1/fields/missing | jq '.items[:5]'

# Start a fresh observation window after rolling out a new rule pack.
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/fields/observer
```

Three Prometheus surfaces refresh on every `/metrics` scrape (`rsigma_fields_observed_total`, `rsigma_fields_observer_unique_keys`, `rsigma_fields_observer_overflow_dropped_total`). A persistent positive rate on `rsigma_fields_observer_overflow_dropped_total` means `--observe-fields-max-keys` is too low for the deployment; bump it or accept that long-tail keys will be invisible.

The same surface works offline via `rsigma engine eval --observe-fields` for CI gap analysis. The end-of-run report has the same JSON shape as `GET /api/v1/fields`, so a single `jq` query works against either runtime:

```bash
rsigma engine eval -r rules/ -e @events.ndjson \
    --observe-fields \
    --observe-fields-report coverage.json

jq '.summary | {events_observed, unknown_count, missing_count}' coverage.json
```

See [HTTP API: Field observability](../reference/http-api.md#field-observability) for the daemon endpoint payloads and pagination, [`engine daemon`](../cli/engine/daemon.md#field-observability-advanced) for the daemon flags, and [`engine eval`](../cli/engine/eval.md#field-observability-offline-coverage-report) for the offline equivalent.

## Health probes

For Kubernetes-style orchestrators:

| Endpoint | Returns | Wire to |
|----------|---------|---------|
| `/healthz` | 200 once the listener is up. | `livenessProbe`. Restart the container if this stops responding. |
| `/readyz` | 200 once rules and pipelines are loaded; 503 during startup or after a failed reload. | `readinessProbe`. Drain traffic when this returns 503. |

`/healthz` is intentionally cheap and side-effect-free; do not rely on it to detect "the engine is silently dropping events". Use `rsigma_back_pressure_events_total`, `rsigma_dlq_events_total`, and `rsigma_reloads_failed_total` for that.

## OpenTelemetry receivers

OTLP is one of the [supported input formats](otlp-integration.md) for the daemon (with the `daemon-otlp` feature). RSigma does NOT export traces of its own internal work over OTLP; the OTLP wiring is one-way and is for receiving log records from agents.

If you want to ship the daemon's `tracing` events into a tracing backend, the standard `tracing-opentelemetry` Rust bridge would be the path, but no first-party integration ships today. The structured JSON log stream is the canonical observability surface; pipe it into Loki, Vector → ClickHouse, Datadog Logs, or any equivalent.

## Quick verification

```bash
# Confirm the metrics endpoint is alive.
curl -s http://127.0.0.1:9090/metrics | head -20

# Confirm structured-log emission with the daemon target.
rsigma engine daemon -r rules/ 2>&1 | head -3
```

The first line of `/metrics` should be a `# HELP rsigma_back_pressure_events_total ...` block. The first daemon log line should be a `Rules loaded` event with `target=rsigma::daemon::server`. If either is missing, the build is probably without the `daemon` feature or with a broken `--api-addr`.

## See also

- [Streaming Detection](streaming-detection.md) for the daemon's HTTP API surface that complements the metrics endpoint.
- [Performance Tuning](performance-tuning.md) for which metric to watch when sizing `--buffer-size`, `--batch-size`, or correlation `max_state_entries`.
- [NATS Streaming](nats-streaming.md) for the NATS-specific log targets (`async_nats::connector`).
- [Visibility and Data Sources](visibility-and-data-sources.md) for turning the `--observe-fields` signal into DeTT&CT and Navigator visibility artifacts.
- [Prometheus metrics reference](../reference/metrics.md) for the full 38-metric catalog.
- [HTTP API reference](../reference/http-api.md) for every endpoint exposed alongside `/metrics`.
- [`tracing` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives) for the exact `RUST_LOG` directive grammar.
