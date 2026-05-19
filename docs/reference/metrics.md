# Prometheus Metrics

The `engine daemon` exposes Prometheus metrics on `GET /metrics` on the same `--api-addr` as the REST API. The full definition catalogue is 27 metric names across three concerns; the runtime exposes the ones that have ever fired in a given process. A startup scrape shows 21 names by default (one of the per-rule counters surfaces immediately because the registry pre-creates it for documentation); the remaining six lazy metrics register on first use of dynamic pipelines or OTLP.

The exact source of truth is the [`daemon/metrics`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/daemon/metrics.rs) module.

## Engine core (16 metrics)

These always show up. They cover ingest, matches, queue depth, back-pressure, reloads, and resource usage.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_events_processed_total` | counter | — | Total events processed by the engine. |
| `rsigma_events_parse_errors_total` | counter | — | JSON or log-format parse errors at the source. |
| `rsigma_detection_matches_total` | counter | — | Total detection matches emitted. |
| `rsigma_correlation_matches_total` | counter | — | Total correlation matches emitted. |
| `rsigma_detection_rules_loaded` | gauge | — | Number of detection rules currently loaded. |
| `rsigma_correlation_rules_loaded` | gauge | — | Number of correlation rules currently loaded. |
| `rsigma_correlation_state_entries` | gauge | — | Active entries in the correlation state. Watch versus the `max_state_entries` cap (default 100000). |
| `rsigma_reloads_total` | counter | — | Total reload attempts (file watcher, SIGHUP, `POST /api/v1/reload`). |
| `rsigma_reloads_failed_total` | counter | — | Reload attempts that produced parse or compile errors. |
| `rsigma_uptime_seconds` | gauge | — | Daemon uptime in seconds. |
| `rsigma_input_queue_depth` | gauge | — | Events currently buffered in the source→engine channel. |
| `rsigma_output_queue_depth` | gauge | — | Results currently buffered in the engine→sink channel. |
| `rsigma_back_pressure_events_total` | counter | — | Times a source was blocked on a full event channel. |
| `rsigma_event_processing_seconds` | histogram | — | Per-event processing latency. |
| `rsigma_pipeline_latency_seconds` | histogram | — | End-to-end latency from event dequeue to sink send. |
| `rsigma_batch_size` | histogram | — | Number of events processed per batch. |
| `rsigma_dlq_events_total` | counter | — | Events routed to the dead-letter queue. |

## Per-rule labels (2 metrics)

These counters carry labels that identify which rule fired. They surface on `/metrics` only after the first match for that kind.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_detection_matches_by_rule_total` | counter | `rule_title`, `level` | Detection matches per rule. |
| `rsigma_correlation_matches_by_rule_total` | counter | `rule_title`, `level`, `correlation_type` | Correlation matches per rule (`correlation_type` is `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, or `value_median`). |

`rule_title` is not guaranteed to be unique in a rule set. If two rules share a title, their counters add together. For collision-free per-rule analytics, scrape `rsigma_detection_matches_total` and join against your detection NDJSON stream by `rule_id` outside Prometheus.

## Dynamic pipeline sources (5 metrics)

Exposed when one or more pipelines declare dynamic sources. The labelled counters surface after the first resolve attempt for the relevant source; `source_cache_hits_total` and `source_resolve_seconds` are global (no `source_id` label).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_source_resolves_total` | counter | `source_id`, `source_type` (`file`, `http`, `command`, `nats`) | Total dynamic source resolution attempts. Counts every attempt, successful or not. |
| `rsigma_source_resolve_errors_total` | counter | `source_id`, `error_kind` (`Fetch`, `Parse`, `Extract`, `Timeout`, `ResourceLimit`) | Failed dynamic source resolutions. |
| `rsigma_source_resolve_seconds` | histogram | — | Dynamic source resolution latency. Aggregated across all sources. |
| `rsigma_source_cache_hits_total` | counter | — | Times cached source data was served on resolution failure. Aggregated across all sources. |
| `rsigma_source_last_resolved_timestamp` | gauge | `source_id` | Unix timestamp of the last successful resolution per source. Alert on staleness. |

The `error_kind` values come from `rsigma_runtime::sources::SourceErrorKind`. `Fetch` covers HTTP / file / command / NATS connect-or-read failures (per-protocol details land in the `error_message` log field, not the label). `ResourceLimit` covers the 10 MiB body cap, 30 s command exec cap, and similar.

## OTLP (3 metrics)

Exposed when the daemon is built with `daemon-otlp` and an OTLP receiver is active. The labelled counters surface after the first request of that kind.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_otlp_requests_total` | counter | `transport` (`http`, `grpc`), `encoding` (e.g. `json`, `protobuf`, `protobuf+gzip`) | OTLP export requests received. |
| `rsigma_otlp_log_records_total` | counter | — | Log records ingested via OTLP. |
| `rsigma_otlp_errors_total` | counter | `transport`, `reason` (`unsupported_content_type`, `decompression`, `decode`, `channel_closed`) | OTLP request errors. |

## Scrape configuration

Minimum Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: rsigma
    scrape_interval: 15s
    static_configs:
      - targets: ['rsigma.internal:9090']
```

15-30 s intervals are reasonable. The histograms use the default `prometheus` bucket boundaries; alert on the `_bucket{le="..."}` quantiles you care about rather than the average, which becomes meaningless under bimodal latency.

## Useful alerts

```yaml
groups:
  - name: rsigma
    rules:
      # Engine cannot keep up.
      - alert: RsigmaBackPressure
        expr: rate(rsigma_back_pressure_events_total[5m]) > 0
        for: 10m
        labels: {severity: warning}

      # Correlation state above 80% of the default 100000 cap.
      - alert: RsigmaCorrelationStatePressure
        expr: rsigma_correlation_state_entries > 80000
        for: 10m
        labels: {severity: warning}

      # DLQ taking traffic.
      - alert: RsigmaDlqVolume
        expr: rate(rsigma_dlq_events_total[5m]) > 1
        for: 15m
        labels: {severity: warning}

      # Reloads failing means rules are broken on disk.
      - alert: RsigmaReloadsFailing
        expr: rate(rsigma_reloads_failed_total[5m]) > 0
        for: 10m
        labels: {severity: critical}

      # Dynamic source went stale (no successful resolve in 10 minutes).
      - alert: RsigmaSourceStale
        expr: time() - rsigma_source_last_resolved_timestamp > 600
        for: 5m
        labels: {severity: warning}
```

## Histograms: bucket guidance

| Metric | Typical p50 | Typical p99 | Notes |
|--------|-------------|-------------|-------|
| `rsigma_event_processing_seconds` | 1-30 µs | < 1 ms | Per-event evaluation against the loaded rule set. Spikes correlate with reload events. |
| `rsigma_pipeline_latency_seconds` | 1-100 µs | < 5 ms | End-to-end from event dequeue to sink send. Dominated by sink latency (file vs NATS). |
| `rsigma_batch_size` | 1 | 1 | Default `--batch-size 1`. With `--batch-size 64` and load, p50 trends toward 64. |

`event_processing_seconds` p99 above 5 ms is usually a sign of misuse (regex-heavy rules without `--cross-rule-ac`, or many `|all` modifiers).

## See also

- [Observability](../guide/observability.md) for the broader observability story, including the `tracing` event targets that complement these metrics.
- [Performance Tuning](../guide/performance-tuning.md) for which metric to watch when sizing `--buffer-size`, `--batch-size`, or correlation `max_state_entries`.
- [Streaming Detection](../guide/streaming-detection.md#http-api) for how the `/metrics` endpoint fits into the broader daemon API.
- [`daemon/metrics` source](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/daemon/metrics.rs) for the registry implementation.
