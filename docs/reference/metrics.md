# Prometheus Metrics

The `engine daemon` exposes Prometheus metrics on `GET /metrics` on the same `--api-addr` as the REST API. The full definition catalogue under `--all-features` (which is how the prebuilt release archives and the GHCR Docker image are built) is 44 metric names across nine concerns: 39 are always registered, and the OTLP (3) and TLS (2) families are feature-gated on `daemon-otlp` and `daemon-tls` respectively. The runtime exposes the ones that have ever fired in a given process. The three field-observer surfaces always render their `# HELP`/`# TYPE` lines (and stay at zero unless `--observe-fields` was passed); the others follow the lazy-registration pattern documented per section below.

The exact source of truth is the [`daemon/metrics`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/daemon/metrics.rs) module.

## Engine core (17 metrics)

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
| `rsigma_input_queue_depth` | gauge | — | Events currently buffered in the source→engine channel. Tracked for every input, including the HTTP and OTLP push receivers. |
| `rsigma_output_queue_depth` | gauge | — | Results currently buffered in the engine→sink channel. |
| `rsigma_back_pressure_events_total` | counter | — | Times a source was blocked on a full event channel. |
| `rsigma_event_processing_seconds` | histogram | — | Per-event processing latency. |
| `rsigma_pipeline_latency_seconds` | histogram | — | End-to-end latency from event dequeue to sink send. |
| `rsigma_batch_size` | histogram | — | Number of events processed per batch. |
| `rsigma_dlq_events_total` | counter | — | Events routed to the dead-letter queue. |
| `rsigma_sink_queue_depth` | gauge | `sink` | Results buffered in each sink's delivery queue. |
| `rsigma_sink_retries_total` | counter | `sink` | Sink delivery retries after a retryable failure. |
| `rsigma_sink_dropped_total` | counter | `sink` | Results dropped because a lossy sink's queue was full (`?on_full=drop`). |
| `rsigma_sink_delivery_failures_total` | counter | `sink` | Sink deliveries that exhausted retries and were routed to the DLQ. |
| `rsigma_webhook_requests_total` | counter | `webhook_id`, `outcome` (`success`, `permanent_failure`, `rate_limited_wait`) | Webhook requests by outcome. Queue depth, retries, drops, and DLQ routing are read from the shared per-sink series above, keyed by `sink=<webhook id>` (one-to-one with `webhook_id`). |
| `rsigma_webhook_request_duration_seconds` | histogram | `webhook_id` | Per-webhook HTTP request latency. |

## Per-rule labels (2 metrics)

These counters carry labels that identify which rule fired. They surface on `/metrics` only after the first match for that kind.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_detection_matches_by_rule_total` | counter | `rule_title`, `level` | Detection matches per rule. |
| `rsigma_correlation_matches_by_rule_total` | counter | `rule_title`, `level`, `correlation_type` | Correlation matches per rule (`correlation_type` is `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, or `value_median`). |

`rule_title` is not guaranteed to be unique in a rule set. If two rules share a title, their counters add together. For collision-free per-rule analytics, scrape `rsigma_detection_matches_total` and join against your detection NDJSON stream by `rule_id` outside Prometheus.

These two families feed the silence and noisy signals of [`rule hygiene`](../cli/rule/hygiene.md) (and the production-volume column of [`rule scorecard`](../cli/rule/scorecard.md)): pass a saved scrape or a live endpoint as `--metrics` and they join per-rule by `rule_title`.

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

## Enrichment (6 metrics)

Exposed when the daemon is built with `daemon` and `--enrichers` is passed. Every `(enricher_id, kind, status)` triple and every HTTP-cache `enricher_id` row is pre-registered at startup, so all six families render with their `# HELP` / `# TYPE` lines and zeroed counters on the first scrape, even before any event has fired. Filtered (kind- or scope-mismatched) enricher calls do not increment any counter, so cardinality stays bounded by the number of configured enrichers.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_enrichment_total` | counter | `enricher_id`, `kind` (`detection`, `correlation`), `status` (`success`, `skip`, `error`, `timeout`, `drop`) | Per-call outcome counter. `kind` is the enricher's declared kind (the YAML `kind:` field), not a per-result discriminator. |
| `rsigma_enrichment_duration_seconds` | histogram | `enricher_id`, `kind` | Per-enricher latency. Buckets target both fast `template` calls and slower `http`/`command` invocations. |
| `rsigma_enrichment_queue_depth` | gauge | — | Pending enrichment calls (sum across both kinds). Watch this versus `max_concurrent_enrichments`. |
| `rsigma_enrichment_http_cache_hits_total` | counter | `enricher_id` | HTTP enricher response-cache hits. Mandatory signal for any rate-limited API recipe. |
| `rsigma_enrichment_http_cache_misses_total` | counter | `enricher_id` | HTTP enricher response-cache misses. |
| `rsigma_enrichment_http_cache_expirations_total` | counter | `enricher_id` | HTTP enricher response-cache entries evicted on expiry. |

The `kind` label is carried even though `enricher_id` typically already encodes it (`asset_lookup_det` vs `asset_lookup_corr`), so dashboards can compute `sum by (kind)` without depending on a naming convention.

## Alert pipeline (13 metrics)

Exposed when the daemon is built with `daemon`. The fixed label sets on `rsigma_dedup_results_total`, `rsigma_incidents_emitted_total`, and `rsigma_incident_overmerge_total`, plus the `rsigma_dedup_store_entries`, `rsigma_incidents_open`, `rsigma_silences_active`, and `rsigma_inhibit_sources_active` gauges, are pre-registered at startup, so they render with their `# HELP` / `# TYPE` lines and zeroed series on the first scrape, even before `--alert-pipeline` is passed or any event fires. The `rsigma_inhibited_total{rule}` series appears once a rule first inhibits. See the [Alert Pipeline](../guide/alert-pipeline.md) guide.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_dedup_results_total` | counter | `action` (`emitted`, `folded`, `repeat`, `resolved`) | Dedup outcomes: first fires emitted, duplicates folded, repeat re-emits, and resolved records. |
| `rsigma_dedup_store_entries` | gauge | — | Active dedup alerts currently tracked. |
| `rsigma_dedup_evictions_total` | counter | — | Active alerts evicted after resolving. |
| `rsigma_dedup_summaries_emitted_total` | counter | — | Dedup summary records emitted (repeat re-emits plus resolved records). |
| `rsigma_incidents_open` | gauge | — | Open incidents currently tracked by the grouping stage. |
| `rsigma_incidents_emitted_total` | counter | `trigger` (`group_wait`, `group_interval`, `repeat`, `resolved`) | Incident emissions by trigger. |
| `rsigma_incident_results_total` | counter | — | Total incident records emitted. |
| `rsigma_incident_overmerge_total` | counter | `guard` (`stop_value`, `cardinality_ceiling`) | Entity-graph guard hits that suppressed a join. |
| `rsigma_silenced_total` | counter | — | Results muted by an active silence. |
| `rsigma_silences_active` | gauge | — | Currently-active silences. |
| `rsigma_inhibited_total` | counter | `rule` | Results muted by an inhibition rule, by rule name. |
| `rsigma_inhibit_sources_active` | gauge | — | Currently-active inhibition sources. |
| `rsigma_alert_pipeline_duration_seconds` | histogram | — | Alert-pipeline stage duration in seconds. |

## Risk-based alerting (9 metrics)

Exposed when the daemon is built with `daemon`. The fixed label set on `rsigma_risk_annotations_total` and `rsigma_risk_incidents_emitted_total`, plus the `rsigma_risk_entities_open` and `rsigma_risk_state_entries` gauges, are pre-registered at startup, so they render with their `# HELP` / `# TYPE` lines and zeroed series on the first scrape, even before `--risk` is passed or any event fires. See the [Risk-Based Alerting](../guide/risk-based-alerting.md) guide.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_risk_annotations_total` | counter | `action` (`scored`, `no_entity`, `skipped`) | Risk-annotation outcomes: scored with entities, scored with no entity, or skipped (out of scope). |
| `rsigma_risk_annotation_score` | histogram | — | Distribution of the per-detection resolved risk score. |
| `rsigma_risk_objects_total` | counter | — | Risk objects extracted from firing detections. |
| `rsigma_risk_entities_open` | gauge | — | Entities currently tracked by the risk accumulator. |
| `rsigma_risk_state_entries` | gauge | — | Risk contributions currently retained across all entities. |
| `rsigma_risk_evictions_total` | counter | — | Entities dropped from the accumulator (store full or aged out). |
| `rsigma_risk_incidents_emitted_total` | counter | `trigger` (`score`, `tactic_count`) | Risk incidents emitted by trigger. |
| `rsigma_risk_incident_results_total` | counter | — | Total risk incident records emitted. |
| `rsigma_risk_layer_duration_seconds` | histogram | — | Risk-layer stage duration in seconds. |

## OTLP (3 metrics)

Exposed when the daemon is built with `daemon-otlp` and an OTLP receiver is active. The labelled counters surface after the first request of that kind.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_otlp_requests_total` | counter | `transport` (`http`, `grpc`), `encoding` (e.g. `json`, `protobuf`, `protobuf+gzip`) | OTLP export requests received. |
| `rsigma_otlp_log_records_total` | counter | — | Log records ingested via OTLP. |
| `rsigma_otlp_errors_total` | counter | `transport`, `reason` (`unsupported_content_type`, `decompression`, `decode`, `channel_closed`) | OTLP request errors. |

## TLS (2 metrics)

Exposed when the daemon is built with `daemon-tls`. Both metrics render with their `# HELP` and `# TYPE` lines as soon as TLS is configured, even before the first handshake.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_tls_certificate_expiry_seconds` | gauge | — | Seconds until the active TLS server certificate's `not_after`. Signed: negative once expired. Updated at startup and after every successful SIGHUP-triggered reload. |
| `rsigma_tls_active_connections` | gauge | — | Currently active TLS-terminated connections on the API listener. Decrements on connection close (including handshake failure). |

## Field observability (3 metrics)

Exposed unconditionally; values stay at zero unless the daemon was started with `--observe-fields`. All three refresh on every `/metrics` scrape and after every successful `/api/v1/fields/*` call. See [HTTP API: Field observability](http-api.md#field-observability) for the matching endpoints.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_fields_observed_total` | counter | — | Total events scanned by the opt-in field observer. Advances regardless of whether the event had structured fields. |
| `rsigma_fields_observer_unique_keys` | gauge | — | Distinct field names currently tracked. Saturates at `--observe-fields-max-keys` (default `10000`). |
| `rsigma_fields_observer_overflow_dropped_total` | counter | — | New-key insert attempts dropped because the observer was at capacity. A persistent positive rate signals that `--observe-fields-max-keys` is too low for the deployment. |

## Schema observability (4 metrics)

Exposed unconditionally; values stay at zero unless the daemon was started with `--observe-schemas` (or `--discover-schemas`, which implies it). All refresh on every `/metrics` scrape and on every `GET /api/v1/schemas` call. See [HTTP API: Schema observability](http-api.md#schema-observability) for the matching endpoint.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_events_by_schema_total` | counter | `schema` | Events classified into each recognized schema (`ecs`, `sysmon`, `windows_eventlog`, `cef`, `ocsf`, `generic_json`, or a user-defined name). |
| `rsigma_events_unknown_schema_total` | counter | — | Events that matched no schema signature. A rising rate signals a source whose schema RSigma does not recognize; add a signature with `--schema-config`. |
| `rsigma_events_ambiguous_schema_total` | counter | — | Events where two different-name signatures tied at the winning specificity, so the name tie-break decided routing. Resolve by giving one signature a distinguishing predicate or a higher specificity. |
| `rsigma_unknown_schema_clusters` | gauge | — | Distinct clusters of unrecognized event shapes that schema discovery would propose a signature for. Zero unless the daemon was started with `--discover-schemas`; drives the [`GET /api/v1/schemas/suggestions`](http-api.md#get-apiv1schemassuggestions) endpoint. |

## Logsource-aware evaluation (4 metrics)

Exposed unconditionally; values stay at zero unless the daemon was started with `--logsource-routing`. All refresh on every `/metrics` scrape. See [Logsource-Aware Evaluation](../guide/logsource-routing.md).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_rules_pruned_by_logsource_total` | counter | — | Always-evaluated rules skipped because their product conflicts with the event's logsource. The scaling signal: it rises with the conflicting fraction of a mixed-product ruleset. |
| `rsigma_events_without_logsource_total` | counter | — | Events with no extractable logsource, evaluated against every rule (fail-open). A high rate means events are not carrying a logsource tag and no static override or field map is set. |
| `rsigma_schema_rules_eligible` | gauge | `schema` | Rules a schema's events evaluate after logsource pruning. Set when both schema routing and logsource routing are active; refreshed on scrape and reload. |
| `rsigma_schema_rules_pruned` | gauge | `schema` | Rules pruned for a schema by its implied logsource. The higher this is relative to eligible, the less of the ruleset that schema exercises. |

## Live event tap (4 metrics)

Exposed unconditionally; values stay at zero unless the tap is enabled (`daemon.tap.enabled: true`) and an operator opens a session. See [HTTP API: Live event tap](http-api.md#live-event-tap) and [`rsigma engine tap`](../cli/engine/tap.md).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_tap_sessions_total` | counter | — | Total tap sessions opened over the daemon's lifetime. |
| `rsigma_tap_active_sessions` | gauge | — | Currently active tap sessions. Bounded by `daemon.tap.max_sessions`. |
| `rsigma_tap_events_streamed_total` | counter | — | Events streamed to tap clients. |
| `rsigma_tap_events_dropped_total` | counter | — | Events dropped from a tap (a full per-session buffer, or an unparseable line in a redacting raw capture). A positive rate means captured fixtures have gaps. |

## Live detection tail (2 metrics)

Exposed unconditionally; values stay at zero unless the tail is enabled (`daemon.tail.enabled: true`) and an operator opens a session. See [HTTP API: Live detection tail](http-api.md#live-detection-tail) and [`rsigma engine tail`](../cli/engine/tail.md).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_tail_active_sessions` | gauge | — | Currently active tail sessions. Bounded by `daemon.tail.max_sessions`. |
| `rsigma_tail_detections_dropped_total` | counter | — | Detections dropped from a tail because a session buffer was full. A positive rate means a tail client could not keep up. |

## Triage feedback loop (4 metrics)

Exposed when the triage feedback loop is enabled (`daemon.dispositions.enabled: true` or `--enable-dispositions`). The ingest counters pre-register their fixed label sets so they render with zeroed series on the first scrape; `rsigma_rule_false_positive_ratio` is absent for a rule until it reaches `daemon.dispositions.min_sample`. See the [Triage Feedback Loop](../guide/triage-feedback.md) guide and [HTTP API: Dispositions](http-api.md#dispositions).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_rule_false_positive_ratio` | gauge | `rule_title` | Per-rule false-positive ratio over the rolling window. Absent until the rule reaches `min_sample` dispositions. |
| `rsigma_dispositions_total` | counter | `rule_title`, `verdict` | Analyst dispositions counted, by rule and verdict (`true_positive`, `false_positive`, `benign_true_positive`). |
| `rsigma_disposition_ingest_total` | counter | `source`, `result` | Ingest outcomes by source (`api`, `file`, `http`, `nats`) and result (`accepted`, `duplicate`, `rejected`). |
| `rsigma_disposition_ingest_errors_total` | counter | `reason` | Ingest errors by reason (`parse`, `validation`). |

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

      # Enricher consistently failing (timeouts or fetch errors).
      - alert: RsigmaEnrichmentFailing
        expr: |
          sum by (enricher_id) (
            rate(rsigma_enrichment_total{status=~"error|timeout"}[5m])
          ) > 1
        for: 10m
        labels: {severity: warning}

      # TLS certificate expires within 14 days.
      - alert: RsigmaTlsCertExpiring
        expr: rsigma_tls_certificate_expiry_seconds < 14 * 86400
        for: 5m
        labels: {severity: warning}

      # TLS certificate has already expired.
      - alert: RsigmaTlsCertExpired
        expr: rsigma_tls_certificate_expiry_seconds < 0
        for: 1m
        labels: {severity: critical}
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
