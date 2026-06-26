# Alert Pipeline

The alert pipeline is an optional post-engine stage in the daemon's output path, between post-evaluation [enrichment](enrichers.md) and the sinks. It is modeled on the Prometheus Alertmanager processing pipeline and is strictly post-engine: it consumes `EvaluationResult`s and emits `EvaluationResult`s, so the evaluation hot path is untouched.

It is configured with a separate YAML file via `--alert-pipeline <path>` (or the `daemon.alert_pipeline` config key) and is hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; a failed reload keeps the previous pipeline active.

This page covers deduplication.

## Deduplication

Deduplication collapses repeated firings of the same logical alert into a single active alert, modeled on Alertmanager's dedup behavior rather than a silent drop.

Each in-scope result is reduced to a **fingerprint**: the rule identity plus the configured selector values. The first fire for a fingerprint passes through unchanged and opens an *active alert*. Subsequent fires within the window **fold** into that alert, incrementing its fire count and `last_seen`, instead of being emitted again. A periodic tick then:

- re-emits a still-active alert every `repeat_interval`, carrying the accumulated fire count (set `repeat_interval: 0` for pure suppression with no re-emits), and
- emits a final `resolved` record once `resolve_timeout` elapses with no further fires, and evicts the alert.

Re-emit and resolved records are ordinary NDJSON results carrying a `dedup_state` key (`repeat` or `resolved`) in their `enrichments`, so they ride the existing sink path and wire shape. They also carry `dedup_fingerprint`, `dedup_fire_count`, `dedup_first_seen`, `dedup_last_seen`, and the resolved `dedup_fields` values.

### Configuration

```yaml
# alert-pipeline.yml
strip_event: false
scope:
  levels: [high, critical]
  tags: [attack.*]
dedup:
  fingerprint:
    - rule
    - match.SourceIp
  repeat_interval: 1h    # 0 disables re-emits (pure suppression)
  resolve_timeout: 30m
```

| Key | Default | Description |
|-----|---------|-------------|
| `strip_event` | `false` | Retain the event for selector resolution, then drop raw event payloads (detection `event`, correlation `events` / `event_refs`) before sink delivery. |
| `scope.rules` / `scope.tags` / `scope.levels` | empty | Restrict which results the layer acts on. Out-of-scope results pass through untouched. Same syntax as the enrichers `scope`. |
| `dedup.fingerprint` | required | Selectors hashed (with the rule identity) into the fingerprint. At least one is required when `dedup` is set. |
| `dedup.repeat_interval` | `0` | Re-emit cadence for a still-active alert (humantime, e.g. `1h`). `0` means pure suppression. |
| `dedup.resolve_timeout` | `1h` | Idle timeout after which an active alert resolves and is evicted (humantime). |

### Field selectors

The fingerprint is built from selectors over the `EvaluationResult` namespace:

| Selector | Resolves to |
|----------|-------------|
| `rule` | the rule id, falling back to the rule title |
| `level` | the severity, lowercased (`high`, `critical`, ...) |
| `event.<path>` | a dotted path into the retained event JSON (requires a retained event; see below) |
| `match.<field>` | a matched field value (detection results only) |
| `enrichment.<path>` | a dotted path into `enrichments` (so [enrichers](enrichers.md) can supply fingerprint fields) |
| `correlation.group_key.<field>` | a group-by value (correlation results only) |

A selector that resolves to nothing contributes an explicit null marker to the fingerprint. A malformed selector rejects the daemon at startup with an error naming the offending selector.

### Retained events and `strip_event`

`event.*` selectors only resolve when the event is retained on the result (`--include-event` or per-rule `rsigma.include_event`). If you need to fingerprint on an event field but do not want full events in the output, set `strip_event: true`: the layer reads the event for selector resolution, then removes the raw event payload from each pass-through result before delivery.

### Metrics

The dedup stage exposes (see [Metrics](../reference/metrics.md)):

- `rsigma_dedup_results_total{action}` — outcomes (`emitted`, `folded`, `repeat`, `resolved`).
- `rsigma_dedup_store_entries` — active alerts currently tracked.
- `rsigma_dedup_evictions_total` — alerts evicted after resolving.
- `rsigma_dedup_summaries_emitted_total` — `repeat` plus `resolved` records emitted.
- `rsigma_alert_pipeline_duration_seconds` — stage duration.

### Relationship to `rsigma.suppress`

Dedup here is a sink-path stage that applies to detection and correlation results alike. It is distinct from the correlation engine's per-rule `rsigma.suppress`, which is engine-side and applies only to correlation firings. The two can be used together.
