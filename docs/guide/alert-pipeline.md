# Alert Pipeline

The alert pipeline is an optional post-engine stage in the daemon's output path, between post-evaluation [enrichment](enrichers.md) and the sinks. It is modeled on the Prometheus Alertmanager processing pipeline and is strictly post-engine: it consumes `EvaluationResult`s and emits `EvaluationResult`s, so the evaluation hot path is untouched.

It is configured with a separate YAML file via `--alert-pipeline <path>` (or the `daemon.alert_pipeline` config key) and is hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; a failed reload keeps the previous pipeline active.

This page covers silencing, inhibition, deduplication, and incident grouping. The stages run in that order (the mute stages first): a muted result never dedups or opens an incident.

## Silencing

A silence mutes results matching a set of matchers for a time window, modeled on Alertmanager silences. A muted result is acked and dropped before dedup, so it neither emits nor contributes to an incident.

Silences come from two origins:

- **static**: declared in the `--alert-pipeline` config under `silences:`. Re-seeded on hot-reload (the previous static set is replaced); use these for maintenance-as-code.
- **api**: created at runtime over `POST /api/v1/silences`, independent of the config file. Use these for ad-hoc mutes during an incident.

### Matchers

A matcher is `selector <op> value`, where the left-hand side is a [field selector](#field-selectors) and `<op>` is one of `=` (equals), `!=` (not equals), `=~` (regex match), `!~` (regex no-match). Regex operators are anchored (full match). A matcher set is ANDed: every matcher must match. The same matcher engine backs inhibition.

### Config (static silences)

```yaml
silences:
  - matchers:
      - selector: rule
        op: "="
        value: noisy-rule
      - selector: level
        op: "!="
        value: critical
    comment: "muted during migration"
    created_by: ops
    # starts_at / ends_at are optional RFC 3339 timestamps; absent means
    # active immediately / never expires.
```

### The silence API

- `POST /api/v1/silences` creates a silence from a JSON body (`matchers`, optional `starts_at`/`ends_at` RFC 3339, `created_by`, `comment`) and returns the assigned `id`. It returns `429 Too Many Requests` once the dynamic-silence cap (`max_silences`, default 1000) is reached; delete silences or raise the cap.
- `GET /api/v1/silences` lists every silence with its derived `state` (`pending` / `active` / `expired`) and `origin`.
- `DELETE /api/v1/silences/{id}` removes a silence.

Expired silences are garbage-collected on the background tick. The dynamic (API) silence count is bounded by `max_silences` so an unbounded number of silences cannot accumulate; static silences from the config do not count against it. Metrics: `rsigma_silenced_total` (results muted) and `rsigma_silences_active` (currently-active silences).

## Inhibition

Inhibition mutes a *target* result while a matching *source* result is active, modeled on Alertmanager `inhibit_rules`. Each rule is `{ source_match, target_match, equal, duration }`: while a result matching `source_match` has been seen within `duration`, any result matching `target_match` that shares the same `equal` selector values is muted. The classic use is letting a `critical` alert suppress the lower-severity `high` alerts for the same entity.

```yaml
inhibit_rules:
  - name: critical-inhibits-high
    source_match:
      - selector: level
        op: "="
        value: critical
    target_match:
      - selector: level
        op: "="
        value: high
    equal:
      - match.SourceIp
    duration: 5m
```

`source_match` and `target_match` use the [matcher engine](#matchers); both are required. `equal` is a list of selectors whose values must match between source and target (an empty `equal` means any active source of the rule inhibits any target). `duration` (humantime, default `5m`) is how long a source stays active after it was last seen.

Two behaviors follow Alertmanager:

- A **self-inhibition guard**: a result matching both `source_match` and `target_match` does not inhibit itself.
- Inhibition is **non-transitive**: a *silenced* source still inhibits its targets (the source index is updated before silencing), but an *inhibited* target does not become a source.

Metrics: `rsigma_inhibited_total{rule}` (results muted, by rule name) and `rsigma_inhibit_sources_active` (currently-active sources).

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
| `dedup.max_active_alerts` | `100000` | Ceiling on concurrently-active alerts. Once reached, a first-fire for a new fingerprint passes through un-deduped instead of growing the store, so a high-cardinality fingerprint cannot exhaust memory. The `rsigma_dedup_store_entries` gauge plateauing at this value signals saturation. |
| `max_silences` | `1000` | Ceiling on concurrently-tracked dynamic (API) silences. `POST /api/v1/silences` returns `429` past this. Static silences from the config do not count against it. |

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

## Persistence

When the daemon runs with `--state-db <PATH>`, the alert pipeline's state is persisted to the SQLite store alongside the correlation snapshot, in its own `rsigma_alert_pipeline_state` table. The snapshot carries the active dedup alerts, open incidents, the dynamic (API) silences, and the inhibition active-source index; static silences come from config and are re-seeded on boot. It is written periodically (`--state-save-interval`) and on graceful shutdown, and restored on boot.

Restore is window-aware: dedup alerts past `resolve_timeout`, incidents past their `resolve_timeout`, silences past `ends_at`, and inhibition sources past their rule's `duration` are dropped during restore, so stale state never lingers. Deterministic `group_by` incident ids are preserved across the restart. A snapshot whose version does not match the current build is ignored with a warning (the daemon starts fresh). `--clear-state` skips the restore (and `--keep-state` forces it), matching the correlation-state flags.

### Relationship to `rsigma.suppress`

Dedup here is a sink-path stage that applies to detection and correlation results alike. It is distinct from the correlation engine's per-rule `rsigma.suppress`, which is engine-side and applies only to correlation firings. The two can be used together.

## Grouping

Grouping collapses related results into incidents and emits a higher-level `IncidentResult` on the Alertmanager timers. Pass-through results are never delayed: each survivor flows to the sinks immediately, annotated with its `incident_id` in `enrichments`. The incident itself is emitted by a background tick.

Two modes:

- `group_by` (default): group by equality on an ordered selector list. The `incident_id` is a deterministic fingerprint of the `(selector -> value)` pairs, so the same logical incident keeps one id across restarts and re-emissions. The rule identity is deliberately excluded from the key, so an incident can span rules that share the group value.
- `entity_graph` (opt-in): union-find over `(selector, value)` entity pairs. A result joins (and merges) any open incident that shares an entity value, and the `incident_id` is a surrogate UUID. This is powerful but prone to the *giant-component* failure, where one common value (a domain controller, a shared service account, an egress NAT IP) transitively merges unrelated incidents. It ships with mandatory guards: a `stop_values` list of non-joinable values and a per-value `max_value_cardinality` ceiling above which a value stops acting as a join key (both surfaced on `rsigma_incident_overmerge_total`).

### Timers

- `group_wait`: initial batching delay before the first incident emission, so a burst lands as one incident.
- `group_interval`: minimum delay before emitting an updated incident after new results join.
- `repeat_interval`: re-emit cadence for a still-open incident (`0` disables re-emits).
- `resolve_timeout`: idle timeout after which the incident emits a final `resolved` record and is evicted.

### Configuration

```yaml
group:
  mode: group_by          # or entity_graph
  by:                     # group_by mode: the group key selectors
    - match.SourceIp
  entities:               # entity_graph mode: the join-edge selectors
    - match.SourceIp
    - match.User
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 0
  resolve_timeout: 1h
  include: refs           # refs | results
  caps:
    max_open_incidents: 10000
    max_entities_per_incident: 1000
    max_results_per_incident: 1000
    max_value_cardinality: 10000
  stop_values: ["0.0.0.0", "-", ""]   # entity_graph
  nats_subject: rsigma.incidents       # optional, route incidents to a dedicated NATS subject
```

`include: refs` (default) embeds lightweight `{rule, level}` references; `include: results` embeds the full (event-stripped) contributing results, bounded by `max_results_per_incident`.

### Wire shape

An `IncidentResult` is one flat NDJSON object, disambiguated downstream by the presence of an `incident_id` key. It carries the `state` (`open` / `resolved`), the `trigger` (`group_wait` / `group_interval` / `repeat` / `resolved`), the window bounds, the `max_level`, the `result_count`, per-rule `rule_counts`, the `group_by` key (group_by mode) or `entities` map (entity_graph mode), and the `refs` or `results`. Incidents are delivered to stdout/file/NATS sinks; with `nats_subject` set, incidents publish to that dedicated subject instead of the detection stream. OTLP and webhook sinks do not receive incidents.

Open incidents are also readable at `GET /api/v1/incidents`.

### Metrics

- `rsigma_incidents_open` — open incidents currently tracked.
- `rsigma_incidents_emitted_total{trigger}` — incident emissions by trigger.
- `rsigma_incident_results_total` — total incident records emitted.
- `rsigma_incident_overmerge_total{guard}` — entity-graph guard hits (`stop_value` / `cardinality_ceiling`).
