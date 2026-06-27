# Risk-Based Alerting

Risk-based alerting (RBA) shifts the unit of alerting from the individual detection to the **entity** a detection touches. Instead of paging on every firing, the daemon annotates each firing with a risk score and one or more risk objects (entities such as a user, host, or source IP), accumulates that risk per entity over a sliding window, and raises a single high-fidelity incident only when an entity's accumulated risk crosses a threshold. This is the model Splunk RBA and Entity Risk Scoring popularized: many low-signal detections become one well-evidenced incident on the entity they implicate.

It is an optional, post-engine layer. It runs in the daemon sink path after enrichment and before the alert pipeline, so the evaluation hot path is untouched, and it is off unless you pass `--risk <path>` (or set `daemon.risk` in the config). Enabling annotation alone (no `incident:` block) is valid: every firing is scored and tagged with its entities, and you can route or accumulate that downstream.

## Where it runs

```
sources -> engine -> enrichment -> risk -> alert pipeline -> sinks
```

Risk runs before the alert pipeline deliberately. Risk must accrue on **every** firing, including duplicates, which is the opposite of dedup's intent; and the alert pipeline's silencing and inhibition stages drop results outright. Placing risk first means an entity's risk reflects everything that fired, even results that are about to be folded, silenced, or inhibited. The rare `RiskIncidentResult` bypasses the alert pipeline and flows straight to the sinks.

## Stage one: annotation

Every in-scope firing is assigned an integer **risk score** and a list of **risk objects**.

### Score sourcing

The score is resolved by a fixed precedence, so you can reason about it without reading code:

1. An explicit per-rule score: the `rsigma.risk_score` custom attribute (settable in a processing pipeline with `SetCustomAttribute`). A number or a numeric string wins outright.
2. A `tag_scores` map, scoring by tag. Keys are an exact tag or a `prefix.*` wildcard such as `attack.*`. When more than one entry matches, `tag_reducer` combines them (`sum`, the default, or `max`).
3. A `level_scores` map, mapping the severity (`informational` / `low` / `medium` / `high` / `critical`) to a number.
4. `default_score` for everything else.

### Risk objects

Each risk object is a `{type, value}` pair extracted with the shared field-selector namespace (the same one the alert pipeline uses): `rule`, `level`, `event.<path>`, `match.<field>`, `enrichment.<path>`, and `correlation.group_key.<field>`. A selector that resolves to nothing contributes no object, so there are no phantom entities, and one firing can raise risk on several entities at once. Enrichers (for example a directory lookup that adds `enrichment.user`) can supply entity context the raw event lacks.

`event.<path>` selectors require the event to be retained (`--include-event` or per-rule `rsigma.include_event`). Set `strip_event: true` to retain the event for extraction and then drop raw event payloads before delivery.

The score and objects are injected into `header.enrichments` under the reserved `risk.score` and `risk.objects` keys; a collision with a user enricher logs a debug line and the layer wins. With `emit_risk_events: true`, the layer also emits one compact risk event per `(detection, risk object)` pair, disambiguated on the wire by a `risk_event` key and optionally routed to a dedicated NATS subject for external risk consumers.

## Stage two: the risk-incident layer

When an `incident:` block is configured, a per-entity sliding-window accumulator keyed by `(entity_type, entity_value)` sums risk over the window and tracks two modifiers: the **distinct ATT&CK tactic count** (read from each firing's `attack.<tactic>` tags) and the **distinct contributing-source count** (distinct rule identities). A `RiskIncidentResult` fires when an entity crosses `score_threshold` (the window risk sum) or `tactic_count_threshold` (distinct tactics over the window), subject to a per-entity `cooldown` so one entity does not re-fire on every subsequent event. At least one of the two thresholds is required.

The incident is one flat NDJSON object disambiguated by a `risk_incident_id` (UUIDv4). It carries the entity, the window score, the contributing tactics and sources, the window bounds, the `trigger` (`score` or `tactic_count`), and the top contributing detections (`include: refs` for lightweight references, the default, or `include: results` for full event-stripped results), bounded by the caps. It is delivered through the same sink path as the alert pipeline's incidents, optionally to a dedicated NATS subject.

The accumulator is bounded by `max_open_entities` (a new entity past the cap is not tracked, bounding memory), `max_sources_per_entity` (distinct sources listed per incident), and `max_results_per_incident` (contributions retained per entity and embedded per incident). Entries age out of the window on a one-second tick.

## Configuration

```yaml
# Restrict which results the layer acts on (optional). Out-of-scope results
# pass through untouched.
scope:
  levels: [low, medium, high, critical]

# Retain the event for selector resolution, then drop raw payloads before delivery.
strip_event: false

# Score sourcing (precedence: attribute, tag_scores, level_scores, default).
score:
  # attribute: rsigma.risk_score   # custom-attribute key (this is the default)
  tag_scores:
    "attack.*": 10
    crown-jewel: 50
  tag_reducer: sum                 # sum (default) or max
  level_scores:
    high: 40
    critical: 80
  default_score: 1

# Risk objects (at least one required).
objects:
  - type: user
    selector: enrichment.user
  - type: src_ip
    selector: match.SourceIp

# Emit a compact risk event per (detection, risk object) pair (optional).
emit_risk_events: false
# nats_subject: risk.events        # dedicated subject for risk events

# Per-entity risk-incident accumulator (optional; omit for annotation only).
incident:
  window: 24h
  score_threshold: 100             # set at least one of these two
  tactic_count_threshold: 3
  cooldown: 1h
  include: refs                    # refs (default) or results
  # nats_subject: risk.incidents   # dedicated subject for incidents
  caps:
    max_open_entities: 100000
    max_sources_per_entity: 1000
    max_results_per_incident: 1000
```

Point the daemon at it with `--risk /etc/rsigma/risk.yml` or `daemon.risk: /etc/rsigma/risk.yml`. The config hot-reloads on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; a failed reload keeps the previous config active, and in-flight accumulators survive the swap.

## Persistence

When `--state-db` is set, a versioned risk snapshot is saved to the SQLite store on the periodic and shutdown hooks beside the correlation and alert-pipeline snapshots, and restored on boot with window-aware pruning (contributions already past the window are dropped, entities left empty are skipped). `--clear-state` skips the restore and `--keep-state` forces it, matching the other state domains; a snapshot-version mismatch starts fresh with a warning.

## Observability

The open entities, each with its current window score, distinct tactic count, source count, and window bounds, are readable at `GET /api/v1/risk`. The layer exposes nine Prometheus metrics: `rsigma_risk_annotations_total{action}`, `rsigma_risk_annotation_score`, `rsigma_risk_objects_total`, `rsigma_risk_entities_open`, `rsigma_risk_state_entries`, `rsigma_risk_evictions_total`, `rsigma_risk_incidents_emitted_total{trigger}`, `rsigma_risk_incident_results_total`, and `rsigma_risk_layer_duration_seconds`.

## Relationship to the alert pipeline

The risk layer and the [alert pipeline](alert-pipeline.md) are siblings built on the same post-engine plumbing: the same field-selector namespace, the same scope filter, the same incident delivery path, and the same SQLite snapshot store under a separate table. Where the alert pipeline collapses noisy duplicates into incidents, the risk layer accumulates the risk those firings represent onto the entities they touch. They compose: when both run, the order is enrichment, risk, alert pipeline, sinks.
