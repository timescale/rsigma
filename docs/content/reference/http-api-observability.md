---
description: "RSigma daemon HTTP API for live observability: field and schema observation, bounded event taps, and live detection tails, with permissions."
---

# HTTP API: Live Observability

The daemon's endpoints for looking at live traffic: which fields and schemas arrive, a bounded tap of raw events, and a live tail of detections. Most are opt-in. The [HTTP API](http-api.md#endpoint-summary) page lists every route with its permission; [authentication](http-api.md#authentication) applies to all of them.

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
    "ambiguous": 0,
    "uptime_seconds": 612.4
  },
  "by_schema": [
    {"schema": "ecs", "count": 900},
    {"schema": "sysmon", "count": 250},
    {"schema": "generic_json", "count": 53}
  ],
  "unknown_shapes": [
    {"keys": ["deviceModel", "vendorField", "widgetId"], "count": 45}
  ],
  "routing_pruning": [
    {"schema": "sysmon", "eligible": 120, "pruned": 380}
  ]
}
```

`unknown_shapes` is a bounded, redacted sample of the field-key sets (key names only, never values) of unknown events, so you can author a signature for what is unrecognized. `routing_pruning` is the per-schema eligible-versus-pruned rule count, present when schema routing and logsource routing are both active. The same signals are exposed as the `rsigma_events_by_schema_total{schema}`, `rsigma_events_unknown_schema_total`, `rsigma_events_ambiguous_schema_total`, `rsigma_schema_rules_eligible{schema}`, and `rsigma_schema_rules_pruned{schema}` Prometheus metrics. A rising unknown rate flags a source whose schema RSigma does not recognize; add a signature with `--schema-config`.

### `GET /api/v1/schemas/suggestions`

Mines the daemon's unrecognized-event sample into candidate schema signatures, the live equivalent of [`engine discover-schemas`](../cli/engine/discover-schemas.md). Requires `--discover-schemas` (which implies `--observe-schemas`); returns `503` when that sampler is off. Because the sample is keys-only (values are never retained), proposals use presence predicates and are tagged `source: keys-only`; run the offline command over a corpus for value markers.

```bash
curl -sS http://127.0.0.1:9090/api/v1/schemas/suggestions
```

```json
{
  "summary": {"events_mined": 320, "shapes": 4, "clusters": 2, "candidates": 2},
  "candidates": [
    {
      "name": "discovered_devicevendor",
      "specificity": 60,
      "source": "keys-only",
      "support": 210,
      "coverage_of_unknown": 0.66,
      "predicates": ["field_present: deviceVendor", "field_present: signatureId"],
      "sample_field_sets": [["deviceVendor", "signatureId", "src"]],
      "overlap_warnings": []
    }
  ],
  "signatures_yaml": "schemas:\n  - name: discovered_devicevendor\n    specificity: 60\n    match:\n      - field_present: deviceVendor\n      - field_present: signatureId\n"
}
```

The `rsigma_unknown_schema_clusters` gauge tracks how many distinct schemas discovery would propose. Review, rename, and refine the `signatures_yaml` before committing it to a `--schema-config` file.

### `DELETE /api/v1/schemas`

Reset the schema observer, clearing the per-schema counts, the unknown-shape sample, and the discovery sample. The discovery sample is capped and not a reservoir, so on a long-running daemon it eventually stops admitting genuinely new shapes; a `DELETE` refreshes it without a restart. Returns `503` when `--observe-schemas` is off.

```bash
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/schemas
```

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

**Redaction is server-side.** Raw values for redacted fields never cross the wire. Each value is replaced with a deterministic per-session token (`rsigma:redacted:<16 hex>`), so equal values map to equal tokens within one capture (preserving correlation cardinality on replay) while a random per-session salt blocks dictionary reversal and cross-fixture linkage. Paths use the same object-key/numeric-index navigation as the [enrichment template engine](../guide/enrichers.md), except a non-numeric segment meeting an array fans out to every element (fail-closed).

Error semantics:

| Status | When |
|--------|------|
| `400 Bad Request` | Malformed params, an invalid `stage`, or a `duration` over `daemon.tap.max_duration`. |
| `409 Conflict` | The concurrent-session cap (`daemon.tap.max_sessions`, default `2`) is reached. |
| `503 Service Unavailable` | The tap is disabled (the default; not enabled via `daemon.tap.enabled: true` or `--enable-tap`). |

::: callout warning "The tap exfiltrates raw events"
Anyone who can reach this endpoint can read live event traffic. It is off by default; enable it only behind mTLS and redact sensitive fields. See [Security](security.md#live-event-tap).
:::

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

For rules that use array object-scope matching, `matched_fields` entries carry indexed paths such as `connections[2].ip`; see [Evaluating rules](../guide/evaluating-rules.md#match-detail) for the recording rules.

Error semantics:

| Status | When |
|--------|------|
| `400 Bad Request` | Malformed params or an invalid `level`. |
| `409 Conflict` | The concurrent-session cap (`daemon.tail.max_sessions`, default `2`) is reached. |
| `503 Service Unavailable` | The tail is disabled (the default; not enabled via `daemon.tail.enabled: true` or `--enable-tail`). |

Two Prometheus metrics track the tail: `rsigma_tail_active_sessions` and `rsigma_tail_detections_dropped_total`. See [Prometheus metrics](metrics.md).

## See also

- [HTTP API](http-api.md) for the endpoint summary, authentication, and the per-route permissions.
- [Streaming Detection](../guide/streaming-detection.md) for the daemon overview.
- [Visibility and Data Sources](../guide/visibility-and-data-sources.md) for the field observer.
- [Schema Routing](../guide/schema-routing.md) for schema observation and discovery.
- [`engine tap`](../cli/engine/tap.md) and [`engine tail`](../cli/engine/tail.md) for the CLI clients of the streaming endpoints.
