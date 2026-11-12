---
description: "RSigma daemon HTTP API for detection state: counters, correlation windows, incidents, risk, silences, audit trail, and analyst dispositions."
---

# HTTP API: Detection State

The daemon's read and control endpoints for detection state: counters, correlation windows, incidents, risk, silences, the audit trail, and analyst dispositions. The [HTTP API](http-api.md#endpoint-summary) page lists every route with its permission; [authentication](http-api.md#authentication) applies to all of them.

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

### `GET /api/v1/correlations`

The compiled correlation list with per-group counts (no window contents). Empty when the engine has no correlation rules.

```bash
curl -sS http://127.0.0.1:9090/api/v1/correlations
```

```json
{
  "correlations": [
    {
      "index": 0,
      "title": "Many Logins",
      "type": "event_count",
      "timespan_secs": 3600,
      "group_by": ["User"],
      "rule_refs": ["login-rule"],
      "threshold": ">= 3",
      "active_groups": 1
    }
  ],
  "count": 1
}
```

### `GET /api/v1/correlations/state`

The live per-group window snapshot, the live counterpart of [`engine eval --dump-correlation-state`](../cli/engine/eval.md). Each group reports the current aggregate (`got`) against the `threshold`, whether the condition is currently `met`, the window `entries`, `earliest`/`latest` timestamps, `seconds_to_eviction`, the `last_alert` and `suppression_remaining` (when applicable), and the raw `window` state. Filter with `?id=` (correlation id, name, or title) and `?group=` (substring of the rendered `field=value` key).

```bash
curl -sS 'http://127.0.0.1:9090/api/v1/correlations/state?group=admin'
```

```json
{
  "correlations": [ { "index": 0, "title": "Many Logins", "type": "event_count", "threshold": ">= 3", "active_groups": 1, "...": "..." } ],
  "groups": [
    {
      "correlation_index": 0,
      "correlation_title": "Many Logins",
      "type": "event_count",
      "group_key": [ { "field": "User", "value": "admin" } ],
      "group_key_display": "User=admin",
      "got": 2.0,
      "threshold": ">= 3",
      "met": false,
      "entries": 2,
      "timespan_secs": 3600,
      "seconds_to_eviction": 3590,
      "window": { "EventCount": { "timestamps": [1767225600, 1767225610] } }
    }
  ],
  "count": 1
}
```

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
      "refs": [{"rule": "rule-1", "level": "high"}],
      "sample_mode": "refs",
      "bundle_ready": true
    }
  ]
}
```

The `include` mode configured on the `group` block decides whether each incident carries lightweight `refs` or full `results`. See the [Alert Pipeline](../guide/alert-pipeline.md) guide.

Two fields appear only on snapshots, never on emitted incidents:

- `sample_mode` reports which sample kinds the incident actually retained: `refs`, `results`, `mixed`, or `none`. Samples are retained when a result is absorbed but reported under the mode configured at read time, so changing `include` while an incident is open leaves both kinds behind. `mixed` says so instead of hiding one of them.
- `bundle_ready` is `false` while the incident is still inside `group_wait` and has not been reported yet. Its contents can still change, so the bundle route withholds it until this is `true`.

### `GET /api/v1/incidents/{id}`

One open incident, in the same shape as a list entry. Returns `404` when the id is unknown, which includes an incident that has already resolved and been evicted, and `503` when the alert pipeline has no `group` block.

```bash
curl -sS http://127.0.0.1:9090/api/v1/incidents/f8bcd62a829b1126
```

### `GET /api/v1/incidents/{id}/bundle`

A self-contained incident report: the incident joined to the [ADS](../guide/detection-strategy.md) documentation of every rule that contributed and the risk entities it overlaps. Requires `incident-bundles:read`, which is deliberately separate from `incidents:read` because a bundle hands out more than the incident list does.

| Parameter | Values | Default | Description |
|---|---|---|---|
| `format` | `json`, `markdown` (`md`) | `json` | The rendering. JSON is served as `application/json`, Markdown as `text/markdown; charset=utf-8`. |

```bash
curl -sS http://127.0.0.1:9090/api/v1/incidents/f8bcd62a829b1126/bundle
curl -sS 'http://127.0.0.1:9090/api/v1/incidents/f8bcd62a829b1126/bundle?format=markdown'
```

```json
{
  "schema_version": 1,
  "generated_at": "2026-07-26T12:00:00Z",
  "sources": {"rules": true, "risk": true},
  "incident": { "incident_id": "f8bcd62a829b1126", "...": "as above" },
  "rules": [
    {
      "key": "rule-1",
      "count": 2,
      "resolution": "unique",
      "documents": [
        {
          "identity": {"kind": "detection", "id": "rule-1", "title": "Whoami execution"},
          "level": "high",
          "tags": ["attack.discovery"],
          "ads": {"sections": [{"id": "goal", "required": true, "present": true, "carrier": "description", "content": "Detects whoami execution."}]}
        }
      ]
    }
  ],
  "risk": [
    {"matched_on": "risk_object", "entity_type": "user", "entity_value": "alice", "score": 120, "...": "as GET /api/v1/risk"}
  ]
}
```

An incident records only a rule *key* per contributing result: the rule id, or the title for a rule without one. `resolution` reports how that key resolved against the currently loaded rule set:

- `unique`: exactly one rule carries the key, and `documents` has one entry.
- `ambiguous`: several loaded rules carry it with differing documentation, and every one is listed. A routed rule set compiles the same rule once per pipeline-set, so this appears when a pipeline rewrites a rule's documentation for one schema but not another.
- `missing`: no loaded rule carries the key, and `documents` is empty. Expected when the rule set changed while the incident was open.

Risk entities join on the entity type as well as its value, so the user `alice` is never tied to the host `alice`. `matched_on` says which evidence produced the join: `risk_object` when a retained result named the entity in its `risk.objects` enrichment, and `group_key` when the incident retained only references and the join came from its own grouping key. `sources.risk` is `false` when no risk accumulator is configured, which is not the same as an incident with no risk overlap.

The route returns:

| Status | Meaning |
|---|---|
| `400` | Unknown `format`. |
| `404` | Unknown incident id, or one that has already resolved and been evicted. |
| `409` | The incident is still inside `group_wait`, so its contents can still change. |
| `503` | The alert pipeline has no `group` block, so the daemon tracks no incidents. |

The CLI wraps this route: see [`rsigma engine incidents export`](../cli/engine/incidents-export.md).

### `GET /api/v1/risk`

Open entities tracked by the risk accumulator (present when `--risk` configures an `incident` block). Each entry reports the entity, its accumulated window score, the distinct ATT&CK tactic count, the distinct contributing-source count, the retained contribution count, the window bounds, and the last-fired timestamp (when the entity has fired). Empty when no risk accumulator is configured.

```bash
curl -sS http://127.0.0.1:9090/api/v1/risk
```

```json
{
  "count": 1,
  "entities": [
    {
      "entity_type": "user",
      "entity_value": "alice",
      "score": 120,
      "tactic_count": 2,
      "source_count": 2,
      "result_count": 2,
      "window_start": 1719412800,
      "window_end": 1719412860,
      "last_fired": 1719412860
    }
  ]
}
```

See the [Risk-Based Alerting](../guide/risk-based-alerting.md) guide.

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

Create a silence. The body is a JSON object with `matchers` (required; each `{selector, op, value}` where `op` is `=`, `!=`, `=~`, or `!~`), optional `starts_at` and `ends_at` (RFC 3339), `created_by`, and `comment`. Returns `201` with the assigned `id`. A missing matcher list or a bad regex returns `400`. Once the dynamic-silence cap (`max_silences`, default 1000) is reached it returns `429`; delete silences or raise the cap.

{{ added "0.27.0" }} The alert pipeline's silence limits also return `400`, with an `error` and a `hint`:

- `ends_at` is required and must be no more than `max_silence_duration` (default `720h`) from now. `max_silence_duration: 0` removes the bound.
- At least one matcher must be `=` with a non-empty value on `rule`, `match.<field>`, or `correlation.group_key.<field>`, unless `allow_broad_silences: true` is set. `rule =~ .*`, `rule != x`, or `level = high` alone is refused.

Without an alert pipeline (`--alert-pipeline`), the endpoint returns `409`, because no stage would apply the silence.

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/silences \
  -d '{"matchers":[{"selector":"rule","op":"=","value":"noisy-rule"}],"ends_at":"2026-11-06T09:00:00Z","comment":"muted"}'
```

```json
{ "status": "created", "id": "0b6c..." }
```

### `DELETE /api/v1/silences/{id}`

Remove a silence by id. Returns `200` when removed, `404` when no such silence exists.

```bash
curl -sS -X DELETE http://127.0.0.1:9090/api/v1/silences/0b6c...
```

## Audit trail

Append-only log of control-plane mutations (silences, dispositions, reload, source cache invalidation, field/schema observer resets). Enabled automatically when the daemon is started with `--state-db`; disable or tune retention with the `daemon.api.audit` config block. Data-plane ingest (`POST /api/v1/events`, OTLP) is never recorded. Each entry stores the HTTP method, matched route pattern, bearer token name (when authentication is enabled), response status, Unix timestamp, and an optional SHA-256 hex digest of the request body. The body itself is never stored. A request whose body exceeds `max_body_bytes` (default 64 KiB), whether declared via `Content-Length` or streamed, is rejected with `413` before the handler runs, and the rejected attempt is itself recorded (with a `null` digest).

Auth denials (`401`/`403`) are tracked separately via `rsigma_api_auth_failures_total`, not in this log.

### `GET /api/v1/audit`

Paginated read of the audit log, newest first. Query parameters: `limit` (default 100, max 1000), `offset`, `since` and `until` (Unix seconds, inclusive bounds on `ts`). Returns `503` when audit is disabled (no state database). Requires `audit:read` when authentication is enabled.

```bash
curl -sS 'http://127.0.0.1:9090/api/v1/audit?limit=50'
```

```json
{
  "count": 1,
  "entries": [
    {
      "id": 42,
      "ts": 1714500000,
      "method": "POST",
      "endpoint": "/api/v1/silences",
      "token": "op",
      "payload_digest": "a1b2...",
      "status": 201
    }
  ]
}
```

Retention pruning runs on daemon startup and on every state-save interval (default 30s): rows older than `max_age` (default 720h) are deleted, then the table is trimmed to the newest `max_entries` (default 10000). An optional `sink` emits each record as a JSON line with `on_full=drop` backpressure.

## Dispositions

The triage feedback loop. Disabled by default; both routes return `503` unless the daemon was started with `daemon.dispositions.enabled: true`, `--enable-dispositions`, or a configured `daemon.dispositions.source`. See the [Triage Feedback Loop](../guide/triage-feedback.md) guide.

### `POST /api/v1/dispositions`

Ingest one or more analyst dispositions. The body is a single JSON object, a JSON array of objects, or NDJSON. Each object carries `rule_id` (required for `detection` scope, with a title fallback), `verdict` (`true_positive`, `false_positive`, or `benign_true_positive`), an optional `scope` (`detection` default, or `incident` with an `incident_id`), optional `fingerprint`/`incident_id` alert identities, an optional RFC 3339 `timestamp`, and optional `analyst` and `note` (`note` max 2048 bytes). Returns `200` with an ingest summary; a whole-body parse failure returns `400`. Requires `dispositions:write` when API authentication is enabled. When capture is also enabled, POST additionally requires `capture:write` and the summary may include a `capture` array (`queued`, `exists`, `miss`, `queue_full`). Disposition accounting stays accepted even if corpus spooling misses. There is no API to read the capture ring or the spool. See [Verdict-Driven Corpora](../guide/verdict-to-corpus.md).

```bash
curl -sS -X POST http://127.0.0.1:9090/api/v1/dispositions \
  -d '{"rule_id":"proc-injection","verdict":"false_positive","analyst":"alice"}'
```

```json
{ "accepted": 1, "duplicate": 0, "rejected": 0 }
```

Redelivery is idempotent: records deduplicate on `(fingerprint or incident_id, verdict, rule_id)`, falling back to `(rule_id, timestamp, analyst)`. The `rule_id` is part of the identity key so an incident-scoped fan-out does not collapse per-rule records. An `incident`-scoped record with no `rule_id` resolves to the incident's contributing rules through the live incident map; an unknown incident is reported in the summary's `errors` and counted as `rejected`.

### `GET /api/v1/dispositions`

The per-rule false-positive ratio view: the active `window_seconds`, `numerator`, and `min_sample`, plus a `rules` array (each with `rule_id`, the verdict counts, `total`, and `fp_ratio`, which is `null` until the rule reaches `min_sample`). This document deserializes directly as the `rule scorecard --triage` input. Requires `dispositions:read` when API authentication is enabled.

```bash
curl -sS http://127.0.0.1:9090/api/v1/dispositions
```

```json
{
  "window_seconds": 2592000,
  "numerator": "fp_only",
  "min_sample": 5,
  "rules": [
    { "rule_id": "proc-injection", "true_positives": 8, "false_positives": 1, "benign_true_positives": 0, "total": 9, "fp_ratio": 0.111 }
  ]
}
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

## See also

- [HTTP API](http-api.md) for the endpoint summary, authentication, and the per-route permissions.
- [Streaming Detection](../guide/streaming-detection.md) for the daemon overview.
- [Alert Pipeline](../guide/alert-pipeline.md) for incidents and silences.
- [Risk-Based Alerting](../guide/risk-based-alerting.md) for the risk accumulator.
- [Triage Feedback Loop](../guide/triage-feedback.md) for dispositions.
