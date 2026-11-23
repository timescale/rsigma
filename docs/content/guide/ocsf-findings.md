---
description: "Emit Sigma detections and incidents as OCSF Detection Finding (2004) and Incident Finding (2005) JSON for Splunk, Elastic, Security Lake, and Datadog."
---

# OCSF Findings

{{ added "0.21.0" }}

The daemon can emit every finding as an [OCSF](https://ocsf.io) **Detection Finding** (class 2004) JSON object instead of RSigma's native NDJSON. OCSF is the finding interchange format Splunk, Elastic, CrowdStrike NG-SIEM, Amazon Security Lake, and Datadog converged on, so a `?format=ocsf` sink drops findings into those pipelines without a transform step of your own.

It is a per-sink serialization choice, not a new sink type and not a new config section: append `?format=ocsf` to a line-oriented or OTLP sink spec, or reference the finding from a webhook body.

```bash
rsigma engine daemon -r rules/ \
  --output 'file:///var/log/rsigma/findings.ocsf.ndjson?format=ocsf'
```

```yaml
daemon:
  output:
    sinks:
      - "file:///var/log/rsigma/findings.ocsf.ndjson?format=ocsf"
      - "nats://localhost:4222/findings.ocsf?format=ocsf"
```

`ndjson` is the default, so existing sinks are unchanged. Formats are per sink, so one daemon can feed an OCSF collector and a native consumer at the same time:

```bash
rsigma engine daemon -r rules/ \
  --output 'file:///var/log/rsigma/findings.ndjson' \
  --output 'nats://localhost:4222/findings.ocsf?format=ocsf'
```

## Where it applies

| Sink | `?format=` |
|------|------------|
| `stdout`, `file://`, `nats://`, `unix://` | `ndjson` (default) or `ocsf` |
| `otlp://`, `otlps://`, `otlphttp://`, `otlphttps://` | `ndjson` (default) or `ocsf`. With `ocsf`, each log record's body is the finding. See [OTLP log bodies](#otlp-log-bodies). {{ added "0.28.0" }} |
| Webhooks | No query surface. A body template inserts the finding with `${detection.ocsf}` or `${correlation.ocsf}`. See [Webhook bodies](#webhook-bodies). |
| `--dlq`, `daemon.api.audit.sink` | Rejected at startup: those channels carry DLQ entries and API audit records, not findings. |

An unusable or unknown `format` value fails startup with a pointed message.

Every sink a dispatch reaches gets the same finding for the same detection: line sinks, OTLP sinks, and webhook bodies share `finding_info.uid`, `metadata.uid`, and `time`, so a consumer can deduplicate across them.

## What a finding looks like

One JSON object per line, exactly as with NDJSON. A detection:

```json
{
  "action_id": 0,
  "action": "Unknown",
  "activity_id": 1,
  "activity_name": "Create",
  "category_uid": 2,
  "category_name": "Findings",
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "type_uid": 200401,
  "type_name": "Detection Finding: Create",
  "severity_id": 4,
  "severity": "High",
  "status_id": 1,
  "status": "New",
  "time": 1767225600000,
  "timezone_offset": 0,
  "message": "Suspicious PowerShell",
  "metadata": {
    "product": { "name": "rsigma", "vendor_name": "rsigma", "version": "0.20.0" },
    "version": "1.1.0",
    "uid": "6f1c2e0e-0f2a-4a1e-9a3f-2b7c9d1e5a44"
  },
  "finding_info": {
    "title": "Suspicious PowerShell",
    "uid": "b1c0a5d2-0d7e-4f66-9b7a-0a2f5e6d8c31",
    "analytic": { "type_id": 1, "type": "Rule", "name": "Suspicious PowerShell", "uid": "rule-1" },
    "attacks": [
      { "sub_technique": { "uid": "T1059.001" } },
      { "tactic": { "name": "Execution", "uid": "TA0002" } }
    ]
  },
  "evidences": [
    { "data": { "matched_fields": { "CommandLine": "powershell -enc ZQBjAGgAbwA=" } } }
  ],
  "unmapped": {
    "matched_selections": ["selection"],
    "matched_fields": [{ "field": "CommandLine", "value": "powershell -enc ZQBjAGgAbwA=" }],
    "tags": ["attack.t1059.001", "attack.execution"]
  }
}
```

## The mapping

By default all four emitted shapes (detections, correlations, alert-pipeline incidents, and risk incidents) are class 2004, distinguished by their activity. A sink can instead emit the two incident shapes as [Incident Findings](#incident-finding-class-2005) (class 2005).

| OCSF field | Source |
|------------|--------|
| `action_id` / `action` | `0` (`Unknown`): RSigma reports the detection but does not itself take a control action. |
| `class_uid` / `category_uid` / `class_name` / `category_name` | Constants: `2004` / `2` / `Detection Finding` / `Findings`. |
| `activity_id` / `activity_name` | Detections, correlations, and risk incidents: `1` (`Create`). Alert-pipeline incidents by trigger: `group_wait` is `1` (`Create`), `group_interval` and `repeat` are `2` (`Update`), `resolved` is `3` (`Close`). |
| `type_uid` / `type_name` | `class_uid * 100 + activity_id`, so `200401` / `200402` / `200403`. |
| `status_id` / `status` | `1` (`New`), or `4` (`Resolved`) for a resolved incident. |
| `severity_id` / `severity` | From the rule level: informational `1`, low `2`, medium `3`, high `4`, critical `5`. An absent or unrecognized level is `0` (`Unknown`), never a guess. A risk incident carries no rule level, so its severity is `Unknown` and its weight rides `risk_score`. |
| `time` | Detections, correlations, and alert-pipeline incidents: the serialization/emission clock. Risk incidents: `window_end`. Always UTC milliseconds, with `timezone_offset: 0`. |
| `start_time` / `end_time` | `first_seen` / `last_seen` on incidents, `window_start` / `window_end` on risk incidents. |
| `message` | The same string as `finding_info.title`, so a consumer that renders only `message` still shows something readable. |
| `metadata` | `product` names `rsigma` and its version, `version` is the OCSF schema version (`1.1.0` by default), and `uid` uniquely identifies the emitted event. Daemon delivery derives it from stable per-dispatch state, so fan-out and retries preserve it. Class 2004 sets `profiles` to `["security_control"]`, and appends `"host"` when the finding has an `actor`. A detection whose enrichments include a string `incident_id` copies it to `correlation_uid`. |
| `finding_info.title` | The rule title for detections and correlations. Incidents carry no rule name, so the title is synthesized: the busiest contributing rule plus the count of the others (`rule-1 and 2 other rules`, or `rule-1 and 1 other rule` for a single peer), falling back to the group key (`incident for match.User=alice`) and then the bare id. A risk incident names what crossed and for whom (`risk threshold crossed for user alice`). |
| `finding_info.uid` | The incident id for the two incident shapes (re-emissions of one incident share it). Per-result findings use an identifier minted once per dispatch and preserved across sinks and retries. OCSF requires this to identify the finding, and one rule produces many, so rule identity lives in `analytic.uid` instead. |
| `finding_info.analytic` | `{type_id: 1, type: "Rule", name: <rule title>, uid: <rule id>}` for detections and correlations. Incidents name the `alert pipeline`, risk incidents the `risk accumulator`, with their contributing rules in `related_analytics`. |
| `finding_info.attacks[]` | Parsed from the rule's tags: `attack.t1059.001` becomes `sub_technique: {uid: "T1059.001"}` and `attack.credential_access` becomes `tactic: {name: "Credential Access", uid: "TA0006"}`. A risk incident's contributing tactics map the same way. A tag cannot say which tactic a technique was used for, so techniques and tactics are separate entries rather than paired by guesswork. Tags in other taxonomies are skipped here and carried under `unmapped.tags`. |
| `evidences[]` | One entry whose `data` holds what the result carried into the finding: matched field/value pairs when present, plus the retained event when `--include-event` or per-rule `rsigma.include_event` kept it; for correlations, the retained `events` or `event_refs` and their `event_sources`. Omitted only when that map would be empty (no matched fields and no retained event payload). {{ added "0.28.0" }} |
| `resources[]` | The [risk](risk-based-alerting.md) layer's `risk.objects` entries as `{type, name}`, and an incident's `group_by` / `entities` values the same way. |
| `actor.user.name` | The first `risk.objects` entry of type `user`, or a risk incident whose entity type is `user`. |
| `risk_score` | The `risk.score` enrichment, or a risk incident's accumulated `score`. |
| `count` | `result_count` on both incident shapes: OCSF's occurrence count for the group. |
| `unmapped` | Everything without a faithful OCSF home, under its native key: `matched_selections`, `matched_fields` in full fidelity, `correlation_type`, `group_key`, `aggregated_value`, `timespan_secs`, `tags`, `custom_attributes`, `ruleset` {{ added "0.28.0" }} (the named ruleset that produced the match), the remaining enrichments (including the alert pipeline's `incident_id`), and the incident-only `state`, `trigger`, `rule_counts`, `refs`, `results`, `tactic_count`, `tactic_count_threshold`, `score_threshold`, and `source_count`. |

### Nothing is dropped

The mapping is conservative on purpose. A field moves into OCSF only where the fit is faithful; everything else rides under `unmapped` with the key it has on the native line. This makes `?format=ocsf` safe as a daemon's only output: a consumer that only understands class 2004 gets a conformant finding, and a consumer that knows RSigma finds the rest where it expects it.

The risk enrichments are the one place keys move: `risk.score` and `risk.objects` are lifted to `risk_score`, `resources[]`, and `actor`, and removed from the `unmapped.enrichments` copy. A malformed value (a `risk.objects` that is not an array of `{type, value}` pairs, a non-integer `risk.score`) is left in `unmapped` untouched rather than coerced.

### Detections carry no event time

An `EvaluationResult` has no event-timestamp field (the native NDJSON has none either), so a detection or correlation finding stamps `time` with the serialization clock. When you need event time, either retain the event (`--include-event` or `rsigma.include_event`) and read it from `evidences[].data.event`, or consume the incident shapes, whose `start_time` and `end_time` are real observed bounds.

### Batch commands

`engine eval` accepts `--finding-format ocsf` (and `--ocsf-version 1.1.0|1.3.0`). Each rule fire becomes one OCSF Detection Finding (class 2004). The flag composes with `--output-format json` or `ndjson`; `table`, `csv`, and `tsv` are a config error. `--pretty` pretty-prints each finding when stdout is a TTY.

`rule backtest` accepts the same flags plus `--findings <PATH>`, which must not collide with the corpus, `--report`, or `--junit`. The human summary stays on stderr and `--report` continues to write the native JSON report. {{ added "0.28.0" }} See [Output Formats](../reference/output.md).

### Dedup and risk-event sidecars

| Native line | OCSF activity | OCSF status |
|-------------|---------------|-------------|
| Dedup `repeat` summary | Update | New |
| Dedup `resolved` summary | Close | Resolved |
| Risk event (`risk_event: true`) | Create | New |

On an OCSF sink (`?format=ocsf`), each sidecar maps to class 2004 like detections. The native NDJSON wire is unchanged on an NDJSON sink. A dedup finding's `finding_info.uid` is `dedup-<fingerprint>-<first_seen>`. `dedup_fire_count`, `dedup_first_seen`, and `dedup_last_seen` become `count`, `start_time`, and `end_time` (epoch milliseconds); the fingerprint, state, and matched fields stay under `unmapped.enrichments`. A risk event sets `finding_info.types` to `["Risk Event"]` and adds the `host` profile when its actor is a user. {{ added "0.28.0" }}

## Incident Finding (class 2005)

{{ added "0.28.0" }}

OCSF has a dedicated class for a grouped incident: **Incident Finding** (class 2005), which references the findings it groups instead of describing one detection. Select it per sink with `ocsf_incident_class`:

```bash
rsigma engine daemon -r rules/ --alert-pipeline pipeline.yml \
  --output 'file:///var/log/rsigma/findings.ocsf.ndjson?format=ocsf&ocsf_incident_class=2005'
```

| Value | Alert-pipeline and risk incidents become |
|-------|------------------------------------------|
| `2004` (default) | Detection Findings, as described in [The mapping](#the-mapping). |
| `2005` | Incident Findings. |

The parameter is valid only with `format=ocsf`, may appear once per sink, and any other value fails startup. It changes only the incident shapes: detections, correlations, and the dedup and risk-event sidecars stay class 2004 on the same sink. Sinks are independent, so one daemon can send class 2005 to one collector and class 2004 or native NDJSON to another.

### Linking an incident to its Detection Findings

Each incident lists its contributors in `finding_info_list[]`. When a contributor's Detection Finding was emitted by this daemon, the entry's `uid` is that finding's `finding_info.uid`, so a consumer can join the incident to the class-2004 findings it groups. The daemon mints that identifier once per detection, before the risk layer and the alert pipeline run, and uses it both for the Detection Finding and for the incident's reference to it.

The link is made for every contributor the incident retains: `refs` (the default `include`) and `results`. When no retained contributor has a known Detection Finding, for example because `include` kept no samples or the incident was restored from a snapshot, `finding_info_list[]` falls back to one entry per contributing rule (or per contributing source on a risk incident), with a `uid` of `<incident id>:<rule>`. OCSF requires a `uid` on every entry, so the fallback always produces one, but it does not match any emitted finding.

The identifier is in memory only. It is not written to the native NDJSON incident, the state database, or the incident API.

A risk contributor that the alert pipeline later folds into a dedup alert or silences keeps the identifier minted for it, even though no Detection Finding with that `uid` reached a sink. A consumer joining on `finding_info_list[].uid` should treat an unmatched entry as a contributor that was suppressed downstream, not as an error.

### The class-2005 mapping

| OCSF field | Source |
|------------|--------|
| `class_uid` / `class_name` / `category_uid` / `category_name` | Constants: `2005` / `Incident Finding` / `2` / `Findings`. |
| `activity_id` / `activity_name` | Alert-pipeline incidents by trigger, as in class 2004: `group_wait` is `1` (`Create`), `group_interval` and `repeat` are `2` (`Update`), `resolved` is `3` (`Close`). Risk incidents: `1` (`Create`). |
| `type_uid` / `type_name` | `200501` / `200502` / `200503`. |
| `status_id` / `status` | `1` (`New`), or `4` (`Resolved`) for a resolved incident. |
| `severity_id` / `severity` | The incident's `max_level`. A risk incident carries no rule level, so its severity is `0` (`Unknown`). |
| `time`, `start_time`, `end_time`, `count`, `message` | As in class 2004. |
| `metadata.correlation_uid` | The incident id (`incident_id` or `risk_incident_id`). Every emission of one incident shares it. Class 2005 does not set `metadata.profiles`. |
| `assignee_group` | `{name}` from `?ocsf_assignee_group=<name>`. Required when `ocsf_incident_class=2005` and rejected on any other class, including OTLP. |
| `finding_info_list[]` | One `{uid, title, analytic}` entry per linked contributor, or the per-rule fallback described above. `analytic` names the rule (`type: "Rule"`) and carries its id as `analytic.uid` when a retained result supplies it. |
| `attacks[]` | Risk incidents only: the contributing tactics, mapped as in class 2004. |
| `unmapped` | Alert-pipeline incidents: `state`, `trigger`, `rule_counts`, `group_by`, `entities`, `refs`, and `results`. Risk incidents: `entity_type`, `entity_value`, `trigger`, `score`, `score_threshold`, `tactic_count`, `tactic_count_threshold`, `sources`, `source_count`, `refs`, and `results`. |

An Incident Finding has no `finding_info` and no `action_id` / `action`: OCSF defines neither on class 2005. A risk incident's `risk_score`, `resources[]`, and `actor` are class-2004 fields, so on class 2005 the score, entity, and threshold values ride under `unmapped` instead.

## OTLP log bodies

{{ added "0.28.0" }}

An OTLP sink with `?format=ocsf` exports each detection and correlation as one log record whose body is the OCSF Detection Finding as a JSON string, the same bytes a line sink would write. The record keeps the severity mapped from the Sigma level and the same attributes a native OTLP record carries, including `rule_title`, `rule_id`, `level`, and `tags`.

```bash
rsigma engine daemon -r rules/ --input http \
  --output 'otlphttp://otel-collector:4318?format=ocsf'
```

`?ocsf_version=<v>` selects the schema version as on a line sink. OTLP sinks carry detections and correlations only; alert-pipeline incidents, risk incidents, and the dedup and risk-event sidecars are not exported over OTLP in either format, so `?ocsf_incident_class` on an OTLP sink fails startup.

## Webhook bodies

{{ added "0.28.0" }}

A webhook body can insert the result's OCSF Detection Finding as raw JSON with `${detection.ocsf}` (a `kind: detection` webhook) or `${correlation.ocsf}` (a `kind: correlation` webhook):

```yaml
webhooks:
  - id: siem
    kind: detection
    url: https://siem.example/ingest
    headers:
      Content-Type: application/json
    body: '{"source": "rsigma", "finding": ${detection.ocsf}}'
```

The reference must stand where a whole JSON value can: as an object member value, an array element, or the entire body. Startup fails when it appears inside a string literal, in key position, in `url` or a header, or in any enricher template. Set `ocsf_version` to `1.1.0` (the default) or `1.3.0`. Startup fails when `ocsf_version` is set and the body does not contain `${detection.ocsf}` or `${correlation.ocsf}`. See [Webhooks](webhooks.md#templating).

## Consumer notes

- **Splunk**: ingest as `_json` and let the OCSF add-on map the class, or index the file directly. `finding_info.title` and `message` are the human-readable fields; `unmapped` survives as a nested object.
- **Elastic**: OCSF findings ingest cleanly through Filebeat or an Elastic Agent `filestream` input with a JSON parser. Map `severity_id` if you want an ECS `event.severity`.
- **CrowdStrike NG-SIEM**: third-party OCSF ingest expects one finding per line, which is exactly the sink's shape.
- **Amazon Security Lake**: a custom source requires OCSF in Parquet, which RSigma does not write. Land the JSON in S3 and transcode with Firehose, Glue, or any collector that converts JSON to Parquet.

## Schema versions

RSigma pins a **closed set** of OCSF schema versions. Each finding records the version in `metadata.version`. The default is `1.1.0`; line sinks may select another pinned version with `?format=ocsf&ocsf_version=<v>` (see [`engine daemon`](../cli/engine/daemon.md)). Goldens and a committed conformance schema per class (2004 and 2005) live under `tests/fixtures/ocsf/<version>/` in the `rsigma-runtime` crate; CI never fetches schemas from the network. Chasing the newest OCSF minor is not a goal: adding a version is deliberate and visible in the goldens. {{ added "0.28.0" }}

## An output dialect, not an input vocabulary

This is output only. RSigma does not deserialize OCSF findings, does not bless a canonical event schema, and does not change how rules name fields. The schema classifier's ability to recognize OCSF *events* on the input side is a separate, unrelated feature; see [Schema Routing](schema-routing.md).

## See also

- [Alert Pipeline](alert-pipeline.md) for the incident shapes the `Create`, `Update`, and `Close` activities describe.
- [Risk-Based Alerting](risk-based-alerting.md) for the `risk.score` and `risk.objects` enrichments that become `risk_score`, `resources[]`, and `actor`.
- [Streaming Detection](streaming-detection.md) for the sink and delivery model the format rides on.
- [Schema Routing](schema-routing.md) for recognizing OCSF events on the input side.
- [`rsigma engine daemon`](../cli/engine/daemon.md) for the full sink-spec grammar.
