---
description: "Emit Sigma detections as OCSF Detection Finding (class 2004) JSON from the RSigma daemon, ready for Splunk, Elastic, Amazon Security Lake, and Datadog."
---

# OCSF Findings

{{ added "0.21.0" }}

The daemon can emit every finding as an [OCSF](https://ocsf.io) **Detection Finding** (class 2004) JSON object instead of RSigma's native NDJSON. OCSF is the finding interchange format Splunk, Elastic, CrowdStrike NG-SIEM, Amazon Security Lake, and Datadog converged on, so a `?format=ocsf` sink drops findings into those pipelines without a transform step of your own.

It is a per-sink serialization choice, not a new sink type and not a new config section: append `?format=ocsf` to any line-oriented sink spec.

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
| `otlp://`, `otlps://`, `otlphttp://`, `otlphttps://` | Rejected at startup: the OTLP sink emits OTLP log records, which have their own mapping. |
| Webhooks | No query surface. Webhooks are declared in `--webhook` YAML files; a body template can render whatever JSON the endpoint wants. |
| `--dlq`, `daemon.api.audit.sink` | Rejected at startup: those channels carry DLQ entries and API audit records, not findings. |

An unusable or unknown `format` value fails startup with a pointed message.

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

All four emitted shapes (detections, correlations, alert-pipeline incidents, and risk incidents) are class 2004, distinguished by their activity.

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
| `metadata` | `product` names `rsigma` and its version, `version` is the OCSF schema version (`1.1.0`), and `uid` uniquely identifies the emitted event. Daemon delivery derives it from stable per-dispatch state, so fan-out and retries preserve it. |
| `finding_info.title` | The rule title for detections and correlations. Incidents carry no rule name, so the title is synthesized: the busiest contributing rule plus the count of the others (`rule-1 and 2 other rules`, or `rule-1 and 1 other rule` for a single peer), falling back to the group key (`incident for match.User=alice`) and then the bare id. A risk incident names what crossed and for whom (`risk threshold crossed for user alice`). |
| `finding_info.uid` | The incident id for the two incident shapes (re-emissions of one incident share it). Per-result findings use an identifier minted once per dispatch and preserved across sinks and retries. OCSF requires this to identify the finding, and one rule produces many, so rule identity lives in `analytic.uid` instead. |
| `finding_info.analytic` | `{type_id: 1, type: "Rule", name: <rule title>, uid: <rule id>}` for detections and correlations. Incidents name the `alert pipeline`, risk incidents the `risk accumulator`, with their contributing rules in `related_analytics`. |
| `finding_info.attacks[]` | Parsed from the rule's tags: `attack.t1059.001` becomes `sub_technique: {uid: "T1059.001"}` and `attack.credential_access` becomes `tactic: {name: "Credential Access", uid: "TA0006"}`. A risk incident's contributing tactics map the same way. A tag cannot say which tactic a technique was used for, so techniques and tactics are separate entries rather than paired by guesswork. Tags in other taxonomies are skipped here and carried under `unmapped.tags`. |
| `evidences[]` | One entry whose `data` holds what the result carried into the finding: matched field/value pairs when present, plus the retained event when `--include-event` or per-rule `rsigma.include_event` kept it; for correlations, the retained `events` or `event_refs`. Omitted only when that map would be empty (no matched fields and no retained event payload). |
| `resources[]` | The [risk](risk-based-alerting.md) layer's `risk.objects` entries as `{type, name}`, and an incident's `group_by` / `entities` values the same way. |
| `actor.user.name` | The first `risk.objects` entry of type `user`, or a risk incident whose entity type is `user`. |
| `risk_score` | The `risk.score` enrichment, or a risk incident's accumulated `score`. |
| `count` | `result_count` on both incident shapes: OCSF's occurrence count for the group. |
| `unmapped` | Everything without a faithful OCSF home, under its native key: `matched_selections`, `matched_fields` in full fidelity, `correlation_type`, `group_key`, `aggregated_value`, `timespan_secs`, `tags`, `custom_attributes`, the remaining enrichments (including the alert pipeline's `incident_id`), and the incident-only `state`, `trigger`, `rule_counts`, `refs`, `results`, `tactic_count`, `tactic_count_threshold`, `score_threshold`, and `source_count`. |

### Nothing is dropped

The mapping is conservative on purpose. A field moves into OCSF only where the fit is faithful; everything else rides under `unmapped` with the key it has on the native line. This makes `?format=ocsf` safe as a daemon's only output: a consumer that only understands class 2004 gets a conformant finding, and a consumer that knows RSigma finds the rest where it expects it.

The risk enrichments are the one place keys move: `risk.score` and `risk.objects` are lifted to `risk_score`, `resources[]`, and `actor`, and removed from the `unmapped.enrichments` copy. A malformed value (a `risk.objects` that is not an array of `{type, value}` pairs, a non-integer `risk.score`) is left in `unmapped` untouched rather than coerced.

### Detections carry no event time

An `EvaluationResult` has no event-timestamp field (the native NDJSON has none either), so a detection or correlation finding stamps `time` with the serialization clock. When you need event time, either retain the event (`--include-event` or `rsigma.include_event`) and read it from `evidences[].data.event`, or consume the incident shapes, whose `start_time` and `end_time` are real observed bounds.

### Sidecar lines stay native

Two payloads travel the incident channel as opaque native JSON and are **not** mapped to class 2004: the alert pipeline's dedup `repeat` and `resolved` summary records, and the compact risk events emitted with `emit_risk_events: true`. They appear as native NDJSON lines even on an OCSF sink. If your consumer requires a homogeneous OCSF stream, route those to their own sink (the risk layer supports a dedicated NATS subject) or filter them by their distinguishing keys (`enrichments.dedup_state` and `risk_event`).

## Consumer notes

- **Splunk**: ingest as `_json` and let the OCSF add-on map the class, or index the file directly. `finding_info.title` and `message` are the human-readable fields; `unmapped` survives as a nested object.
- **Elastic**: OCSF findings ingest cleanly through Filebeat or an Elastic Agent `filestream` input with a JSON parser. Map `severity_id` if you want an ECS `event.severity`.
- **CrowdStrike NG-SIEM**: third-party OCSF ingest expects one finding per line, which is exactly the sink's shape.
- **Amazon Security Lake**: a custom source requires OCSF **in Parquet**, which RSigma does not write. Land the JSON in S3 and transcode with Firehose, Glue, or any collector that converts JSON to Parquet.

## Pinned schema version

The serializer targets one OCSF version, `1.1.0`, recorded in `metadata.version` and pinned by a committed conformance fixture that every golden test validates against. Chasing the newest OCSF minor release is not a goal; a version change is deliberate and visible in the goldens.

## An output dialect, not an input vocabulary

This is output only. RSigma does not deserialize OCSF findings, does not bless a canonical event schema, and does not change how rules name fields. The schema classifier's ability to recognize OCSF *events* on the input side is a separate, unrelated feature; see [Schema Routing](schema-routing.md).

## See also

- [Alert Pipeline](alert-pipeline.md) for the incident shapes the `Create`, `Update`, and `Close` activities describe.
- [Risk-Based Alerting](risk-based-alerting.md) for the `risk.score` and `risk.objects` enrichments that become `risk_score`, `resources[]`, and `actor`.
- [Streaming Detection](streaming-detection.md) for the sink and delivery model the format rides on.
- [Schema Routing](schema-routing.md) for recognizing OCSF events on the input side.
- [`rsigma engine daemon`](../cli/engine/daemon.md) for the full sink-spec grammar.
