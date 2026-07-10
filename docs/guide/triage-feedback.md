# Triage Feedback Loop

The triage feedback loop captures an analyst's verdict on the alerts a ruleset produces and turns the stream of verdicts into a live per-rule **false-positive ratio**, the canonical SOC detection-quality metric. Mature programs target it below 10 to 15 percent and treat it as the primary tuning signal, but computing it requires capturing a disposition on every alert and tracing it back to the rule that fired.

It is a measurement loop, not a case manager: it ingests a verdict and emits a ratio. It deliberately does not add an alert queue, ownership, an investigation timeline, ticketing, or any UI. The durable record of every alert stays in NATS, files, or your downstream SIEM.

It is opt-in and off by default. Enable it with `--enable-dispositions` or `daemon.dispositions.enabled: true`.

## Concepts

A **disposition** is one analyst verdict on an alert. The store keeps per-rule verdict counts in time buckets over a rolling window (daily buckets, default 30 days) and recomputes the ratio on every change. The store is fed only by its ingestion paths and reads rule identity from each record, so it never sits in the evaluation or sink path and cannot affect detection throughput.

The false-positive ratio for a rule is `false_positive / total_dispositioned` over the window, across all three verdicts. It is suppressed (absent, not zero) until the rule reaches `min_sample` dispositions, so a single false positive cannot publish a misleading 100 percent.

## Disposition format

A disposition is one JSON object. The `POST` body accepts a single object or an array; a pull-source payload is NDJSON or a JSON array.

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | yes (for `detection` scope) | The rule the analyst is dispositioning, with the title as the fallback the per-rule metrics use. |
| `verdict` | yes | `true_positive`, `false_positive`, or `benign_true_positive`. |
| `scope` | no (default `detection`) | `detection` or `incident`. |
| `fingerprint` | no | The alert-pipeline `dedup_fingerprint`, when the dedup layer is enabled. |
| `incident_id` | no | The alert-pipeline `incident_id`; required when `scope` is `incident`. |
| `timestamp` | no | RFC 3339; defaults to ingest time. Used for rolling-window placement. |
| `analyst` | no | Recorded for traceability; does not affect the ratio. |
| `note` | no | Bounded free text, recorded for traceability. |

An `incident`-scoped verdict with no `rule_id` resolves to the incident's contributing rules through the live alert-pipeline incident map (the same state behind `GET /api/v1/incidents`). When the incident is unknown or the alert pipeline is not enabled, supply an explicit `rule_id` or the record is rejected with a pointed error.

```bash
# A single false positive on one rule.
curl -sS -X POST http://127.0.0.1:9090/api/v1/dispositions \
  -d '{"rule_id":"proc-injection","verdict":"false_positive","analyst":"alice"}'

# A batch, keyed to alert-pipeline identities for redelivery-safe ingest.
curl -sS -X POST http://127.0.0.1:9090/api/v1/dispositions -d '[
  {"rule_id":"proc-injection","verdict":"true_positive","fingerprint":"a1b2"},
  {"scope":"incident","incident_id":"7f3c","verdict":"false_positive"}
]'

# The per-rule ratio view.
curl -sS http://127.0.0.1:9090/api/v1/dispositions
```

## Ingestion paths

There are two ways in, and both are idempotent:

- **The endpoint.** `POST /api/v1/dispositions` for push-style ingest from whatever delivered the alert.
- **A pull source.** `--disposition-source <PATH>` (or `daemon.dispositions.source`) points at a dynamic-source file (the same format as `--source`) whose payload is the disposition records. File, HTTP, and NATS transports are supported, refreshed per the source's policy. See [Disposition Source Recipes](disposition-recipes.md) for copy-paste, tested configs that pull verdicts from TheHive, Jira, and GitHub Issues.

Redelivery is safe: dispositions deduplicate on `(fingerprint or incident_id, verdict)`, falling back to `(rule_id, timestamp, analyst)` when no alert identity is carried, so a file re-read, a NATS redelivery, or an HTTP re-poll never double counts.

## The numerator knob

By default the numerator counts false positives only. A benign-but-correct fire is still triage noise, so whether `benign_true_positive` also counts is the `daemon.dispositions.numerator` knob (`fp_only` default, or `fp_and_btp`). Set it to match whatever convention your program already reports against.

## Closing the loop with delivery

The alert delivered by the [webhook sink](webhooks.md) (or a NATS sink) is the carrier an analyst dispositions. Include `rule_id` and the alert-pipeline `incident_id` in the delivered payload (a webhook template field) so the returned verdict keys cleanly; `incident_id` is the identity present on the first-fire pass-through alert.

## Feeding the scorecard

The [detection scorecard](detection-scorecard.md) reads a triage feed through its `--triage` input to fold the live false-positive ratio into its keep/tune/retire verdicts. The `GET /api/v1/dispositions` view is consumable directly as that feed (a `rules` array keyed by `rule_id` carrying the true/false-positive counts and the derived `fp_ratio`):

```bash
curl -sS http://127.0.0.1:9090/api/v1/dispositions > triage.json
rsigma rule scorecard --backtest backtest.json --coverage coverage.json --triage triage.json
```

## Persistence

When the daemon runs with `--state-db`, the disposition store persists across restarts: a versioned snapshot is saved to its own table in the SQLite state store on the periodic and shutdown hooks beside the correlation and alert-pipeline snapshots, and restored on boot with window-aware pruning (buckets past the window are dropped). `--clear-state` skips the restore; a version mismatch starts fresh with a warning.

## Configuration

The `daemon.dispositions` section:

```yaml
daemon:
  dispositions:
    enabled: false      # also enabled by --enable-dispositions or a configured source
    # source: /etc/rsigma/dispositions-source.yml
    window: 30d
    numerator: fp_only  # or fp_and_btp
    min_sample: 5
```

## Metrics

See [Triage feedback loop](../reference/metrics.md#triage-feedback-loop-4-metrics) in the metrics reference for the four series (`rsigma_rule_false_positive_ratio`, `rsigma_dispositions_total`, `rsigma_disposition_ingest_total`, `rsigma_disposition_ingest_errors_total`).

## See also

- [Disposition Source Recipes](disposition-recipes.md)
- [HTTP API: Dispositions](../reference/http-api.md#dispositions)
- [Detection Scorecard](detection-scorecard.md)
- [Alert Pipeline](alert-pipeline.md)
- [Webhooks](webhooks.md)
