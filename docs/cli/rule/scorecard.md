# `rsigma rule scorecard`

Fuse the detection-as-code rule-side outputs into the per-rule keep/tune/retire verdict table a mature detection program reviews on a cadence.

## Synopsis

```text
rsigma rule scorecard --backtest <FILE> --coverage <FILE> [OPTIONS]
```

## Description

`rule scorecard` reads JSON the toolkit already emits and turns it into a decision. The [`rule backtest`](backtest.md) report answers "do my rules fire correctly" (and surfaces unexpected fires on a benign corpus as the false-positive signal); the [`rule coverage`](coverage.md) report answers "what does my rule set cover"; the per-rule Prometheus counters answer "how often does each rule fire in production." Each is a raw output. The scorecard is the fusion-and-verdict layer that joins them into the single artifact a program acts on: for every rule, a precision proxy, volume, ATT&CK context, and a keep/tune/retire verdict with a reason.

It runs no evaluation and re-reads no corpus. It fuses already-aggregated reports, so it is an offline `rule`-group command with no engine or hot-path involvement.

The two JSON reports are required. The Prometheus snapshot and the triage feed are optional enrichers: a scorecard run with only the two required inputs still produces a meaningful corpus-derived table, and a missing optional input degrades the verdict rather than blocking it.

## Inputs

| Input | Flag | Required | What it supplies |
|-------|------|----------|------------------|
| Backtest report | `--backtest <FILE>` | yes | Precision proxy and recall, per-rule corpus fire counts, level, logsource. The unexpected-fire rollup is the corpus false-positive signal. |
| Coverage report | `--coverage <FILE>` | yes | Per-rule ATT&CK technique and tactic mapping, plus the per-technique rule count used for sole-coverage analysis. |
| Prometheus snapshot or endpoint | `--metrics <FILE\|URL>` | no | Production true-positive volume from `rsigma_detection_matches_by_rule_total` and `rsigma_correlation_matches_by_rule_total`, joined by `rule_title`. |
| Prometheus query API | `--metrics-window <DURATION>` | no | When `--metrics` is a Prometheus query-API base, switches to a `query_range` over the window to derive last-fired and the current value. |
| Triage disposition feed | `--triage <FILE>` | no | Live per-rule false-positive ratio and, where present, MTTD/MTTR. |

Both JSON reports are owned by rsigma, so the scorecard shares the producer structs and version-checks any on-disk report against the shipped release: a report from an incompatible build fails the typed deserialize and exits `3`.

The Prometheus join inherits the caveat documented in [Metrics](../../reference/metrics.md): `rule_title` is not guaranteed unique, so when two rules share a title their counters add together. The scorecard keys its records by `rule_id`, sums the colliding title for the volume column, and flags the affected records with `title_collision`. For collision-free production volume, scrape `rsigma_detection_matches_total` and join your detection NDJSON by `rule_id` outside Prometheus.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--backtest <FILE>` | required | The backtest JSON report (from `rule backtest --report`). May also be supplied via `scorecard.backtest`. |
| `--coverage <FILE>` | required | The coverage JSON report (from `rule coverage --output-format json`). May also be supplied via `scorecard.coverage`. |
| `--metrics <FILE\|URL>` | unset | A Prometheus exposition snapshot file or a `/metrics` URL. May also be supplied via `scorecard.metrics`. |
| `--metrics-window <DURATION>` | unset | Range-query window (e.g. `7d`, `24h`) when `--metrics` is a query-API base. May also be supplied via `scorecard.metrics_window`. |
| `--triage <FILE>` | unset | The triage disposition feed. May also be supplied via `scorecard.triage`. |
| `--fail-on <POLICY>` | `none` | Exit `1` when any rule's verdict is at or worse than the policy: `retire` fails on retire; `tune` fails on tune and retire; `none` reports only. May also be supplied via `scorecard.fail_on`. |
| `--report <PATH>` | unset | Write the program artifact; `.md`/`.markdown` to markdown, `.html`/`.htm` to HTML. May also be supplied via `scorecard.report`. |
| `--report-format <FMT>` | from extension | Override the `--report` format (`markdown` or `html`). |
| `--min-precision <F>` | `0.80` | Keep floor: precision proxy at or above this keeps the rule. |
| `--tune-max-precision <F>` | `0.50` | Upper edge of the review band (used in the tune reason). |
| `--retire-max-precision <F>` | `0.10` | Retire floor: precision proxy below this retires the rule. |
| `--min-volume <N>` | `1` | Minimum total volume for a keep verdict. |
| `--stale-window <DAYS>` | `30` | Staleness window; a rule that has not fired within it is not kept (enforced only when last-fired is known via `--metrics-window`). |
| `--max-fp-ratio <F>` | `0.50` | Live false-positive-ratio ceiling; a rule above it is at best tuned. |
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the discovery chain. |
| `--dry-run` | off | Print the effective `scorecard` section and exit `0` without running. |

The global `--output-format` applies: `table` (the TTY default) renders the human scorecard grouped by verdict under a summary header, `json` emits the single scorecard document, and `ndjson`/`csv`/`tsv` emit one row per rule.

## Verdict model

Each fused per-rule record carries a precision proxy, recall, the corpus false-positive signal, true-positive volume (corpus plus production where `--metrics` is given), last-fired and latency where available, ATT&CK context with a sole-coverage flag, the live false-positive ratio, a keep/tune/retire verdict, and a reason. Every cell records which input supplied it under `provenance`, so corpus-derived numbers are distinguishable from production-derived ones.

The bands default to the SOC quality-metrics thresholds and are fully configurable:

- **retire**: precision proxy below the retire floor (`0.10`), or zero volume across both the corpus and the metrics window (a dead rule).
- **tune**: precision proxy in the review band (at or above the retire floor and below the keep floor), or a live false-positive ratio above the ceiling (`0.50`). A retire candidate that is the sole coverage for an ATT&CK technique is downgraded here with a coverage-risk note, so the program never silently drops coverage.
- **keep**: precision proxy at or above the keep floor (`0.80`), with enough volume and a recent enough last-fired.

Missing optional inputs degrade the verdict rather than blocking it: with no `--metrics`, volume and staleness come from the corpus alone; with no `--triage`, the live false-positive ratio and latency are blank and the verdict falls back to the corpus precision proxy.

## Triage feed

The triage feed is the live disposition signal. It is a JSON document keyed by `rule_id`:

```json
{
  "rules": [
    { "rule_id": "5f0d7d3c-...", "true_positives": 8, "false_positives": 2, "mttd_seconds": 1800, "mttr_seconds": 3600 },
    { "rule_id": "a2b1c0d9-...", "fp_ratio": 0.4 }
  ]
}
```

Each entry supplies either an explicit `fp_ratio` or the `true_positives`/`false_positives` counts to derive it, plus optional `mttd_seconds`/`mttr_seconds`.

## Report

The JSON document (`--output-format json`) has a stable shape:

- `summary`: rule count, keep/tune/retire counts, portfolio precision proxy, ATT&CK technique count and tagged percentage, and the effective thresholds.
- `records[]`: per rule, the id, title, level, logsource, precision proxy, recall, false-positive signal, corpus and production volume, last-fired and latency where available, ATT&CK context with the sole-coverage flag, the live false-positive ratio, the title-collision flag, the verdict and its reason, and per-cell provenance.
- `inputs`: which optional inputs contributed.

`--report` writes the same content as a standalone markdown or HTML artifact grouped by verdict, for sharing in a review.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success, or verdicts were produced but none tripped `--fail-on`. |
| `1` | `--fail-on` was set and at least one rule's verdict is at or worse than the policy. |
| `2` | A required or optional input is missing or unfetchable. |
| `3` | A bad flag, or a malformed or version-mismatched report. |

## Examples

### Produce the corpus-derived scorecard from the two required reports

```bash
rsigma rule scorecard --backtest backtest.json --coverage coverage.json
```

### Enrich with production volume and analyst dispositions

```bash
rsigma rule scorecard --backtest backtest.json --coverage coverage.json \
    --metrics http://localhost:9090/metrics --triage triage.json
```

### Write the weekly review artifact

```bash
rsigma rule scorecard --backtest backtest.json --coverage coverage.json \
    --report scorecard.md
```

### Gate CI on retire-grade rules

```bash
rsigma rule scorecard --backtest backtest.json --coverage coverage.json \
    --fail-on retire
```

## See also

- [Detection Scorecard](../../guide/detection-scorecard.md) for the program artifact and the review cadence.
- [`rule backtest`](backtest.md) and [`rule coverage`](coverage.md) produce the two JSON reports the scorecard fuses.
- [CI/CD](../../guide/ci-cd.md) for wiring the scorecard in as the metrics gate atop the triad.
- [Configuration](../../reference/configuration.md) for the `scorecard` config section.
- [Exit Codes reference](../../reference/exit-codes.md) for the canonical table.
