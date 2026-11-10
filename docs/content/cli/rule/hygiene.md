---
description: "Reference for rsigma rule hygiene: flag silent, noisy, untagged, ownerless, and deprecated Sigma rules as maintenance and retirement candidates in one report."
---

# `rsigma rule hygiene`

{{ added "0.18.0" }}

Flag rule hygiene and retirement candidates in one report.

## Synopsis

```text
rsigma rule hygiene --rules <PATH>... [OPTIONS]
```

## Description

`rule hygiene` assembles the raw signals RSigma already produces into a single report of retirement and clean-up candidates. Mature detection programs treat rule management and maintenance as ongoing work (see Elastic's [DEBMM](https://www.elastic.co/security-labs/elastic-releases-debmm) and the [SANS detection engineering lifecycle](https://www.sans.org/blog/logs-alerts-introducing-detection-engineering-poster)): without a cull, the catalog fills with silent, noisy, unowned, and stale rules.

It runs no event evaluation unless `--corpus` is set. The static signals read straight off the parsed rules; with `--corpus`, the command replays the corpus through the engine for per-rule fire counts; the silence and noisy signals also join a Prometheus snapshot or endpoint; the broken-coverage signal joins a field-observability snapshot. It is an offline `rule`-group command with no daemon hot-path involvement.

Only `-r/--rules` is required. The static signals (untagged, no-owner, incomplete-ads, deprecated/stale) report from the rules alone; the silence and noisy signals need `--metrics` or `--corpus`; the broken-coverage signal needs `--fields`.

## Signals

| Signal | Source | What it flags |
|--------|--------|---------------|
| `silent` | `--metrics` or `--corpus` | A rule with no matches in the snapshot/corpus, or one whose last-fired (with `--metrics-window`) is older than `--silent-threshold`. |
| `noisy` | `--metrics` or `--corpus` | A fire-count outlier over the window: a robust median-plus-MAD test by default, or any rule at or above an absolute `--noisy-threshold`. |
| `untagged` | `--rules` | A rule carrying no `attack.*` ATT&CK tag. This is the same notion of "untagged" [`rule coverage`](coverage.md) reports, computed by the same shared extractor. |
| `no-owner` | `--rules` | A rule with no owner: no `custom_attributes` `owner` key and no `author`. |
| `incomplete-ads` | `--rules` | A `stable` detection rule, not ADS-exempt, that is missing at least one required ADS section. Mirrors the default bar of the [ADS presence lint](lint.md); finer control stays in the linter. |
| `broken-fields` | `--fields` | A detection rule whose referenced fields are all in the snapshot's never-seen (`missing`) set. |
| `deprecated` | `--rules` | A rule with `status: deprecated` or `status: unsupported`, or a `modified`/`date` older than `--stale-threshold`. |

## Inputs

| Input | Flag | Required | What it supplies |
|-------|------|----------|------------------|
| Rules | `-r, --rules <PATH>` | yes | The rule set to report on (repeatable; file or directory). |
| Prometheus snapshot or endpoint | `--metrics <FILE\|URL>` | no | Per-rule fire volume from `rsigma_detection_matches_by_rule_total` and `rsigma_correlation_matches_by_rule_total`, joined by `rule_title`. Drives `silent` and `noisy`. |
| Prometheus query API | `--metrics-window <DURATION>` | no | When `--metrics` is a Prometheus query-API base, switches to a `query_range` over the window to derive a true last-fired timestamp. |
| Event corpus | `--corpus <PATH>` | no | The offline alternative to `--metrics` (no daemon, no Prometheus): a file or directory replayed through the engine for per-rule fire counts. Combined with `--metrics`, the counts are summed. Also drives `silent` and `noisy`. A `--corpus` path that contains no readable files exits `3` rather than marking every rule silent. |
| Field-observability snapshot | `--fields <FILE>` | no | The `/api/v1/fields` payload (or its `missing` array) from a daemon with `--observe-fields`, or the `rsigma engine eval --observe-fields` report. Drives `broken-fields`. |

At least one of `--metrics` or `--corpus` is required for the `silent` and `noisy` signals; the static signals need only `--rules`.

The Prometheus join inherits the caveat documented in [Metrics](../../reference/metrics.md): `rule_title` is not guaranteed unique, so when two rules share a title their counters add together. The shared reader is the same one [`rule scorecard`](scorecard.md) uses.

The broken-coverage rollup needs each rule's full referenced-field set, so it joins the snapshot's `missing` field names against the fields extracted from `--rules`. Generate the snapshot from the same rule set so the field names line up.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>` | required | Sigma rule file or directory (repeatable). May also be supplied via `hygiene.rules`. |
| `--metrics <FILE\|URL>` | unset | A Prometheus exposition snapshot file or a `/metrics` URL. May also be supplied via `hygiene.metrics`. |
| `--metrics-window <DURATION>` | unset | Range-query window (e.g. `7d`, `24h`) when `--metrics` is a query-API base. May also be supplied via `hygiene.metrics_window`. |
| `--corpus <PATH>` | unset | Event corpus file or directory replayed for offline fire counts (repeatable). |
| `--input-format <FORMAT>` | `auto` | Input log format for non-NDJSON corpus files (`json`, `syslog`, `plain`, `logfmt`, `cef`, `auto`). Only used with `--corpus`. |
| `--fields <FILE>` | unset | A field-observability JSON snapshot. May also be supplied via `hygiene.fields`. |
| `--silent-threshold <DURATION>` | `365d` | Age past which a never-fired rule is a retirement candidate. May also be supplied via `hygiene.silent_threshold`. |
| `--stale-threshold <DURATION>` | `365d` | Modified-date age past which a rule is flagged stale. May also be supplied via `hygiene.stale_threshold`. |
| `--noisy-threshold <COUNT>` | unset | Absolute per-window fire ceiling that overrides the robust outlier test. May also be supplied via `hygiene.noisy_threshold`. |
| `--report <FILE>` | unset | Write the full JSON report to disk, independent of `--output-format`. |
| `--fail-on <CONDITION>` | unset | Exit `1` when a selected finding matches at least one rule (repeatable): `silent`, `noisy`, `untagged`, `no-owner`, `incomplete-ads`, `broken-fields`, `deprecated`, or `any`. May also be supplied via `hygiene.fail_on`. |
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the discovery chain. |
| `--dry-run` | off | Print the effective `hygiene` section and exit `0` without running. |

The global `--output-format` applies: `table` (the TTY default) renders the flagged rules under a per-signal summary, `json` emits the full report document, and `ndjson`/`csv`/`tsv` emit one row per flagged rule.

## Report

The JSON document (`--output-format json`) has a stable shape:

- `summary`: total, detection, and correlation rule counts, the flagged count, which sources contributed, and a per-signal count.
- `rules[]`: per flagged rule, its title, id, kind, the signals it tripped, fire count and last-fired where known, owner, status, and tags.
- the per-signal lists `never_fired`, `noisy`, `untagged`, `no_owner`, `incomplete_ads`, `broken_coverage`, and `stale_status`.

`--report` writes the same JSON document to a file regardless of the chosen output format.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success, or findings were produced but none tripped `--fail-on`. |
| `1` | `--fail-on` was set and at least one selected condition matched. |
| `2` | The rules could not be loaded. |
| `3` | A bad flag, an unreadable or malformed metrics/fields/corpus input, or a `--report` write failure. |

## Examples

### Report from the rules alone (static signals)

```bash
rsigma rule hygiene --rules ./rules
```

### Add production fire volume for silence and noise

```bash
rsigma rule hygiene --rules ./rules --metrics http://localhost:9090/metrics
```

### Use a replayed corpus instead of Prometheus (offline)

```bash
rsigma rule hygiene --rules ./rules --corpus ./corpus
```

### Add broken field coverage from a field-observability snapshot

```bash
rsigma rule hygiene --rules ./rules \
    --metrics http://localhost:9090/metrics \
    --fields fields.json
```

### Gate CI on rules silent longer than a year

```bash
rsigma rule hygiene --rules ./rules --metrics metrics.txt \
    --silent-threshold 365d --fail-on silent
```

## See also

- [Rule Hygiene](../../guide/rule-hygiene.md) for the retirement-cadence workflow and how each input feeds each signal.
- [`rule coverage`](coverage.md) shares the ATT&CK tag extraction behind the untagged signal; [`rule scorecard`](scorecard.md) is the quantitative keep/tune/retire verdict this report complements.
- [Observability](../../guide/observability.md) for generating the field-observability snapshot.
- [Configuration](../../reference/configuration.md) for the `hygiene` config section.
- [Exit Codes reference](../../reference/exit-codes.md) for the canonical table.
