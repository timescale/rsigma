---
description: "Keep a Sigma rule set healthy with rsigma rule hygiene: find silent, noisy, untagged, and ownerless rules, read the report, and gate retirement in CI."
---

# Rule Hygiene

{{ added "0.18.0" }}

Detection programs accumulate rules faster than they retire them. Elastic's [Detection Engineering Behavior Maturity Model (DEBMM)](https://www.elastic.co/security-labs/elastic-releases-debmm) puts structured rule management, continuous review, and low-noise maintenance at the center of a mature detection program, and published lifecycles such as the [SANS detection engineering lifecycle](https://www.sans.org/blog/logs-alerts-introducing-detection-engineering-poster) treat deployment and maintenance (including tuning and retirement) as an ongoing phase rather than a one-time ship. Without a forcing function, the catalog fills with unowned, untagged, never-firing, and stale rules. `rsigma rule hygiene` provides one: it assembles the signals RSigma already produces into one report of retirement and clean-up candidates, then lets CI gate on them.

This guide covers which input feeds which signal, how to read the report, and how to wire `--fail-on` into CI.

## What it flags

The report carries seven signals in one pass:

- **silent**: a rule with no matches over the metrics window, or one whose last-fired is older than `--silent-threshold` (default `365d`). A rule that has not fired in a year is a deletion candidate.
- **noisy**: a fire-count outlier. By default a robust median-plus-MAD test over peers that have fired; set `--noisy-threshold` for an absolute per-window ceiling instead. A rule that fires far more than its peers is either too broad or firing only on false positives.
- **untagged**: a rule with no `attack.*` ATT&CK tag. This is the same untagged set [`rule coverage`](../cli/rule/coverage.md) reports, rolled into the hygiene verdict rather than recomputed.
- **no-owner**: a rule with neither an `author:` field nor a custom-attribute `owner` key, so no one is accountable for tuning or retiring it.
- **incomplete-ads**: a `stable` detection rule (not ADS-exempt) missing required [ADS](detection-strategy.md) sections, so it ships to production without a documented strategy.
- **broken-fields**: a rule whose referenced fields are all in the field-observability snapshot's never-seen set, so it cannot fire no matter what.
- **deprecated**: a rule already marked `deprecated`/`unsupported`, or one whose `modified:` (falling back to `date:`) is older than `--stale-threshold` (default `365d`).

## Which input feeds which signal

| You have | Pass | You unlock |
|----------|------|------------|
| Just the rules | `--rules <PATH>` | untagged, no-owner, incomplete-ads, deprecated |
| A Prometheus scrape or endpoint | `--metrics <FILE\|URL>` | silent, noisy |
| An event corpus (offline) | `--corpus <PATH>` | silent, noisy |
| A field-observability snapshot | `--fields <FILE>` | broken-fields |

The static signals need only `--rules`, so the cheapest useful run is one that flags untagged, unowned, undocumented, and deprecated rules with no infrastructure at all. Layering in `--metrics` (or `--corpus`) and `--fields` adds the data-driven signals. For non-NDJSON corpus files, pass `--input-format` (`json`, `syslog`, `plain`, `logfmt`, `cef`, or `auto`).

### Production fire volume

`--metrics` reads the two per-rule counter families (`rsigma_detection_matches_by_rule_total` and `rsigma_correlation_matches_by_rule_total`, joined by `rule_title`). Point it at a saved `/metrics` scrape or a live endpoint:

```bash
rsigma rule hygiene --rules ./rules --metrics http://localhost:9090/metrics
```

A point-in-time scrape establishes silence by absence: a rule whose counter has never registered has never fired in that process. For a true last-fired timestamp, point `--metrics` at a Prometheus query-API base and pass `--metrics-window`:

```bash
rsigma rule hygiene --rules ./rules \
    --metrics http://prometheus:9090 --metrics-window 90d \
    --silent-threshold 90d
```

When there is no daemon or Prometheus to read, `--corpus` is the offline alternative: it replays a corpus (a file or a directory walked recursively) through the engine and counts per-rule fires, producing the same silence and noisy signals. Correlation state resets per file. Combined with `--metrics`, the counts are summed.

```bash
rsigma rule hygiene --rules ./rules --corpus ./corpus
```

### Broken field coverage

`--fields` consumes a [field-observability](observability.md) snapshot: the daemon's `/api/v1/fields` payload, or the report from `rsigma engine eval --observe-fields`. Its `missing` set is the rule-referenced fields that no event ever carried. Hygiene rolls that up per rule: a rule whose every referenced field is unseen is flagged `broken-fields`. Generate the snapshot from the same rule set so the field names line up.

## Reading the report

On a TTY the default `table` view prints a per-signal summary on stderr and the flagged rules on stdout:

```text
Rules: 7 (7 detection, 0 correlation) | Flagged: 6 | Sources: rules + metrics + fields
  1 silent  1 noisy  1 untagged  1 no-owner  1 incomplete-ads  1 broken-fields  1 deprecated

RULE                   KIND       SIGNALS            FIRES  LAST_FIRED  OWNER  STATUS
---------------------  ---------  -----------------  -----  ----------  -----  ----------
Bravo Noisy            detection  noisy                500  -           Bob    test
Charlie Quiet          detection  silent                 0  -           Carol  test
Delta Untagged Orphan  detection  untagged,no-owner      3  -           -      test
Echo Incomplete ADS    detection  incomplete-ads         2  -           Eve    stable
Foxtrot Deprecated     detection  deprecated             4  -           Frank  deprecated
Golf Broken Fields     detection  broken-fields          6  -           Grace  test
```

Without `--metrics`/`--corpus` or `--fields`, the sources line reads `rules only`.

For machine consumption, `--output-format json` emits the full document (a `summary`, a `rules[]` array of flagged verdicts, and a per-signal list for each signal), and `ndjson`/`csv`/`tsv` emit one row per flagged rule. The JSON list keys use snake_case names that differ from the signal labels: `never_fired` (silent), `broken_coverage` (broken-fields), and `stale_status` (deprecated); the other lists match (`noisy`, `untagged`, `no_owner`, `incomplete_ads`). `--report <FILE>` always writes the full JSON document regardless of the chosen output format, so a CI job can both print a table and archive the JSON.

## Gating CI

`--fail-on` is repeatable and exits `1` when a selected condition matches at least one rule. Gate on the conditions your program treats as blocking:

```bash
# Fail the build if any rule has been silent past the threshold or has no owner.
rsigma rule hygiene --rules ./rules --metrics metrics.txt \
    --silent-threshold 365d \
    --fail-on silent --fail-on no-owner
```

Use `--fail-on any` to fail on any finding, or set the policy in the config file under `hygiene.fail_on`. The exit codes follow the [house convention](../reference/exit-codes.md): `0` clean (or report-only), `1` a selected condition matched, `2` the rules could not load, `3` a bad flag or an unreadable metrics/fields input.

## Relationship to the scorecard

Hygiene is the static, coverage-structural half of the retirement story: it surfaces candidates from owner, tag, status, silence, noise, and field-coverage signals, and stops at flagging them. The [Detection Scorecard](detection-scorecard.md) is the quantitative keep/tune/retire verdict that fuses a backtest and coverage report (and optionally the same Prometheus volume) into a precision-driven decision. Run hygiene for the cheap, no-backtest sweep; run the scorecard when you have the backtest and coverage reports and want the graded verdict.

## See also

- [`rule hygiene` reference](../cli/rule/hygiene.md) for the full flag and exit-code tables.
- [Configuration](../reference/configuration.md) for the `hygiene.*` config section.
- [Detection Scorecard](detection-scorecard.md) for the quantitative verdict.
- [Observability](observability.md) for generating the field-observability snapshot.
- [CI/CD](ci-cd.md) for wiring hygiene into a pipeline alongside lint, validate, and backtest.
- [DEBMM](https://www.elastic.co/security-labs/elastic-releases-debmm) and the [SANS detection engineering lifecycle](https://www.sans.org/blog/logs-alerts-introducing-detection-engineering-poster) for the maturity and maintenance framing this command operationalizes.
- [Detection Engineering Loop](detection-engineering-loop.md) for how hygiene sits in the Measure station.
