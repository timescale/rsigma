# Detection Scorecard

The detection scorecard is the single artifact a mature detection program reviews on a cadence: a per-rule table of precision, volume, ATT&CK context, and a keep/tune/retire verdict. [`rsigma rule scorecard`](../cli/rule/scorecard.md) produces it by fusing the rule-side outputs the toolkit already emits, so it adds no new collection or evaluation.

## Why a scorecard

The detection-as-code triad gives you the inputs but not the decision:

- [`rule backtest`](../cli/rule/backtest.md) answers "do my rules fire correctly" and, on a known-benign corpus, surfaces unexpected fires as the false-positive signal.
- [`rule coverage`](../cli/rule/coverage.md) answers "what does my rule set cover" and emits the per-rule ATT&CK mapping.
- The per-rule Prometheus counters answer "how often does each rule fire in production."

Each is a raw output. None is the artifact you act on. The SOC quality-metrics literature is explicit about the shape that is: the per-rule scorecard that pulls precision (a false-positive proxy), volume (true-positive count), latency (MTTD/MTTR), and the verdict into one table, reviewed on a cadence. `rule scorecard` is that fusion-and-verdict layer.

## The verdict model

Every rule gets one of three verdicts:

- **keep**: the rule is precise enough (precision proxy at or above the keep floor, default `0.80`), carries enough volume, and has fired recently enough. Leave it alone.
- **tune**: the rule needs work. Its precision proxy is in the review band (between the retire floor and the keep floor), or its live false-positive ratio from the triage feed is over the ceiling (default `0.50`). It still has value worth keeping while you sharpen it.
- **retire**: the rule's precision proxy is below the retire floor (default `0.10`), or it is dead (zero volume across the corpus and the metrics window). It is a candidate for removal.

A retire candidate that is the **sole coverage** for an ATT&CK technique is downgraded to tune with a coverage-risk note, so the program never silently drops the only rule covering a technique. The thresholds are defaults from the SOC quality-metrics literature and are fully configurable through flags and the `scorecard` config section.

The verdict degrades gracefully with the inputs you have. With only the two required JSON reports it is corpus-derived; add `--metrics` for production volume and staleness, and `--triage` for the live false-positive ratio and latency. Every cell in a record records which input supplied it, so you can always tell a corpus-derived number from a production-derived one.

## The review cadence

The literature prescribes a two-tier cadence, and the scorecard supports both:

- **Weekly, for new rules.** Run the scorecard over a recent backtest and the production metrics for rules added in the last cycle. New rules are where tuning pays off most; the `tune` list is your work queue.
- **Monthly, for the full portfolio.** Run it over the whole rule set. The `retire` list is your pruning queue (minus the sole-coverage rules it protects), and the portfolio precision proxy in the summary is the trend line to watch over time.

Write the artifact with `--report scorecard.md` (or `.html`) and attach it to the review. It is grouped by verdict under a summary header, so the meeting starts from the retire and tune lists.

## Wiring it into CI

The scorecard is a reporting command by default (`--fail-on none`), but `--fail-on` turns it into a gate. Use it as the metrics gate atop the backtest and coverage steps:

```bash
# 1. Backtest the rules against the corpus, writing the JSON report.
rsigma rule backtest -r rules/ --corpus ci/corpus/ \
    --expectations ci/expectations.yml --report backtest.json

# 2. Map coverage, writing the JSON report.
rsigma rule coverage -r rules/ --output-format json > coverage.json

# 3. Fuse and gate: fail the build if the portfolio accrues retire-grade rules.
rsigma rule scorecard --backtest backtest.json --coverage coverage.json \
    --metrics http://prometheus/metrics --fail-on retire --report scorecard.md
```

`--fail-on retire` fails only on retire-grade rules; `--fail-on tune` is stricter and fails on tune as well. See [CI/CD](ci-cd.md) for the full pipeline.

## See also

- [`rule scorecard`](../cli/rule/scorecard.md) for the full flag, input, and report reference.
- [ATT&CK Coverage](attack-coverage.md) and [`rule backtest`](../cli/rule/backtest.md) for the two reports the scorecard fuses.
- [Configuration](../reference/configuration.md) for the `scorecard` config section.
