---
description: "Measure MITRE ATT&CK coverage of your Sigma rules with RSigma: export Navigator heatmaps and diff coverage against Atomic Red Team and SigmaHQ."
---

# ATT&CK Coverage

{{ added "0.17.0" }}

[`rsigma rule coverage`](../cli/rule/coverage.md) maps a rule set onto the MITRE ATT&CK matrix. It answers "what does my rule set cover, and where are the holes" by reading the `attack.*` tags off your rules, exporting an ATT&CK Navigator heatmap, and diffing your coverage against external references.

Where [`rule backtest`](../cli/rule/backtest.md) tells you whether your rules fire correctly, `rule coverage` tells you whether you have rules for the techniques you care about.

## How techniques are extracted

Coverage reads the `tags:` block of every detection and correlation rule (filter rules are excluded, since they suppress rather than detect):

- `attack.t1059`, `attack.t1059.001` become technique IDs `T1059`, `T1059.001`.
- `attack.execution`, `attack.privilege-escalation`, ... become tactic annotations. Both the hyphenated spelling SigmaHQ uses (`privilege-escalation`) and the underscore spelling from the Sigma spec (`privilege_escalation`) are accepted and normalized to the canonical Navigator slug.
- Any other `attack.*` tag (ATT&CK groups, software, or a custom taxonomy) counts the rule as tagged but contributes no technique.

A rule carrying no `attack.*` tag at all is reported under `untagged_rules`, a tagging-hygiene signal worth driving to zero.

```yaml
# A rule that contributes T1059.001 under the "execution" tactic.
title: PowerShell Download Cradle
logsource: { category: process_creation, product: windows }
detection:
  sel: { Image|endswith: '\powershell.exe', CommandLine|contains: DownloadString }
  condition: sel
tags:
  - attack.execution
  - attack.t1059.001
```

### Sub-technique roll-up

A rule on a sub-technique covers its parent for gap analysis: a rule tagged `attack.t1059.001` makes a target of `T1059` count as covered (reported as `covered_via_subtechnique`). The reverse does not hold. A rule on the parent `T1059` does not vouch for a specific sub-technique target like `T1059.002`, because the coarser rule does not guarantee detection of that exact variant. The exported Navigator layer always keeps exact per-ID scores; the roll-up only affects the gap math.

## Export an ATT&CK Navigator layer

```bash
rsigma rule coverage -r rules/ --navigator coverage.json
```

The layer is [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) format 4.5. Each technique is scored by the number of rules that reference it, the same "score function count" semantics SigmaHQ uses for its published heatmap, so your layer and the SigmaHQ baseline share a gradient and overlay cleanly. Open `coverage.json` in the Navigator (Open Existing Layer) to see the heatmap, or commit it as a coverage artifact.

## Cross-references

Each cross-reference is optional and additive. Combine as many as you like in one run.

### Atomic Red Team

```bash
rsigma rule coverage -r rules/ --atomics
```

A bare `--atomics` fetches the upstream [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) `atomics/Indexes/index.yaml` (cached for 7 days under the user cache directory). Pass a local `index.yaml`, an atomic-red-team `atomics/` checkout, or a URL to use your own copy. The report splits the gap two ways:

- `atomics_without_rule`: techniques that have an atomic test but no detection rule. These are your **detection gaps**, the highest-value place to write a new rule, because there is a known way to exercise the technique that nothing would catch.
- `rules_without_atomic`: techniques you detect that have no atomic test. These are **validation gaps**, where you cannot easily prove the rule works.

### SigmaHQ baseline

```bash
rsigma rule coverage -r rules/ --baseline --output-format json | jq '.baseline'
```

A bare `--baseline` fetches the [SigmaHQ coverage heatmap](https://github.com/SigmaHQ/sigma/blob/master/other/sigma_attack_nav_coverage.json) (itself a Navigator layer), so the diff is layer-to-layer. Like `--atomics`, the default upstream fetch is cached for 7 days. The report shows `baseline_not_covered` (techniques the public corpus covers that you do not) and `ahead_of_baseline` (techniques you cover that the baseline does not, often your environment-specific detections).

### Target technique list

```bash
rsigma rule coverage -r rules/ --targets threat-model.txt
```

A target list is your own prioritized set of techniques (an internal threat model, the M-Trends top techniques, a red-team engagement scope), one technique ID per line with `#` comments allowed:

```text
# Q3 threat model
T1059        # command and scripting
T1003        # credential dumping
T1486        # data encrypted for impact
```

The report's `targets.uncovered` is the list to work down.

## From gaps to simulations

{{ added "0.22.0" }}

`atomics_without_rule` is the set of techniques you could validate with Atomic Red Team today but have no detection for. `--emit atomics-plan` turns that list into a file: per uncovered technique, the test names, `auto_generated_guid`s, supported platforms, and ready-to-paste `Invoke-AtomicTest` invocations.

```bash
rsigma rule coverage -r rules/ --atomics --emit atomics-plan --platforms windows \
    --output-format tsv > atomics-plan.tsv
```

rsigma does not run the tests. Attack simulation stays [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s job: take the `INVOCATION` column into a lab, capture the resulting telemetry, and feed it back as a [`rule backtest`](../cli/rule/backtest.md) corpus or as [`rsigma.exemplars`](../cli/rule/test.md) on the new rules. The next `rule coverage` run then shows those techniques as covered.

`--fail-on-gaps` keeps its usual meaning under `--emit atomics-plan`: a non-empty uncovered-but-testable set still exits `1`.

## Gate CI on coverage

`--fail-on-gaps` turns any requested cross-reference's uncovered set into a non-zero exit, so coverage becomes a CI gate. The most common use is a target list that must stay fully covered:

```bash
rsigma rule coverage -r rules/ --targets threat-model.txt --fail-on-gaps
```

This exits `1` (findings) the moment a targeted technique loses its last rule, so deleting or renaming a rule that was your only coverage for a priority technique fails the build. The exit codes follow the [house scheme](../reference/exit-codes.md): `0` clean, `1` gaps, `2` unreadable rules, `3` a bad cross-reference input.

See [CI/CD](ci-cd.md) for the full detection-as-code pipeline that runs lint, validate, backtest, and coverage together.

## Configuration

The rules path and cross-reference inputs can be set as project defaults in a [config file](../reference/configuration.md) so CI invocations stay short:

```yaml
coverage:
  rules: [./rules]
  atomics: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml
  targets: ./threat-model-techniques.txt
  fail_on_gaps: true
```

CLI flags always win over the config file. When `-r`/`--rules` is omitted, `coverage.rules` fills it.

## See also

- [`rule coverage`](../cli/rule/coverage.md) for the full flag reference.
- [`rule scorecard`](../cli/rule/scorecard.md) to feed this JSON report (with the backtest report) into per-rule keep/tune/retire verdicts.
- [Visibility and Data Sources](visibility-and-data-sources.md) for the complementary visibility axis: which telemetry your rules depend on, scored against ATT&CK data sources.
- [`rule backtest`](../cli/rule/backtest.md) for the corpus-replay test harness.
- [Linting Rules](linting-rules.md) for tag-format validation that keeps `attack.*` tags well-formed.
- [CI/CD](ci-cd.md) for wiring coverage into a pipeline.
- [Configuration](../reference/configuration.md) for the `coverage` config section.
