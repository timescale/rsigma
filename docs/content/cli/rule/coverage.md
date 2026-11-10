---
description: "Reference for rsigma rule coverage: map Sigma rules onto MITRE ATT&CK, export a Navigator layer, and report gaps against Atomic Red Team and SigmaHQ."
---

# `rsigma rule coverage`

{{ added "0.17.0" }}

Map a rule set onto MITRE ATT&CK: export an ATT&CK Navigator layer and report coverage gaps against the Atomic Red Team library, the SigmaHQ baseline heatmap, and a target technique list.

## Synopsis

```text
rsigma rule coverage [OPTIONS] --rules <PATH>
```

## Description

`rule coverage` reads the `attack.*` tags off every detection and correlation rule, builds an inventory of which ATT&CK techniques the rule set covers (scored by the number of rules per technique), and answers the operational question "what does my rule set cover, and where are the holes."

It produces two kinds of output:

- An [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer (format 4.5) written with `--navigator`, scored the same way SigmaHQ scores its published heatmap (`score` = rule count), so a RSigma-generated layer overlays cleanly on the SigmaHQ baseline.
- A coverage report on stdout, optionally cross-referenced three ways:
    - `--atomics` against the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) index: techniques that have atomics but no rule (a detection gap) and rules whose technique has no atomic (a validation gap).
    - `--baseline` against a baseline Navigator layer (the SigmaHQ heatmap by default): baseline techniques you do not cover, and techniques you cover that the baseline does not.
    - `--targets` against a plain-text technique list (an internal threat model): which targeted techniques are uncovered.

The command works entirely from the technique IDs already on the rules. It does not download the full ATT&CK matrix: the Navigator renders that, and each cross-reference supplies its own technique set.

### Sub-technique roll-up

A rule tagged with a sub-technique (`attack.t1059.001`) counts toward its parent technique (`T1059`) for gap analysis, reported as `covered_via_subtechnique`. The reverse does not hold: a rule on the parent `T1059` does not vouch for a specific sub-technique target like `T1059.002`. The exported Navigator layer always keeps exact per-ID scores.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>` | required | Sigma rule file or directory of rules. Repeatable. May also be supplied via `coverage.rules`. |
| `--navigator <FILE>` | unset | Write an ATT&CK Navigator layer (format 4.5) to this file. |
| `--atomics [<PATH_OR_URL>]` | unset | Cross-reference the Atomic Red Team index. A bare `--atomics` uses the upstream `atomics/Indexes/index.yaml`; pass a local `index.yaml`, an atomic-red-team `atomics/` directory, or a URL. May also be supplied via `coverage.atomics`. |
| `--baseline [<PATH_OR_URL>]` | unset | Cross-reference a baseline Navigator layer. A bare `--baseline` uses the SigmaHQ coverage heatmap; pass a local path or URL. May also be supplied via `coverage.baseline`. |
| `--targets <FILE>` | unset | Cross-reference a target technique list (one technique ID per line; `#` comments allowed). May also be supplied via `coverage.targets`. |
| `--fail-on-gaps` | off | Exit `1` when any requested cross-reference reports uncovered techniques. May also be supplied via `coverage.fail_on_gaps`. Same meaning under `--emit atomics-plan`. |
| `--emit <report\|atomics-plan>` | `report` | What to print. `report` is the coverage document (default). `atomics-plan` emits, for each uncovered-but-testable technique, the Atomic Red Team test names, GUIDs, platforms, and ready-to-paste `Invoke-AtomicTest` invocations. Requires `--atomics` (a config-file `coverage.atomics` counts). CLI-only; not a config key. {{ added "0.22.0" }} |
| `--platforms <LIST>` | unset | Comma-separated platform filter (`windows,linux,macos,...`) applied to `--emit atomics-plan`. Keeps tests whose `supported_platforms` intersect the list and drops techniques that then have no tests. Unfiltered output is the default. Ignored with a warning under `--emit report`. CLI-only. {{ added "0.22.0" }} |
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the discovery chain. |
| `--dry-run` | off | Print the effective `coverage` section and exit `0` without running. |

Bare `--atomics` and `--baseline` fetch their default upstream sources over HTTP and cache them for 7 days under the user cache directory (`~/.cache/rsigma/coverage` on Linux), with a stale-cache fallback when offline.

The global `--output-format` applies. For `--emit report` (the default): `table` (the TTY default) renders the human report with gap sections, `json` emits the single report document, and `ndjson`/`csv`/`tsv` emit one row per technique. For `--emit atomics-plan`: `json` emits the plan document, `ndjson`/`csv`/`tsv` emit one row per runnable test (`TECHNIQUE`, `TEST`, `GUID`, `PLATFORMS`, `INVOCATION`), and `table` renders a human summary grouped by technique.

## Targets file

```text
# Internal threat-model: techniques we want covered.
T1059        # covered directly
T1059.001    # a sub-technique target
T1003        # uncovered -> fails under --fail-on-gaps
```

One technique ID per line. Blank lines and `#` comments are ignored; lines that are not valid technique IDs are skipped with a warning.

## Report

The JSON document (`--output-format json`) has a stable shape:

- `summary`: total rules, tagged vs untagged rules, technique and sub-technique counts, and tactic count.
- `techniques[]`: per technique, the ID, the tactics its rules tagged, the rule count, and the rule titles.
- `untagged_rules`: rules carrying no `attack.*` tag (a tagging-hygiene signal).
- `atomics` (when `--atomics` is set): `atomics_without_rule` (detection gaps) and `rules_without_atomic` (validation gaps).
- `baseline` (when `--baseline` is set): `baseline_not_covered` (the baseline covers it, you do not) and `ahead_of_baseline` (you cover it, the baseline does not).
- `targets` (when `--targets` is set): `uncovered` and `covered_via_subtechnique`.

## Atomics plan

{{ added "0.22.0" }}

`--emit atomics-plan` prints a different document. It includes exactly the techniques the report would list as `atomics.atomics_without_rule` (the same sub-technique roll-up: a parent is covered by a sub-technique rule, a sub-technique is not covered by a parent rule). rsigma emits the plan and does not run the tests.

The JSON document (`--emit atomics-plan --output-format json`) has this shape:

- `summary`: `atomics_total`, `uncovered_testable` (the `atomics_without_rule` count), `techniques_in_plan` and `tests_in_plan` after the platform filter, and the `platforms` filter echoed back when set.
- `techniques[]`: one entry per uncovered technique, sorted by id: `technique`, `tactics` (from the index's outer keys; empty when `--atomics` is a directory checkout), `tests[]` (each `name`, `guid` when present, `platforms`), a technique-level `invocation` (`Invoke-AtomicTest T1566.001`), and a per-test `invocation` (`Invoke-AtomicTest T1566.001 -TestGuids <guid>`). A test with no GUID keeps its name and gets the technique-level invocation only; rsigma never fabricates a GUID.

`--platforms windows,linux` filters tests by `supported_platforms` intersection and drops techniques whose test list empties.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. With `--fail-on-gaps`, no requested cross-reference reported uncovered techniques. |
| `1` | `--fail-on-gaps` was set and at least one cross-reference reported uncovered techniques. |
| `2` | The rules path could not be read or parsed. |
| `3` | A cross-reference input could not be fetched or parsed, or an invalid flag was passed. |

## Examples

### Export a Navigator layer

```bash
rsigma rule coverage -r rules/ --navigator coverage.json
```

Open `coverage.json` in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see the heatmap.

### Diff your coverage against the SigmaHQ baseline

```bash
rsigma rule coverage -r rules/ --baseline --output-format json | jq '.baseline'
```

### Find techniques with atomics but no detection rule

```bash
rsigma rule coverage -r rules/ --atomics --output-format json \
    | jq '.atomics.atomics_without_rule'
```

### Emit a runnable Atomic Red Team test plan

```bash
rsigma rule coverage -r rules/ --atomics --emit atomics-plan --output-format tsv \
    | cut -f5 | tail -n +2
```

Each TSV row is one test. Column 5 is the `Invoke-AtomicTest` invocation. Run those in a lab; rsigma does not execute them. `--platforms windows` keeps only tests that list `windows`.

### Gate CI on a target technique list

```bash
rsigma rule coverage -r rules/ --targets threat-model.txt --fail-on-gaps
```

## See also

- [ATT&CK Coverage](../../guide/attack-coverage.md) for the end-to-end workflow.
- [`rule backtest`](backtest.md) for the corpus-replay test harness.
- [`rule scorecard`](scorecard.md) to feed this JSON report (with the backtest report) into per-rule keep/tune/retire verdicts.
- [CI/CD](../../guide/ci-cd.md) for wiring coverage into a pipeline.
- [Configuration](../../reference/configuration.md) for the `coverage` config section.
- [Exit Codes reference](../../reference/exit-codes.md) for the canonical table.
