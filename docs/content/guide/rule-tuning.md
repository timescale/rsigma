# Rule Tuning

`rsigma rule tune` turns analyst-confirmed false positives into a reviewable Sigma filter rule while protecting a required set of known true positives. The command proposes a separate filter artifact; it never rewrites the detection rule and never merges a change.

## Workflow

```bash
# Collect events that fired the same target rule and classify them.
rsigma rule tune \
  -r rules/ \
  --rule 929a690e-bef0-4204-a928-ef5e620d6fcc \
  --fp @false-positives.ndjson \
  --tp @true-positives.ndjson \
  > tuning-filter.yml

# Review the rationale and machine-readable verification.
rsigma rule tune \
  -r rules/ \
  --rule 929a690e-bef0-4204-a928-ef5e620d6fcc \
  --fp @false-positives.ndjson \
  --tp @true-positives.ndjson \
  --expectations expectations.yml \
  --emit report \
  --output-format json

# Confirm the artifact after any manual edits.
rsigma rule lint tuning-filter.yml
rsigma rule backtest -r rules-with-filter/ --corpus regression-events/
```

`--rule` accepts a rule id or an exact title. It is required when the ruleset contains more than one detection rule, except when `--from-dispositions` supplies the evidence: that mode tunes every represented detection rule unless `--rule` narrows it. The true-positive set is mandatory: a suppression proposal without a do-not-break corpus can reduce noise by silently deleting useful coverage, so an empty TP set is an error. `--from-dispositions` fails the same way when a rule has false-positive bundles and no true-positive protection set.

On success, stderr reports both sides of the contract, for example `suppressed 2/2 false positives; protected 1/1 true positives`. If an FP or TP does not fire the unfiltered target, the command exits `2` with a labeling error such as:

```text
error tuning rule: labeled exemplars do not fire the target rule before filtering (false-positive indexes: [], true-positive indexes: [0])
```

Fix the labels or the target selection before asking for a filter.

A verified filter looks like this:

```yaml
title: Tuning filter for Suspicious Backup Tool
id: 31117a32-fe5c-4c4c-b0e7-7c149925c596
description: 'Suppresses 2 observed false-positive exemplars; verified against 1 true-positive exemplars.'
author: 'rsigma rule tune'
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        Image: 'C:\Program Files\Veeam\backup.exe'
        User: svc_backup
    condition: not selection
```

## Closed verification

Tuning runs the target through the real evaluator twice:

1. The target rule is compiled without a filter. Every supplied FP and TP must fire, otherwise the command returns the non-firing exemplar indexes as a labeling error.
2. The target and proposed filter are added to one collection. `Engine::add_collection` applies the filter exactly as production loading does. Every TP must still fire and every covered FP must stop firing.

This catches polarity errors, Sigma wildcard escaping, modifier semantics, pipeline field mappings, filter targeting, and logsource compatibility through the production code path rather than a second approximation.

When `--expectations` is supplied, report mode also lists the target's existing backtest bounds and emits list entries to add under the file's existing `expectations` key. Relative `@path` inputs preserve their directory scope; `--fp-corpus` and `--tp-corpus` provide explicit scopes for absolute or inline inputs. The entries pin the post-filter FP count and require at least the verified TP count, so the tuning change can carry its own regression evidence into CI.

## Why the condition is negated

The Sigma filter parser stores the condition under the `filter:` section, and RSigma ANDs that condition into the target rule exactly as written. There is no implicit negation. A filter intended to suppress `selection` must therefore emit:

```yaml
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User: svc_backup
    condition: not selection
```

Writing `condition: selection` would invert the intent and narrow the target so it fired only on the benign pattern.

## Contrastive field selection

The profiler shares rule drafting's typed values, volatility detection, pattern inference, wildcard escaping, and YAML writer. It ranks fields that are stable across FPs and rare across TPs. Each selection includes stable context from at least two fields by default, even when one field separates the sampled corpora. Any candidate or conjunction that suppresses a TP is rejected.

Exact value sets may contain up to eight values by default because benign service-account or host allowlists commonly exceed the drafting default of four. String values above that limit may still become a readable prefix, suffix, or token form. Regex synthesis is intentionally excluded.

## Disjoint benign patterns

When one conjunction cannot separate the entire FP set, tuning may partition it into supported clusters and emit multiple selections:

```yaml
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User: svc_backup
        Image|startswith: 'C:\Program Files\Veeam\'
    selection_2:
        User: svc_acronis
        Image|startswith: 'D:\Tools\Acronis\'
    condition: not (selection or selection_2)
```

Each emitted selection, including a single-selection proposal, must represent at least two FP exemplars by default, which prevents a unique event from being memorized as a tuning pattern. One filter contains at most five clusters by default so the proposal remains reviewable.

If some FPs do not share a clean pattern with the rest, `--allow-partial` may emit the verified clusters and name the uncovered FP indexes. No option permits suppressing a TP.

## Pipelines and logsource

Pass the same `-p` / `--pipeline` values used by evaluation or deployment. The target rule is transformed before tuning, so emitted field names and the copied logsource match the compiled detection. Copying the target's post-pipeline logsource keeps the filter lint-clean and guarantees `filter_logsource_contains` cannot skip it.

## Human review boundary

Treat the output as a proposed code change with regression evidence. Review whether an attacker could deliberately satisfy the benign pattern, prefer stable identity/context pairs over broad paths or networks, document the operational reason for the exception, and rerun the report against an expanded TP corpus before merging.

## See also

- [`rule tune` reference](../cli/rule/tune.md) for flags and exit codes.
- [Verdict-Driven Corpora](verdict-to-corpus.md) for building FP/TP sets from accepted dispositions.
- [Drafting Rules from Logs](rule-drafting.md) for creating new detection rules from positive exemplars.
- [Triage Feedback Loop](triage-feedback.md) for the analyst dispositions that identify noisy rules.
- [Detection Scorecard](detection-scorecard.md) for per-rule tune recommendations.
