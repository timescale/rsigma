# `rsigma rule tune`

Propose a verified Sigma filter rule from false-positive and true-positive exemplar events.

## Synopsis

```text
rsigma rule tune --rules <PATH> --fp <JSON|@PATH> --tp <JSON|@PATH> [OPTIONS]
rsigma rule tune --rules <PATH> --from-dispositions <SPOOL_DIR> [OPTIONS]
```

## Description

`rule tune` profiles events labeled as false positives against a required set of known true positives and emits a standard Sigma filter rule. The proposal targets one detection rule by id, copies its post-pipeline logsource, and uses `condition: not selection` because the evaluation engine injects a filter condition exactly as written.

The command verifies two invariants before printing anything. First, every supplied FP and TP must fire the unfiltered target rule; non-firing events are labeling errors. Second, after applying the emitted filter through the real `Engine::add_collection` path, no covered FP may fire and every TP must still fire. The command refuses to emit when no clean separator exists.

## Inputs

- `-r, --rules <PATH>`: Sigma rule file or directory.
- `--rule <ID|TITLE>`: target rule id, with exact-title fallback. Required for a ruleset containing more than one detection rule.
- `--fp <JSON|@PATH>`: false-positive events as one inline JSON event or an NDJSON/EVTX file. When omitted, reads NDJSON from stdin. Conflicts with `--from-dispositions`.
- `--tp <JSON|@PATH>`: required true-positive events as one inline JSON event or an NDJSON/EVTX file. Required unless `--from-dispositions` is set. Conflicts with `--from-dispositions`.
- `--from-dispositions <SPOOL_DIR>`: read versioned capture bundles written by `engine daemon`. Derives each rule's FP and TP sets from provenance `matches`. Rejects unknown major versions, unsupported bundle kinds, and malformed documents with the file path. Errors when a rule has FP evidence and no TP protection set. Optional `--rule` narrows the run; otherwise every represented detection rule is tuned.
- `-p, --pipeline <PATH|NAME>`: repeatable processing pipeline applied before profiling and verification (`ecs_windows`, `fibratus_windows`, `sysmon`, or YAML paths). Emitted fields and logsource reflect the transformed rule.

## Tuning controls

- `--max-fields <N>` defaults to `4` and limits each filter conjunction.
- `--min-fields <N>` defaults to `2` and requires each filter conjunction to include stable context from at least two fields.
- `--max-value-cardinality <N>` defaults to `8` and limits exact values in one OR list.
- `--min-cluster-support <N>` defaults to `2`; every emitted selection must cover at least this many FP exemplars, so a single-event proposal is refused as memorization.
- `--max-clusters <N>` defaults to `5` and limits selections in one filter.
- `--allow-partial` permits a proposal that covers only cleanly separable FP clusters while still suppressing no TP. The report names every uncovered FP index.
- `--expectations <PATH>` validates an existing `rule backtest` expectations file and adds before/after fire counts plus list entries to insert under its existing `expectations` key.
- `--fp-corpus <RELATIVE_PATH>` and `--tp-corpus <RELATIVE_PATH>` override the generated backtest corpus scopes. Relative `@path` inputs preserve their directory scope automatically; absolute and inline inputs use stable fallback names unless overridden.
- `--emit yaml|report` defaults to `yaml`. Report mode follows the global output format.

## Example

```bash
rsigma rule tune -r rules/ --rule 929a690e-bef0-4204-a928-ef5e620d6fcc --fp @false-positives.ndjson --tp @true-positives.ndjson > tuning-filter.yml
rsigma rule lint tuning-filter.yml
```

```yaml
title: Tuning filter for Suspicious Backup Tool
id: 3f7b1c2e-9a44-4d1e-8f61-2b0c5d9e7a10
description: 'Suppresses 2 observed false-positive exemplars; verified against 4 true-positive exemplars.'
author: 'rsigma rule tune'
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User: svc_backup
        Image|startswith: 'C:\Program Files\Veeam\'
    condition: not selection
```

### Carry regression evidence into a rule change

```bash
rsigma rule tune -r rules/ --rule 929a690e-bef0-4204-a928-ef5e620d6fcc --fp @false-positives.ndjson --tp @true-positives.ndjson --expectations expectations.yml --emit report --output-format json
```

The `expectation_diff` object records target fires over each supplied corpus before and after filtering, lists existing bounds for the target, and emits list entries with `exactly: 0` for a fully covered FP corpus plus `at_least: <TP count>` for the protected corpus. Insert the entries under the existing top-level `expectations` key.

## Exit codes

- `0`: a verified filter or report was emitted.
- `2`: rules/events could not be read, labels did not fire before filtering, the target was ambiguous, a pipeline failed, or no clean separator existed.
- `3`: the expectations file could not be loaded or resolved.

## See also

- [Rule Tuning](../../guide/rule-tuning.md) for the workflow and safety model.
- [Verdict-Driven Corpora](../../guide/verdict-to-corpus.md) for the spool layout and the exact backtest command.
- [`rule draft`](draft.md) for authoring a new detection from positive exemplars.
- [`rule backtest`](backtest.md) for corpus-level regression expectations.
