# `rsigma rule draft`

Draft a Sigma detection rule or temporal correlation from exemplar events, optionally contrasted against a baseline corpus.

## Synopsis

```text
rsigma rule draft [OPTIONS]
```

## Description

Feed the interesting events (the malicious or noteworthy ones) and get back a complete paste-ready draft rule. The command profiles every field across the exemplars, drops volatile fields (timestamps, GUIDs, process/thread ids, high-entropy unique values), scores the survivors by value stability across exemplars times rarity in the `--baseline` corpus, infers a value form and a small modifier vocabulary per field (plain equals, an OR value list, `|endswith`/`|startswith` from a shared path tail or prefix, `|contains` from shared tokens), assembles a minimal selection, and infers the `logsource` by classifying the exemplars with the built-in schema classifier (a shared Sysmon EventID maps to its Sigma category, so EventID 1 exemplars yield `category: process_creation`).

The draft is verified before it is printed: the emitted YAML is parsed and compiled through the real evaluation engine, and it must match every exemplar (fields that break the match are dropped, bounded by a two-field floor; below the floor the command errors instead of emitting an over-broad rule). With a baseline, the draft is also evaluated against it and the hit count is reported as the estimated false-positive rate.

Values containing literal `*` or `?` are escaped so an observed wildcard character never silently broadens the match. When exemplars fall into distinct value groups on the same fields (for example `vssadmin` and `wmic` variants of the same technique), the draft splits into `selection_<name>` blocks combined with `condition: 1 of selection_*`.

Two things stay yours: the metadata (title, description, tags, level are placeholders to edit) and the field names. The draft uses the exemplars' native field names, so evaluate it without a mapping pipeline; ECS exemplars produce a rule over `process.command_line`, not `CommandLine`.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --event <EVENT>` | stdin | Exemplars: a single event as a JSON string, or `@path` to an NDJSON file (or `.evtx` in builds with the `evtx` feature). If omitted, reads NDJSON from stdin. |
| `--groups <@PATH>` | unset | Grouped, timed exemplars from one envelope NDJSON file or a directory containing one NDJSON file per group. |
| `--negative <@PATH>` | unset | Grouped examples that the drafted correlation must not match. Requires `--groups`. |
| `--group-by <FIELD>` | inferred | Correlation entity field. Repeatable for an explicit composite key. |
| `--correlation-type <auto\|temporal\|temporal_ordered>` | `auto` | Infer consistent ordering, force unordered temporal behavior, or require consistent ordering. |
| `--min-groups <N>` | `3` | Minimum positive groups required for correlation drafting. |
| `--window-margin <F>` | `1.5` | Multiplier applied to the maximum observed positive-group span before rounding up. |
| `--baseline <@PATH>` | unset | Baseline corpus of normal traffic (NDJSON or `.evtx`). Used for contrastive field scoring and the final false-positive estimate. |
| `--max-fields <N>` | `4` | Maximum fields in the drafted selection. |
| `--min-prevalence <F>` | `1.0` | Fraction of exemplars a field must appear in to be a candidate. |
| `--include-field <FIELD>` | unset | Force this field into the selection. Repeatable. |
| `--exclude-field <FIELD>` | unset | Never consider this field. Repeatable. |
| `--logsource-category <C>` | inferred | Logsource category override. |
| `--logsource-product <P>` | inferred | Logsource product override. |
| `--logsource-service <S>` | inferred | Logsource service override. |
| `--title <TITLE>` | derived | Rule title (derived from the dominant marker when omitted). |
| `--skip-baseline-eval` | off | Keep the baseline for scoring but skip the final baseline evaluation pass. |
| `--emit <yaml\|report>` | `yaml` | `yaml` prints only the paste-ready rule (field report on stderr unless `--quiet`); `report` prints the full analysis in the global output format with the rule embedded. |

## Examples

### Draft from captured incident events against a day of normal traffic

```bash
rsigma rule draft -e @incident.ndjson --baseline @normal-day.ndjson
```

```yaml
title: 'Draft: Microsoft-Windows-Sysmon/Operational (Channel)'
id: 3e95027f-f04b-4ed1-ba88-60118ead5b6d
status: experimental
description: 'TODO: describe what this rule detects and why it matters.'
author: 'TODO: your name'
date: 2026-07-03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Channel: 'Microsoft-Windows-Sysmon/Operational'
        EventID: 1
        CommandLine|startswith: whoami
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - 'TODO: list known benign triggers.'
level: medium
```

The stderr report shows each field's stability class, chosen modifier, and baseline prevalence, plus the verification line (`matches 3/3 exemplars, 0/86400 baseline events (0.0%)`).

### Draft straight from a Windows event log

```bash
rsigma rule draft -e @security.evtx --exclude-field 'Event.System.Computer'
```

Requires a build with the `evtx` feature (the prebuilt binaries include it).

### Inspect the full analysis instead of the rule

```bash
rsigma rule draft -e @incident.ndjson --emit report --output-format json | jq '.fields'
```

### Confirm the draft before committing

```bash
rsigma rule draft -e @incident.ndjson > draft.yml
rsigma rule lint draft.yml
rsigma engine eval --rules draft.yml -e @incident.ndjson
```

The command already runs this loop internally (the draft is guaranteed to parse, lint findings surface as warnings, and every exemplar matches), but re-running it after your metadata edits catches typos.

### Draft a temporal correlation

Envelope NDJSON carries a group id, exactly one time key, and an event:

```json
{"group":"incident-1","offset":"0s","event":{"eventType":"factor.reset","user":"alice"}}
{"group":"incident-1","offset":"4m","event":{"eventType":"session.start","user":"alice","newAsn":true}}
```

Provide at least three observed groups by default:

```bash
rsigma rule draft --groups @observed.ndjson --negative @benign.ndjson > correlation.yml
rsigma rule test --rules correlation.yml
```

Absolute RFC3339 `timestamp` values can replace offsets, but one group cannot mix the two modes. Directory input uses each filename stem as the group id, so each line contains only `timestamp`/`offset` and `event`.

The command clusters recurring event key shapes into slots, drops incidental clusters missing from any positive group, and rejects repeated retained slots. `auto` emits `temporal_ordered` only when every group has the same slot order. Otherwise it emits `temporal` and reports the disagreeing groups. A forced `temporal_ordered` request errors on an inversion.

The window is the maximum positive first-to-last retained-slot span multiplied by `--window-margin`, rounded up to a human-readable duration. Each slot rule is contrasted against sibling slots and the optional baseline. Grouping fields are excluded from slot predicates.

Without `--group-by`, exactly one field must be present and stable within every positive group and distinct across groups. Zero or multiple candidates return an ambiguity error. Composite keys always require repeated `--group-by`.

Each group is verified in a fresh correlation engine. Positive groups must fire only after all slots are consumed, and negative groups must never fire. The correlation document embeds a median-span positive group under `rsigma.exemplars`, so `rule test` replays the draft directly.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | A verified draft was emitted. |
| `2` | Exemplars could not be read, no rule could honestly cover them, grouped input was invalid, entity/slot inference was ambiguous, or isolated verification failed. |
| `3` | A `--baseline` value without the `@path` prefix. |

## See also

- [Drafting Rules from Logs](../../guide/rule-drafting.md) for the full workflow and heuristics.
- [`rule lint`](lint.md) to re-check the draft after editing the metadata.
- [`engine eval`](../engine/eval.md) to replay the draft against more telemetry.
- [`engine discover-schemas`](../engine/discover-schemas.md) for the schema-signature sibling of this command.
