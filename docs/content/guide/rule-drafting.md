# Drafting Rules from Logs

`rsigma rule draft` turns exemplar events into a complete draft Sigma rule. You supply the interesting events (from an incident, a red-team exercise, or a threat report's sample telemetry) and optionally a baseline corpus of normal traffic; the tool classifies fields and values, picks the discriminative ones, and emits standard Sigma YAML you review, edit, and commit. It proposes, you decide: the output is a starting point with explicit `TODO` placeholders, not a finished detection.

## Workflow

```bash
# 1. Collect exemplars (here: the malicious process creations from an incident)
jq -c 'select(.CommandLine | test("whoami"))' incident.json > exemplars.ndjson

# 2a. Draft from exemplars alone
rsigma rule draft -e @exemplars.ndjson > draft.yml

# 2b. Or contrast against a day of normal traffic (preferred when you have it)
rsigma rule draft -e @exemplars.ndjson --baseline @normal-day.ndjson > draft.yml

# 3. Edit the metadata (title, description, tags, level), then confirm
rsigma rule lint draft.yml
rsigma engine eval --rules draft.yml -e @more-telemetry.ndjson
```

Before printing the YAML, the command verifies the draft through the real evaluation engine: every exemplar must match. Without a baseline, stderr ends with a line like `matches 3/3 exemplars`. With a baseline, it also reports the false-positive estimate, for example `matches 3/3 exemplars, 0/86400 baseline events (0.0%)`. A draft that cannot honestly cover the exemplars is an error, not a weaker rule.

You can also draft from a Windows Event Log file (`-e @Security.evtx`) when the `evtx` feature is compiled in; the prebuilt binaries include it.

### Without a baseline

Exemplars alone favor constants shared by every event (`Channel`, `EventID`) plus patterned markers (`CommandLine`, `Image`):

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

### With a baseline

The same exemplars against normal Sysmon process-creation traffic demote fields that are also common in the baseline (`EventID: 1` drops out) and promote rare patterned fields (`User|startswith: 'CORP\\'`). The title follows the strongest marker:

```yaml
title: 'Draft: whoami (CommandLine)'
id: 7ff5f141-2430-4ae0-a43e-6cb0fe97a093
status: experimental
description: 'TODO: describe what this rule detects and why it matters.'
author: 'TODO: your name'
date: 2026-08-02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|startswith: whoami
        Image|endswith: '\whoami.exe'
        User|startswith: 'CORP\\'
        Channel: 'Microsoft-Windows-Sysmon/Operational'
    condition: selection
falsepositives:
    - 'TODO: list known benign triggers.'
level: medium
```

Metadata placeholders stay yours to fill in either case. Use `--include-field` / `--exclude-field` when the scorer's pick is close but not quite right for your environment.

## How fields are chosen

Every leaf field across the exemplars is profiled and classified:

| Class | Meaning | Emitted as |
|-------|---------|------------|
| constant | The same value in every exemplar | Plain equals (`EventID: 1`) |
| enumerable | A small distinct value set | OR value list |
| patterned | Differing values sharing a prefix, suffix, or token | `\|startswith`, `\|endswith`, `\|contains` (or `\|contains\|all`) |
| volatile | No usable structure | Never selected |

Volatile fields are dropped up front: timestamp-shaped names and values (`UtcTime`, `@timestamp`, RFC3339 strings, epoch numbers), UUID/GUID shapes (`ProcessGuid`), per-event counters (`ProcessId`, `ThreadId`, `LogonId`, record and sequence numbers), and long random-looking values that are unique per exemplar (hashes, tokens).

The survivors are scored. With a baseline, the score is exemplar stability times baseline rarity, so a `field: value` pair present in every exemplar and absent from normal traffic ranks first, and a field that is ubiquitous in the baseline (`proto: tcp`) sinks even when constant in the exemplars. Without a baseline, constant beats enumerable beats patterned, and envelope fields (`hostname`, `severity`) are demoted. The top fields (default 4, `--max-fields`) form the selection.

Two guards keep pattern inference honest: shared tokens shorter than 4 characters are never used for `|contains`, and with a baseline, tokens matching more than 5% of baseline values for that field are rejected as too generic (`powershell` will not become the detection just because every exemplar contains it). Literal `*` and `?` in observed values are escaped, so a logged `SELECT * FROM` cannot silently become a wildcard match.

### Pin or drop fields

Force a field into the selection with `--include-field`, or ban one with `--exclude-field` (both are repeatable). Use these when the scorer is right on average but wrong for your case: keep a rare but critical marker, or drop a noisy host-specific key such as `Event.System.Computer` when drafting from EVTX.

### Inspect the analysis

By default stderr carries a field report (class, chosen modifier, baseline prevalence) alongside the YAML on stdout. For a machine-readable view of the same analysis, use `--emit report` and the global output format:

```bash
rsigma rule draft -e @exemplars.ndjson --baseline @normal-day.ndjson --emit report --output-format json | jq '.fields'
```

## Variant grouping

When exemplars fall into distinct value groups over the same fields, the draft splits into one selection per group:

```yaml
detection:
    selection_vssadmin:
        Image|endswith: '\vssadmin.exe'
        CommandLine: 'vssadmin delete shadows'
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine: 'wmic shadowcopy delete'
    condition: 1 of selection_*
```

The split only happens when it is earned: each group needs at least two exemplars, and the split must make some multi-valued field single-valued within every group (otherwise a flat OR list is emitted instead, which matches the same events without the cross-field precision).

## Logsource inference

The exemplars are classified with the built-in schema classifier ([schema routing](schema-routing.md) uses the same signatures). Sysmon exemplars yield `product: windows`, and a shared EventID maps to its Sigma category (EventID 1 gives `category: process_creation`); rendered Windows Event Log yields `product: windows`; ECS platform specializations yield their platform. Anything else gets a `product: todo` placeholder plus a warning. `--logsource-category` / `--logsource-product` / `--logsource-service` override any inference per dimension.

## The draft is schema-native

The rule uses the exemplars' field names as they appear in the events. ECS exemplars produce `process.command_line`, Sysmon exemplars produce `CommandLine`. Evaluate the draft against the same telemetry shape it was mined from, without a mapping pipeline; if you need the generic SigmaHQ field vocabulary, rename the fields as part of your review. Pipelines are out of scope at draft time: map or rename after you accept the draft.

## Drafting correlations

Use `--groups` when each positive example is a timed sequence rather than one event. An envelope NDJSON file identifies every event's group and supplies exactly one RFC3339 `timestamp` or Sigma `offset`:

```json
{"group":"g1","offset":"0s","event":{"eventType":"factor.reset","user":"alice"}}
{"group":"g1","offset":"4m","event":{"eventType":"session.start","user":"alice","newAsn":true}}
```

A directory is also accepted. Each filename stem becomes the group id, and each line contains the time key plus `event`; an embedded `group` key is an error in directory form. The command requires at least three groups and two events per group by default. Mixed time modes, duplicate times, repeated recurring slots, and malformed envelopes are errors with group and source-line context.

Recurring slots are inferred from event field-key shapes. Clusters missing from any positive group are treated as incidental noise and reported. Each retained slot must appear exactly once per group. Slot rules are drafted against their assigned positives while sibling slots and `--baseline` provide contrast. The selected group-by fields are always excluded from slot predicates.

Pass repeatable `--group-by` fields for an explicit entity, especially a composite key. Without it, one field must be stable inside every group and distinct across groups. The command reports zero or multiple candidates as an ambiguity instead of choosing one.

The default `--correlation-type auto` emits `temporal_ordered` only when every group agrees on slot order. An inversion downgrades to `temporal` with a warning. Use `--correlation-type temporal_ordered` to make an inversion an error, or `temporal` to request unordered behavior.

The timespan starts from the maximum observed first-to-last retained-slot span, not the median. The maximum is multiplied by `--window-margin` and rounded up. The median-span group is used only as the embedded `rsigma.exemplars` sequence.

Verification uses a fresh correlation engine for every positive and negative group. Every assigned event must match only its slot rule. A positive correlation cannot fire before all slots and must fire by the end. Any `--negative` group that fires is a terminal error. Clean up heterogeneous exemplars, add a representative baseline, or edit the emitted rules manually when slot rules collide.

```bash
rsigma rule draft --groups @observed.ndjson --negative @benign.ndjson > correlation.yml
rsigma rule test --rules correlation.yml
```

The emitted multi-document YAML contains named slot detections, the temporal correlation, and a representative positive sequence under `rsigma.exemplars`. This makes the draft directly testable after metadata edits.

## What it will not do

- No aggregate correlation synthesis (`event_count`, `value_count`, or numeric aggregates) and no filter rules.
- No repeated retained stage within one group.
- No ATT&CK tags or severity judgment; the metadata placeholders are yours to fill.
- No regex synthesis; patterns stay within prefix/suffix/token modifiers a reviewer can read at a glance.
- No online drafting from the daemon: the daemon never retains event values, and presence-only rules are not useful detections. Draft from captured NDJSON or EVTX instead.

## See also

- [Rule Tuning](rule-tuning.md) to turn classified false positives into a verified filter for an existing rule.
- [`rule draft` reference](../cli/rule/draft.md) for every flag and exit code.
- [Evaluating Rules](evaluating-rules.md) to replay the draft against telemetry.
- [Linting Rules](linting-rules.md) for the checks the draft is held to.
- [Schema Routing](schema-routing.md) for the classifier behind the logsource inference.
