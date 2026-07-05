# Drafting Rules from Logs

`rsigma rule draft` turns exemplar events into a complete draft Sigma rule. You supply the interesting events (from an incident, a red-team exercise, or a threat report's sample telemetry) and optionally a baseline corpus of normal traffic; the tool classifies fields and values, picks the discriminative ones, and emits standard Sigma YAML you review, edit, and commit. It proposes, you decide: the output is a starting point with explicit `TODO` placeholders, not a finished detection.

## Workflow

```bash
# 1. Collect exemplars (here: the malicious process creations from an incident)
jq -c 'select(.CommandLine | test("whoami"))' incident.json > exemplars.ndjson

# 2. Draft against a baseline of normal traffic
rsigma rule draft -e @exemplars.ndjson --baseline @normal-day.ndjson > draft.yml

# 3. Edit the metadata (title, description, tags, level), then confirm
rsigma rule lint draft.yml
rsigma engine eval --rules draft.yml -e @more-telemetry.ndjson
```

The command verifies the draft before printing it: the YAML is parsed and compiled through the real evaluation engine, every exemplar must match, and the baseline hit count is reported as the estimated false-positive rate. A draft that cannot honestly cover the exemplars is an error, not a weaker rule.

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

The exemplars are classified with the built-in schema classifier ([schema routing](schema-routing.md) uses the same signatures). Sysmon exemplars yield `product: windows`, and a shared EventID maps to its Sigma category (EventID 1 gives `category: process_creation`); rendered Windows Event Log yields `product: windows`; ECS platform specializations yield their platform. Anything else gets a `product: todo` placeholder plus a warning. `--logsource-category/--logsource-product/--logsource-service` override any inference per dimension.

## The draft is schema-native

The rule uses the exemplars' field names as they appear in the events. ECS exemplars produce `process.command_line`, Sysmon exemplars produce `CommandLine`. Evaluate the draft against the same telemetry shape it was mined from, without a mapping pipeline; if you need the generic SigmaHQ field vocabulary, rename the fields as part of your review.

## What it will not do

- No correlation or filter rules; detection rules only.
- No ATT&CK tags or severity judgment; the metadata placeholders are yours to fill.
- No regex synthesis; patterns stay within prefix/suffix/token modifiers a reviewer can read at a glance.
- No online drafting from the daemon: the daemon never retains event values, and presence-only rules are not useful detections. Draft from captured NDJSON or EVTX instead.

## See also

- [`rule draft` reference](../cli/rule/draft.md) for every flag and exit code.
- [Evaluating Rules](evaluating-rules.md) to replay the draft against telemetry.
- [Linting Rules](linting-rules.md) for the checks the draft is held to.
- [Schema Routing](schema-routing.md) for the classifier behind the logsource inference.
