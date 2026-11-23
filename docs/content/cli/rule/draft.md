---
description: "Reference for rsigma rule draft: generate a draft Sigma detection rule or temporal correlation from exemplar events, or from a STIX indicator bundle."
---

# `rsigma rule draft`

{{ added "0.19.0" }}

Draft a Sigma detection rule or temporal correlation from exemplar events, optionally contrasted against a baseline corpus. With the `stix-draft` feature, the same command also drafts rules from a STIX 2.1 bundle.

## Synopsis

```text
rsigma rule draft [OPTIONS]
```

## Description

Feed the interesting events (the malicious or noteworthy ones) and get back a complete paste-ready draft rule. The command profiles every field across the exemplars, drops volatile fields (timestamps, GUIDs, process/thread ids, high-entropy unique values), scores the survivors by value stability across exemplars times rarity in the `--baseline` corpus, infers a value form and a small modifier vocabulary per field (plain equals, an OR value list, `|endswith`/`|startswith` from a shared path tail or prefix, `|contains` from shared tokens), assembles a minimal selection, and infers the `logsource` by classifying the exemplars with the built-in schema classifier (a shared Sysmon EventID maps to its Sigma category, so EventID 1 exemplars yield `category: process_creation`).

The draft is verified before it is printed: the emitted YAML is parsed and compiled through the real evaluation engine, and it must match every exemplar (fields that break the match are dropped, bounded by a two-field floor; below the floor the command errors instead of emitting an over-broad rule). With a baseline, the draft is also evaluated against it and the hit count is reported as the estimated false-positive rate.

Values containing literal `*` or `?` are escaped so an observed wildcard character never silently broadens the match. When exemplars fall into distinct value groups on the same fields (for example `vssadmin` and `wmic` variants of the same technique), the draft splits into `selection_<name>` blocks combined with `condition: 1 of selection_*`.

For a draft from events, two things stay yours: the metadata (title, description, tags, and level are placeholders to edit) and the field names. The draft uses the exemplars' native field names, so evaluate it without a mapping pipeline; ECS exemplars produce a rule over `process.command_line`, not `CommandLine`. A draft from a STIX indicator fills the title, description, references, tags, and level from the indicator. `author` and `falsepositives` stay placeholders in both cases.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --event <EVENT>` | stdin | Exemplars: a single event as a JSON string, or `@path` to an NDJSON file (or `.evtx` in builds with the `evtx` feature). If omitted, reads NDJSON from stdin. |
| `--groups <@PATH>` | unset | Grouped, timed exemplars from one envelope NDJSON file or a directory containing one NDJSON file per group. {{ added "0.22.0" }} |
| `--negative <@PATH>` | unset | Grouped examples that the drafted correlation must not match. Requires `--groups`. {{ added "0.22.0" }} |
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
| `--title <TITLE>` | derived | Rule title (derived from the dominant marker when omitted). For a STIX draft, this title is used on every emitted rule. |
| `--date <YYYY-MM-DD>` | today (UTC) | Calendar date written into the draft. Applies to event drafts, correlation drafts, and `--from-stix`. Omit it and the date is today in UTC, so a file you save today will differ tomorrow. Pass it when the YAML must stay byte-stable. A value that is not `YYYY-MM-DD` exits 3. {{ added "0.28.0" }} |
| `--from-stix <PATH>` | unset | STIX 2.1 bundle, or one indicator object. `-` reads stdin. Requires the `stix-draft` feature. Without that feature the flag is absent from `--help` and passing it fails. {{ added "0.28.0" }} |
| `--observable <KIND>` | every mapped kind | Observable kind to draft. Repeatable. Requires `--from-stix`. Without that flag the command exits 2. An unknown key exits 3 and the message lists the valid keys. {{ added "0.28.0" }} |
| `--include-expired` | off | Keep indicators whose `valid_until` has passed and indicators whose `valid_from` is still ahead. Revoked indicators are still skipped. Requires `--from-stix`. Without that flag the command exits 2. {{ added "0.28.0" }} |
| `--skip-baseline-eval` | off | Keep the baseline for scoring but skip the final baseline evaluation pass. |
| `--emit <yaml\|report>` | `yaml` | `yaml` prints only the paste-ready rule (field report on stderr unless `--quiet`). For an event draft, `report` prints the full analysis in the global output format with the rule embedded. For `--from-stix`, `report` prints the JSON document below. A non-JSON `--output-format` warns and the JSON is still printed. |

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

{{ added "0.22.0" }}

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

## Draft from a STIX indicator

{{ added "0.28.0" }}

`--from-stix` turns STIX 2.1 indicators into Sigma rules. It reads a bundle, or one indicator object, keeps the indicators that are in force, and prints one rule for each logsource those indicators map to. Each rule is parsed and compiled before it is printed. This path does not profile events and it does not read a baseline.

### Build

The flag exists only in a build with the `stix-draft` feature. A default `cargo build` or `cargo install rsigma` does not include it: `rsigma rule draft --help` will not mention `--from-stix`, and passing the flag fails. Check a binary with `rsigma --features`.

```bash
cargo build -p rsigma --features stix-draft
```

Release archives and the Docker image are built with `--all-features`, so they include the flag. The feature pulls `rstix` into the CLI only. `rsigma-eval` does not depend on `rstix`. The detection engine stays free of the STIX parser. The CLI extracts the values and calls `draft_rule_from_values`.

### Input

The path is a file, or `-` to read stdin.

- A JSON object with `"type": "bundle"` is parsed as a bundle. Objects that are not indicators are ignored.
- A JSON object with `"type": "indicator"` is wrapped into a one-object bundle and then parsed the same way.
- Any other top-level `type`, invalid JSON, an unreadable path, or a bundle the STIX parser rejects exits 2. The message names the failure. One bad indicator fails the whole file. The command does not skip a single object that the parser itself rejected. Two objects with the same id are that kind of failure: the parser reports `duplicate bundle object id` and the command exits 2. A bundle cannot carry an older copy and a newer revoked copy of one indicator.
- Custom object types are accepted and ignored. A bundle is limited to 100,000 objects.

`--from-stix` is the whole input. It cannot be combined with the event-draft flags. If one of these is set, the command exits 3 and names the flag:

| Flag | Rejected when |
|------|----------------|
| `--event`, `--groups`, `--negative`, `--baseline`, `--group-by` | the flag is present |
| `--include-field`, `--exclude-field`, `--skip-baseline-eval` | the flag is present |
| `--correlation-type` | the value is not `auto` |
| `--min-groups` | the value is not `3` |
| `--window-margin` | the value is not `1.5` |
| `--max-fields` | the value is not `4` |
| `--min-prevalence` | the value is not `1.0` |

`--title`, `--date`, `--logsource-category`, `--logsource-product`, `--logsource-service`, `--observable`, `--include-expired`, and `--emit` do apply.

### Which indicators are kept

Each indicator id appears once. A repeated id never reaches these checks. It fails the parse, as described above. The checks below run on the objects the parser accepted. The clock is the time the command runs.

| Condition | Result | Reason in the report |
|-----------|--------|----------------------|
| `revoked` is true | skipped, including when `--include-expired` is set | `revoked` |
| `valid_from` is after the command's clock, and `--include-expired` is off | skipped | `not_yet_valid` |
| `valid_until` is set and is at or before the command's clock, and `--include-expired` is off | skipped | `expired` |
| `pattern_type` is not `stix` | skipped | `pattern_type` |
| The pattern is not a simple comparison | skipped | `unsupported_pattern` |
| Every observable is an unmapped kind | skipped | `unmapped_observable` |
| `--observable` removed every mapped kind | skipped | `filtered_observable` |

A simple comparison is one observation, or several observations joined only with `OR`, where every comparison is `=` or `IN` of a string or an integer. `AND`, `NOT`, `FOLLOWEDBY`, qualifiers, and any other operator are `unsupported_pattern`.

An unset `valid_until` does not expire. There is no minimum confidence. A low or missing confidence is still drafted. It only changes `level`.

An indicator that has at least one mapped kind is used. Unmapped kinds on that same indicator are left out of the rule, and the indicator is not listed under `skipped`. `--observable` with no value means every mapped kind. Repeat the flag to keep a subset (`--observable domain --observable ipv4`). An unknown key exits 3. The message lists the valid keys: `asn`, `domain`, `email`, `file_name`, `ipv4`, `ipv4_cidr`, `ipv6`, `ipv6_cidr`, `mac`, `md5`, `mutex`, `registry_key`, `sha1`, `sha256`, `sha512`, `url`.

### What each rule contains

One document is emitted per mapped logsource. Several documents are joined with `---`. `--logsource-category`, `--logsource-product`, and `--logsource-service` are written onto every document. The split follows the mapped category, so two documents stay two documents when an override makes the printed categories the same. The rule `id` is computed from the mapped category, not from the override.

`ipv4` and `ipv6` are separate selections on `DestinationIp`. A CIDR value is its own selection with `|cidr`. The four hash kinds share one `Hashes|contains` list. Values in a selection are deduplicated and sorted. Domain names and hashes are lowercased. An IPv6 address is written in RFC 5952 form, the form Sysmon records, so `2001:0DB8:0000:0000:0000:0000:0000:0001` becomes `2001:db8::1`. A value that is not an IPv6 address is kept as written. An `ipv6_cidr` value is kept as written, because `|cidr` compares addresses numerically.

| Observable | Logsource category | Detection |
|------------|--------------------|-----------|
| `ipv4` | `network_connection` | `DestinationIp`, selection `selection_destination_ip` |
| `ipv6` | `network_connection` | `DestinationIp`, selection `selection_destination_ipv6` |
| `ipv4_cidr` | `network_connection` | `DestinationIp\|cidr`, selection `selection_destination_ip_cidr` |
| `ipv6_cidr` | `network_connection` | `DestinationIp\|cidr`, selection `selection_destination_ipv6_cidr` |
| `domain` | `dns_query` | `QueryName` |
| `url` | `proxy` | `c-uri` |
| `md5`, `sha1`, `sha256`, `sha512` | `process_creation` | one `Hashes\|contains` selection, values `MD5=<hex>`, `SHA1=<hex>`, `SHA256=<hex>`, `SHA512=<hex>` |
| `file_name` | `file_event` | `TargetFilename\|endswith`. Each value gains one leading `\`, so `evil.exe` is matched as `\evil.exe` |
| `registry_key` | `registry_set` | `TargetObject\|contains`. The hive is removed: `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_USERS`, `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_CONFIG`, and the short forms `HKLM`, `HKCU`, `HKU`, `HKCR`, `HKCC`. The comparison ignores case. The remaining key is wrapped in backslashes, so `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` is `\Software\Microsoft\Windows\CurrentVersion\Run\`. That matches a Sysmon `TargetObject`, which uses the short hive and appends the value name (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil`), and a current-user key under `HKU\<SID>\`. A key that does not start with one of those hives keeps its whole path, wrapped the same way. A hive with no key path is not drafted. |
| `email`, `mutex`, `mac`, `asn` | none | not drafted |

`status` is `experimental`. `author` stays `TODO: your name`. `falsepositives` stays `TODO: list known benign triggers.` Edit both before you commit the rule. Literal `*`, `?`, and a backslash that would become a wildcard are escaped in detection values.

| Field | How it is chosen |
|-------|------------------|
| Title | `--title` on every document. Otherwise the indicator `name` when exactly one indicator contributed to that document and the name is not blank. Otherwise `Indicators: <category> (<n>)`. |
| Description | The contributing indicators in id order. A name and a description become `<name>: <description>`. A name alone is the name. Blank text on every indicator keeps the description `TODO` placeholder. The text is cut at 1,000 characters, on a character boundary. Newlines become spaces. |
| References | The `url` of each external reference on a contributing indicator. Duplicates are dropped. The list is sorted. |
| Tags | `attack.<phase>` for each kill chain whose `kill_chain_name` is `mitre-attack`. Hyphens in the phase become underscores, and the phase is lowercased. Other kill chains are ignored. Duplicates are dropped. The list is sorted. |
| Level | `high` only when every contributing indicator has a confidence of at least 85. One missing confidence, or one value below 85, makes the level `medium`. |
| `id` | UUID v5 of a fixed namespace, the mapped logsource category, and the contributing indicator ids in sorted order. The same indicators and the same category always produce the same id. |
| `date` | `--date` when you pass it. Otherwise today in UTC. |

### Report

`--emit yaml` is the default. It prints the rule documents on stdout and nothing else about the indicators it skipped. When the file parsed and every indicator was skipped, stdout is empty, stderr says `no draftable indicators`, and the exit code is 1.

`--emit report` prints one JSON object. This shape does not follow `--output-format`. If you set a format other than JSON, the command warns and still prints this object.

```json
{
  "rules": ["title: Beacon address\nstatus: experimental\n..."],
  "used": [
    {"id": "indicator--00000000-0000-4000-8000-000000000001", "kinds": ["ipv4"], "values": ["198.51.100.7"]}
  ],
  "skipped": [
    {"id": "indicator--00000000-0000-4000-8000-000000000007", "reason": "revoked"}
  ]
}
```

`rules` is the same YAML the default mode would print, one string per document. `used` is one row per indicator that contributed, with the observable kinds and the original values (a hash is the hex, not the `MD5=` form written into the rule). `skipped` is one row per indicator that was left out, with the reason from the table above. Both lists are ordered by indicator id. On a file that drafts nothing, the JSON is still printed and the exit code is 1, so the reasons are visible.

| Exit code | When |
|-----------|------|
| 0 | At least one rule was emitted. |
| 1 | The file parsed, and nothing in it was draftable. |
| 2 | The path could not be read, the JSON is invalid, the top-level type is not a bundle or an indicator, or the STIX parser rejected the bundle. `--observable` or `--include-expired` without `--from-stix` is also exit 2. |
| 3 | `--from-stix` was combined with an event-draft flag, `--date` is not `YYYY-MM-DD`, or `--observable` named a key that is not in the list above. |

### Examples

Draft every mapped kind. `--date` pins the `date` field so the file does not change the next day. The `id` is already stable.

```bash
rsigma rule draft --from-stix indicators.json --date 2026-06-01 > draft.yml
rsigma rule lint draft.yml
```

The same indicator object on stdin:

```bash
rsigma rule draft --from-stix - --date 2026-06-01 < indicators.json
```

Only domains, including from an indicator that also carries an address:

```bash
rsigma rule draft --from-stix indicators.json --observable domain --date 2026-06-01
```

Keep indicators that have expired or are not yet valid. A revoked indicator is still omitted:

```bash
rsigma rule draft --from-stix indicators.json --include-expired --emit report --date 2026-06-01
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | A verified draft was emitted. |
| `1` | A STIX bundle parsed and nothing in it was draftable. |
| `2` | Exemplars or STIX input could not be read or parsed, no rule could honestly cover the exemplars, grouped input was invalid, entity/slot inference was ambiguous, or isolated verification failed. `--observable` or `--include-expired` without `--from-stix` is also exit 2. |
| `3` | A `--baseline` value without the `@path` prefix, `--from-stix` combined with an event-draft flag, an unknown `--observable` key, or a `--date` that is not `YYYY-MM-DD`. |

## See also

- [Drafting Rules from Logs](../../guide/rule-drafting.md) for the full workflow and heuristics.
- [From a TI report to a rule](../../guide/threat-intel-watchlists.md#from-a-ti-report-to-a-rule) for drafting from a STIX bundle.
- [`rule lint`](lint.md) to re-check the draft after editing the metadata.
- [`engine eval`](../engine/eval.md) to replay the draft against more telemetry.
- [`engine discover-schemas`](../engine/discover-schemas.md) for the schema-signature sibling of this command.
