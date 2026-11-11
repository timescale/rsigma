---
description: "Reference for rsigma engine explain: show why a Sigma rule did or did not match a single event, selection by selection, to debug missed detections."
---

# `rsigma engine explain`

{{ added "0.18.0" }}

Explain why a detection rule did or did not match a single event.

## Synopsis

```text
rsigma engine explain --rules <PATH>... [OPTIONS]
```

## Description

Validation, linting, and the LSP answer "is this rule well-formed?" They cannot answer "given this event, why did the rule not match?" because they have no event data. `engine explain` fills that gap: it runs a non-short-circuiting, bloom-free recording evaluator over one rule and one event and reports, for every condition node and field, whether it matched and why not (field absent, value mismatch with the actual value, case mismatch, existence check failed, no keyword match).

The verdict can never disagree with the production engine: every per-node result is computed from the same eval primitives the engine uses, so `matched` equals what `engine eval` would decide for the same rule and event.

It consumes event data, so it lives under `engine` (the `rule` group stays static). Event input is a single JSON object; for streaming evaluation use [`engine eval`](eval.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>...` | required | Sigma rule file(s) or director(ies) to explain. Repeatable. |
| `-e, --event <JSON\|@FILE\|->` | stdin | The event to explain against: inline JSON, `@path` to a JSON file, or `-` (or omitted) to read a single JSON object from stdin. |
| `-p, --pipeline <PATH\|NAME>` | none | Processing pipeline(s) to apply before evaluation. Builtin names (`ecs_windows`, `ecs_linux`, `fibratus_windows`, `sysmon`) or YAML file paths. Repeatable, applied in priority order. |
| `--rule-id <ID>` | unset | Only explain the rule with this id (falling back to an exact title). |
| `--show-pipeline` | off | Print the pipeline transformation summary before each human-tree trace. No effect without `-p`, and ignored for `json`/`ndjson`/`csv`/`tsv` output. |

The global [`--output-format`](../../reference/output.md) flag selects the renderer: the default is a human tree; `json` and `ndjson` serialize the full trace; `csv` and `tsv` emit a flat per-leaf table.

## Output

The default human renderer is an indented tree with `PASS`/`FAIL` markers and a one-line reason per failed leaf:

```text
Suspicious PowerShell (ps-1): NO MATCH
  FAIL all of:
    FAIL selection
      FAIL Image|endswith "\powershell.exe"  actual="C:\Windows\cmd.exe" (value mismatch)
      PASS CommandLine|contains "-enc" (matched)
    FAIL not:
      PASS filter
        PASS User|exact "system" (matched)
```

`--output-format json` serializes `RuleExplanation` (one array entry per rule): a tree of condition nodes (`selection`, `and`, `or`, `not`, `quantified`), each detection's items, and per-item `matcher`, `pattern`, `actual`, `matched`, and `reason`. JSON `reason` values are snake_case: `matched`, `field_absent`, `value_mismatch`, `case_mismatch`, `existence`, and `no_keyword_match`. The human tree prints the same reasons as spaced phrases (`field absent`, `value mismatch`, `existence check failed`, …).

Array object-scope detections serialize as `array_match` nodes: `field`, `quantifier` (`any`/`all`/`all_or_empty`/`none`), `matched`, `member_count`, `matched_count` (body-matching members counted over the full array, so truncation never understates it), optional `scalar`/`empty_reason`/`truncated`/`omitted`, and a `members` array of `{index, matched, detection}`. Extended `condition:` bodies serialize as `conditional` with a nested condition tree. Human output indents `member[i]` under `array_match "field" quantifier (N members, matched [...])`; when truncation omits matching members the list ends with `+N more`; fieldless items inside a member render as `.`. Recorded members are capped at 32 per node, keeping the decisive class first (binding members for `any`/`none`, failing members for `all`/`all_or_empty`) and listed in index order. CSV/TSV emit one row per leaf with an indexed FIELD (`connections[0].protocol`, `connections[0]` for the member itself, `rules[0].ip[1]` for nested arrays). {{ added "0.22.0" }}

## Examples

Explain why a rule did not match an event:

```bash
rsigma engine explain -r rules/ -e '{"Image":"C:\\Windows\\cmd.exe"}'
```

Read the event from a file and focus one rule:

```bash
rsigma engine explain -r rules/ --rule-id ps-1 -e @event.json
```

Explain through a pipeline and show the transformation summary first:

```bash
rsigma engine explain -r rules/ -p ecs_windows --show-pipeline -e @event.json
```

Emit the trace as JSON for tooling:

```bash
rsigma engine explain -r rule.yml -e @event.json --output-format json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (regardless of match) |
| `2` | Bad rule input (empty ruleset, parse/compile or pipeline error, unknown `--rule-id`) |
| `3` | Bad event input (invalid JSON, unreadable file, empty stdin) |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.

## See also

- [Evaluating Rules](../../guide/evaluating-rules.md) for the miss-debugging workflow that uses `engine explain`.
- [`engine eval`](eval.md) for one-shot evaluation of many events.
- [`pipeline diff`](../pipeline/diff.md) for the rewrite summary `--show-pipeline` prints.
- [Processing Pipelines](../../guide/processing-pipelines.md) for `-p` semantics.
