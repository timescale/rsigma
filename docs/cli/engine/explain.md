# `rsigma engine explain`

Explain why a detection rule did or did not match a single event.

## Synopsis

```text
rsigma engine explain --rules <PATH>... [OPTIONS]
```

## Description

Validation, linting, and the LSP answer "is this rule well-formed?" They cannot answer "given this event, why did the rule not match?" because they have no event data. `engine explain` fills that gap: it runs a non-short-circuiting, bloom-free recording evaluator over one rule and one event and reports, for every condition node and field, whether it matched and why not (field absent, value mismatch with the actual value, case mismatch, existence, no keyword match).

The verdict can never disagree with the production engine: every per-node result is computed from the same eval primitives the engine uses, so `matched` equals what `engine eval` would decide for the same rule and event.

It consumes event data, so it lives under `engine` (the `rule` group stays static). Event input is a single JSON object; for streaming evaluation use [`engine eval`](eval.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>...` | required | Sigma rule file(s) or director(ies) to explain. Repeatable. |
| `-e, --event <JSON\|@FILE\|->` | stdin | The event to explain against: inline JSON, `@path` to a JSON file, or `-` (or omitted) to read a single JSON object from stdin. |
| `-p, --pipeline <PATH\|NAME>` | none | Processing pipeline(s) to apply before evaluation. Builtin names (`ecs_windows`, `sysmon`) or YAML file paths. Repeatable, applied in priority order. |
| `--rule-id <ID>` | unset | Only explain the rule with this id (falling back to an exact title). |
| `--show-pipeline` | off | Print the pipeline transformation summary before each trace. No effect without `-p`. |

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

`--output-format json` serializes `RuleExplanation` (one array entry per rule): a tree of condition nodes (`selection`, `and`, `or`, `not`, `quantified`), each detection's items, and per-item `matcher`, `pattern`, `actual`, `matched`, and `reason`. The reasons are `matched`, `field_absent`, `value_mismatch`, `case_mismatch`, `existence`, and `no_keyword_match`.

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
| `2` | Bad rule input (parse/compile error, unknown `--rule-id`) |
| `3` | Bad event input (invalid JSON, unreadable file) |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.
