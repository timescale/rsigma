---
description: "Reference for rsigma pipeline diff: show how processing pipelines rewrite a Sigma rule's fields and values before evaluation or conversion."
---

# `rsigma pipeline diff`

{{ added "0.18.0" }}

Show how processing pipelines rewrite a rule before evaluation.

## Synopsis

```text
rsigma pipeline diff --rules <PATH>... -p <PIPELINE>... [OPTIONS]
```

## Description

A rule can work in isolation yet silently fail through an ECS/CIM pipeline because a field was renamed or an `AllOf` was expanded into an `AnyOf` of alternatives. Static tooling never shows the post-transform rule that actually runs. `pipeline diff` serializes the rule AST before and after applying the pipelines, prints a unified diff, and lists the transformation ids that fired.

This is the rule-side companion to [`pipeline resolve`](resolve.md) (which inspects dynamic source data) and to [`engine explain --show-pipeline`](../engine/explain.md) (which prints the same transformation summary before a match trace).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>...` | required | Sigma rule file(s) or director(ies) to diff. Repeatable. |
| `-p, --pipeline <PATH\|NAME>...` | required | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `ecs_linux`, `fibratus_windows`, `sysmon`) or YAML file paths. Repeatable, applied in priority order. |
| `--rule-id <ID>` | unset | Only diff the rule with this id (falling back to an exact title). |

The global [`--output-format`](../../reference/output.md) flag selects the renderer: the default (and `table`) is a human unified diff; `json` and `ndjson` emit `{ rule_title, rule_id, changed, applied_items, before, after }` per rule; `csv` and `tsv` emit one delimited row per rule with the same columns (AST columns are compact JSON strings).

## Output

The default human output prints, per rule, the applied transformation ids and a unified diff of the rule AST:

```text
Suspicious PowerShell (ps-1)
  transformations applied: rename_image
  --- before
  +++ after
  @@ ... @@
  -              "name": "Image"
  +              "name": "process.executable"
```

A rule the pipeline does not touch prints `(no change)`. Note that only transformations with an `id:` are tracked, so a real change can occur with an empty applied list; the human output says so, and the JSON `changed` flag is authoritative.

## Examples

Diff a rule through a builtin pipeline:

```bash
rsigma pipeline diff -r rules/ -p ecs_windows
```

Diff one rule and emit the before/after AST as JSON:

```bash
rsigma pipeline diff -r rule.yml -p pipeline.yml --rule-id ps-1 --output-format json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `2` | No rules found, unknown `--rule-id`, or a pipeline transformation error while rewriting a rule. |
| `3` | Pipeline path could not be loaded (unknown builtin name or unreadable YAML). |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.
