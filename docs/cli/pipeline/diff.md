# `rsigma pipeline diff`

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
| `-p, --pipeline <PATH\|NAME>...` | required | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `sysmon`) or YAML file paths. Repeatable, applied in priority order. |
| `--rule-id <ID>` | unset | Only diff the rule with this id (falling back to an exact title). |

The global [`--output-format`](../../reference/output.md) flag selects the renderer: the default is a human unified diff; `json` and `ndjson` emit `{ before, after, applied_items, changed }` per rule. The `csv` and `tsv` formats fall back to the human diff, since the change is structural rather than tabular.

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
| `0` | Success |
| `2` | Bad rule input, bad pipeline, or unknown `--rule-id` |
| `3` | Bad config |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.
