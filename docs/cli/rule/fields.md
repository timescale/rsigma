# `rsigma rule fields`

List all fields referenced by a directory of Sigma rules.

## Synopsis

```text
rsigma rule fields [OPTIONS] --rules <RULES>
```

## Description

Walks every rule under `--rules`, optionally applies one or more processing pipelines, then prints a table (or JSON) of every distinct field name those rules touch along with the count of rules that reference each field.

Useful for two operational tasks: confirming your event schema covers every field a ruleset depends on (so you know which fields a pipeline must produce or map to), and auditing rule sets before deploying them against a specific log source.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <RULES>` | required | Path to a Sigma rule file or directory of rules. |
| `-p, --pipeline <PIPELINES>` | unset | Processing pipeline(s) to apply before extracting fields. Builtin names (`ecs_windows`, `sysmon`) or YAML file paths. Repeatable. When set, fields are reported after the pipeline rewrite (so an `ecs_windows` pipeline against Sysmon rules will show `process.command_line`, not `CommandLine`). |
| `--no-filters` | off | Exclude fields that only appear in filter rules. |
| `--json` | off | Output as JSON instead of a table. |

## Examples

### Audit fields used by a Sigma corpus

```bash
rsigma rule fields -r rules/
```

```text
Field                    Rule count
─────────────────────────────────────
CommandLine              42
Image                    38
ParentImage              12
User                      7
EventID                   5
…
```

### See fields as they will look after a pipeline rewrite

```bash
rsigma rule fields -r rules/ -p ecs_windows
```

Outputs ECS-mapped field names (`process.command_line`, `process.executable`, `user.name`, etc.).

### Machine-readable output for tooling

```bash
rsigma rule fields -r rules/ --json | jq 'keys'
```

### Cross-check against an event schema

```bash
rsigma rule fields -r rules/ --json --no-filters \
    | jq -r 'keys[]' > rule-fields.txt
diff <(sort rule-fields.txt) <(sort schema-fields.txt)
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. Per-rule parse errors are reported as a stderr warning but do not change the exit code. |
| `2` | Rules path could not be read. |
| `3` | Pipeline file could not be loaded. |

For a strict gate that fails on per-rule parse or compile errors, use [`rule validate`](validate.md).

## See also

- [Processing Pipelines](../../guide/processing-pipelines.md) for `-p` semantics.
- [Rule Conversion](../../guide/rule-conversion.md#skipping-unsupported-rules) for using `rule fields` to audit before converting to PostgreSQL.
- [`rule lint`](lint.md) for spec-conformance checks on the same rule set.
