---
description: "Reference for rsigma backend build: convert every configured ruleset group into query files and manifests for CI or scheduled-query pipelines."
---

# `rsigma backend build`

{{ added "0.28.0" }}

Convert configured ruleset groups into query files and manifests in one run.

## Synopsis

```text
rsigma backend build [OPTIONS]
```

## Description

Reads the `convert:` section of the configuration and runs each group in name order. A group names a ruleset, a target, and an output path. The command writes the converted queries to `output` and a manifest to `<output>.manifest.json`.

`--group` restricts the run to named groups. A group that fails does not stop the others: the command continues, writes what it can, and exits `2` when any conversion failed. Configuration problems exit `3`, and a pipeline that fails to load fails only its group. Two groups whose output or manifest paths collide exit `3` before anything is written. With `--check` nothing is written, and drift in either file exits `1`.

Pipelines come only from the group or from `convert.defaults`, never from the ruleset. Delegated targets without a native backend are resolved and materialized into a temporary directory before sigma-cli runs, the same way [`backend convert --ruleset`](convert.md) does it, and their pipeline names go to sigma-cli untouched. Relative `output` and `pipelines` paths resolve against the working directory, like [ruleset sources](../../guide/rulesets.md).

## Flags

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Path to an rsigma config file. Overrides config-file discovery. |
| `--group <NAME>` | Convert only this group. Repeatable. Unknown names exit `3`. |
| `--check` | Compare both files with what a build would write, without writing. Exits `1` on drift. |

## Configuration

```yaml
rulesets:
  linux_edge:
    sources: [rules/linux]
  cloud_audit:
    sources: [rules/cloud]

convert:
  defaults:
    format: default
    skip_unsupported: true
    options:
      correlation_method: join
  groups:
    linux_edge_lynxdb:
      ruleset: linux_edge
      target: lynxdb
      pipelines: [sysmon]
      output: build/lynxdb/linux_edge.txt
      metadata:
        rule_group: linux
        time_window: 5m
    cloud_audit_postgres:
      ruleset: cloud_audit
      target: postgres
      output: build/postgres/cloud_audit.sql
```

`defaults` fills any field a group leaves unset, and a group's `options` merge per key over the defaults. Group names follow the ruleset name pattern: start with `a-z`, then `a-z`, `0-9`, `_`, or `-`, up to 64 characters. Groups replace wholesale across config layers, so a higher layer that redefines a group does not inherit the lower layer's fields.

| Group field | Meaning |
|-------------|---------|
| `ruleset` | Named ruleset from the `rulesets` section. |
| `target` | Conversion target. Native backends run in process; other targets delegate to sigma-cli when installed. |
| `format` | Backend-specific output format. Defaults to `default`. |
| `pipelines` | Conversion pipelines, as builtin names or YAML paths. Never inherited from the ruleset. |
| `options` | Backend options, the `-O key=value` equivalents. |
| `skip_unsupported` | Record rules the backend cannot convert as `skipped` instead of `failed`. |
| `without_pipeline` | Skip the backend's pipeline-requirement check. |
| `output` | Query output path. The manifest is written next to it. |
| `metadata` | Opaque values copied verbatim into the manifest. |

`metadata` is never interpreted. Scheduled-query concepts such as a rule group, a lookback, or a time window ride there for the consumer that reads the manifest.

## Manifest

```json
{
  "manifest_version": 1,
  "group": "linux_edge_lynxdb",
  "ruleset": "linux_edge",
  "target": "lynxdb",
  "format": "default",
  "pipelines": ["sysmon"],
  "output": "build/lynxdb/linux_edge.txt",
  "generator": "rsigma 0.28.0",
  "queries": 41,
  "rules": [
    {
      "kind": "detection",
      "id": "bbbbbbbb-0000-4000-8000-000000000001",
      "title": "Linux SSH login",
      "sha256": "eeca31eccce05e09b6fa9d4815a59bc584cd86de9593c781239ec2751c7981e0",
      "status": "converted"
    }
  ],
  "metadata": {"rule_group": "linux", "time_window": "5m"}
}
```

`rules[].sha256` is the canonical document hash the ruleset build lockfile records. Native targets report a status per rule: `converted` when the backend returned a query for it, `skipped` or `failed` when it could not convert the rule, and `no_query` when the backend returned nothing of its own for it, for example a detection that only feeds a correlation. Delegated targets omit `status`, because sigma-cli reports no per-rule outcome; their manifest lists every detection and correlation document in the resolved ruleset.

Filter rules are applied during conversion and do not appear in `rules`.

## Examples

### Build every group

```bash
rsigma backend build --config rsigma.yaml
```

```text
GROUP                RULESET     TARGET    RULES  QUERIES  STATUS   OUTPUT
linux_edge_lynxdb    linux_edge  lynxdb    41     41       written  build/lynxdb/linux_edge.txt
cloud_audit_postgres cloud_audit postgres  12     12       written  build/postgres/cloud_audit.sql
```

### Build one group as JSON

```bash
rsigma backend build --config rsigma.yaml --group cloud_audit_postgres --output-format json
```

```json
{
  "groups": [
    {
      "group": "cloud_audit_postgres",
      "ruleset": "cloud_audit",
      "target": "postgres",
      "rules": 12,
      "queries": 12,
      "status": "written",
      "output": "build/postgres/cloud_audit.sql"
    }
  ]
}
```

### Fail CI on drift

```bash
rsigma backend build --config rsigma.yaml --check
```

```text
GROUP                PATH
linux_edge_lynxdb    build/lynxdb/linux_edge.txt
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every selected group converted and wrote its files, or `--check` found no drift. |
| `1` | `--check` found drift in at least one output or manifest. |
| `2` | At least one rule failed to convert without `skip_unsupported`. The other groups still ran and wrote their files. |
| `3` | Configuration error: no `convert:` groups, an unknown group, an unknown ruleset, a missing `target` or `output`, two groups writing the same file, a pipeline that fails to load, an unknown target or format, an unwritable output, or a delegated target without sigma-cli. |

## See also

- [`backend convert`](convert.md) for one-off conversion and the flag-level backend options.
- [Rule Conversion](../../guide/rule-conversion.md#convert-named-rulesets) for the workflow.
- [Rulesets](../../guide/rulesets.md) for the sources, selectors, and overlays behind each group.
- [Configuration Reference](../../reference/configuration.md) for the full `convert:` section.
