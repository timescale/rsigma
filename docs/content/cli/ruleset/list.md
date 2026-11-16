---
description: "List declared rulesets, their source counts, selectors, overlays, pipelines, and resolution status."
---

# `rsigma ruleset list`

{{ added "unreleased" }}

List the rulesets declared in `rsigma.yaml` and report whether each one resolves.

## Synopsis

```text
rsigma ruleset list [--config <PATH>]
```

## Description

`ruleset list` reads the merged `rulesets:` section, resolves each named ruleset, and prints one row per ruleset. The row reports source paths, kept document counts by kind, overlay and pipeline counts, and a status. A ruleset that fails to resolve prints its error without hiding the other rows. A ruleset that resolves while some source files fail to parse keeps the `ok` status, and its error column reports how many source parse errors were skipped.

An unknown ruleset name is not an input here; the command lists every declared name. When no rulesets are defined, it prints a hint that no rulesets were found in the configuration.

Output uses the global `--output-format` layer. The JSON envelope carries the rows, including a `status` and an `error` field for each ruleset.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | discovery | Configuration file to read rulesets from. |

## Examples

### List rulesets

```bash
rsigma ruleset list
```

```text
NAME    SOURCES  DETECTION  CORRELATION  FILTER  OVERLAYS  PIPELINES  STATUS  ERROR
------  -------  ---------  -----------  ------  --------  ---------  ------  -----
vendor  vendor           4            2       1         3  sysmon     ok
```

### JSON output

```bash
rsigma ruleset list --output-format json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every declared ruleset resolved. |
| `3` | A ruleset failed to resolve, or the configuration could not be read. Other rows are still printed. |

## See also

- [`rsigma ruleset show`](show.md)
- [`rsigma ruleset build`](build.md)
- [Rulesets guide](../../guide/rulesets.md)
