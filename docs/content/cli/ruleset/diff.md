---
description: "Compare a resolved ruleset with its lockfile and gate CI on additions, removals, and changes."
---

# `rsigma ruleset diff`

{{ added "0.28.0" }}

Compare a resolved ruleset with a lockfile produced by `ruleset build`.

## Synopsis

```text
rsigma ruleset diff <NAME> [--config <PATH>] [--lock <PATH>] [--fail-on-change]
```

## Description

`ruleset diff` resolves the named ruleset, reads the lockfile, and compares the two document sets by kind and output file. It reports added, removed, and changed documents. A changed document lists the fields that differ, such as `title`, `decision`, `overlays`, or `origin`. It also reports whether the source digests, overlay files, or spec digest changed.

The lockfile path defaults to the ruleset's `output` directory plus `ruleset.lock.json`. Pass `--lock` to compare against a lockfile elsewhere.

A lockfile whose `lock_version` is not 1 is a configuration error. With `--fail-on-change`, any difference exits 1, which makes the command a CI gate.

Output uses the global `--output-format` layer. The JSON envelope carries the counts, the change flags, and a `documents` array with one `{ change, kind, id, title, detail }` row per added, removed, or changed document, where `detail` lists the changed fields. The table output carries the same rows.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | discovery | Configuration file to read rulesets from. |
| `--lock` | the ruleset's `output` | Lockfile to compare against. |
| `--fail-on-change` | off | Exit 1 when the ruleset differs from the lockfile. |

## Examples

### Compare a ruleset with its lockfile

```bash
rsigma ruleset diff linux_edge --lock build/linux_edge/ruleset.lock.json
```

### Gate CI

```bash
rsigma ruleset diff linux_edge --lock build/linux_edge/ruleset.lock.json --fail-on-change
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No change, or changes without `--fail-on-change`. |
| `1` | Changes were found and `--fail-on-change` was set. |
| `3` | Resolution error, missing or unreadable lockfile, unknown lock version, or unreadable configuration. |

## See also

- [`rsigma ruleset build`](build.md)
- [`rsigma ruleset show`](show.md)
- [Rulesets guide](../../guide/rulesets.md)
