---
description: "Materialize a resolved ruleset into canonical YAML files and a deterministic lockfile."
---

# `rsigma ruleset build`

{{ added "0.28.0" }}

Materialize a resolved ruleset into a directory of canonical YAML files and a lockfile.

## Synopsis

```text
rsigma ruleset build <NAME> [--config <PATH>] [-o <DIR>] [--force] [--check]
```

## Description

`ruleset build` resolves the named ruleset, emits every kept document as canonical YAML, and writes a deterministic lockfile. The output directory contains `rules/<stem>.yml`, `correlations/<stem>.yml`, `filters/<stem>.yml`, and `ruleset.lock.json`. `<stem>` is the lowercased id when it is filesystem-safe, otherwise a content hash.

Writes are atomic and minimal. The build computes the full desired file set first, writes only files whose bytes differ, removes stale `.yml` files under the three subdirectories, and writes the lockfile last. The lockfile records the spec digest, source digests, overlay files, pipelines, and every document with its hash and applied overlays. It has no timestamps, so an unchanged rebuild is byte-identical. Source and overlay digests read CRLF line endings as LF, so a checkout that converts line endings produces the same lockfile. {{ added "0.28.0" }}

The build refuses to write into an existing non-empty directory that has no `ruleset.lock.json` unless `--force` is given. It never deletes anything outside the three subdirectories.

A source parse error fails the build with exit 2 and lists the errors. Resolution errors exit 3. With `--check`, the build writes nothing and exits 1 when the directory differs from what a build would write.

The output defaults to the ruleset's `output` key. Pass `-o` to override it.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | discovery | Configuration file to read rulesets from. |
| `--output` / `-o` | the ruleset's `output` | Output directory. |
| `--force` | off | Write into a non-empty directory that has no lockfile. |
| `--check` | off | Report drift and exit 1 instead of writing. |

## Examples

### Build a ruleset

```bash
rsigma ruleset build linux_edge -o build/linux_edge
```

### Verify committed output in CI

```bash
rsigma ruleset build linux_edge -o build/linux_edge --check
```

### Load the build output

```bash
rsigma engine eval --rules build/linux_edge --event @event.json
rsigma engine daemon --rules build/linux_edge
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The build wrote the output, or `--check` found no drift. |
| `1` | `--check` found drift. |
| `2` | A source had parse errors. |
| `3` | Resolution error, missing output directory, non-empty directory without `--force`, or unreadable configuration. |

## See also

- [`rsigma ruleset diff`](diff.md)
- [`rsigma ruleset show`](show.md)
- [Rulesets guide](../../guide/rulesets.md)
