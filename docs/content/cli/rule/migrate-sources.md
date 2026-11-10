---
description: "Reference for rsigma rule migrate-sources: move sources blocks embedded in processing pipelines into standalone dynamic source files."
---

# `rsigma rule migrate-sources`

{{ added "0.13.0" }}

Extract pipeline-embedded `sources:` blocks into standalone source files.

## Synopsis

```text
rsigma rule migrate-sources -p <PIPELINE> -o <OUTPUT> [--strategy <STRATEGY>] [--dry-run]
```

## Description

Scans one or more pipeline files for inline `sources:` blocks, extracts them into standalone source file(s), and rewrites the original pipeline files with the `sources:` block removed. This is the migration path off pipeline-embedded `sources:`, which was removed in v0.19.0 in favor of the `--source` daemon flag: a pipeline that still declares an inline `sources:` block is now rejected everywhere else, so run this tool to move the declarations into a standalone `--source` file.

The tool detects source ID collisions across pipelines and exits with an error if two pipelines declare the same source ID.

Explicit `--output-format` is unsupported and warns: this command emits source YAML or writes files.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pipeline <PATH>` | (required) | Pipeline file or directory of pipeline files to migrate. Repeatable. |
| `-o, --output <PATH>` | (required) | Output file (for `single` strategy) or directory (for `per-pipeline` strategy). |
| `--strategy <single\|per-pipeline>` | `single` | `single`: consolidate all sources into one file. `per-pipeline`: write one file per pipeline. |
| `--dry-run` | off | Preview the extracted sources on stdout without writing files. |

## Examples

Consolidate all sources from a pipeline directory into a single file:

```bash
rsigma rule migrate-sources -p pipelines/ -o sources.yml
```

Then update the daemon invocation to load the sources from the new file:

```bash
rsigma engine daemon -r rules/ -p pipelines/ --source sources.yml
```

Preview what would be extracted without writing:

```bash
rsigma rule migrate-sources -p pipeline.yml -o sources.yml --dry-run
```

Write one output file per pipeline:

```bash
rsigma rule migrate-sources -p pipelines/ -o sources.d/ --strategy per-pipeline
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Extraction completed, dry-run printed, or no inline sources were found. |
| `2` | A pipeline file or inline `sources:` block could not be read or parsed. |
| `3` | Missing pipeline files, duplicate source IDs, output write/create failure, or other configuration error. |

## See also

- [Dynamic Sources reference](../../reference/dynamic-sources.md) for the standalone `sources:` schema.
- [`pipeline resolve`](../pipeline/resolve.md) to exercise the extracted sources offline.
- [`engine daemon`](../engine/daemon.md) `--source` for loading them at runtime.
