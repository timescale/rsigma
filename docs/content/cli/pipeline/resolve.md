---
description: "Reference for rsigma pipeline resolve: resolve dynamic pipeline sources (HTTP, file, command, NATS) offline, with an optional dry-run mode."
---

# `rsigma pipeline resolve`

{{ added "0.12.0" }}

Offline resolution of dynamic pipeline sources, with an optional dry-run mode.

## Synopsis

```text
rsigma pipeline resolve [OPTIONS] --pipeline <PIPELINES> --source-file <FILE_OR_DIR>
```

## Description

Loads standalone dynamic-source declarations (HTTP, file, command, NATS), fetches each source, applies any `extract:` expression, and prints the resulting JSON. Useful for verifying that sources are reachable, that the `extract` selectors return the expected shape, and that a remote feed is publishing what the rule expects.

Source declarations live in standalone YAML files with a top-level `sources:` block and are loaded with `--source-file` (the same shape as the daemon's `--source` and `rule validate --source`). Pipeline-embedded `sources:` blocks are rejected; migrate them with [`rule migrate-sources`](../rule/migrate-sources.md). The required `-p` flag still parses each pipeline so a stale inline `sources:` block surfaces its migration error; resolution output is driven by the loaded `--source-file` declarations.

This command does not load rules or evaluate events. It is the offline counterpart of what [`engine daemon`](../engine/daemon.md) does at rule-load time for dynamic sources. Use it locally before pushing a dynamic pipeline to production, and in CI as a gate for [`rule validate --resolve-sources`](../rule/validate.md).

For narrative coverage see [Processing Pipelines: dynamic pipelines](../../guide/processing-pipelines.md#dynamic-pipelines).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pipeline <PIPELINES>` | required | Path to one or more pipeline YAML files. Repeatable. Parsed for migration errors and dynamic references; source values come from `--source-file`. |
| `--source-file <FILE_OR_DIR>` | unset | External source file(s) or directory of source files. Repeatable. A file path loads one YAML file with a top-level `sources:` block; a directory path loads all `*.yml`/`*.yaml` files in it, alphabetically. Without at least one declared source the command exits `2`. |
| `-s, --source <ID>` | unset | Resolve only the named source ID instead of every loaded source. |
| `--pretty` | off | Pretty-print JSON output. Applies when the effective format is JSON (including the historical default when `--output-format` is unset). Ignored for table/csv/tsv/ndjson. |
| `--dry-run` | off | List each source's type, refresh policy, and `required` flag without performing any fetch. |

The global [`--output-format`](../../reference/output.md) flag applies. When unset, the historical default is compact JSON (or pretty JSON with `--pretty`), with a single object when exactly one source is reported and an array otherwise. Explicit `json`/`ndjson`/`table`/`csv`/`tsv` use the tabular row shape (`pipeline`, `source_id`, `source_type`, `status`, `data_or_error`).

## Examples

### Resolve every source

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --source-file sources.yml --pretty
```

```json
[
  {
    "pipeline": "external:sources.yml",
    "source_id": "ip_blocklist",
    "status": "ok",
    "data": ["10.0.0.5", "192.168.99.99", "203.0.113.42"]
  },
  {
    "pipeline": "external:sources.yml",
    "source_id": "field_config",
    "status": "ok",
    "data": {"src_ip": "SourceIp", "dst_ip": "DestinationIp"}
  }
]
```

The `pipeline` field names the declaration site (`external:<path>`), not the `-p` pipeline name.

### Resolve a single source

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --source-file sources.yml --source ip_blocklist --pretty
```

### Dry-run: inspect the source declarations without fetching

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --source-file sources.yml --dry-run
```

```json
[
  {"pipeline":"external:sources.yml","source_id":"ip_blocklist","source_type":"Http","required":true,"refresh":"Interval(300s)"},
  {"pipeline":"external:sources.yml","source_id":"field_config","source_type":"File","required":true,"refresh":"Once"}
]
```

Use it to catch typos and refresh-policy mistakes before they reach production.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every resolved source returned `"status": "ok"` (or a successful `--dry-run`). |
| `1` | At least one source returned `"status": "error"`. Per-source details are still printed. |
| `2` | Pipeline file could not be read or parsed, no sources matched `-s/--source`, or no sources were loaded from `--source-file`. |
| `3` | Bad CLI argument or `--source-file` load failure (for example a malformed sources YAML). |

For a stricter CI gate that also validates rules, pair with [`rule validate --resolve-sources`](../rule/validate.md), which exits `3` if any source fails.

## See also

- [Processing Pipelines](../../guide/processing-pipelines.md) for the dynamic-source spec, extract languages, refresh policies, and the `vars` + `value_placeholders` pattern.
- [`rule validate --resolve-sources`](../rule/validate.md) for the CI-gate variant that also validates rules at the same time.
- [`rule migrate-sources`](../rule/migrate-sources.md) for extracting legacy inline `sources:` blocks.
- [Dynamic Sources reference](../../reference/dynamic-sources.md) for the full source type catalog and security limits.
