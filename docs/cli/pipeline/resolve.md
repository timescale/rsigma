# `rsigma pipeline resolve`

Offline resolution of dynamic pipeline sources, with an optional dry-run mode.

## Synopsis

```text
rsigma pipeline resolve [OPTIONS] --pipeline <PIPELINES>
```

## Description

Loads a processing pipeline that declares dynamic sources (HTTP, file, command, NATS), fetches each source, applies any `extract:` expression, and prints the resulting JSON. Useful for verifying that a dynamic pipeline's sources are reachable, that the `extract` selectors return the expected shape, and that a remote feed is publishing what the rule expects.

This command does not load rules or evaluate events. It is the offline counterpart of what [`engine daemon`](../engine/daemon.md) does at rule-load time for any pipeline that declares sources. Use it locally before pushing a dynamic pipeline to production, and in CI as a gate for [`rule validate --resolve-sources`](../rule/validate.md).

For narrative coverage see [Processing Pipelines: dynamic pipelines](../../guide/processing-pipelines.md#dynamic-pipelines).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pipeline <PIPELINES>` | required | Path to one or more pipeline YAML files containing dynamic sources. Repeatable. |
| `-s, --source <ID>` | unset | Resolve only the named source instead of every source in the pipeline. |
| `--pretty` | off | Pretty-print JSON output. |
| `--dry-run` | off | List each source's type, refresh policy, and `required` flag without performing any fetch. |

## Examples

### Resolve every source

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --pretty
```

```json
[
  {
    "pipeline": "dynamic_test",
    "source_id": "ip_blocklist",
    "status": "ok",
    "data": ["10.0.0.5", "192.168.99.99", "203.0.113.42"]
  },
  {
    "pipeline": "dynamic_test",
    "source_id": "field_config",
    "status": "ok",
    "data": {"src_ip": "SourceIp", "dst_ip": "DestinationIp"}
  }
]
```

### Resolve a single source

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --source ip_blocklist --pretty
```

### Dry-run: inspect the source declarations without fetching

```bash
rsigma pipeline resolve -p pipelines/dynamic.yml --dry-run
```

```json
[
  {"pipeline":"dynamic_test","source_id":"ip_blocklist","source_type":"Http","required":true,"refresh":"Interval(300s)"},
  {"pipeline":"dynamic_test","source_id":"field_config","source_type":"File","required":true,"refresh":"Once"}
]
```

Good for catching typos and refresh-policy mistakes before they hit production.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The command ran. Per-source results are in the JSON output; each one carries `"status": "ok"` or `"status": "error"`. **`pipeline resolve` does NOT propagate per-source errors to its exit code.** For a strict CI gate, pair with [`rule validate --resolve-sources`](../rule/validate.md), which exits `3` if any source fails. |
| `2` | Pipeline file could not be read or parsed. |
| `3` | Bad CLI argument (e.g. unknown `--source` ID). |

## See also

- [Processing Pipelines](../../guide/processing-pipelines.md) for the dynamic-source spec, extract languages, refresh policies, and the `vars` + `value_placeholders` pattern.
- [`rule validate --resolve-sources`](../rule/validate.md) for the CI-gate variant that also validates rules at the same time.
- [Dynamic Sources reference](../../reference/dynamic-sources.md) for the full source type catalog and security limits.
