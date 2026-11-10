---
description: "Reference for rsigma backend formats: list the output formats and correlation methods that one Sigma conversion backend supports, with flags and examples."
---

# `rsigma backend formats`

{{ added "0.12.0" }}

List the output formats (and correlation methods) supported by one backend.

## Synopsis

```text
rsigma backend formats [OPTIONS] <TARGET>
```

## Description

Prints every `-f <FORMAT>` value [`backend convert`](convert.md) accepts for the given backend, plus any selectable correlation methods (passed as `-O correlation_method=NAME`). Each entry has a short description.

Native targets (`postgres`, `lynxdb`, `fibratus`, and the internal `test` backend) are listed by RSigma. Any other target is delegated to an installed [sigma-cli](../../reference/backends/sigma-cli.md).

## Flags

| Flag | Description |
|------|-------------|
| `<TARGET>` | Backend name (e.g. `postgres`, `lynxdb`, `fibratus`). Use [`backend targets`](targets.md) for the live list. |

The global [`--output-format`](../../reference/output.md) selector is honored: the human listing is the default, and `json`/`ndjson`/`table`/`csv`/`tsv` emit `TARGET,KIND,NAME,DESCRIPTION` rows (`kind` is `format` or `correlation_method`). JSON also includes `default_correlation_method` for native targets.

## Examples

### PostgreSQL formats

```bash
rsigma backend formats postgres
```

```text
Available formats for 'postgres':
  default               - Plain PostgreSQL SQL
  view                  - CREATE OR REPLACE VIEW for each rule
  timescaledb           - TimescaleDB-optimized queries with time_bucket()
  continuous_aggregate  - CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)
  sliding_window        - Correlation queries using window functions for per-row sliding detection

Correlation methods for 'postgres' (select with -O correlation_method=NAME, default: sliding):
  sliding   - Trailing per-event window (default; preserves existing SQL)
  tumbling  - Fixed boundary-aligned buckets (time_bucket/date_bin)
  session   - Gaps-and-islands sessionization (requires a gap)
```

### LynxDB formats

```bash
rsigma backend formats lynxdb
```

```text
Available formats for 'lynxdb':
  default  - full query: FROM <index> | search ..., or FROM <index> | where ...
  minimal  - search expression only (no FROM prefix); * | where ... for a where query
```

### Fibratus formats

```bash
rsigma backend formats fibratus
```

```text
Available formats for 'fibratus':
  default  - one YAML rule document per Sigma rule, --- separated
  expr     - filter expression only, no YAML envelope
  yaml     - alias of `default`
  rule     - alias of `default`

Correlation methods for 'fibratus' (select with -O correlation_method=NAME, default: sliding):
  sliding  - Native sliding sequence with `maxspan` (default; the Fibratus sequence DSL's only time-window primitive is a total-span cap, which is a sliding constraint per stage)
  session  - Degraded: emits a sliding sequence and a warning that the requested per-step gap is not enforced (Fibratus has no `maxpause`-style inactivity timeout)
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Formats listed (native target, or a successful sigma-cli listing). |
| `3` | Unknown non-native target and no usable sigma-cli result (not installed, launch failure, or sigma-cli exited non-zero). |

## See also

- [`backend convert`](convert.md) for using a format.
- [`backend targets`](targets.md) for the list of backends.
- [Rule Conversion](../../guide/rule-conversion.md) for when to pick each format.
- [Fibratus backend reference](../../reference/backends/fibratus.md) for Fibratus-specific options and envelopes.
