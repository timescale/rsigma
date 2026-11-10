---
description: "Reference for rsigma backend convert: translate Sigma rules into PostgreSQL, LynxDB, or Fibratus queries natively, or other SIEM targets through sigma-cli."
---

# `rsigma backend convert`

{{ added "0.12.0" }}

Convert Sigma rules into backend-native queries (SQL, SPL, …).

## Synopsis

```text
rsigma backend convert [OPTIONS] --target <TARGET> [RULES]...
```

## Description

Reads one or more rule files (or a directory) and emits backend-native query strings, one per rule. Output goes to stdout by default; use `-o` to write to a file. Sigma filters among the input files are merged into the rules they reference before pipelines run, and a correlation rule fails with `UnsupportedCorrelation` on a backend without correlation support. {{ added "0.24.0" }} Use [`backend targets`](targets.md) to list available backends and [`backend formats`](formats.md) to list the output formats supported by a specific backend.

Targets with no native backend are delegated to an external [sigma-cli](https://github.com/SigmaHQ/sigma-cli) when one is installed, which reaches the full pySigma backend set (`splunk`, `elasticsearch`, `kusto`, `qradar`, `loki`, …). See [sigma-cli delegation](../../reference/backends/sigma-cli.md) for discovery, the `RSIGMA_SIGMA_CLI` override, the flag mapping, and limitations.

For narrative coverage, including the PostgreSQL and LynxDB workflows, see [Rule Conversion](../../guide/rule-conversion.md).

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-t, --target <TARGET>` | Backend to convert to. Run [`backend targets`](targets.md) for the live list. Native: `postgres` (aliases `postgresql`, `pg`), `lynxdb`, `fibratus`, `test`. Any other target is delegated to sigma-cli when installed. |
| `[RULES]...` | Path(s) to Sigma rule file(s) or a directory. |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format <FORMAT>` | `default` | Backend-specific query format. Run [`backend formats <TARGET>`](formats.md) for the list. PostgreSQL examples: `default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`. Distinct from the global `--output-format` wire selector. |
| `-o, --output <PATH>` | stdout | Write to a file instead of stdout. Always writes raw query text. |

Global `--output-format json` wraps queries in a `{target, format, queries:[…]}` envelope; `ndjson` emits one query record per line; `table`/`csv`/`tsv` warn and keep raw text. See [Output Formats](../../reference/output.md).

### Pipeline

| Flag | Description |
|------|-------------|
| `-p, --pipeline <PIPELINE>` | Processing pipeline(s) (repeatable). Builtin names (`ecs_windows`, `fibratus_windows`, `sysmon`) or YAML file paths. |
| `--without-pipeline` | Skip the pipeline-requirement check that some backends enforce. Use when you know the rules already match your target schema. |

### Backend options and error handling

| Flag | Description |
|------|-------------|
| `-O, --option <KEY=VALUE>` | Backend-specific option. Repeatable. PostgreSQL examples: `-O table=okta_events`, `-O json_field=data`, `-O timestamp_field=time`. Correlation engines that advertise methods also accept `-O correlation_method=NAME` (see [`backend formats`](formats.md)). See [PostgreSQL backend reference](../../reference/backends/postgres.md) for the full list. |
| `-s, --skip-unsupported` | Skip rules that the backend cannot represent instead of failing the run with exit `2`. The skipped rules are reported on stderr. |

Dynamic pipeline sources are not resolved by `backend convert`. A pipeline that references `${source.<id>}` still converts with unresolved placeholders; use [`pipeline resolve`](../pipeline/resolve.md) to inspect sources or [`engine daemon`](../engine/daemon.md) to evaluate with live resolution.

## Examples

### PostgreSQL default

```bash
rsigma backend convert -t postgres rules/
```

```sql
SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

### PostgreSQL view per rule

```bash
rsigma backend convert -t postgres -f view -p ecs_windows rules/
```

```sql
CREATE OR REPLACE VIEW sigma_8b1d8c97_5b3a_4d77_9b48_7c5f7c8b1a2a AS
    SELECT * FROM security_events WHERE "process.command_line" ILIKE '%whoami%'
```

### JSONB mode against an Okta-style schema

```bash
rsigma backend convert -t postgres \
    -O table=okta_events \
    -O json_field=data \
    -O timestamp_field=time \
    rules/
```

```sql
SELECT * FROM okta_events
WHERE data->>'eventType' ILIKE 'group.user\_membership.add'
  AND data->'actor'->>'alternateId' ILIKE '%@partner.example.com'
```

### LynxDB SPL2

```bash
rsigma backend convert -t lynxdb rules/
```

### Sliding-window correlation (skip the base detection rules)

```bash
rsigma backend convert -t postgres -f sliding_window --skip-unsupported rules/
```

Base detection rules return `unknown output format: sliding_window` and are skipped; only the correlation rule converts.

### Convert a whole tree to a file

```bash
rsigma backend convert rules/ -t postgres -f view \
    -p pipelines/ocsf_postgres.yml \
    --skip-unsupported \
    -o /var/lib/rsigma/sql/views.sql
psql -f /var/lib/rsigma/sql/views.sql
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Conversion succeeded. |
| `2` | One or more rules failed to convert (unless `--skip-unsupported`), rules path empty, or a delegated sigma-cli run exited non-zero (its stderr is relayed). |
| `3` | Unknown `--format`, unwritable `--output`, a target with no native backend and no sigma-cli installed, a directory `--output` for a delegated target, or other CLI configuration error. |

## See also

- [Rule Conversion](../../guide/rule-conversion.md) for the full workflow.
- [`backend targets`](targets.md) and [`backend formats`](formats.md) for the discovery commands.
- [PostgreSQL backend reference](../../reference/backends/postgres.md), [LynxDB backend reference](../../reference/backends/lynxdb.md), [Fibratus backend reference](../../reference/backends/fibratus.md).
- [`rule fields`](../rule/fields.md) for auditing which fields each rule references before conversion.
