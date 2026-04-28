# rsigma-convert

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-convert` is a Sigma rule conversion engine that transforms parsed Sigma rules into backend-native query strings (SQL, SPL, KQL, Lucene, etc.).

This library is part of [rsigma].

## Overview

The crate provides a generic conversion framework that any backend can plug into:

- **`Backend` trait** with ~30 methods covering condition dispatch, detection item conversion, field/value escaping, regex, CIDR, comparison operators, field existence, field references, keywords, IN-list optimization, deferred expressions, and query finalization.
- **`TextQueryConfig`** with ~90 configuration fields mirroring pySigma's `TextQueryBackend` class variables: precedence, boolean operators, wildcards, string/field quoting, match expressions (startswith/endswith/contains + case-sensitive variants), regex/CIDR templates, compare ops, IN-list optimization, unbound values, deferred parts, and query envelope.
- **Condition tree walker** that recursively converts `ConditionExpr` nodes into query strings with selector/quantifier support.
- **Orchestrator** via `convert_collection()`, which applies pipelines, converts each rule, and collects results and errors.
- **Deferred expressions** through the `DeferredExpression` trait and `DeferredTextExpression` for backends that need post-query appendages (e.g. Splunk `| regex`, `| where`).
- **Test backend** with `TextQueryTestBackend` and `MandatoryPipelineTestBackend` for backend-neutral foundation testing.
- **PostgreSQL/TimescaleDB backend** with native `ILIKE`, regex (`~*`), CIDR (`inet`/`cidr`), full-text search (`tsvector`/`tsquery`), JSONB field access, correlation via CTEs and window functions, and TimescaleDB-specific output formats (continuous aggregates, `time_bucket` queries, view generation).

## Backends

| Backend | Target names | Description |
|---------|-------------|-------------|
| Test | `test` | Backend-neutral text queries for foundation testing |
| PostgreSQL | `postgres`, `postgresql`, `pg` | Native PostgreSQL SQL with TimescaleDB support |

## Usage

### Test backend

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_convert::{convert_collection, Backend};
use rsigma_convert::backends::test::TextQueryTestBackend;

let yaml = r#"
title: Detect Whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

let collection = parse_sigma_yaml(yaml).unwrap();
let backend = TextQueryTestBackend::new();

let output = convert_collection(&backend, &collection, &[], "default").unwrap();
for result in &output.queries {
    for query in &result.queries {
        println!("{query}");
        // Output: CommandLine contains "whoami"
    }
}
```

### PostgreSQL backend

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_convert::{convert_collection, Backend};
use rsigma_convert::backends::postgres::PostgresBackend;

let yaml = r#"
title: Detect Whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

let collection = parse_sigma_yaml(yaml).unwrap();
let backend = PostgresBackend::new();

let output = convert_collection(&backend, &collection, &[], "default").unwrap();
for result in &output.queries {
    for query in &result.queries {
        println!("{query}");
        // Output: SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
    }
}
```

### PostgreSQL output formats

| Format | Description |
|--------|-------------|
| `default` | Plain `SELECT * FROM {table} WHERE ...` queries |
| `view` | `CREATE OR REPLACE VIEW sigma_{id} AS SELECT ...` |
| `timescaledb` | Queries with `time_bucket()` for TimescaleDB optimization |
| `continuous_aggregate` | `CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)` |
| `sliding_window` | Correlation queries using window functions for per-row sliding detection |

### SELECT column selection

When a Sigma rule specifies `fields:`, the backend emits `SELECT field1, field2, ...` instead of `SELECT *`. Function calls (e.g. `count(*)`) pass through unchanged, and `field as alias` is supported with both sides quoted independently.

### CLI backend options

Backend configuration can be set via `-O key=value` flags on the CLI, which are wired through to `PostgresBackend::from_options`. Recognized keys: `table`, `schema`, `database`, `timestamp_field`, `json_field`, `case_sensitive_re`.

```bash
rsigma convert -r rules/ -t postgres -O table=security_logs -O schema=public -O timestamp_field=created_at
```

### Custom table, schema, and database

The target table and schema can be set at three levels (highest precedence first):

1. **Rule-level `custom_attributes`**: `postgres.table`, `postgres.schema`, `postgres.database`
2. **Pipeline state**: `set_state` with `key: table`, `key: schema`
3. **CLI backend options**: `-O table=...`, `-O schema=...`, `-O database=...`
4. **Backend defaults**: `PostgresBackend.table`, `.schema`, `.database`

Example rule with custom attributes:

```yaml
title: Process Creation
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
custom_attributes:
    postgres.table: process_events
    postgres.schema: siem
```

### OCSF pipelines

Two OCSF processing pipelines are included:

| Pipeline | Description |
|----------|-------------|
| `pipelines/ocsf_postgres.yml` | Single-table: all events go to `security_events` |
| `pipelines/ocsf_postgres_multi_table.yml` | Per-logsource routing: each category gets its own table (`process_events`, `network_events`, etc.) |

```bash
# Single-table pipeline
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml

# Multi-table pipeline (per-logsource routing)
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml

# With output format
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml -f view
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml -f continuous_aggregate
```

### Multi-table temporal correlations

When a temporal correlation rule references detection rules that target different tables (via per-logsource pipeline routing or custom attributes), the backend automatically generates a `UNION ALL` CTE:

```sql
-- Rules targeting different tables produce UNION ALL
WITH matched AS (
    SELECT *, 'process_rule' AS rule_name FROM process_events
        WHERE time >= NOW() - INTERVAL '300 seconds'
    UNION ALL
    SELECT *, 'network_rule' AS rule_name FROM network_events
        WHERE time >= NOW() - INTERVAL '300 seconds'
)
SELECT "User", COUNT(DISTINCT rule_name) AS distinct_rules,
    MIN(time) AS first_seen, MAX(time) AS last_seen
FROM matched
GROUP BY "User"
HAVING COUNT(DISTINCT rule_name) >= 2
```

When all referenced rules share the same table, the simpler single-table approach is used instead.

Per-rule schemas are also tracked: if different detection rules set different schemas (via `postgres.schema` custom attribute or `set_state key: schema` in the pipeline), each leg of the UNION ALL uses the correct `schema.table`.

> **Important:** The multi-table `UNION ALL` uses `SELECT *` in each leg, so PostgreSQL requires all referenced tables to have the same column count and compatible column types. This works well when tables share a normalized event schema. If your tables have different column layouts, either normalize them through pipeline field-mappings or use a single-table approach with a discriminator column (e.g. `rule_name`) instead.

### Reference schema

A reference TimescaleDB schema is provided at [`schema/timescaledb_security_events.sql`](./schema/timescaledb_security_events.sql) with hypertable setup, indexes (B-tree, GIN for full-text and JSONB), compression, retention policies, and an example continuous aggregate.

## Backend Trait

Backends implement the `Backend` trait to produce query strings from Sigma AST nodes. The trait operates on **parsed** types from `rsigma-parser` (not compiled matchers) because conversion needs the original field names, modifiers, and values.

Key methods:

| Method | Description |
|--------|-------------|
| `convert_rule` | Convert a single `SigmaRule` into query strings |
| `convert_condition` | Walk a `ConditionExpr` tree |
| `convert_detection` | Convert a `Detection` (AllOf/AnyOf/Keywords) |
| `convert_detection_item` | Convert a single `DetectionItem` (field + modifiers + values) |
| `convert_field_eq_str` | String value matching with modifier dispatch |
| `convert_field_eq_re` | Regex matching |
| `convert_field_eq_cidr` | CIDR matching |
| `convert_field_compare` | Numeric comparison (`gt`, `gte`, `lt`, `lte`) |
| `convert_field_exists` | Field existence check |
| `convert_keyword` | Unbound/keyword value matching |
| `finish_query` | Assemble final query with deferred parts |
| `finalize_query` | Apply output format to a query |
| `finalize_output` | Finalize the complete output |

## TextQueryConfig

For text-based query backends (the vast majority), create a `TextQueryConfig` with your backend's tokens and expressions, then delegate to the `text_convert_*` free functions:

| Function | Description |
|----------|-------------|
| `text_escape_and_quote_field` | Escape and optionally quote a field name |
| `text_convert_value_str` | Convert a `SigmaString` with escaping and quoting |
| `text_convert_value_re` | Escape a regex pattern |
| `text_convert_condition_and` | Join expressions with AND token |
| `text_convert_condition_or` | Join expressions with OR token |
| `text_convert_condition_not` | Negate an expression |
| `text_convert_condition_group` | Precedence-aware grouping |
| `text_convert_field_eq_str` | String match dispatch (contains/startswith/endswith/wildcard/exact) |
| `text_finish_query` | Assemble query with deferred parts and state substitution |

## Implementing a Backend

1. Define a `TextQueryConfig` constant with your backend's tokens and expressions.
2. Create a struct that implements `Backend`, delegating most methods to the `text_convert_*` helpers.
3. Override specific methods for backend-specific behavior (e.g. deferred regex for Splunk, SQL-specific CIDR handling for PostgreSQL).
4. Register your backend in the CLI's `get_backend()` registry.

See `backends/test.rs` for a complete reference implementation and `backends/postgres.rs` for a production backend with SQL-specific overrides.

## PostgreSQL Backend Details

The PostgreSQL backend (`PostgresBackend`) leverages native PostgreSQL features that map cleanly to Sigma modifiers:

| Sigma Modifier | PostgreSQL SQL |
|----------------|---------------|
| `contains` | `ILIKE` (case-insensitive) |
| `startswith` / `endswith` | `ILIKE` |
| `cased` | `LIKE` (case-sensitive) |
| `re` | `~*` (case-insensitive regex) or `~` (with `cased`) |
| `cidr` | `field::inet <<= 'value'::cidr` |
| `exists` | `IS NOT NULL` / `IS NULL` |
| keywords | `to_tsvector() @@ plainto_tsquery()` |

Correlation rules are converted to SQL using `GROUP BY` / `HAVING` for aggregation types (`event_count`, `value_count`, `value_sum`, `value_avg`, `value_percentile`, `value_median`) and CTEs for temporal correlation. Multi-table temporal correlations automatically generate `UNION ALL` CTEs when referenced rules target different tables.

Non-temporal correlations support CTE-based pre-filtering: when the correlation references detection rules that were converted in the same collection, the backend wraps their queries in a `WITH combined_events AS (q1 UNION ALL q2 ...)` CTE so the aggregate only counts events matching the detection logic.

The `sliding_window` output format uses SQL window functions for `event_count` correlations, producing a per-row sliding window that emits every event crossing the threshold:

```sql
WITH combined_events AS (...),
event_counts AS (
    SELECT *, COUNT(*) OVER (
        PARTITION BY "User"
        ORDER BY time
        RANGE BETWEEN INTERVAL '300 seconds' PRECEDING AND CURRENT ROW
    ) AS correlation_event_count
    FROM combined_events
)
SELECT * FROM event_counts WHERE correlation_event_count >= 5
```

### Configuration

`PostgresBackend` fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `table` | `String` | `"security_events"` | Default table name (overridden by pipeline state or `postgres.table` custom attribute) |
| `timestamp_field` | `String` | `"time"` | Timestamp column for time-windowed queries |
| `json_field` | `Option<String>` | `None` | If set, fields are accessed via JSONB (`col->>'field'`) |
| `case_sensitive_re` | `bool` | `false` | Use `~` instead of `~*` for regex |
| `schema` | `Option<String>` | `None` | PostgreSQL schema name (overridden by pipeline state or `postgres.schema` custom attribute) |
| `database` | `Option<String>` | `None` | PostgreSQL database name (connection-level metadata) |
| `timescaledb` | `bool` | `false` | Enable TimescaleDB-specific features |

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
