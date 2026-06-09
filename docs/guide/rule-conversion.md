# Rule Conversion

`rsigma backend convert` translates Sigma rules into queries for a specific log analytics backend. Instead of evaluating rules against live events, conversion produces query strings that you can run against an existing log store: PostgreSQL/TimescaleDB, LynxDB, and any future backend that implements the `Backend` trait. This is the right path for historical threat hunting and for retroactive coverage testing against months of already-collected logs.

This page covers the two production backends, their output formats and backend options, multi-table correlation, and the workflow for integrating converted queries into Grafana, dashboards, or SOAR playbooks.

## When to convert instead of evaluate

| You want to... | Use |
|----------------|-----|
| Stream live events through Sigma rules with sub-millisecond latency. | [Streaming Detection](streaming-detection.md). |
| Run a Sigma rule across 90 days of logs already in PostgreSQL. | `backend convert -t postgres` and execute the SQL. |
| Build a Grafana dashboard from Sigma rules. | `backend convert -t postgres -f view` and add the views as Grafana panels. |
| Generate a TimescaleDB continuous aggregate from a correlation rule. | `backend convert -t postgres -f continuous_aggregate`. |
| Forward Sigma rules to LynxDB. | `backend convert -t lynxdb`. |

The output of conversion is plain text on stdout, one query per rule. Pipe it into `psql`, save it to a versioned `.sql` file, or wrap it in a deployment pipeline.

## Backends and targets

List what is available:

```bash
rsigma backend targets
```

```text
Available conversion targets:
  postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)
  lynxdb    - LynxDB log analytics engine
  test      - Backend-neutral test backend
```

The `test` backend produces backend-neutral text queries and is mainly used by the test suite, but it is handy for seeing how a rule lowers to a generic boolean expression.

Each backend supports one or more output formats:

```bash
rsigma backend formats postgres
```

```text
Available formats for 'postgres':
  default  - Plain PostgreSQL SQL
  view  - CREATE OR REPLACE VIEW for each rule
  timescaledb  - TimescaleDB-optimized queries with time_bucket()
  continuous_aggregate  - CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)
  sliding_window  - Correlation queries using window functions for per-row sliding detection
```

## PostgreSQL and TimescaleDB

The PostgreSQL backend is the most fully featured. It leverages native operators that map cleanly to Sigma modifiers:

| Sigma modifier | PostgreSQL operator |
|----------------|---------------------|
| `contains`, `startswith`, `endswith` | `ILIKE` (case-insensitive) |
| `cased` variants | `LIKE` |
| `re` | `~*` (case-insensitive regex), `~` with `cased` |
| `cidr` | `field::inet <<= 'value'::cidr` |
| `exists` | `IS NOT NULL` / `IS NULL` |
| keywords | `to_tsvector() @@ plainto_tsquery()` |

### Basic conversion

```bash
rsigma backend convert rules/ -t postgres
```

For a single-detection rule:

```sql
SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

### Backend options

`-O key=value` passes options into the PostgreSQL backend. The most useful ones:

| Option | Effect |
|--------|--------|
| `table` | Override the default `security_events` table name. |
| `schema` | Set the PostgreSQL schema. |
| `database` | Connection-level metadata used by some output formats. |
| `timestamp_field` | Column name for the timestamp (default `time`). |
| `json_field` | Treat fields as paths inside a JSONB column with that name (see JSONB mode below). |
| `case_sensitive_re` | Use `~` instead of `~*` for regex. |

Combine options for production schemas:

```bash
rsigma backend convert rules/ -t postgres \
    -O table=okta_events \
    -O json_field=data \
    -O timestamp_field=time
```

### JSONB mode

When events live as a JSONB column (`{"data": {"actor": {"name": "..."}}, "time": "..."}`), set `json_field` and Sigma field references become JSONB extraction expressions:

```sql
-- Sigma field: eventType
data->>'eventType'

-- Sigma field: securityContext.isProxy
data->'securityContext'->>'isProxy'

-- Sigma field: actor.detail.alternateId
data->'actor'->'detail'->>'alternateId'
```

Intermediate path segments use `->` (returns `jsonb`) and the last segment uses `->>` (returns `text`), which mirrors how `rsigma-eval` walks nested JSON during streaming evaluation.

### Output formats

#### `default`

Plain `SELECT * FROM table WHERE ...` queries, one per rule. Use this for ad-hoc execution in psql or for embedding into application code.

#### `view`

Wraps each rule's query in `CREATE OR REPLACE VIEW sigma_<rule-id> AS SELECT ...`. Useful for dashboards: each rule becomes a named view that downstream tools can query without parsing SQL.

```bash
rsigma backend convert rules/ -t postgres -f view
```

#### `timescaledb`

Adds `time_bucket()` clauses and other TimescaleDB-specific optimizations. Use this when your events sit on a TimescaleDB hypertable.

#### `continuous_aggregate`

Wraps each base detection rule in `CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous) AS ... WITH NO DATA`. For a Sigma `EventID: 4625` rule, you get:

```sql
CREATE MATERIALIZED VIEW sigma_9d2e7c48_4a3b_4f99_93c9_1c5f7c8b1a2b
    WITH (timescaledb.continuous) AS
    SELECT time_bucket('1 hour', time) AS bucket, *
    FROM security_events WHERE "EventID" = 4625
    WITH NO DATA
```

TimescaleDB then refreshes the aggregate in the background and your dashboards query the materialised result instead of the raw hypertable. Convert the base detection rules separately (or pass `--skip-unsupported`) and skip the `event_count`/`value_count` correlation rules; the materialised view above is the queryable surface you want.

#### `sliding_window`

Uses SQL window functions for `event_count` correlations, producing a per-row sliding window that emits every event that crosses the threshold. Only the correlation rule itself converts under this format; base detection rules return `unknown output format: sliding_window`, so pair the conversion with `--skip-unsupported`:

```bash
rsigma backend convert rules/ -t postgres -f sliding_window --skip-unsupported
```

```sql
WITH source AS (
    SELECT * FROM security_events
    WHERE time >= NOW() - INTERVAL '300 seconds'
),
event_counts AS (
    SELECT *, COUNT(*) OVER (
        PARTITION BY "User"
        ORDER BY time
        RANGE BETWEEN INTERVAL '300 seconds' PRECEDING AND CURRENT ROW
    ) AS correlation_event_count
    FROM source
)
SELECT * FROM event_counts WHERE correlation_event_count >= 5
```

This is the right format when you want per-event explanations of why a brute-force correlation fired, rather than a single aggregate row.

### Correlation window modes

A correlation rule can declare how its `timespan` is anchored to the event stream with the optional `window` attribute (`sliding`, `tumbling`, or `session`). The PostgreSQL backend renders the windowing strategy from this attribute, independent of the output format:

- `window` absent or `sliding`: the SQL is unchanged from before this attribute existed (the per-format aggregate, or the window-function form under `sliding_window`), so existing rules and queries are unaffected.
- `window: tumbling`: fixed, boundary-aligned buckets sized to the rule's `timespan`. On TimescaleDB this is `time_bucket('<timespan> seconds', time)`; on plain PostgreSQL it is `date_bin('<timespan> seconds', time, TIMESTAMPTZ 'epoch')`, both added to the `GROUP BY` alongside the group-by columns.
- `window: session`: a gaps-and-islands query. `LAG` flags the first event of each session (a gap larger than `gap`), a running `SUM` assigns a per-group `session_id`, and the aggregate is computed per session:

```sql
WITH source AS (SELECT * FROM security_events),
marked AS (
    SELECT *,
        CASE WHEN LAG(time) OVER (PARTITION BY "User" ORDER BY time) IS NULL
             OR time - LAG(time) OVER (PARTITION BY "User" ORDER BY time) > INTERVAL '30 seconds'
        THEN 1 ELSE 0 END AS is_new_session
    FROM source
),
sessions AS (
    SELECT *, SUM(is_new_session) OVER (
        PARTITION BY "User" ORDER BY time ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS session_id
    FROM marked
)
SELECT "User", session_id, COUNT(*) AS event_count,
    MIN(time) AS first_seen, MAX(time) AS last_seen
FROM sessions
GROUP BY "User", session_id
HAVING COUNT(*) >= 3 AND (MAX(time) - MIN(time)) <= INTERVAL '3600 seconds'
```

The `gap` is honored exactly. The `timespan` cap is enforced as the trailing `HAVING` filter, which drops sessions longer than the cap rather than splitting them mid-session as the runtime engine does; `rsigma backend convert` prints a warning to stderr noting this. Tumbling and session apply to every correlation type. For `temporal`/`temporal_ordered`, the combined detections (the `matched` CTE) are bucketed or sessionized and each window counts the distinct referenced rules with `COUNT(DISTINCT rule_name)`; order is not enforced for `temporal_ordered`, the same limitation as the default temporal path.

### Multi-table temporal correlations

When a `temporal` correlation references detection rules that target different tables (via per-logsource pipeline routing or the `postgres.table` custom attribute), the backend automatically generates a `UNION ALL` CTE:

```sql
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

When every referenced rule targets the same table, the backend emits the simpler single-table form. The multi-table form expects compatible column layouts (same columns in each `SELECT *`). If your tables differ, normalize them through pipeline field mappings or use a single-table approach with a discriminator column.

### OCSF pipelines

Two pipelines are included for OCSF-style schemas:

```bash
# Single-table: every event class goes to security_events
rsigma backend convert rules/ -t postgres -p pipelines/ocsf_postgres.yml

# Multi-table: per-logsource routing to process_events, network_events, etc.
rsigma backend convert rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml
```

Both are bundled in the repository at `crates/rsigma-convert/pipelines/`. They are good starting points; copy and customise them for your schema.

### Custom table per rule

Three layers of precedence control the target table, schema, and database, in this order:

1. Rule-level `custom_attributes` (`postgres.table`, `postgres.schema`, `postgres.database`).
2. Pipeline state (`set_state` with `key: table`, `key: schema`).
3. CLI backend options (`-O table=...`).
4. Backend defaults (`security_events`).

Rule-level wins. This lets you keep most rules on the default table while routing exceptions:

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

## LynxDB

The LynxDB backend produces SPL2-compatible queries. Translation favours the native search syntax and falls back to `| where` pipeline stages for features that LynxDB's parser does not support directly (regex, CIDR, single-character wildcards).

!!! tip "LynxDB's own Sigma guide"
    LynxDB maintains the canonical operator-facing guide for running Sigma rules on a LynxDB cluster, including the REST API path, saved queries, and end-to-end tutorials (whoami, bulk conversion, EVTX, CloudTrail, scheduled detection). See [Sigma rules on LynxDB](https://docs.lynxdb.org/docs/sigma/) and the linked subpages (compatibility, SPL2 mapping, pipelines, cookbook, troubleshooting, limitations, drift runbook). RSigma is the engine that emits the SPL2 in that flow.

| Sigma feature | LynxDB syntax |
|---------------|---------------|
| Field equality | `field=value`, `field="quoted"` |
| Wildcard `*` | `field=prefix*`, `field=*contains*` |
| Wildcard `?` | Deferred to a `where field=~"regex"` pipeline stage. |
| Regex (`re` modifier) | Deferred to a `where field=~"pattern"` pipeline stage. |
| CIDR (`cidr` modifier) | Deferred to a `where cidrmatch("cidr", field)` pipeline stage. |
| Case-sensitive (`cased` modifier) | `field=CASE(value)` |
| Boolean AND/OR/NOT | Explicit parenthesisation for LynxDB's non-standard precedence (`NOT > OR > AND`) |
| IN-list | `field IN (val1, val2, ...)` |

"Deferred" means the feature does not translate to a native LynxDB search term and is instead emitted as an SPL2 pipeline stage downstream of `search`.

```bash
rsigma backend convert rules/ -t lynxdb
```

Two output formats: `default` produces a full query with index prefix (`FROM main | search ...`), and `minimal` produces just the search expression for use as an API `q` parameter.

The target index defaults to `main`. Override it via pipeline state:

```yaml
transformations:
  - type: set_state
    key: index
    value: security_logs
```

```bash
rsigma backend convert rules/ -t lynxdb -p pipeline.yml
# Output: FROM security_logs | search ...
```

## Selecting columns with `fields:`

When a Sigma rule lists `fields:`, the backend emits `SELECT field1, field2, ...` instead of `SELECT *`. Function calls (e.g. `count(*)`) and `field as alias` are preserved. This gives you control over what each generated query returns without writing the SELECT clause by hand.

```yaml
title: Sad Puppy in Dog Supply Line
detection:
    selection:
        status: "sad"
    condition: selection
fields:
    - dog_name
    - dog_breed
    - status as current_state
```

```sql
SELECT "dog_name", "dog_breed", "status" AS "current_state"
FROM security_events
WHERE "status" ILIKE 'sad'
```

## Skipping unsupported rules

Not every rule in a large ruleset translates cleanly to every backend. Use `--skip-unsupported` to drop those rules silently and continue:

```bash
rsigma backend convert rules/ -t postgres --skip-unsupported
```

Without the flag, the first unsupported rule fails the run with exit code 2 (rule error). Use the [`rsigma rule fields`](../cli/rule/fields.md) command beforehand to audit which fields each rule depends on, before discovering at conversion time that one is unsupported by your pipeline.

## Saving output

`-o path/to/output.sql` writes to a file instead of stdout. Combine with `--skip-unsupported` for a one-shot pipeline build:

```bash
rsigma backend convert rules/ -t postgres -f view \
    -p pipelines/ocsf_postgres.yml \
    --skip-unsupported \
    -o /var/lib/rsigma/sql/views.sql
psql -f /var/lib/rsigma/sql/views.sql
```

## Workflow: from rules to a Grafana dashboard

A typical detection-engineering loop with the PostgreSQL backend:

1. Author rules in a Git-tracked directory.
2. CI runs `rsigma rule lint` and `rsigma rule validate` (see [Linting Rules](linting-rules.md) and [CI/CD](ci-cd.md)).
3. On merge to `main`, CI runs `rsigma backend convert -t postgres -f view -p pipelines/ocsf_postgres.yml` and commits the SQL into a deployment repository.
4. A Terraform or Atlas migration applies the generated `CREATE VIEW` statements to your PostgreSQL.
5. Grafana panels query the resulting views.
6. Alerting rules in Grafana Managed Alerting or in Prometheus query the same views (or the underlying tables) at scheduled intervals.

This avoids the impedance mismatch of running Sigma rules through pySigma at every alert evaluation. The conversion happens once per rule change, and your alerting infrastructure speaks plain SQL.

## See also

- [CLI reference: `backend convert`](../cli/backend/convert.md) for the full flag table.
- [Backends reference: PostgreSQL/TimescaleDB](../reference/backends/postgres.md) for every option, modifier mapping, and edge case.
- [Backends reference: LynxDB](../reference/backends/lynxdb.md) for SPL2 specifics.
- [Sigma rules on LynxDB](https://docs.lynxdb.org/docs/sigma/) for LynxDB-side guides covering compatibility, pipelines, the SPL2 mapping, and operational tutorials.
- [Processing Pipelines](processing-pipelines.md) for field mapping (essential for any non-default schema).
- [Linting Rules](linting-rules.md) for catching authoring mistakes before conversion.
