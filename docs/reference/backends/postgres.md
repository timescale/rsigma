# PostgreSQL/TimescaleDB Backend

The `postgres` backend (aliases: `postgresql`, `pg`) converts Sigma rules into PostgreSQL SQL, with optional TimescaleDB-specific extensions. It is the most fully featured of the conversion backends and the default choice for SOCs running PostgreSQL or TimescaleDB as their log store.

For the narrative version with workflow recipes (PostgreSQL view per rule, Grafana wiring, sliding-window correlations) see [Rule Conversion](../../guide/rule-conversion.md). For the CLI surface see [`backend convert`](../../cli/backend/convert.md), [`backend targets`](../../cli/backend/targets.md), [`backend formats`](../../cli/backend/formats.md).

## Backend options

Pass options via `-O key=value` on the command line. Unknown keys are silently ignored so forward-compatible options can land without breaking existing invocations.

| Option | Default | Effect |
|--------|---------|--------|
| `table` | `security_events` | Default table name. Overridden by pipeline `set_state` and per-rule `postgres.table` custom attribute. |
| `schema` | unset | PostgreSQL schema. Final reference becomes `schema.table`. |
| `database` | unset | Connection-level metadata used by some output formats. |
| `timestamp_field` | `time` | Column used for time-windowed queries (correlation `timespan`, `time_bucket` in TimescaleDB mode). |
| `json_field` | unset | When set, fields are accessed via JSONB extraction. See [JSONB mode](#jsonb-mode). |
| `case_sensitive_re` | `false` | Use `~` instead of `~*` for regex. Setting to `true` makes regex matches case-sensitive globally. |

Pipeline `set_state` with keys `table`, `schema`, `database` overrides the corresponding `-O` option for the duration of one rule's conversion. Per-rule `custom_attributes` of `postgres.table`, `postgres.schema`, `postgres.database` override pipeline state. The full precedence chain is documented in [Custom Attributes](../custom-attributes.md#postgres-attributes).

## Modifier mapping

Every Sigma modifier is translated to a native PostgreSQL construct. The mapping is verified by the `postgres` backend's golden tests in [`crates/rsigma-convert/src/backends/postgres/tests.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/src/backends/postgres/tests.rs).

| Sigma modifier | PostgreSQL operator |
|----------------|---------------------|
| equality (no modifier) | `"field" = 'value'` |
| `contains` | `"field" ILIKE '%value%'` (case-insensitive) |
| `startswith` | `"field" ILIKE 'value%'` |
| `endswith` | `"field" ILIKE '%value'` |
| `cased` (any of the above) | switches `ILIKE` to `LIKE` (case-sensitive) |
| `re` | `"field" ~* 'pattern'` (case-insensitive regex); `~` with `cased` or with `case_sensitive_re=true` backend option |
| `cidr` | `("field")::inet <<= 'value'::cidr` |
| `exists: true` | `"field" IS NOT NULL` |
| `exists: false` | `"field" IS NULL` |
| `all` | values combined with `AND` instead of the default `OR` |
| `null` value | `"field" IS NULL` |
| keywords | `to_tsvector('simple', ROW(*)::text) @@ plainto_tsquery('simple', 'value')` |

Keyword matching uses the `'simple'` text-search configuration (no language stemming) over `ROW(*)::text`, so the query matches the token against every column concatenated. This is intentionally broader than per-field FTS: keyword detections in Sigma are unbound, "search this string anywhere in the event".

Field names are always double-quoted (`"CommandLine"`). String literals are always single-quoted with PostgreSQL-standard escaping (`'don''t'`). Identifiers passed through `-O table=...` are validated against `^[A-Za-z_][A-Za-z0-9_$]*$` before insertion; non-matching identifiers fail conversion with `InvalidIdentifier`. See [Security Hardening: SQL injection prevention](../security.md#sql-injection-prevention).

## Output formats

Pick the format with `-f <format>`. List available formats with [`backend formats postgres`](../../cli/backend/formats.md).

### `default`

Plain `SELECT * FROM <table> WHERE ...`, one per rule:

```sql
SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

Use for ad-hoc execution in `psql`, embedding into application code, or as the source for materialised views built elsewhere.

### `view`

Wraps each rule's query in `CREATE OR REPLACE VIEW sigma_<sanitised-id> AS SELECT ...`:

```sql
CREATE OR REPLACE VIEW sigma_8b1d8c97_5b3a_4d77_9b48_7c5f7c8b1a2a AS
    SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

Useful for dashboards: each rule becomes a named view that Grafana, Superset, or any SQL client can query without parsing rsigma's SQL. Combine with a CI pipeline that runs `backend convert -f view ... > views.sql` and `psql -f views.sql` to keep the database in sync with the rule repo.

### `timescaledb`

Adds `time_bucket('1 hour', <timestamp_field>) AS bucket` to the projection. Use when your events sit on a TimescaleDB hypertable:

```sql
SELECT time_bucket('1 hour', time) AS bucket, *
    FROM security_events WHERE "EventID" = 4625
```

### `continuous_aggregate`

Wraps each detection rule in `CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous) AS ... WITH NO DATA`:

```sql
CREATE MATERIALIZED VIEW sigma_9d2e7c48_4a3b_4f99_93c9_1c5f7c8b1a2a
    WITH (timescaledb.continuous) AS
    SELECT time_bucket('1 hour', time) AS bucket, *
    FROM security_events WHERE "EventID" = 4625
    WITH NO DATA
```

TimescaleDB refreshes the aggregate in the background; your dashboards query the materialised result instead of the raw hypertable.

The format applies to base detection rules. Correlation rules are not the right shape for continuous aggregates; convert them separately with `default` or `sliding_window`.

### `sliding_window`

Uses SQL window functions for `event_count` correlations, producing a per-row sliding window that emits every event crossing the threshold:

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

Use when you want per-event explanations of why a brute-force correlation fired (every row above the threshold appears in the output, not just a single aggregate row). Base detection rules return `unknown output format: sliding_window` and must be skipped with `--skip-unsupported`.

## JSONB mode

Setting `-O json_field=data` (or pipeline `set_state` `key: json_field`) switches the backend from bare column references to JSONB extraction. Useful when events land in a single JSONB column (Okta logs, CloudTrail, OCSF, any "blob" shape).

Top-level fields use `->>` (returns `text`):

```sql
-- Sigma field: eventType
data->>'eventType'
```

Dotted field paths emit chained operators. Every intermediate segment uses `->` (returns `jsonb`); the final segment uses `->>` (returns `text`):

```sql
-- Sigma field: securityContext.isProxy
data->'securityContext'->>'isProxy'

-- Sigma field: actor.detail.alternateId
data->'actor'->'detail'->>'alternateId'
```

Each path segment is validated against the SQL identifier regex (`^[A-Za-z_][A-Za-z0-9_$]*$`) before insertion; malformed segments fail conversion. Single quotes inside path segments are doubled (`don''t`). See [Security Hardening](../security.md#sql-injection-prevention).

### Array matching

In JSONB mode the backend lowers the experimental [array matching](../../guide/array-matching.md) constructs:

- **Positional index** `field[N]` emits `->n` / `->>n`. Negative indices use PostgreSQL's native negative subscripts (`->-1`, PG 11+):

```sql
-- Sigma field: args[0]
data->'args'->>0
-- Sigma field: args[-1]  (last element)
data->'args'->>-1
```

- **Object-scope blocks** `field[any]:` / `field[all]:` emit an `EXISTS` over `jsonb_array_elements`, guarded by `jsonb_typeof(...) = 'array'`:

```sql
-- connections[any]: { protocol: TCP, ip|cidr: 123.1.0.0/16 }
(jsonb_typeof(data->'connections') = 'array' AND EXISTS (
  SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0
  WHERE __sigma_e0->>'protocol' = 'TCP'
    AND (__sigma_e0->>'ip')::inet <<= '123.1.0.0/16'::cidr))
```

`[all]` adds a non-empty guard and `NOT EXISTS (... WHERE NOT (...))`. Because `[none]` and `[all_or_empty]` must match an empty or missing array, they lower to a `CASE` that only unnests an actual array and treats a missing/null value as a match:

```sql
-- containers[none]: { privileged: 'true' }
(CASE WHEN jsonb_typeof(data->'containers') = 'array'
  THEN NOT EXISTS (SELECT 1 FROM jsonb_array_elements(data->'containers') AS __sigma_e0
    WHERE __sigma_e0->>'privileged' = 'true')
  ELSE data->'containers' IS NULL OR jsonb_typeof(data->'containers') = 'null' END)
```

`[all_or_empty]` uses the same shape with `WHERE NOT (...)`.

An **extended** block body (a `condition:` plus named element-scoped sub-selections) lowers to the same primitive, with the condition compiled into the inner predicate as a boolean expression over the element (`OR`, and a parenthesized `NOT`):

```sql
-- connections[any]: { condition: in_cidr and not is_tcp, in_cidr: {ip|cidr: ...}, is_tcp: {protocol: TCP} }
(jsonb_typeof(data->'connections') = 'array' AND EXISTS (
  SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0
  WHERE (__sigma_e0->>'ip')::inet <<= '123.1.0.0/16'::cidr
    AND NOT (__sigma_e0->>'protocol' = 'TCP')))
```

Array matching requires JSONB mode; in flat-column mode the backend reports `UnsupportedArrayMatching`.

## Correlation rules

The backend handles every aggregation type:

| Correlation type | Strategy |
|------------------|----------|
| `event_count` | `GROUP BY <group-by> HAVING COUNT(*) >= N`. With `sliding_window` format, uses `COUNT(*) OVER (PARTITION BY ... ORDER BY <ts> RANGE BETWEEN INTERVAL '<timespan>' PRECEDING AND CURRENT ROW)`. |
| `value_count` | `GROUP BY <group-by> HAVING COUNT(DISTINCT <field>) >= N`. |
| `value_sum` | `GROUP BY ... HAVING SUM(<field>) >= N`. |
| `value_avg` | `GROUP BY ... HAVING AVG(<field>) >= N`. |
| `value_percentile` | `GROUP BY ... HAVING PERCENTILE_CONT(p) WITHIN GROUP (ORDER BY <field>) >= N`. |
| `value_median` | Same as `value_percentile` with `p = 0.5`. |
| `temporal` | CTE: base detections matched in one `WITH combined_events AS (...)`, then a `SELECT <group-by>, COUNT(DISTINCT rule_name) AS distinct_rules FROM combined HAVING ... >= N`. |
| `temporal_ordered` | Roadmap: `LAG()`/`LEAD()` based ordering. Not yet implemented. |

Non-temporal correlations that reference detection rules in the same collection auto-wrap the detection logic in `WITH combined_events AS (q1 UNION ALL q2 ...)`. Multi-table temporal correlations (where referenced detection rules target different tables via pipeline routing) generate `UNION ALL` CTEs with a `rule_name` discriminator column.

### Window modes

A correlation rule's `window` attribute selects the windowing strategy, independent of the output format:

| `window` | Strategy |
|----------|----------|
| absent or `sliding` | Unchanged from before the attribute existed: the per-format aggregate (or the window-function form under `sliding_window`). |
| `tumbling` | Boundary-aligned buckets sized to the rule's `timespan`: `time_bucket('<timespan> seconds', <ts>)` on TimescaleDB, `date_bin('<timespan> seconds', <ts>, TIMESTAMPTZ 'epoch')` on plain PostgreSQL, added to the `GROUP BY`. |
| `session` | Gaps-and-islands: `LAG` marks the first event of each session (gap larger than `gap`), a running `SUM` assigns a per-group `session_id`, and the aggregate is grouped per session. |

Tumbling and session apply to every correlation type. For the aggregate types (`event_count`, `value_count`, `value_sum`, `value_avg`, `value_percentile`, `value_median`) the per-window aggregate is computed over the events; for `temporal`/`temporal_ordered` the combined detections are bucketed (tumbling) or sessionized (session) and each window counts the distinct referenced rules. Order is not enforced for `temporal_ordered`, matching the default temporal path.

For session windows the `gap` is honored exactly, but the `timespan` cap is enforced as a `HAVING (MAX(<ts>) - MIN(<ts>)) <= INTERVAL '<timespan> seconds'` filter, which drops sessions longer than the cap rather than splitting them mid-session as the runtime engine does. `rsigma backend convert` emits a stderr warning noting this approximation.

## Custom attributes

The backend reads three per-rule attributes from `custom_attributes:`:

| Attribute | Effect |
|-----------|--------|
| `postgres.table` | Per-rule table override. Highest precedence. |
| `postgres.schema` | Per-rule schema override. |
| `postgres.database` | Per-rule database metadata. |

See [Custom Attributes](../custom-attributes.md#postgres-attributes) for the precedence chain.

## OCSF pipelines

Two pipelines ship with `rsigma-convert` for Open Cybersecurity Schema Framework deployments:

| Pipeline | What it does |
|----------|--------------|
| [`pipelines/ocsf_postgres.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/pipelines/ocsf_postgres.yml) | Single-table: every event class routes to `security_events`. |
| [`pipelines/ocsf_postgres_multi_table.yml`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/pipelines/ocsf_postgres_multi_table.yml) | Per-logsource routing: `process_events`, `network_events`, `dns_events`, etc. |

Both are starting points; copy and customise for your schema.

## Roadmap

Tracked items not yet implemented:

- `temporal_ordered` correlation via `LAG()`/`LEAD()`.
- `prepared` output format that emits PL/pgSQL-friendly placeholders for parameter binding.
- Value modifier transforms (`base64`, `base64offset`, `wide`, `utf16le`) — currently fail with `Unsupported`. Most workloads do not need these because they can be preprocessed at ingest by the agent.

These are tracked on the project roadmap and are not blocking any current user.

## See also

- [Rule Conversion](../../guide/rule-conversion.md) for the workflow walkthrough.
- [`backend convert`](../../cli/backend/convert.md) for the CLI flag table.
- [Custom Attributes](../custom-attributes.md) for `postgres.*` per-rule overrides.
- [LynxDB backend reference](lynxdb.md) for the alternate target.
- [Security Hardening](../security.md#sql-injection-prevention) for identifier validation and escape rules.
- [`crates/rsigma-convert/src/backends/postgres`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/postgres) for the implementation.
