---
description: "RSigma PostgreSQL and TimescaleDB backend reference: convert Sigma rules to SQL, with output formats, backend options, correlations, and type mappings."
---

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
| `correlation_method` | unset | Windowing strategy for correlation rules (`sliding`/`tumbling`/`session`), overriding each rule's own `window`. See [Window modes](#window-modes). |
| `gap` | unset | Default session gap (e.g. `5m`) used when a session window is requested and the rule declares no `gap`. A rule's own `gap` wins. |

Pipeline `set_state` with keys `table`, `schema`, `database` overrides the corresponding `-O` option for the duration of one rule's conversion. Per-rule `custom_attributes` of `postgres.table`, `postgres.schema`, `postgres.database` override pipeline state. The full precedence chain is documented in [Custom Attributes](../custom-attributes.md#postgres-attributes).

## Modifier mapping

Every Sigma modifier is translated to a native PostgreSQL construct. The mapping is verified by the `postgres` backend's golden tests in [`crates/rsigma-convert/src/backends/postgres/tests.rs`](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/src/backends/postgres/tests.rs).

| Sigma modifier | PostgreSQL operator |
|----------------|---------------------|
| equality (no modifier) | `"field" ILIKE 'value'` (case-insensitive, with `%`, `_`, and `\` escaped so they match literally). A value without letters, such as `'4624'` or `'10.0.0.1'`, renders as `"field" = 'value'`, which matches the same rows and also works on an integer, `inet`, or timestamp column. A value with letters needs a text column. {{ added "0.24.0" }} |
| `contains` | `"field" ILIKE '%value%'` (case-insensitive) |
| `startswith` | `"field" ILIKE 'value%'` |
| `endswith` | `"field" ILIKE '%value'` |
| `cased` (any of the above) | switches `ILIKE` to `LIKE` (case-sensitive); a plain `cased` equality renders as `"field" = 'value'` |
| `re` | `"field" ~ 'pattern'` (case-sensitive, as the Sigma specification requires); `~*` with `\|i`. `\|m` adds the `(?w)` embedded option so `^` and `$` match at line breaks, merged into a leading options group such as `(?i)` because PostgreSQL reads only one. PostgreSQL's `.` matches a line break even without `\|s`, so a regex can over-match a multi-line value but never misses one. {{ added "0.24.0" }} |
| `cidr` | `("field")::inet <<= 'value'::cidr` |
| `exists: true` | `"field" IS NOT NULL`; `data->'field' IS NOT NULL` in [JSONB mode](#jsonb-mode) |
| `exists: false` | `"field" IS NULL`; `data->'field' IS NULL` in [JSONB mode](#jsonb-mode) |
| number, `lt`, `lte`, `gt`, `gte` | `"field" > 1000`; JSONB mode casts the text to `numeric` (see [JSONB mode](#jsonb-mode)) |
| boolean | `"field" = true`; `data->>'field' ILIKE 'true'` in JSONB mode |
| `all` | values combined with `AND` instead of the default `OR` |
| `fieldref` | `lower(("field")::text) = lower(("other")::text)` (case-insensitive); `"field" = "other"` with `cased` |
| `fieldref` with `contains` | `strpos(lower(("field")::text), lower(("other")::text)) > 0`. `startswith` uses `strpos(...) = 1`. `endswith` uses `right(("field")::text, char_length(("other")::text)) = ("other")::text`. `|cased` drops the `lower()` calls. `%` and `_` in the referenced value stay literal. {{ added "0.23.0" }} |
| `neq` | `("field" ILIKE 'value') IS NOT TRUE`, which also matches when the field is missing or null. A list negates the whole item: `("field" ILIKE 'a' OR "field" ILIKE 'b') IS NOT TRUE`. {{ added "0.24.0" }} |
| `fieldref` with `neq` | `(lower(("field")::text) = lower(("other")::text)) IS NOT TRUE AND "field" IS NOT NULL`. A missing referenced field still matches when the left field is present. {{ added "0.23.0" }} |
| `null` value | `"field" IS NULL` |
| keywords | `to_tsvector('simple', security_events::text) @@ plainto_tsquery('simple', 'value')` |

Keyword matching uses the `'simple'` text-search configuration (no language stemming) over the whole event: the JSONB column as text with `-O json_field=...`, or the table row as text otherwise, referenced by the unqualified table name. A `query_expression_placeholders` template that gives the table an alias hides that name, so keyword rules need the JSONB column or an unaliased table. The query matches the token against every column concatenated. This is intentionally broader than per-field FTS: keyword detections in Sigma are unbound, "search this string anywhere in the event". Full-text search matches whole tokens, not substrings, and the parser keeps file paths and host names such as `/dev/tcp/10.0.0.1/4444` and `mimikatz.exe` as single tokens, so a keyword that is only part of such a token does not match.

Nested conditions are parenthesized by SQL precedence (`NOT` > `AND` > `OR`): an `OR` under an `AND`, such as a value list in a selection that also tests another field, becomes `("Image" ILIKE '%\\a.exe' OR "Image" ILIKE '%\\b.exe') AND "CommandLine" ILIKE '%x%'`, and every negation, such as `not 1 of filter_*`, becomes `(... OR ...) IS NOT TRUE`. {{ added "0.24.0" }}

A comparison on a missing field is NULL in SQL, and `NOT NULL` is still NULL, so `NOT` would drop an event that Sigma matches: `selection and not filter` must match when the event lacks the field `filter` tests. `IS NOT TRUE` maps NULL to true, which matches Sigma and the rsigma engine. {{ added "0.24.0" }}

Field names are always double-quoted (`"CommandLine"`). String literals are always single-quoted with PostgreSQL-standard escaping (`'don''t'`). Identifiers passed through `-O table=...` are validated against `^[A-Za-z_][A-Za-z0-9_$]*$` before insertion; non-matching identifiers fail conversion with `InvalidIdentifier`. See [Security Hardening: SQL injection prevention](../security.md#sql-injection-prevention).

## Output formats

Pick the format with `-f <format>`. List available formats with [`backend formats postgres`](../../cli/backend/formats.md).

### `default`

Plain `SELECT * FROM <table> WHERE ...`, one per rule:

```sql
SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

Use for ad-hoc execution in `psql`, embedding into application code, or as the source for materialized views built elsewhere.

### `view`

Wraps each rule's query in `CREATE OR REPLACE VIEW sigma_<sanitized-id> AS SELECT ...`:

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

TimescaleDB refreshes the aggregate in the background; your dashboards query the materialized result instead of the raw hypertable.

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

Typed values need care because `->>` returns text. {{ added "0.24.0" }}

- A number or a `lt`/`lte`/`gt`/`gte` comparison casts the text to `numeric` only when it reads as a number of at most 100 digits on each side of the decimal point and a three-digit exponent, so a JSON number and a numeric string such as `"1500"` both compare numerically, as in the rsigma engine, and a value such as `"abc"` or `"9e999999"` compares as NULL instead of failing the whole query. Elements of a scalar array (`ports[any]: 4444`) get the same cast:

```sql
-- Sigma: ProcessId|gt: 1000
(CASE WHEN data->>'ProcessId' ~ '^[-+]?([0-9]{1,100}\.?[0-9]{0,100}|\.[0-9]{1,100})([eE][-+]?[0-9]{1,3})?$'
  THEN (data->>'ProcessId')::numeric END) > 1000
```

- A boolean compares the text case-insensitively (`data->>'Elevated' ILIKE 'true'`), which matches a JSON `true` and the string `"true"`, in a field or a scalar array element.
- `exists` tests the `->` (jsonb) form, which is SQL NULL only when the key is absent. A key whose value is JSON `null` exists, as Sigma requires. Flat columns cannot make this distinction, because a typed column stores an absent field and a null value as the same SQL NULL.

Each path segment is validated against the SQL identifier regex (`^[A-Za-z_][A-Za-z0-9_$]*$`) before insertion; malformed segments fail conversion. Single quotes inside path segments are doubled (`don''t`). See [Security Hardening](../security.md#sql-injection-prevention).

### Array matching

In JSONB mode the backend lowers the experimental [array matching](../../guide/array-matching.md) constructs:

- **Positional index** `field[N]` emits `->n`/`->>n`. Negative indices use PostgreSQL's native negative subscripts (`->-1`, PG 11+):

```sql
-- Sigma field: args[0]
data->'args'->>0
-- Sigma field: args[-1]  (last element)
data->'args'->>-1
```

- **Object-scope blocks** `field[any]:` and `field[all]:` emit an `EXISTS` over `jsonb_array_elements`, guarded by `jsonb_typeof(...) = 'array'`:

```sql
-- connections[any]: { protocol: TCP, ip|cidr: 123.1.0.0/16 }
(jsonb_typeof(data->'connections') = 'array' AND EXISTS (
  SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0
  WHERE __sigma_e0->>'protocol' ILIKE 'TCP'
    AND (__sigma_e0->>'ip')::inet <<= '123.1.0.0/16'::cidr))
```

`[all]` adds a non-empty guard and `NOT EXISTS (... WHERE (...) IS NOT TRUE)`, so an element that lacks a field the body tests fails the block. Because `[none]` and `[all_or_empty]` must match an empty or missing array, they lower to a `CASE` that only unnests an actual array and treats a missing/null value as a match:

```sql
-- containers[none]: { privileged: 'true' }
(CASE WHEN jsonb_typeof(data->'containers') = 'array'
  THEN NOT EXISTS (SELECT 1 FROM jsonb_array_elements(data->'containers') AS __sigma_e0
    WHERE __sigma_e0->>'privileged' ILIKE 'true')
  ELSE data->'containers' IS NULL OR jsonb_typeof(data->'containers') = 'null' END)
```

`[all_or_empty]` uses the same shape with `WHERE (...) IS NOT TRUE`.

An **extended** block body (a `condition:` plus named element-scoped sub-selections) lowers to the same primitive, with the condition compiled into the inner predicate as a boolean expression over the element (`AND`, `OR`, and `NOT`, grouped by SQL precedence):

```sql
-- connections[any]: { condition: in_cidr and not is_tcp, in_cidr: {ip|cidr: ...}, is_tcp: {protocol: TCP} }
(jsonb_typeof(data->'connections') = 'array' AND EXISTS (
  SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0
  WHERE (__sigma_e0->>'ip')::inet <<= '123.1.0.0/16'::cidr
    AND (__sigma_e0->>'protocol' ILIKE 'TCP') IS NOT TRUE))
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
| `temporal` | CTE: the referenced rules' hits selected from the source table in `WITH matched AS (SELECT * FROM <table> WHERE rule_name IN (...))`, then a `SELECT <group-by>, COUNT(DISTINCT rule_name) AS distinct_rules FROM matched HAVING ... >= N`. |
| `temporal_ordered` | The `temporal` query plus one CTE per referenced rule that takes the earliest hit of that rule at or after the previous rule's step, per group (`MIN(CASE WHEN rule_name = '<rule>' AND <ts> >= __step_<n-1> THEN <ts> END) OVER (PARTITION BY <group-by>)`). `HAVING ... AND MAX(__step_<last>) IS NOT NULL` keeps a group only when the rules hit in `rules` order; equal timestamps count as in order. {{ added "0.24.0" }} |

Non-temporal correlations that reference detection rules in the same collection auto-wrap the detection logic in `WITH combined_events AS (q1 UNION ALL q2 ...)`. A non-temporal correlation that references another correlation, or a detection rule that failed to convert, fails to convert, because there is no detection query to embed. {{ added "0.24.0" }} Multi-table temporal correlations (where referenced detection rules target different tables via pipeline routing) generate `UNION ALL` CTEs with a `rule_name` discriminator column.

### Window modes

A correlation rule's `window` attribute selects the windowing strategy, independent of the output format:

| `window` | Strategy |
|----------|----------|
| absent or `sliding` | Unchanged from before the attribute existed: the per-format aggregate (or the window-function form under `sliding_window`). |
| `tumbling` | Boundary-aligned buckets sized to the rule's `timespan`: `time_bucket('<timespan> seconds', <ts>)` on TimescaleDB, `date_bin('<timespan> seconds', <ts>, TIMESTAMPTZ 'epoch')` on plain PostgreSQL, added to the `GROUP BY`. |
| `session` | Gaps-and-islands: `LAG` marks the first event of each session (gap larger than `gap`), a running `SUM` assigns a per-group `session_id`, and the aggregate is grouped per session. |

Tumbling and session apply to every correlation type. For the aggregate types (`event_count`, `value_count`, `value_sum`, `value_avg`, `value_percentile`, `value_median`) the per-window aggregate is computed over the events; for `temporal`/`temporal_ordered` the combined detections are bucketed (tumbling) or sessionized (session) and each window counts the distinct referenced rules. `temporal_ordered` enforces the order within each bucket or session. {{ added "0.24.0" }}

For session windows the `gap` is honored exactly, but the `timespan` cap is enforced as a `HAVING (MAX(<ts>) - MIN(<ts>)) <= INTERVAL '<timespan> seconds'` filter, which drops sessions longer than the cap rather than splitting them mid-session as the runtime engine does. `rsigma backend convert` emits a stderr warning noting this approximation.

The strategy can also be chosen at conversion time with `-O correlation_method=NAME`, following pySigma's `correlation_methods` model. The backend advertises `sliding` (default), `tumbling`, and `session` (run `rsigma backend formats postgres` to list them); the option overrides a rule's own `window` for that conversion and is rejected if it is not one of the advertised methods. With no option, the rule's own `window` is used. For `correlation_method=session` over rules that declare no `gap`, pass `-O gap=5m` as the conversion default; a rule's own `gap` always wins over the option.

Unlike the sliding queries, tumbling and session queries carry no `NOW() - INTERVAL` bound (their windows derive from the data, and a session may extend arbitrarily far back), so they scan the whole table or view they run against. Schedule them against time-partitioned tables (hypertables) or bound the source with a view to keep scan costs predictable.

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

Both are starting points; copy and customize for your schema.

Encoding modifiers (`windash`, `wide`, `utf16le`, `utf16be`, `utf16`, `base64`, `base64offset`) convert to an OR of one `ILIKE` (or `=`) per encoded variant, as pySigma does. PostgreSQL text cannot hold a NUL character, so a UTF-16 encoding without a following `base64` or `base64offset` fails with `UnsupportedValue`. {{ added "0.24.0" }} There is no `prepared` output format today.

## Executing hunts

[`rsigma hunt run`](../../cli/hunt/run.md) converts detection rules with this backend's `default` format and executes the wrapped query read-only against your archive, streaming matching rows back as exemplar-shaped NDJSON. The `-O` options above (`table`, `schema`, `json_field`, `timestamp_field`) pass through unchanged; the wrapper adds `--since`/`--until` predicates on the `timestamp_field`, `ORDER BY`, and `--limit`. In JSONB mode the `json_field` column is emitted verbatim as the event; flat-column rows are reconstructed into JSON keys. Correlation rules are not huntable (aggregate rows, not events); convert them and run the SQL manually. See [Hunting in the archive](../../guide/hunting.md) for the workflow.

## See also

- [Rule Conversion](../../guide/rule-conversion.md) for the workflow walkthrough.
- [`backend convert`](../../cli/backend/convert.md) for the CLI flag table.
- [Custom Attributes](../custom-attributes.md) for `postgres.*` per-rule overrides.
- [LynxDB backend reference](lynxdb.md) for the alternate target.
- [Security Hardening](../security.md#sql-injection-prevention) for identifier validation and escape rules.
- [`crates/rsigma-convert/src/backends/postgres`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-convert/src/backends/postgres) for the implementation.
