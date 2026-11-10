---
description: "Reference for rsigma hunt run: convert Sigma rules to SQL, run them read-only against a PostgreSQL or TimescaleDB log archive, and stream matches as NDJSON."
---

# `rsigma hunt run`

{{ added "0.22.0" }}

Convert detection rules with the PostgreSQL backend, execute the query read-only against a log archive, and stream the matching rows back as exemplar-shaped NDJSON events.

## Synopsis

```text
rsigma hunt run [OPTIONS] --target postgres --rules <PATH>...
```

## Description

`hunt run` closes the loop between conversion and authoring: `backend convert -t postgres` emits the SQL, and this command runs it against your PostgreSQL/TimescaleDB archive and returns the matching rows as one raw JSON event object per line, ready to feed [`rule draft`](../rule/draft.md), [`rule tune`](../rule/tune.md), [`rule test`](../rule/test.md) exemplars, or a [`rule backtest`](../rule/backtest.md) corpus.

rsigma is a read-only client of a store it already generates queries for; it does not store or search logs itself. The session opens with `SET default_transaction_read_only = on` and a server-side statement timeout before any hunt SQL runs, so the server enforces read-only access. Rows stream without OFFSET paging, so memory is bounded by one row regardless of result size.

The generated per-rule `SELECT` is wrapped, never edited:

```sql
SELECT * FROM (<generated>) AS __hunt
WHERE <timestamp_field> >= '<since>' AND <timestamp_field> < '<until>'
ORDER BY <timestamp_field>
LIMIT <n>
```

Only the `WHERE`/`ORDER BY`/`LIMIT` wrapper is hunt-owned SQL. Note that `ORDER BY <timestamp_field>` is not deterministic on timestamp ties; for exemplar harvesting that is acceptable and no synthetic tiebreaker is invented. A rule's `fields:` list is cleared before conversion: hunts want whole rows, and a declared projection would both starve the exemplar contract in flat mode and replace the raw `json_field` column with extractions in JSONB mode.

### Row-to-event reshaping

- **JSONB mode** (`-O json_field=data`) is the high-fidelity path: the stored column *is* the original event, so it is emitted verbatim, merging the timestamp column under its column name when the event body lacks one (the body's value wins on conflict, with a one-time note on stderr).
- **Flat-column mode** reconstructs the event from the row: each non-NULL column becomes a JSON key named by the column. `timestamptz`/`timestamp` become RFC 3339 strings, `inet` becomes a string, integer and float types become numbers, `numeric` becomes a number when the value round-trips through a double exactly and the exact decimal string otherwise, `bool` stays boolean, `jsonb` is inlined as its JSON value. NULL columns are dropped rather than emitted as `null`, because the reference schema is a wide single-landing-table where most category-specific columns are NULL for any given event. Columns of a type with no decoder (e.g. `tsvector`) are skipped with a one-time stderr warning naming the column and type.

The columns are post-pipeline names (the pipeline mapped the rule's fields to the archive's columns before conversion), so hunt output events carry the archive's native field names. Consume them downstream *without* re-applying the mapping pipeline.

### Scope

Hunts run detection rules only. Correlation rules are rejected with an error, because correlation SQL returns aggregate rows (group keys plus counts) instead of events. `--target postgres` is the only accepted value; every other target stays convert-only (delegated sigma-cli targets by definition, since rsigma cannot execute a Splunk query), and the error points at `backend convert`.

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-r, --rules <PATH>...` | Sigma rule file(s) or director(ies) to hunt with. Repeatable. |
| `-t, --target <TARGET>` | Hunt target. Only `postgres` (aliases `postgresql`, `pg`) is executable. |

### Connection

| Flag | Default | Description |
|------|---------|-------------|
| `--dsn <DSN>` | `$RSIGMA_HUNT_DSN` | PostgreSQL connection string (URL or keyword form). Required for `--emit events`. The password is never rendered in logs or errors; messages show a DSN rebuilt from the non-secret fields. `sslmode` is honored (`disable`, `prefer` with plaintext fallback, `require`); TLS uses rustls with the system root store. A dedicated read-only role is recommended but not relied upon. |
| `--timeout <DURATION>` | `60s` | Server-side `statement_timeout` for the hunt session, rendered as an integer millisecond literal. Must be between `1ms` and `2147483647ms` (a sub-millisecond value would truncate to `0`, which disables the server timeout). Validated on every path, including `--emit sql`. |

### Query shaping

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pipeline <PIPELINE>` | none | Processing pipeline(s) (repeatable). Builtin names or YAML file paths, same as [`backend convert`](../backend/convert.md). |
| `-O, --option <KEY=VALUE>` | none | Backend options (repeatable): `table`, `schema`, `json_field`, `timestamp_field`. See the [PostgreSQL backend reference](../../reference/backends/postgres.md). |
| `--since <WHEN>` | none | Window start: an RFC 3339 instant or a duration relative to now (`30m`, `12h`, `7d`). |
| `--until <WHEN>` | none | Window end (exclusive). Same syntax as `--since`; a duration is relative to now, so `--until 1h` means "up to one hour ago". |
| `--limit <N>` | `1000` | Maximum rows per rule. `0` means unbounded. Hitting the limit is reported on stderr so a truncated hunt is never mistaken for a complete one. |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--emit <MODE>` | `events` | `events` streams NDJSON; `sql` prints the wrapped queries with attribution headers and exits without connecting (works in every build, including binaries without the `hunt-postgres` feature). |
| `-o, --output <PATH>` | stdout | Write events (or SQL) to a file instead of stdout. In events mode the file opens on the first event (or, for a successful hunt with no matches, at completion), so a hunt that fails before producing output never clobbers an existing file. |

Events are always NDJSON: one raw JSON event object per line, nothing else on stdout. Per-rule row counts and the final summary (rows, elapsed, truncation) go to stderr and honor `--quiet` and `--no-stats`.

## Examples

### Hunt the last 30 days into an exemplar file

```bash
rsigma hunt run -r rules/suspicious_curl.yml -t postgres \
    --dsn postgres://hunter@archive.example/siem \
    --since 30d -o hunted.ndjson
```

### Review the SQL without connecting

```bash
rsigma hunt run -r rules/ -t postgres -O table=okta_events -O json_field=data \
    --since 2026-07-01T00:00:00Z --emit sql
```

```sql
-- timestamp_field: time
-- json_field: data
-- rule: Suspicious Curl (id: 00000000-0000-0000-0000-000000000201)
SELECT * FROM (SELECT * FROM okta_events WHERE data->>'Image' ILIKE '/usr/bin/curl') AS __hunt WHERE time >= '2026-07-01T00:00:00+00:00'::timestamptz ORDER BY time LIMIT 1000;
```

### Feed a draft

```bash
rsigma hunt run -r hunts/okta_group_add.yml -t postgres --since 7d -o /tmp/tp.ndjson
rsigma rule draft -e @/tmp/tp.ndjson
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The hunt ran; events (or SQL) were emitted. |
| `2` | A rule failed to load or convert, a correlation rule was passed, or a rule produced non-`SELECT` output. |
| `3` | Bad flags or options (unknown target, empty window, invalid identifier or time bound), missing DSN, a binary built without `hunt-postgres`, or a connection/execution failure against the archive. |

## See also

- [Hunting in the archive](../../guide/hunting.md) for the hunt-to-exemplar workflow end to end.
- [PostgreSQL backend reference](../../reference/backends/postgres.md) for the `-O` options and JSONB mode.
- [`backend convert`](../backend/convert.md) for convert-only targets.
- [Feature flags](../../reference/feature-flags.md) for the `hunt-postgres` gate; [Environment variables](../../reference/environment-variables.md) for `RSIGMA_HUNT_DSN`.
