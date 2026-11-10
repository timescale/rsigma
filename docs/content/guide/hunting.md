---
description: "Threat hunt with Sigma rules in your PostgreSQL or TimescaleDB log archive using rsigma hunt run, and stream the matching rows back as NDJSON exemplars."
---

# Hunting in the Archive

{{ added "0.22.0" }}

`rsigma hunt run` closes the bottom arrow of the [detection-engineering loop](detection-engineering-loop.md): a hunt takes a detection rule, runs it against the PostgreSQL/TimescaleDB archive your telemetry already lands in, and streams the matching rows back as exemplar-shaped NDJSON that every downstream authoring tool already reads.

The boundary is deliberate: rsigma does not store or search logs. The logs stay in your store; rsigma is a read-only client of a store it already generates queries for and whose SQL dialect it owns via the [PostgreSQL backend](../reference/backends/postgres.md). It has no index, retention, or query language of its own.

## Workflow

```bash
# 1. Review the query without connecting (works in every build).
rsigma hunt run -r hunts/suspicious_curl.yml -t postgres \
    -O table=security_events --since 7d --emit sql

# 2. Run the hunt read-only, streaming matches to an exemplar file.
rsigma hunt run -r hunts/suspicious_curl.yml -t postgres \
    --dsn postgres://hunter@archive.example/siem \
    --since 7d -o hunted.ndjson

# 3. Feed the exemplars to the authoring tools.
rsigma rule draft -e @hunted.ndjson
rsigma rule tune -r rules/ --rule <id> --fp @false-positives.ndjson --tp @hunted.ndjson
rsigma rule backtest -r rules/ --corpus hunted.ndjson
```

Each line of the output is one raw JSON event object; per-rule row counts, warnings, and the final summary (rows, elapsed, truncation) go to stderr, so stdout pipes cleanly into files and other tools. When `--limit` (default 1000 per rule) is hit, stderr says so: a truncated hunt is never mistaken for a complete one.

## Field names: no reverse mapping

Hunt output events carry the archive's *native* field names, because the pipeline mapped the rule's fields to the archive's columns before conversion. Consume the output downstream **without** re-applying the mapping pipeline; `rule draft` and friends mine the exemplars' native field names, which is exactly what the archive produced.

## Flat tables vs JSONB

Two archive layouts are supported, selected by the backend's `-O` options:

- **Flat-column tables** (the reference `security_events` layout): each non-NULL column becomes a JSON key. `timestamptz` becomes an RFC 3339 string, `inet` a string, ints/floats numbers, `jsonb` is inlined. NULL columns are dropped so presence-based mining downstream is not skewed by the wide table's mostly-NULL category columns.
- **JSONB tables** (`-O json_field=data`): the stored document *is* the original event and is emitted verbatim, with the timestamp column merged under its column name when the body lacks one. Round-trip fidelity is exact by construction; prefer this layout when you control the schema.

## Safety posture

- **Read-only is enforced by the session.** The session opens with `SET default_transaction_read_only = on` and `SET statement_timeout = <timeout>` before any hunt SQL runs, so even a buggy generated query cannot write and a pathological scan is bounded server-side. A dedicated read-only role for the DSN is still recommended defense in depth.
- **DSN hygiene.** The connection string comes from `--dsn` or `RSIGMA_HUNT_DSN` (keeping the password out of `ps aux` and shell history). Logs and errors render a DSN rebuilt from the non-secret fields; the password never appears.
- **TLS from the start.** rustls with the system root store; `sslmode` in the DSN is honored (`disable`, `prefer` with plaintext fallback, `require`).

## Scope and alternatives

`hunt run` is a one-shot batch operation: it is not a daemon endpoint, not a scheduled job, and it does not label exemplars (deciding which matches are true positives is the operator's job, or `rule tune`'s verification loop's).

- **Correlation rules** return aggregate rows (group keys plus counts), not events, and are rejected with a pointed error. Convert with `backend convert -t postgres` and run the query manually.
- **Non-postgres targets** stay convert-only: delegated sigma-cli targets by definition (rsigma cannot execute a Splunk query), and other native backends either emit rules rather than queries (Fibratus) or lack a hunt client. The error points at `backend convert -t <target>`, which remains the way to reach Splunk, Elasticsearch, Sentinel, and the rest of the pySigma ecosystem.
- **Grafana-side hunting** (running generated queries inside Grafana against configured data sources) shares the same wrapped-SQL builder; `--emit sql` is the portable artifact between the two.

## See also

- [CLI reference: `hunt run`](../cli/hunt/run.md) for the full flag table.
- [Rule Conversion](rule-conversion.md) for the convert-side workflow this builds on.
- [Rule Drafting](rule-drafting.md), [Rule Tuning](rule-tuning.md), and [Verdict-Driven Corpora](verdict-to-corpus.md) for the exemplar consumers.
- [PostgreSQL backend reference](../reference/backends/postgres.md) for JSONB mode and the `-O` options.
