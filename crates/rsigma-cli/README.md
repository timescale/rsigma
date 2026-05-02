# rsigma

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma` is a command-line interface for parsing, validating, linting, evaluating, converting, and running [Sigma](https://github.com/SigmaHQ/sigma) detection rules as a long-running daemon.

This binary is part of the [rsigma workspace].

## Installation

```bash
cargo install rsigma
```

## Quick Start

```bash
# Single event (inline JSON)
rsigma eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# Long-running daemon with hot-reload, health checks, and Prometheus metrics
hel run | rsigma daemon -r rules/ -p ecs.yml --api-addr 0.0.0.0:9090

# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'

# Convert rules to backend-native queries
rsigma convert -r rules/ -t test

# Convert to PostgreSQL SQL
rsigma convert -r rules/ -t postgres

# List available conversion backends
rsigma list-targets
```

## Subcommands

### `parse`: Parse a single rule

Parse a Sigma YAML file and output the AST as JSON.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a Sigma YAML file |
| `--pretty` / `-p` | flag | **true** | Pretty-print JSON output |

```bash
rsigma parse rule.yml            # print AST as pretty-printed JSON
rsigma parse rule.yml --pretty   # same (default)
```

Note: pretty-print is on by default and cannot be disabled.

### `validate`: Validate rules in a directory

Parse and compile all rules in a directory, reporting errors.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a directory of Sigma YAML files |
| `--verbose` / `-v` | flag | `false` | Show details for each file (parse errors, compile errors) |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s) to apply before compilation |

```bash
rsigma validate path/to/rules/ -v              # verbose output
rsigma validate rules/ -p pipelines/ecs.yml    # validate with pipeline
```

### `lint`: Lint rules against the Sigma specification

Run 66 built-in lint rules with optional JSON schema validation.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a Sigma rule file or directory |
| `--schema` / `-s` | string | none | `"default"` to download the official schema (cached 7 days), or a path to a local JSON schema file |
| `--verbose` / `-v` | flag | `false` | Show details for all files, including those that pass |
| `--color` | string | `"auto"` | `auto`, `always`, or `never` |
| `--disable` | string | `""` | Comma-separated lint rule IDs to suppress |
| `--config` | path | none | Explicit path to `.rsigma-lint.yml` (otherwise auto-discovered by walking ancestor directories) |
| `--exclude` | string | none | Glob pattern for paths to skip (repeatable, relative to lint root) |
| `--fix` | flag | `false` | Automatically apply safe fixes (lowercase keys, correct typos, remove duplicates, etc.) |

```bash
rsigma lint path/to/rules/                     # lint all rules
rsigma lint path/to/rules/ -v                  # verbose (show passing files + info-only)
rsigma lint path/to/rules/ --schema default    # + JSON schema validation (downloads + caches)
rsigma lint rule.yml --schema my-schema.json   # local JSON schema
rsigma lint path/to/rules/ --color always      # force color
rsigma lint rules/ --disable missing_description,missing_author  # suppress specific rules
rsigma lint rules/ --config my-lint.yml        # explicit config file
rsigma lint rules/ --exclude "config/**"       # skip non-rule files
rsigma lint rules/ --exclude "config/**" --exclude "**/unsupported/**"  # multiple patterns
rsigma lint rules/ --fix                       # auto-fix safe issues
```

**Lint output summary format:**

```
Checked N file(s): X passed, Y failed (A error(s), B warning(s), C info(s))
```

**Schema validation skips** documents with `action: global`, `action: reset`, or `action: repeat` (action fragments).

### `daemon`: Run as a long-running detection service

Run rsigma as a long-running daemon that continuously reads NDJSON from stdin, evaluates against rules, writes matches to stdout, and exposes health/metrics/management APIs over HTTP.

Unlike `eval`, the daemon stays alive after stdin reaches EOF and supports hot-reload: adding, modifying, or removing `.yml`/`.yaml` files in the rules directory triggers an automatic reload. SIGHUP and the `/api/v1/reload` endpoint also trigger reloads. The daemon is designed for production deployment behind a log collector (e.g. `hel run | rsigma daemon ...`) or an event bus.

> [!TIP]
> Correlation rules also work in `eval` mode within a single run (via stdin or `@file`), but daemon mode is recommended for continuous stateful tracking with hot-reload and state persistence.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--rules` / `-r` | path | required | Path to Sigma rule file or directory |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s), applied in priority order |
| `--input` | string | `"stdin"` | Event input source: `stdin`, `http`, or `nats://<host>:<port>/<subject>` |
| `--output` | repeatable | `["stdout"]` | Detection output sink (fan-out): `stdout`, `file://<path>`, `nats://<host>:<port>/<subject>` |
| `--input-format` | string | `"auto"` | Input log format: `auto`, `json`, `syslog`, `plain`, `logfmt`\*, `cef`\* |
| `--syslog-tz` | string | `"+00:00"` | Default timezone for RFC 3164 syslog (e.g. `+05:00`, `-08:00`) |
| `--jq` | string | none | jq filter to extract event payload (conflicts with `--jsonpath`) |
| `--jsonpath` | string | none | JSONPath (RFC 9535) query (conflicts with `--jq`) |
| `--include-event` | flag | `false` | Include full event JSON in each detection match |
| `--pretty` | flag | `false` | Pretty-print JSON output |
| `--api-addr` | string | `0.0.0.0:9090` | Address for health, metrics, and management API server |
| `--suppress` | string | none | Suppression window for correlation alerts (e.g. `5m`, `1h`) |
| `--action` | string | none | `alert` or `reset`, the action taken after correlation fires |
| `--no-detections` | flag | `false` | Suppress detection-level output (only show correlation alerts) |
| `--correlation-event-mode` | string | `"none"` | `none`, `full`, or `refs` |
| `--max-correlation-events` | integer | **10** | Max events stored per correlation window |
| `--timestamp-field` | repeatable | `[]` | Event field(s) for timestamp extraction |
| `--buffer-size` | integer | **10000** | Bounded channel capacity for source-to-engine and engine-to-sink queues |
| `--batch-size` | integer | **1** | Maximum events per engine lock acquisition (reduces mutex overhead under load) |
| `--drain-timeout` | integer | **5** | Seconds to wait for in-flight events to drain on shutdown |
| `--dlq` | string | none | Dead-letter queue: `stdout`, `file://<path>`, or `nats://<host>:<port>/<subject>` |
| `--state-db` | path | none | Path to SQLite database for persisting correlation state across restarts |
| `--state-save-interval` | integer | **30** | Seconds between periodic state snapshots (only with `--state-db`) |
| `--clear-state` | flag | `false` | Clear correlation state on startup (conflicts with `--keep-state`) |
| `--keep-state` | flag | `false` | Force restore correlation state on startup, even during replay (conflicts with `--clear-state`) |
| `--timestamp-fallback` | string | `"wallclock"` | `wallclock` (substitute current time) or `skip` (omit from correlation) when events lack parseable timestamps |

**NATS flags** (require `daemon-nats` feature):

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--replay-from-sequence` | integer | none | Replay from a specific JetStream stream sequence number |
| `--replay-from-time` | string | none | Replay from a timestamp (ISO 8601, e.g. `2026-01-15T10:00:00Z`) |
| `--replay-from-latest` | flag | `false` | Start from the latest message, skipping stream history |
| `--consumer-group` | string | none | Shared durable consumer name for load balancing across daemon instances (env: `RSIGMA_CONSUMER_GROUP`) |
| `--nats-creds` | path | none | Credentials file (`.creds`) for JWT + NKey auth (env: `NATS_CREDS`) |
| `--nats-token` | string | none | Authentication token (env: `NATS_TOKEN`) |
| `--nats-user` | string | none | Username (requires `--nats-password`, env: `NATS_USER`) |
| `--nats-password` | string | none | Password (requires `--nats-user`, env: `NATS_PASSWORD`) |
| `--nats-nkey` | string | none | NKey seed (env: `NATS_NKEY`) |
| `--nats-tls-cert` | path | none | Client certificate for mutual TLS (requires `--nats-tls-key`) |
| `--nats-tls-key` | path | none | Client private key for mutual TLS (requires `--nats-tls-cert`) |
| `--nats-require-tls` | flag | `false` | Require TLS on NATS connections |

\* Feature-gated: `logfmt` requires the `logfmt` feature, `cef` requires the `cef` feature.

**Usage:**

```bash
# Basic daemon: stream events, detect, output matches
hel run | rsigma daemon -r rules/ -p ecs.yml

# Accept events via HTTP POST instead of stdin
rsigma daemon -r rules/ --input http
# Then: curl -X POST http://localhost:9090/api/v1/events -d '{"CommandLine":"whoami"}'

# NATS JetStream source and sink
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --output nats://localhost:4222/detections

# Fan-out: write detections to both stdout and a file
hel run | rsigma daemon -r rules/ --output stdout --output file:///tmp/detections.ndjson

# NATS with authentication (credentials file)
rsigma daemon -r rules/ --input nats://nats.example.com:4222/events.> --nats-creds /etc/rsigma/nats.creds

# NATS with token auth (via environment variable)
NATS_TOKEN=secret rsigma daemon -r rules/ --input nats://localhost:4222/events.>

# NATS with mutual TLS
rsigma daemon -r rules/ --input nats://localhost:4222/events.> \
  --nats-tls-cert /etc/rsigma/client.pem --nats-tls-key /etc/rsigma/client-key.pem --nats-require-tls

# Dead-letter queue for failed events
rsigma daemon -r rules/ --input nats://localhost:4222/events.> \
  --dlq file:///var/log/rsigma-dlq.ndjson

# Replay from a specific stream sequence
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 42

# Replay from a point in time
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-time 2026-04-30T00:00:00Z

# Start from the latest message, ignoring history
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-latest

# Consumer groups for horizontal scaling
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --consumer-group detection-workers

# With SQLite state persistence (correlation state survives restarts)
hel run | rsigma daemon -r rules/ -p ecs.yml --state-db ./rsigma-state.db

# Force clear state on startup (ignore any saved state)
rsigma daemon -r rules/ --state-db ./state.db --clear-state

# Force restore state during replay (forward catch-up scenario)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> \
  --state-db ./state.db --replay-from-sequence 1001 --keep-state

# Skip events without timestamps for correlation (forensic replay)
rsigma daemon -r rules/ --timestamp-fallback skip

# Tune pipeline: micro-batch 64 events per lock, 50K buffer, 10s drain on shutdown
rsigma daemon -r rules/ --batch-size 64 --buffer-size 50000 --drain-timeout 10

# With all options
rsigma daemon \
  -r rules/ \
  -p ecs.yml \
  --jq '.event' \
  --suppress 5m \
  --action reset \
  --api-addr 0.0.0.0:9090 \
  --state-db /var/lib/rsigma/state.db
```

**HTTP endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Always returns `{"status": "ok"}` |
| `/readyz` | GET | Returns 200 when rules are loaded, 503 otherwise |
| `/metrics` | GET | Prometheus metrics (events processed, matches, latency, rules loaded, etc.) |
| `/api/v1/status` | GET | Full daemon status (rules, state entries, counters, uptime) |
| `/api/v1/rules` | GET | Rule counts and rules path |
| `/api/v1/reload` | POST | Trigger a manual rule reload |
| `/api/v1/events` | POST | Ingest events (NDJSON body, one event per line). Only available with `--input http` |

**Hot-reload triggers:**

- File system changes to `.yml`/`.yaml` files in the rules directory (debounced 500ms)
- `SIGHUP` signal (Unix only)
- `POST /api/v1/reload`

**Prometheus metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rsigma_events_processed_total` | counter | | Total events processed |
| `rsigma_detection_matches_total` | counter | | Total detection matches (aggregate) |
| `rsigma_detection_matches_by_rule_total` | counter | `rule_title`, `level` | Detection matches per rule |
| `rsigma_correlation_matches_total` | counter | | Total correlation matches (aggregate) |
| `rsigma_correlation_matches_by_rule_total` | counter | `rule_title`, `level`, `correlation_type` | Correlation matches per rule |
| `rsigma_events_parse_errors_total` | counter | | JSON parse errors on input |
| `rsigma_detection_rules_loaded` | gauge | | Number of detection rules loaded |
| `rsigma_correlation_rules_loaded` | gauge | | Number of correlation rules loaded |
| `rsigma_correlation_state_entries` | gauge | | Active correlation state entries |
| `rsigma_reloads_total` | counter | | Total rule reload attempts |
| `rsigma_reloads_failed_total` | counter | | Failed rule reload attempts |
| `rsigma_event_processing_seconds` | histogram | | Per-event processing latency |
| `rsigma_pipeline_latency_seconds` | histogram | | End-to-end latency from event dequeue to sink send |
| `rsigma_batch_size` | histogram | | Number of events processed per batch |
| `rsigma_input_queue_depth` | gauge | | Current events buffered in source-to-engine channel |
| `rsigma_output_queue_depth` | gauge | | Current results buffered in engine-to-sink channel |
| `rsigma_back_pressure_events_total` | counter | | Times a source was blocked on a full event channel |
| `rsigma_uptime_seconds` | gauge | | Daemon uptime in seconds |
| `rsigma_dlq_events_total` | counter | | Events routed to the dead-letter queue |

The per-rule labeled counters (`_by_rule_total`) enable per-rule alerting in Grafana or other Prometheus-based tools. A single PromQL query like `increase(rsigma_detection_matches_by_rule_total[5m]) > 0` produces separate alert instances for each `{rule_title, level}` combination. The aggregate counters (`_total`) remain for lightweight total-throughput monitoring.

**Logging:** structured JSON to stderr, configurable via `RUST_LOG` environment variable (default: `info`).

**State persistence:** when `--state-db` is set, correlation state (window entries, suppression timestamps, event buffers) is persisted to a SQLite database. State is loaded on startup, saved periodically (default every 30s, configurable via `--state-save-interval`), and saved on graceful shutdown. This allows correlation windows to survive daemon restarts. For example, an `event_count` correlation that saw 2 of 3 required events before a restart will resume from 2 after restarting. The database uses WAL journal mode and stores a single JSON snapshot row. Correlation entries are keyed by stable rule identifiers (id/name), so state survives rule reloads even if internal ordering changes.

**State restore during replay:** when restarting with a NATS replay flag (`--replay-from-sequence`, `--replay-from-time`, `--replay-from-latest`), the daemon automatically decides whether to restore or clear correlation state based on the replay direction. The last-acked NATS stream sequence and timestamp are stored in SQLite alongside the snapshot. If the replay starts after the stored position (forward catch-up), state is restored safely. If the replay starts at or before the stored position (backward replay or forensic investigation), state is cleared to prevent double-counting. Use `--keep-state` to override the automatic decision and always restore, or `--clear-state` to always start fresh.

**Timestamp fallback:** the `--timestamp-fallback` flag controls how correlation windows handle events without parseable timestamp fields. The default `wallclock` substitutes the current time (suitable for live streaming). The `skip` mode omits the event from correlation state updates while still firing stateless detections, which prevents wall-clock times from corrupting temporal windows during forensic replay of historical data.

**At-least-once delivery:** when using NATS JetStream input, messages are held in an `AckToken` until the sink confirms delivery. If the daemon crashes before acknowledging, NATS redelivers the message after the consumer's `ack_wait` expires.

**Dead-letter queue:** events that fail processing (parse errors, sink delivery failures) are routed to the `--dlq` target instead of being silently discarded. Each DLQ entry is a JSON object containing `original_event`, `error`, and `timestamp`.

**Consumer groups:** the `--consumer-group` flag sets a shared durable consumer name. Multiple daemon instances using the same group pull from a single JetStream consumer, and NATS distributes messages for load balancing. When not specified, the consumer name is derived from the subject.

**Feature flags:** the daemon subcommand requires the `daemon` feature (enabled by default). NATS flags require the `daemon-nats` feature. To build without daemon dependencies: `cargo build --no-default-features`.

### `eval`: Evaluate events against rules

Evaluate JSON events against Sigma detection and correlation rules.

> [!TIP]
> Eval mode builds correlation state in memory for the duration of a single run, so correlation rules fire when multiple events are processed together (via stdin or `@file`). State is not persisted between runs. For continuous correlation over time, use `daemon` mode.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--rules` / `-r` | path | required | Path to Sigma rule file or directory |
| `--event` / `-e` | string | none | A single event as a JSON string, or `@path` to read NDJSON from a file. If omitted, reads NDJSON from stdin |
| `--pretty` | flag | **false** | Pretty-print JSON output |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s), applied in priority order |
| `--jq` | string | none | jq filter to extract event payload (conflicts with `--jsonpath`) |
| `--jsonpath` | string | none | JSONPath (RFC 9535) query (conflicts with `--jq`) |
| `--suppress` | string | none | Suppression window for correlation alerts (e.g. `5m`, `1h`, `30s`) |
| `--action` | string | none | `alert` or `reset`, the action taken after correlation fires |
| `--no-detections` | flag | `false` | Suppress detection-level output (only show correlation alerts) |
| `--include-event` | flag | `false` | Include full event JSON in each detection match |
| `--correlation-event-mode` | string | `"none"` | `none`, `full`, or `refs` |
| `--max-correlation-events` | integer | **10** | Max events stored per correlation window |
| `--timestamp-field` | repeatable | `[]` | Event field(s) for timestamp extraction (prepended to the default list) |
| `--input-format` | string | `"auto"` | Input log format: `auto`, `json`, `syslog`, `plain`, `logfmt`\*, `cef`\* |
| `--syslog-tz` | string | `"+00:00"` | Default timezone for RFC 3164 syslog (e.g. `+05:00`, `-08:00`) |

\* Feature-gated: `logfmt` requires the `logfmt` feature, `cef` requires the `cef` feature.

**Basic evaluation:**

```bash
# Single event (inline JSON)
rsigma eval -r path/to/rules/ -e '{"CommandLine": "whoami"}'

# Read events from a file (@file syntax, streams as NDJSON, one event per line)
rsigma eval -r path/to/rules/ -e @events.ndjson

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With processing pipeline(s), applied in priority order
rsigma eval -r rules/ -p sysmon.yml -p custom.yml -e '...'
```

The `@file` syntax is equivalent to piping the file via stdin but avoids the pipe:

```bash
# These are equivalent:
rsigma eval -r rules/ -e @events.ndjson
cat events.ndjson | rsigma eval -r rules/
```

**Event extraction (jq / JSONPath):**

`--jq` and `--jsonpath` are mutually exclusive. Both can return multiple values (e.g. `.records[]`, `$.records[*]`), and each returned value is evaluated as a separate event.

```bash
# Unwrap nested payloads with jq syntax
rsigma eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# JSONPath (RFC 9535)
rsigma eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Array unwrapping: yields one event per element
rsigma eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'

# Stream with extraction
hel run | rsigma eval -r rules/ -p ecs.yml --jq '.event'
```

**Detection output:**

```bash
# Include the full matched event JSON in detection output
rsigma eval -r rules/ --include-event -e '{"CommandLine": "whoami"}'
```

**Correlation options:**

```bash
# Suppress duplicate correlation alerts within a time window
rsigma eval -r rules/ --suppress 5m < events.ndjson

# Reset state after alert fires (default: alert)
rsigma eval -r rules/ --suppress 5m --action reset < events.ndjson

# Include full contributing events in correlation output (compressed in memory)
rsigma eval -r rules/ --correlation-event-mode full < events.ndjson

# Include lightweight event references (timestamp + ID) instead
rsigma eval -r rules/ --correlation-event-mode refs < events.ndjson

# Cap stored events per correlation window (default: 10)
rsigma eval -r rules/ --correlation-event-mode full --max-correlation-events 20 < events.ndjson

# Suppress detection output (only show correlation alerts)
rsigma eval -r rules/ --no-detections < events.ndjson

# Custom timestamp field for correlation windowing
rsigma eval -r rules/ --timestamp-field time < events.ndjson
```

### Custom rule attributes

Sigma rules can include `rsigma.*` custom attributes to override CLI defaults on a per-rule basis. These attributes are set in the rule YAML under `custom_attributes` (or via pipeline `SetCustomAttribute` transformations) and take precedence over engine-level settings.

| Attribute | Applies to | Description |
|-----------|-----------|-------------|
| `rsigma.include_event` | detection rules | `"true"` or `"false"`, include the matched event in detection output |
| `rsigma.suppress` | correlation rules | Suppression window (e.g. `"5m"`, `"1h"`), overrides `--suppress` |
| `rsigma.action` | correlation rules | `"alert"` or `"reset"`, overrides `--action` |
| `rsigma.correlation_event_mode` | correlation rules | `"none"`, `"full"`, or `"refs"`, overrides `--correlation-event-mode` |
| `rsigma.max_correlation_events` | correlation rules | Integer as string (e.g. `"25"`), overrides `--max-correlation-events` |

Example rule YAML:

```yaml
title: Brute Force Detection
logsource:
    product: okta
    service: system
correlation:
    type: event_count
    rules: failed_login
    group-by: actor.displayName
    timespan: 5m
    condition:
        gte: 10
custom_attributes:
    rsigma.suppress: "10m"
    rsigma.action: "reset"
    rsigma.correlation_event_mode: "refs"
    rsigma.max_correlation_events: "50"
level: high
```

### `convert`: Convert rules to backend-native queries

Convert Sigma rules into query strings for a specific backend (SQL, SPL, KQL, Lucene, etc.).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `<rules>` | positional, repeatable | required | Path(s) to Sigma rule file(s) or directory |
| `--target` / `-t` | string | required | Backend target name (see `list-targets`) |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s) |
| `--format` / `-f` | string | `"default"` | Output format (see `list-formats`) |
| `-O` / `--option` | repeatable | `[]` | Backend options as `key=value` pairs (e.g. `-O table=logs -O schema=public`) |
| `--output` / `-o` | path | stdout | Write output to a file instead of stdout |
| `--skip-unsupported` / `-s` | flag | `false` | Skip unsupported rules instead of failing |
| `--without-pipeline` | flag | `false` | Skip pipeline requirement check |

Available backends: `test`, `postgres` (aliases: `postgresql`, `pg`).

```bash
# Convert rules using the test backend
rsigma convert rules/ -t test

# Convert with a pipeline and specific output format
rsigma convert rules/ -t test -p pipelines/ecs.yml -f state

# Convert a single rule
rsigma convert rule.yml -t test

# Convert to PostgreSQL SQL
rsigma convert rules/ -t postgres

# Convert to PostgreSQL with OCSF field mapping (single table)
rsigma convert rules/ -t postgres -p pipelines/ocsf_postgres.yml

# Convert with per-logsource table routing (multi-table)
rsigma convert rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml

# Generate PostgreSQL views
rsigma convert rules/ -t postgres -f view

# Generate TimescaleDB continuous aggregates
rsigma convert rules/ -t postgres -f continuous_aggregate

# Custom backend options (table, schema, timestamp field, etc.)
rsigma convert rules/ -t postgres -O table=security_logs -O schema=public -O timestamp_field=created_at

# JSONB mode: access fields inside a JSONB column
rsigma convert rules/ -t postgres -O table=okta_events -O json_field=data -O timestamp_field=time

# Skip rules that the backend does not support
rsigma convert rules/ -t postgres --skip-unsupported

# Write output to a file
rsigma convert rules/ -t postgres -o queries.sql
```

### `list-targets`: List available conversion backends

List all registered conversion backend targets.

```bash
rsigma list-targets
# Output:
#   test      Backend-neutral text queries for testing
#   postgres  PostgreSQL/TimescaleDB SQL
```

### `list-formats`: List output formats for a backend

List the output formats supported by a specific backend.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `<target>` | positional | required | Backend target name |

```bash
rsigma list-formats postgres
# Output:
#   default              Plain PostgreSQL SQL
#   view                 CREATE OR REPLACE VIEW for each rule
#   timescaledb          TimescaleDB-optimized queries with time_bucket()
#   continuous_aggregate CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)
#   sliding_window       Correlation queries using window functions for per-row sliding detection
```

### `condition`: Parse a condition expression

Parse a Sigma condition expression and output the AST as pretty-printed JSON. Output is always pretty-printed.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `expr` | positional | required | The condition expression to parse |

```bash
rsigma condition 'selection and not filter'
```

### `stdin`: Parse YAML from stdin

Read a single Sigma YAML document from stdin and output the AST as JSON.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--pretty` / `-p` | flag | **true** | Pretty-print JSON output |

```bash
cat rule.yml | rsigma stdin
```

## File Discovery

All subcommands that accept a directory path scan recursively for `.yml` and `.yaml` files only.

- **Rule loading:** Files are parsed individually; parse errors are accumulated (not fatal). Rules, correlations, and filters from all files are merged into a single collection.
- **Lint config discovery:** Walks ancestor directories from the target path upward, looking for `.rsigma-lint.yml` or `.rsigma-lint.yaml`. The `--config` flag overrides auto-discovery.

## Event Input Modes

| Mode | Input format | Behavior |
|------|-------------|----------|
| `rsigma eval -e '...'` | Inline JSON string | Parses the string as a single JSON object and evaluates it |
| `rsigma eval -e @path` | NDJSON file | Reads the file line-by-line as NDJSON (same behavior as stdin) |
| `rsigma eval` (no `--event`) | NDJSON from stdin | Each non-blank line is parsed as JSON. Blank lines are skipped. Exits after EOF |
| `rsigma daemon` | NDJSON from stdin | Continuous stdin reader; stays alive after EOF. Exposes HTTP APIs for management |
| `rsigma daemon --input http` | NDJSON via HTTP POST | Events sent to `POST /api/v1/events`. Stays alive, exposes all APIs |
| `rsigma daemon --input nats://...` | NATS JetStream | Subscribes to a JetStream subject. At-least-once delivery with deferred ack |
| `rsigma stdin` | Single YAML document | Parses as Sigma YAML → outputs AST as JSON |

Event filters (`--jq`/`--jsonpath`) are applied to every event regardless of input mode.

## Output Format

### Detection match (JSON)

```json
{
  "rule_title": "Detect Whoami",
  "rule_id": "abc-123-...",
  "level": "medium",
  "tags": ["attack.execution"],
  "matched_selections": ["selection"],
  "matched_fields": [
    { "field": "CommandLine", "value": "cmd /c whoami" }
  ],
  "event": null
}
```

The `event` field is present only when `--include-event` is set.

### Correlation match (JSON)

```json
{
  "rule_title": "Brute Force",
  "rule_id": null,
  "level": "high",
  "tags": [],
  "correlation_type": "event_count",
  "group_key": [["User", "admin"]],
  "aggregated_value": 3.0,
  "timespan_secs": 300,
  "events": null,
  "event_refs": null
}
```

`events` is populated when `--correlation-event-mode full`; `event_refs` when `--correlation-event-mode refs`.

### Stderr messages

- `Loaded N rules from PATH` (detection-only) or `Loaded N detection rules + M correlation rules from PATH`
- `Loaded pipeline: NAME (priority N)` per pipeline
- `Event filter: jq 'EXPR'` or `Event filter: jsonpath 'EXPR'` when using `--jq`/`--jsonpath`
- `No matches.` when a single event yields no matches
- `Invalid JSON event: ...` on parse error (single event)
- `Invalid JSON on line N` for NDJSON parse errors (continues processing)
- `Processed N events, M matches.` (detection-only) or `Processed N events, M detection matches, K correlation matches.` (with correlations)

## Pipeline Loading

- Each `-p PATH` loads one pipeline file.
- Pipelines are sorted by `priority` (ascending); lower priority runs first.
- All pipelines are applied in sequence to each rule before compilation.
- `merge_pipelines` is not used by the CLI; each pipeline remains separate with its own state.

## Environment Variables

| Variable | Scope | Behavior |
|----------|-------|----------|
| `NO_COLOR` | `lint` only | When set, disables color output regardless of `--color` setting |
| `RUST_LOG` | `daemon` only | Log level filter (e.g. `info`, `debug`, `rsigma=debug`). Default: `info` |
| `NATS_CREDS` | `daemon` | NATS credentials file path (alternative to `--nats-creds`) |
| `NATS_TOKEN` | `daemon` | NATS authentication token (alternative to `--nats-token`) |
| `NATS_USER` | `daemon` | NATS username (alternative to `--nats-user`) |
| `NATS_PASSWORD` | `daemon` | NATS password (alternative to `--nats-password`) |
| `NATS_NKEY` | `daemon` | NATS NKey seed (alternative to `--nats-nkey`) |
| `RSIGMA_CONSUMER_GROUP` | `daemon` | Consumer group name (alternative to `--consumer-group`) |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `daemon` | **on** | Enables the `daemon` subcommand (tokio, axum, prometheus, notify, rusqlite) |
| `daemon-nats` | off | Enables NATS JetStream input/output, authentication, replay, and consumer groups (implies `daemon`) |
| `logfmt` | off | Enables `logfmt` input format in `daemon` and `eval` |
| `cef` | off | Enables CEF (ArcSight) input format in `daemon` and `eval` |
| `evtx` | off | Enables EVTX (Windows Event Log) input format |

```bash
# Build with all features
cargo build --release --features daemon-nats,logfmt,cef,evtx

# Build without daemon (parser, eval, convert, lint only)
cargo build --release --no-default-features
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (no errors found for lint; matches may or may not exist for eval) |
| `1` | Error: parse failure, validation error, lint errors found, missing required argument, invalid argument value |

## License

MIT License.

[rsigma workspace]: https://github.com/timescale/rsigma
