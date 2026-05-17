# rsigma

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma` is a command-line interface for parsing, validating, linting, evaluating, converting, inspecting field usage, and running [Sigma](https://github.com/SigmaHQ/sigma) detection rules as a long-running daemon.

This binary is part of the [rsigma workspace].

## Installation

```bash
cargo install rsigma
```

## Quick Start

```bash
# Single event (inline JSON)
rsigma engine eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma engine eval -r path/to/rules/

# Long-running daemon with hot-reload, health checks, and Prometheus metrics
hel run | rsigma engine daemon -r rules/ -p ecs_windows --api-addr 0.0.0.0:9090

# With a builtin pipeline (no external file needed)
rsigma engine eval -r rules/ -p ecs_windows -e '{"process.command_line": "whoami"}'

# Or use a custom pipeline YAML file
rsigma engine eval -r rules/ -p pipelines/custom.yml -e '{"src_ip": "10.0.0.1"}'

# Convert rules to backend-native queries
rsigma backend convert -r rules/ -t test

# Convert to PostgreSQL SQL
rsigma backend convert -r rules/ -t postgres

# List all fields referenced by rules (with optional pipeline mapping)
rsigma rule fields -r rules/ -p ecs_windows

# List available conversion backends
rsigma backend targets
```

## Subcommands

Commands are grouped into five noun-led groups: `engine` (eval / daemon), `rule` (parse / validate / lint / fields / condition / stdin), `backend` (convert / targets / formats), `pipeline` (resolve), and `attack` (reserved; populated by the upcoming MITRE ATT&CK contributor PR).

### Migrating from the old flat commands

Every flat top-level command still works for one release as a visible-deprecated alias. Invoking the old form prints a stderr warning and forwards to the same implementation; stdout, exit codes, and every flag are unchanged.

| Old (flat, deprecated) | New (grouped) |
|------------------------|---------------|
| `rsigma eval ...` | `rsigma engine eval ...` |
| `rsigma daemon ...` | `rsigma engine daemon ...` |
| `rsigma parse ...` | `rsigma rule parse ...` |
| `rsigma validate ...` | `rsigma rule validate ...` |
| `rsigma lint ...` | `rsigma rule lint ...` |
| `rsigma fields ...` | `rsigma rule fields ...` |
| `rsigma condition ...` | `rsigma rule condition ...` |
| `rsigma stdin ...` | `rsigma rule stdin ...` |
| `rsigma convert RULES ...` | `rsigma backend convert RULES ...` |
| `rsigma list-targets` | `rsigma backend targets` |
| `rsigma list-formats TARGET` | `rsigma backend formats TARGET` |
| `rsigma resolve ...` | `rsigma pipeline resolve ...` |

Deprecation timeline: flat aliases are **visible** in `rsigma --help` this release (with `[deprecated]` in the about text), **hidden** from `--help` in the next release, and **removed** in v1.0. Migrate at your convenience within that window.

### `rule parse`: Parse a single rule

Parse a Sigma YAML file and output the AST as JSON.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a Sigma YAML file |
| `--pretty` / `-p` | flag | **true** | Pretty-print JSON output |

```bash
rsigma rule parse rule.yml            # print AST as pretty-printed JSON
rsigma rule parse rule.yml --pretty   # same (default)
```

Note: pretty-print is on by default and cannot be disabled.

### `rule validate`: Validate rules in a directory

Parse and compile all rules in a directory, reporting errors.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `path` | positional | required | Path to a directory of Sigma YAML files |
| `--verbose` / `-v` | flag | `false` | Show details for each file (parse errors, compile errors) |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s) to apply before compilation |
| `--resolve-sources` | flag | `false` | Also resolve dynamic pipeline sources during validation. Sources must be reachable (file/command/HTTP) for validation to pass |

```bash
rsigma rule validate path/to/rules/ -v              # verbose output
rsigma rule validate rules/ -p pipelines/ecs.yml    # validate with pipeline
rsigma rule validate rules/ -p dynamic.yml --resolve-sources  # validate + test source resolution
```

### `rule lint`: Lint rules against the Sigma specification

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
| `--fail-level` | string | `"error"` | Minimum severity for non-zero exit: `error` (default), `warning`, or `info` |

```bash
rsigma rule lint path/to/rules/                     # lint all rules
rsigma rule lint path/to/rules/ -v                  # verbose (show passing files + info-only)
rsigma rule lint path/to/rules/ --schema default    # + JSON schema validation (downloads + caches)
rsigma rule lint rule.yml --schema my-schema.json   # local JSON schema
rsigma rule lint path/to/rules/ --color always      # force color
rsigma rule lint rules/ --disable missing_description,missing_author  # suppress specific rules
rsigma rule lint rules/ --config my-lint.yml        # explicit config file
rsigma rule lint rules/ --exclude "config/**"       # skip non-rule files
rsigma rule lint rules/ --exclude "config/**" --exclude "**/unsupported/**"  # multiple patterns
rsigma rule lint rules/ --fix                       # auto-fix safe issues
rsigma rule lint rules/ --fail-level warning        # CI: fail on warnings too
rsigma rule lint rules/ --fail-level info           # CI: fail on any finding
```

**Lint output summary format:**

```
Checked N file(s): X passed, Y failed (A error(s), B warning(s), C info(s))
```

**Schema validation skips** documents with `action: global`, `action: reset`, or `action: repeat` (action fragments).

### `engine daemon`: Run as a long-running detection service

Run rsigma as a long-running daemon that continuously reads NDJSON from stdin, evaluates against rules, writes matches to stdout, and exposes health/metrics/management APIs over HTTP.

Unlike `engine eval`, the daemon stays alive after stdin reaches EOF and supports hot-reload: adding, modifying, or removing `.yml`/`.yaml` files in the rules directory or any pipeline file passed via `-p` triggers an automatic reload (rules and pipelines are re-read together). SIGHUP and the `/api/v1/reload` endpoint also trigger reloads. The daemon is designed for production deployment behind a log collector (e.g. `hel run | rsigma engine daemon ...`) or an event bus.

> [!TIP]
> Correlation rules also work in `engine eval` mode within a single run (via stdin or `@file`), but `engine daemon` mode is recommended for continuous stateful tracking with hot-reload and state persistence.

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
| `--bloom-prefilter` | flag | `false` | Enable bloom-filter pre-filtering of positive substring matchers (workload-dependent; see `crates/rsigma-eval/README.md`) |
| `--bloom-max-bytes` | integer | **1048576** | Memory budget for the bloom index (no effect without `--bloom-prefilter`) |
| `--cross-rule-ac` | flag | `false` | Enable cross-rule Aho-Corasick pre-filter (requires `--features daachorse-index`; see `crates/rsigma-eval/README.md`) |
| `--buffer-size` | integer | **10000** | Bounded channel capacity for source-to-engine and engine-to-sink queues |
| `--batch-size` | integer | **1** | Maximum events per engine lock acquisition (reduces mutex overhead under load) |
| `--drain-timeout` | integer | **5** | Seconds to wait for in-flight events to drain on shutdown |
| `--dlq` | string | none | Dead-letter queue: `stdout`, `file://<path>`, or `nats://<host>:<port>/<subject>` |
| `--state-db` | path | none | Path to SQLite database for persisting correlation state across restarts |
| `--state-save-interval` | integer | **30** | Seconds between periodic state snapshots (only with `--state-db`) |
| `--clear-state` | flag | `false` | Clear correlation state on startup (conflicts with `--keep-state`) |
| `--keep-state` | flag | `false` | Force restore correlation state on startup, even during replay (conflicts with `--clear-state`) |
| `--timestamp-fallback` | string | `"wallclock"` | `wallclock` (substitute current time) or `skip` (omit from correlation) when events lack parseable timestamps |
| `--allow-remote-include` | flag | `false` | Allow `include` directives in dynamic pipelines to reference remote (HTTP/NATS) sources. Local sources (file/command) are always permitted |

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
hel run | rsigma engine daemon -r rules/ -p ecs.yml

# Accept events via HTTP POST instead of stdin
rsigma engine daemon -r rules/ --input http
# Then: curl -X POST http://localhost:9090/api/v1/events -d '{"CommandLine":"whoami"}'

# NATS JetStream source and sink
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> --output nats://localhost:4222/detections

# Fan-out: write detections to both stdout and a file
hel run | rsigma engine daemon -r rules/ --output stdout --output file:///tmp/detections.ndjson

# NATS with authentication (credentials file)
rsigma engine daemon -r rules/ --input nats://nats.example.com:4222/events.> --nats-creds /etc/rsigma/nats.creds

# NATS with token auth (via environment variable)
NATS_TOKEN=secret rsigma engine daemon -r rules/ --input nats://localhost:4222/events.>

# NATS with mutual TLS
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
  --nats-tls-cert /etc/rsigma/client.pem --nats-tls-key /etc/rsigma/client-key.pem --nats-require-tls

# Dead-letter queue for failed events
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
  --dlq file:///var/log/rsigma-dlq.ndjson

# Replay from a specific stream sequence
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 42

# Replay from a point in time
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-time 2026-04-30T00:00:00Z

# Start from the latest message, ignoring history
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-latest

# Consumer groups for horizontal scaling
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> --consumer-group detection-workers

# With SQLite state persistence (correlation state survives restarts)
hel run | rsigma engine daemon -r rules/ -p ecs.yml --state-db ./rsigma-state.db

# Force clear state on startup (ignore any saved state)
rsigma engine daemon -r rules/ --state-db ./state.db --clear-state

# Force restore state during replay (forward catch-up scenario)
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
  --state-db ./state.db --replay-from-sequence 1001 --keep-state

# Skip events without timestamps for correlation (forensic replay)
rsigma engine daemon -r rules/ --timestamp-fallback skip

# Tune pipeline: micro-batch 64 events per lock, 50K buffer, 10s drain on shutdown
rsigma engine daemon -r rules/ --batch-size 64 --buffer-size 50000 --drain-timeout 10

# With all options
rsigma engine daemon \
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
| `/api/v1/sources` | GET | List dynamic sources and their resolution status |
| `/api/v1/sources/resolve` | POST | Trigger re-resolution of all dynamic sources (or specific ones via request body) |
| `/api/v1/sources/cache/{source_id}` | DELETE | Invalidate the cached value for a specific source |
| `/v1/logs` | POST | OTLP log ingestion (`application/x-protobuf` or `application/json`, gzip supported). Requires `daemon-otlp` feature |

**OTLP log ingestion** (requires `daemon-otlp` feature):

When built with `daemon-otlp`, the daemon accepts [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) log export requests on `/v1/logs` (HTTP) and via gRPC on the same port. The endpoint is always active regardless of `--input`. This lets you point any OpenTelemetry-compatible agent (Grafana Alloy, Vector, Fluent Bit, OTel Collector) at rsigma for real-time detection.

Both transports support gzip compression. OTLP `LogRecord` fields are flattened to JSON: resource attributes are prefixed with `resource.`, log attributes are unprefixed, and key-value map bodies are flattened to top-level fields for direct Sigma rule matching.

```bash
# Send OTLP logs via protobuf
curl -X POST http://localhost:9090/v1/logs \
  -H 'Content-Type: application/x-protobuf' \
  --data-binary @export_logs_request.pb

# Send OTLP logs via JSON
curl -X POST http://localhost:9090/v1/logs \
  -H 'Content-Type: application/json' \
  -d '{"resourceLogs":[...]}'

# Grafana Alloy config (forward to rsigma)
# otelcol.exporter.otlphttp "rsigma" {
#   client { endpoint = "http://rsigma:9090" }
# }

# Vector config
# [sinks.rsigma]
# type = "http"
# uri = "http://rsigma:9090/v1/logs"
# encoding.codec = "native"  # protobuf
```

**Hot-reload triggers:**

- File system changes to `.yml`/`.yaml` files in the rules directory (debounced 500ms)
- `SIGHUP` signal (Unix only) -- triggers both rule reload and dynamic source re-resolution
- `POST /api/v1/reload`
- `POST /api/v1/sources/resolve` -- re-resolves dynamic sources without reloading rules
- NATS control subject `rsigma.control.resolve` (when using NATS sources) -- payload can be empty (resolve all) or `{"source_id": "..."}` (resolve one)

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
| `rsigma_source_resolves_total` | counter | `source_id` | Total dynamic source resolution attempts |
| `rsigma_source_resolve_errors_total` | counter | `source_id` | Total dynamic source resolution failures |
| `rsigma_source_resolve_latency_seconds` | histogram | | Source resolution latency |
| `rsigma_source_cache_hits_total` | counter | | Times a cached value was served instead of fetching fresh |
| `rsigma_source_last_resolved_timestamp` | gauge | `source_id` | Unix timestamp of last successful resolution per source |
| `rsigma_otlp_requests_total` | counter | `transport`, `encoding` | OTLP export requests received (requires `daemon-otlp`) |
| `rsigma_otlp_log_records_total` | counter | | Log records ingested via OTLP (requires `daemon-otlp`) |
| `rsigma_otlp_errors_total` | counter | `transport`, `reason` | OTLP request errors (requires `daemon-otlp`) |

The per-rule labeled counters (`_by_rule_total`) enable per-rule alerting in Grafana or other Prometheus-based tools. A single PromQL query like `increase(rsigma_detection_matches_by_rule_total[5m]) > 0` produces separate alert instances for each `{rule_title, level}` combination. The aggregate counters (`_total`) remain for lightweight total-throughput monitoring.

**Logging:** structured JSON to stderr, configurable via `RUST_LOG` environment variable (default: `info`). Useful filter targets:

- `RUST_LOG=info,tower_http=debug` — HTTP API access logs (method, URI, status, latency) for every request to `/api/v1/*`, `/healthz`, `/metrics`.
- `RUST_LOG=info,rsigma=debug` — verbose batch processing (`Batch processed` events with `batch_size`, `matches`, `elapsed_ms`), DLQ routing, source resolution timing, state snapshot duration, and OTLP per-request fields.
- `RUST_LOG=info,rsigma_runtime::sources=debug` — dynamic source resolution and refresh scheduler details.
- `RUST_LOG=info,rsigma_eval=debug` — correlation engine internals (chain depth limits, hard-cap eviction warnings already emit at `warn`).

The `tracing` spans installed on hot paths (batch processing, source resolution, OTLP ingest, rule loading) double as profiling hooks consumable by `tokio-console` or `tracing-timing` without code changes—just swap in the corresponding subscriber layer.

**CLI subcommand logging:** non-daemon subcommands (everything outside `rsigma engine daemon` — that is, `rsigma engine eval`, the `rsigma rule *` group, `rsigma backend *`, `rsigma pipeline resolve`) default to human-readable stdout/stderr output only. Pass the global `--log-format json` (or `--log-format text`) to additionally install a tracing subscriber on stderr for CI/log aggregation use cases. Verbosity follows `RUST_LOG` (default `info`). Human-readable output is unchanged when the flag is set.

**State persistence:** when `--state-db` is set, correlation state (window entries, suppression timestamps, event buffers) is persisted to a SQLite database. State is loaded on startup, saved periodically (default every 30s, configurable via `--state-save-interval`), and saved on graceful shutdown. This allows correlation windows to survive daemon restarts. For example, an `event_count` correlation that saw 2 of 3 required events before a restart will resume from 2 after restarting. The database uses WAL journal mode and stores a single JSON snapshot row. Correlation entries are keyed by stable rule identifiers (id/name), so state survives rule reloads even if internal ordering changes.

**State restore during replay:** when restarting with a NATS replay flag (`--replay-from-sequence`, `--replay-from-time`, `--replay-from-latest`), the daemon automatically decides whether to restore or clear correlation state based on the replay direction. The last-acked NATS stream sequence and timestamp are stored in SQLite alongside the snapshot. If the replay starts after the stored position (forward catch-up), state is restored safely. If the replay starts at or before the stored position (backward replay or forensic investigation), state is cleared to prevent double-counting. Use `--keep-state` to override the automatic decision and always restore, or `--clear-state` to always start fresh.

**Timestamp fallback:** the `--timestamp-fallback` flag controls how correlation windows handle events without parseable timestamp fields. The default `wallclock` substitutes the current time (suitable for live streaming). The `skip` mode omits the event from correlation state updates while still firing stateless detections, which prevents wall-clock times from corrupting temporal windows during forensic replay of historical data.

**At-least-once delivery:** when using NATS JetStream input, messages are held in an `AckToken` until the sink confirms delivery. If the daemon crashes before acknowledging, NATS redelivers the message after the consumer's `ack_wait` expires.

**Dead-letter queue:** events that fail processing (parse errors, sink delivery failures) are routed to the `--dlq` target instead of being silently discarded. Each DLQ entry is a JSON object containing `original_event`, `error`, and `timestamp`.

**Consumer groups:** the `--consumer-group` flag sets a shared durable consumer name. Multiple daemon instances using the same group pull from a single JetStream consumer, and NATS distributes messages for load balancing. When not specified, the consumer name is derived from the subject.

**Feature flags:** the daemon subcommand requires the `daemon` feature (enabled by default). NATS flags require the `daemon-nats` feature. OTLP log ingestion (HTTP and gRPC) requires the `daemon-otlp` feature. To build without daemon dependencies: `cargo build --no-default-features`.

### `engine eval`: Evaluate events against rules

Evaluate JSON events against Sigma detection and correlation rules.

> [!TIP]
> Eval mode builds correlation state in memory for the duration of a single run, so correlation rules fire when multiple events are processed together (via stdin or `@file`). State is not persisted between runs. For continuous correlation over time, use `daemon` mode.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--rules` / `-r` | path | required | Path to Sigma rule file or directory |
| `--event` / `-e` | string | none | A single event as a JSON string, or `@path` to read from a file. Supports NDJSON files and `.evtx` (Windows Event Log) files (requires `evtx` feature). If omitted, reads NDJSON from stdin |
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
| `--fail-on-detection` | flag | `false` | Exit with code 1 when any detection or correlation fires. Useful for CI/CD pipelines |
| `--bloom-prefilter` | flag | `false` | Enable bloom-filter pre-filtering of positive substring matchers (see `crates/rsigma-eval/README.md` for the trade-off) |
| `--bloom-max-bytes` | integer | **1048576** | Memory budget for the bloom index (no effect without `--bloom-prefilter`) |
| `--cross-rule-ac` | flag | `false` | Enable cross-rule Aho-Corasick pre-filter (requires `--features daachorse-index`; see `crates/rsigma-eval/README.md`) |

\* Feature-gated: `logfmt` requires the `logfmt` feature, `cef` requires the `cef` feature, `evtx` requires the `evtx` feature.

**Basic evaluation:**

```bash
# Single event (inline JSON)
rsigma engine eval -r path/to/rules/ -e '{"CommandLine": "whoami"}'

# Read events from a file (@file syntax, streams as NDJSON, one event per line)
rsigma engine eval -r path/to/rules/ -e @events.ndjson

# Stream NDJSON from stdin
cat events.ndjson | rsigma engine eval -r path/to/rules/

# With processing pipeline(s), applied in priority order
rsigma engine eval -r rules/ -p sysmon.yml -p custom.yml -e '...'
```

The `@file` syntax is equivalent to piping the file via stdin but avoids the pipe:

```bash
# These are equivalent:
rsigma engine eval -r rules/ -e @events.ndjson
cat events.ndjson | rsigma engine eval -r rules/
```

**EVTX (Windows Event Log) files** (requires `evtx` feature):

Files with a `.evtx` extension are automatically detected and parsed as binary Windows Event Log files. Each record is converted to JSON and evaluated against the loaded rules.

```bash
# Evaluate Sigma rules against a Windows Event Log file
rsigma engine eval -r rules/ -e @security.evtx

# With a pipeline and pretty output
rsigma engine eval -r rules/ -p sysmon.yml -e @Microsoft-Windows-Sysmon.evtx --pretty
```

**Event extraction (jq / JSONPath):**

`--jq` and `--jsonpath` are mutually exclusive. Both can return multiple values (e.g. `.records[]`, `$.records[*]`), and each returned value is evaluated as a separate event.

```bash
# Unwrap nested payloads with jq syntax
rsigma engine eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# JSONPath (RFC 9535)
rsigma engine eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Array unwrapping: yields one event per element
rsigma engine eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'

# Stream with extraction
hel run | rsigma engine eval -r rules/ -p ecs.yml --jq '.event'
```

**Detection output:**

```bash
# Include the full matched event JSON in detection output
rsigma engine eval -r rules/ --include-event -e '{"CommandLine": "whoami"}'
```

**Correlation options:**

```bash
# Suppress duplicate correlation alerts within a time window
rsigma engine eval -r rules/ --suppress 5m < events.ndjson

# Reset state after alert fires (default: alert)
rsigma engine eval -r rules/ --suppress 5m --action reset < events.ndjson

# Include full contributing events in correlation output (compressed in memory)
rsigma engine eval -r rules/ --correlation-event-mode full < events.ndjson

# Include lightweight event references (timestamp + ID) instead
rsigma engine eval -r rules/ --correlation-event-mode refs < events.ndjson

# Cap stored events per correlation window (default: 10)
rsigma engine eval -r rules/ --correlation-event-mode full --max-correlation-events 20 < events.ndjson

# Suppress detection output (only show correlation alerts)
rsigma engine eval -r rules/ --no-detections < events.ndjson

# Custom timestamp field for correlation windowing
rsigma engine eval -r rules/ --timestamp-field time < events.ndjson
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

### `backend convert`: Convert rules to backend-native queries

Convert Sigma rules into query strings for a specific backend (SQL, SPL, KQL, Lucene, etc.).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `<rules>` | positional, repeatable | required | Path(s) to Sigma rule file(s) or directory |
| `--target` / `-t` | string | required | Backend target name (see `backend targets`) |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s) |
| `--format` / `-f` | string | `"default"` | Output format (see `backend formats`) |
| `-O` / `--option` | repeatable | `[]` | Backend options as `key=value` pairs (e.g. `-O table=logs -O schema=public`) |
| `--output` / `-o` | path | stdout | Write output to a file instead of stdout |
| `--skip-unsupported` / `-s` | flag | `false` | Skip unsupported rules instead of failing |
| `--without-pipeline` | flag | `false` | Skip pipeline requirement check |

Available backends: `test`, `postgres` (aliases: `postgresql`, `pg`).

```bash
# Convert rules using the test backend
rsigma backend convert rules/ -t test

# Convert with a pipeline and specific output format
rsigma backend convert rules/ -t test -p pipelines/ecs.yml -f state

# Convert a single rule
rsigma backend convert rule.yml -t test

# Convert to PostgreSQL SQL
rsigma backend convert rules/ -t postgres

# Convert to PostgreSQL with OCSF field mapping (single table)
rsigma backend convert rules/ -t postgres -p pipelines/ocsf_postgres.yml

# Convert with per-logsource table routing (multi-table)
rsigma backend convert rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml

# Generate PostgreSQL views
rsigma backend convert rules/ -t postgres -f view

# Generate TimescaleDB continuous aggregates
rsigma backend convert rules/ -t postgres -f continuous_aggregate

# Custom backend options (table, schema, timestamp field, etc.)
rsigma backend convert rules/ -t postgres -O table=security_logs -O schema=public -O timestamp_field=created_at

# JSONB mode: access fields inside a JSONB column
rsigma backend convert rules/ -t postgres -O table=okta_events -O json_field=data -O timestamp_field=time

# Skip rules that the backend does not support
rsigma backend convert rules/ -t postgres --skip-unsupported

# Write output to a file
rsigma backend convert rules/ -t postgres -o queries.sql
```

### `backend targets`: List available conversion backends

List all registered conversion backend targets.

```bash
rsigma backend targets
# Output:
#   test      Backend-neutral text queries for testing
#   postgres  PostgreSQL/TimescaleDB SQL
```

### `backend formats`: List output formats for a backend

List the output formats supported by a specific backend.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `<target>` | positional | required | Backend target name |

```bash
rsigma backend formats postgres
# Output:
#   default              Plain PostgreSQL SQL
#   view                 CREATE OR REPLACE VIEW for each rule
#   timescaledb          TimescaleDB-optimized queries with time_bucket()
#   continuous_aggregate CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)
#   sliding_window       Correlation queries using window functions for per-row sliding detection
```

### `rule fields`: List all fields referenced by Sigma rules

Extract and display every field name referenced across detection rules, correlation rules, filter rules, and rule metadata. Useful for building a field catalog, auditing pipeline coverage, or understanding which fields a ruleset depends on.

When pipelines are provided, fields are shown after pipeline transformations (field name mappings, prefixes, suffixes), so you can verify that your pipeline maps every field your rules need.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--rules` / `-r` | path | required | Path to a Sigma rule file or directory |
| `--pipeline` / `-p` | repeatable | `[]` | Processing pipeline YAML file(s). When provided, fields are shown after transformations |
| `--no-filters` | flag | `false` | Exclude fields contributed by filter rules |
| `--json` | flag | `false` | Output as JSON instead of a table |

**Field sources:** each field is annotated with where it was found:

| Source | Description |
|--------|-------------|
| `detection` | Field names from detection block items (`selection`, `filter`, etc.) |
| `correlation` | `group-by` fields, `condition.field`, and alias mapping values |
| `filter` | Fields from filter rule detection blocks |
| `metadata` | Fields listed in the rule's `fields:` metadata section |

```bash
# List all fields in a ruleset
rsigma rule fields -r rules/

# Show fields after ECS pipeline mapping
rsigma rule fields -r rules/ -p pipelines/ecs.yml

# Exclude filter-contributed fields
rsigma rule fields -r rules/ --no-filters

# JSON output for scripting
rsigma rule fields -r rules/ --json

# Pipe JSON to jq for further analysis
rsigma rule fields -r rules/ --json | jq '.fields[] | select(.sources[] == "detection") | .field'
```

**Table output** writes field data to stdout and a summary line to stderr, so you can pipe the table or redirect it without mixing in summary text.

**JSON output** includes a `summary` object (rule/correlation/filter counts, unique fields, pipelines applied), a `fields` array, and when pipelines are applied, a `pipeline_mappings` array showing each field name transformation.

### `pipeline resolve`: Test dynamic source resolution

Resolve all dynamic sources declared in the given pipeline(s) and print the resulting data as JSON. Useful for testing pipeline source configuration without running the daemon.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--pipeline` / `-p` | repeatable | required | Processing pipeline(s) containing dynamic sources |
| `--source` / `-s` | string | none | Resolve only a specific source by ID |
| `--pretty` | flag | `false` | Pretty-print JSON output |
| `--dry-run` | flag | `false` | Show what would be resolved (source metadata) without performing resolution |

```bash
# Resolve all sources in a dynamic pipeline
rsigma pipeline resolve -p pipelines/dynamic.yml --pretty

# Resolve a specific source by ID
rsigma pipeline resolve -p pipelines/dynamic.yml --source threat_intel

# Dry-run: list sources and metadata without fetching
rsigma pipeline resolve -p pipelines/dynamic.yml --dry-run

# Test multiple pipelines at once
rsigma pipeline resolve -p pipeline1.yml -p pipeline2.yml
```

**Output format (normal mode):**

```json
{
  "pipeline": "dynamic_example",
  "source_id": "field_map",
  "status": "ok",
  "data": { "CommandLine": "process.command_line", "User": "user.name" }
}
```

**Output format (dry-run mode):**

```json
{
  "pipeline": "dynamic_example",
  "source_id": "field_map",
  "source_type": "File",
  "required": true,
  "refresh": "Watch"
}
```

### `rule condition`: Parse a condition expression

Parse a Sigma condition expression and output the AST as pretty-printed JSON. Output is always pretty-printed.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `expr` | positional | required | The condition expression to parse |

```bash
rsigma rule condition 'selection and not filter'
```

### `rule stdin`: Parse YAML from stdin

Read a single Sigma YAML document from stdin and output the AST as JSON.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--pretty` / `-p` | flag | **true** | Pretty-print JSON output |

```bash
cat rule.yml | rsigma rule stdin
```

## File Discovery

All subcommands that accept a directory path scan recursively for `.yml` and `.yaml` files only.

- **Rule loading:** Files are parsed individually; parse errors are accumulated (not fatal). Rules, correlations, and filters from all files are merged into a single collection.
- **Lint config discovery:** Walks ancestor directories from the target path upward, looking for `.rsigma-lint.yml` or `.rsigma-lint.yaml`. The `--config` flag overrides auto-discovery.

## Event Input Modes

| Mode | Input format | Behavior |
|------|-------------|----------|
| `rsigma engine eval -e '...'` | Inline JSON string | Parses the string as a single JSON object and evaluates it |
| `rsigma engine eval -e @path` | NDJSON file | Reads the file line-by-line as NDJSON (same behavior as stdin) |
| `rsigma engine eval -e @path.evtx` | EVTX binary file | Parses the binary Windows Event Log file and evaluates each record (requires `evtx` feature) |
| `rsigma engine eval` (no `--event`) | NDJSON from stdin | Each non-blank line is parsed as JSON. Blank lines are skipped. Exits after EOF |
| `rsigma engine daemon` | NDJSON from stdin | Continuous stdin reader; stays alive after EOF. Exposes HTTP APIs for management |
| `rsigma engine daemon --input http` | NDJSON via HTTP POST | Events sent to `POST /api/v1/events`. Stays alive, exposes all APIs |
| `rsigma engine daemon --input nats://...` | NATS JetStream | Subscribes to a JetStream subject. At-least-once delivery with deferred ack |
| OTLP (any `--input` mode) | OTLP protobuf/JSON via HTTP POST or gRPC | Agents send `ExportLogsServiceRequest` to `/v1/logs` (HTTP) or the gRPC `LogsService/Export` endpoint. Requires `daemon-otlp` feature |
| `rsigma rule stdin` | Single YAML document | Parses as Sigma YAML → outputs AST as JSON |

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

- Each `-p NAME_OR_PATH` loads one pipeline. The argument is first checked against builtin names; if no builtin matches, it is treated as a file path.
- **Builtin pipelines** (no external file needed):
  - `ecs_windows` -- maps Sigma/Sysmon field names to Elastic Common Schema (ECS) fields (e.g. `CommandLine` becomes `process.command_line`). Use with Winlogbeat/Elastic Agent output.
  - `sysmon` -- adds Sysmon `EventID` conditions for logsource routing. Use when evaluating against raw Sysmon JSON that includes `EventID`.
- Pipelines are sorted by `priority` (ascending); lower priority runs first.
- All pipelines are applied in sequence to each rule before compilation.
- In daemon mode, pipeline files are watched for changes and re-read on reload (alongside rules). Builtin pipelines are embedded at compile time and are not file-watched. If a pipeline file becomes invalid, the reload fails and the previous configuration stays active.
- `merge_pipelines` is not used by the CLI; each pipeline remains separate with its own state.

## Dynamic Pipelines

Dynamic pipelines extend static Sigma pipelines with external data sources. Any string, list, or mapping value in the pipeline YAML can contain `${source.<id>}` template references that are resolved at runtime.

### Source declaration

Add a `sources` section to your pipeline YAML:

```yaml
name: dynamic_threat_intel
sources:
  - id: ip_blocklist
    type: http
    url: https://feeds.example.com/blocklist.json
    format: json
    extract: ".ips"
    refresh: 300s
    timeout: 10s
    on_error: use_cached
    required: true

  - id: field_config
    type: file
    path: /etc/rsigma/fields.json
    format: json
    refresh: watch

  - id: enrichment_rules
    type: command
    command: ["generate-transformations", "--format", "json"]
    format: json
    refresh: once

transformations:
  - id: map_fields
    type: field_name_mapping
    mapping: ${source.field_config}

  - id: block_known_bad
    type: add_condition
    conditions:
      - field: DestinationIp
        value: ${source.ip_blocklist}

  - include: ${source.enrichment_rules}
```

### Source types

| Type | Description |
|------|-------------|
| `file` | Read from a local file. Supports `refresh: watch` for automatic reload on change |
| `http` | Fetch from an HTTP endpoint. Supports `method`, `headers`, `timeout` |
| `command` | Run a local command and capture stdout |
| `nats` | Subscribe to a NATS subject for push-based updates (requires `daemon-nats` feature) |

### Data formats

| Format | Description |
|--------|-------------|
| `json` | Parsed with serde_json |
| `yaml` | Parsed with yaml_serde |
| `lines` | One value per line (produces a JSON array of strings) |
| `csv` | Comma-separated values |

### Extraction languages

After parsing the source data, an optional `extract` expression selects a subset:

```yaml
# jq (default) -- plain string is always jq
extract: ".indicators[].ip"

# JSONPath -- structured syntax
extract:
  type: jsonpath
  expr: "$.indicators[*].ip"

# CEL (Common Expression Language) -- structured syntax
extract:
  type: cel
  expr: "data.indicators.filter(i, i.severity > 7)"
```

| Language | Syntax | Library |
|----------|--------|---------|
| jq | Plain string or `{ type: jq, expr: "..." }` | jaq |
| JSONPath | `{ type: jsonpath, expr: "..." }` | jsonpath-rust |
| CEL | `{ type: cel, expr: "..." }` | cel-rust |

### Refresh policies

| Policy | Behavior |
|--------|----------|
| `once` | Fetch at startup only |
| `<duration>` (e.g. `300s`, `5m`) | Re-fetch on a fixed interval |
| `watch` | Watch the file for changes (file sources only) |
| `push` | Updated on each incoming NATS message (NATS sources only) |
| `on_demand` | Fetch at startup, then only when triggered via API or SIGHUP |

### Error policies

| Policy | Behavior |
|--------|----------|
| `use_cached` | Serve the last successfully fetched value on failure |
| `fail` | For required sources: block startup. For optional sources: log and use null |
| `use_default` | Fall back to the `default` value declared in the source config |

### Include directives

The `include` transformation type injects an entire block of transformations from a resolved source:

```yaml
transformations:
  - include: ${source.dynamic_transforms}
```

The source must resolve to a JSON array of transformation objects. Nested includes are rejected (max depth 1). Remote sources (HTTP/NATS) require `--allow-remote-include` for security.

### Startup behavior

- **Required sources** (`required: true`, the default): the daemon blocks until resolution succeeds. If `on_error: fail`, it exits on failure.
- **Optional sources** (`required: false`): if resolution fails at startup, the daemon starts with a null fallback and retries in the background.

### Caching

Resolved values are cached in memory (and optionally SQLite). The cache supports TTL-based expiration. The `use_cached` error policy serves stale data from the cache when a fresh fetch fails. Cache entries can be invalidated per-source via `DELETE /api/v1/sources/cache/{source_id}`.

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
| `daemon` | **on** | Enables the `engine daemon` subcommand (tokio, axum, prometheus, notify, rusqlite) |
| `daemon-nats` | off | Enables NATS JetStream input/output, authentication, replay, and consumer groups (implies `daemon`) |
| `daemon-otlp` | off | Enables OTLP log ingestion via HTTP (protobuf/JSON) and gRPC on `/v1/logs` (implies `daemon`) |
| `logfmt` | off | Enables `logfmt` input format in `daemon` and `eval` |
| `cef` | off | Enables CEF (ArcSight) input format in `daemon` and `eval` |
| `evtx` | off | Enables EVTX (Windows Event Log) input format |
| `daachorse-index` | off | Enables the `--cross-rule-ac` flag and links in [daachorse](https://crates.io/crates/daachorse) for cross-rule Aho-Corasick pre-filtering of large substring-heavy rule sets |

```bash
# Build with all features
cargo build --release --features daemon-nats,daemon-otlp,logfmt,cef,evtx,daachorse-index

# Build without daemon (parser, eval, convert, lint only)
cargo build --release --no-default-features
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success. For `eval`: events processed (detections may or may not have fired, unless `--fail-on-detection` is set). For `lint`: no findings at the configured `--fail-level`. For `validate`: all rules parsed and compiled. |
| `1` | Findings. For `eval --fail-on-detection`: at least one detection or correlation fired. For `lint`: at least one finding at or above `--fail-level` severity. |
| `2` | Rule error. A Sigma rule could not be parsed, compiled, or converted. |
| `3` | Configuration error. A pipeline file could not be loaded, a CLI argument was invalid, or the tool was otherwise misconfigured. |

### CI/CD flags

Use `--fail-on-detection` with `eval` to fail a CI pipeline when a detection rule matches:

```bash
rsigma engine eval -r rules/ --fail-on-detection -e @test-events.ndjson
echo $?  # 0 = no detections, 1 = detections fired, 2 = rule error, 3 = config error
```

Use `--fail-level` with `lint` to control the minimum severity that triggers a non-zero exit:

```bash
rsigma rule lint rules/ --fail-level warning   # exit 1 on warnings or errors
rsigma rule lint rules/ --fail-level info      # exit 1 on any finding
rsigma rule lint rules/                        # default: exit 1 only on errors
```

## License

MIT License.

[rsigma workspace]: https://github.com/timescale/rsigma
