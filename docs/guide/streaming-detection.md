# Streaming Detection

`rsigma engine daemon` runs RSigma as a long-running service: it keeps a compiled engine in memory, reads events from a continuous source, writes detections to one or more sinks, and exposes a small HTTP API for health checks, metrics, and management. This is the mode you deploy in production.

This page covers the daemon's life cycle, input and output options, hot-reload, state persistence, and the HTTP API surface. For NATS-specific operations (auth, replay, consumer groups, DLQ) see [NATS Streaming](nats-streaming.md). For OTLP ingestion see [OTLP Integration](otlp-integration.md).

## What the daemon does

```text
                ┌───────────────┐    ┌──────────────────┐    ┌───────────────┐
events ───────► │ Event source  ├───►│  LogProcessor    ├───►│  Sinks        ├───► detections
                │ stdin/HTTP    │    │  + RuntimeEngine │    │ stdout/file   │
                │ NATS/OTLP     │    │  (Engine + Corr) │    │ NATS/DLQ      │
                └───────────────┘    └──────────────────┘    └───────────────┘
                                            ▲
                                            │
                                     hot-reload triggers
                                  (file watcher, SIGHUP,
                                   POST /api/v1/reload,
                                   atomic ArcSwap)
```

A single daemon process binds one event source, one or more output sinks, a management HTTP API, optional SQLite state persistence, and an optional dead-letter queue for events that fail processing. State and rules can be reloaded without restart.

## Start the daemon

The minimal invocation reads NDJSON from stdin and writes detections to stdout:

```bash
rsigma engine daemon -r rules/
```

The daemon stays alive after stdin reaches EOF, unlike `engine eval`. To send events from a logging agent, pipe directly:

```bash
hel run | rsigma engine daemon -r rules/ -p ecs_windows --api-addr 0.0.0.0:9090
```

A more typical production invocation accepts events via HTTP POST, persists correlation state to SQLite, writes detections to both stdout and a file for fan-out, and binds an explicit management address:

```bash
rsigma engine daemon \
    --rules /etc/rsigma/rules/ \
    --pipeline /etc/rsigma/pipelines/ecs.yml \
    --input http \
    --output stdout \
    --output file:///var/log/rsigma/detections.ndjson \
    --state-db /var/lib/rsigma/state.db \
    --api-addr 0.0.0.0:9090
```

## Input sources

The `--input` flag selects the primary event source:

| Source | Flag | What it does |
|--------|------|--------------|
| stdin | `--input stdin` (default) | Read NDJSON from standard input. |
| HTTP | `--input http` | Accept NDJSON `POST` requests on `/api/v1/events`. |
| NATS JetStream | `--input nats://host:port/subject` | Subscribe to a JetStream subject with at-least-once delivery. Requires the `daemon-nats` feature. |

OTLP ingestion is always available alongside the primary source when the daemon is built with the `daemon-otlp` feature. Agents can post to `/v1/logs` (HTTP, protobuf or JSON) or use the gRPC `LogsService/Export` on the same `--api-addr` port.

See [NATS Streaming](nats-streaming.md) for auth, replay, consumer groups, and DLQ. See [OTLP Integration](otlp-integration.md) for agent recipes.

### Input format and timestamp extraction

By default the daemon auto-detects the line format (JSON, syslog, plain text). Use `--input-format` to lock it in for predictable performance and validation:

```bash
rsigma engine daemon -r rules/ --input-format json
rsigma engine daemon -r rules/ --input-format syslog --syslog-tz +05:30
rsigma engine daemon -r rules/ --input-format logfmt
rsigma engine daemon -r rules/ --input-format cef
```

For correlation windows, the daemon tries a configurable list of timestamp fields. Prepend your own with `--timestamp-field`:

```bash
rsigma engine daemon -r rules/ --timestamp-field time --timestamp-field _ts
```

When an event has no parseable timestamp, the daemon falls back to the wall clock by default. Pass `--timestamp-fallback skip` to instead drop the event from correlation state (detections still fire). This is what you want for forensic replay of historical data.

## Output sinks

The `--output` flag is repeatable, which gives you fan-out for free. Each match is cloned to every configured sink via a bounded mpsc channel:

| Sink URI | Behaviour |
|----------|-----------|
| `stdout` | NDJSON to stdout. Default. |
| `file:///path/to/file.ndjson` | Append NDJSON to a file, rotating only if you wrap it externally (logrotate, etc.). |
| `nats://host:port/subject` | Publish via JetStream with server-confirmed persistence. Requires `daemon-nats`. |

Failed deliveries are routed to the dead-letter queue when `--dlq` is configured:

```bash
rsigma engine daemon -r rules/ \
    --input nats://localhost:4222/events.> \
    --output stdout --output file:///var/log/rsigma/detections.ndjson \
    --dlq file:///var/log/rsigma/dlq.ndjson
```

## Pipeline and back-pressure tuning

A handful of flags control how aggressively the daemon batches and how much it buffers under load:

| Flag | Default | What it controls |
|------|---------|------------------|
| `--buffer-size` | 10000 | Bounded mpsc capacity for source-to-engine and engine-to-sink channels. |
| `--batch-size` | 1 | Max events the engine pulls per mutex acquisition. Higher values amortise lock contention under load. |
| `--drain-timeout` | 5 | Seconds the daemon waits for in-flight events on shutdown. |

For a 50 K/s ingest target, `--buffer-size 50000 --batch-size 64 --drain-timeout 10` is a reasonable starting point. The `rsigma_input_queue_depth`, `rsigma_output_queue_depth`, and `rsigma_back_pressure_events_total` metrics tell you when you are sized too small. See the [observability guide](observability.md) for details.

## Hot-reload

Three triggers cause the daemon to re-read its rules and pipelines, debounced at 500 ms:

1. A file system change to any `.yml` or `.yaml` file under the rules directory or to any pipeline file passed via `-p`.
2. A `SIGHUP` signal (Unix only). This also triggers re-resolution of dynamic pipeline sources.
3. A `POST /api/v1/reload` request.

If the new configuration fails to parse, the daemon keeps the old engine running and increments `rsigma_reloads_failed_total`. Successful reloads atomically swap the in-memory engine via `ArcSwap`, so in-flight events finish on the old engine and new events evaluate against the new one without dropping any.

Builtin pipelines (`ecs_windows`, `sysmon`) are embedded in the binary and are not file-watched.

## State persistence

Without `--state-db`, correlation state lives only in memory and is lost on restart. With `--state-db`:

```bash
rsigma engine daemon -r rules/ --state-db /var/lib/rsigma/state.db
```

The daemon loads any existing snapshot on startup, saves periodically (every 30 s by default, tunable with `--state-save-interval`), and saves on graceful shutdown. The database is a single SQLite file in WAL journal mode that holds one JSON snapshot row.

This means an `event_count` correlation that has seen 4 of 5 required events resumes at 4 after a restart, not 0.

### State restore during NATS replay

When you restart with a NATS replay flag (`--replay-from-sequence`, `--replay-from-time`, `--replay-from-latest`), the daemon stores the last-acked sequence and timestamp alongside the snapshot. On the next start, `decide_state_restore` compares the replay start point against the stored position:

- Replay starts after the stored position (forward catch-up): state is restored safely.
- Replay starts at or before the stored position (backward replay or forensic investigation): state is cleared, preventing double-counting.

Override the automatic decision with `--keep-state` (always restore) or `--clear-state` (always start fresh). The two flags are mutually exclusive.

```bash
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
    --replay-from-sequence 1001 --state-db /var/lib/rsigma/state.db
```

See [NATS Streaming](nats-streaming.md) for the full replay matrix.

## HTTP API

The daemon binds an Axum HTTP server on `--api-addr` (default `0.0.0.0:9090`). It serves both REST and Prometheus endpoints, plus OTLP/gRPC and OTLP/HTTP when the feature is enabled. The full reference is in [HTTP API](../reference/http-api.md). Key endpoints:

| Path | Method | Purpose |
|------|--------|---------|
| `/healthz` | GET | Liveness probe. Always 200 once the listener is up. |
| `/readyz` | GET | Readiness probe. 200 once rules are loaded, 503 otherwise. |
| `/metrics` | GET | Prometheus text format, 27 metrics. |
| `/api/v1/status` | GET | Counters, state-entry counts, uptime. |
| `/api/v1/rules` | GET | Rule counts and rules-directory path. |
| `/api/v1/reload` | POST | Trigger an immediate rules reload. |
| `/api/v1/events` | POST | Ingest events (only when `--input http`). NDJSON body. |
| `/api/v1/sources` | GET | Status of dynamic pipeline sources. |
| `/api/v1/sources/resolve` | POST | Force re-resolution of all (or some) dynamic sources. |
| `/v1/logs` | POST | OTLP log ingestion (`application/x-protobuf` or `application/json`). |

Wire `/readyz` to your orchestrator's startup probe and `/healthz` to the liveness probe. Scrape `/metrics` at 15-30 s intervals.

## Logging

Stderr carries structured JSON logs through `tracing-subscriber`. Verbosity is controlled with `RUST_LOG` (default `info`):

```bash
RUST_LOG=info,tower_http=debug rsigma engine daemon -r rules/
```

Useful filter targets and the spans they enable are documented in the [observability guide](observability.md), including:

- `tower_http=debug` for per-request HTTP access logs.
- `rsigma=debug` for batch processing spans (`batch_size`, `matches`, `elapsed_ms`).
- `rsigma_runtime::sources=debug` for dynamic pipeline source resolution.
- `rsigma_eval=debug` for correlation engine internals (chain depth, hard-cap eviction).

## Graceful shutdown

`SIGINT` (Ctrl+C) and `SIGTERM` both trigger the same shutdown path:

1. Stop accepting new events.
2. Drain in-flight events from the input channel into the engine and through to the sinks, up to `--drain-timeout` seconds.
3. Persist the final correlation snapshot to SQLite if `--state-db` is configured.
4. Close NATS connections, flush sinks, exit 0.

If the drain timeout expires before the queue empties, the daemon force-exits with a `Drain timeout reached, exiting` log line. In-flight events that did not reach a sink are routed to the DLQ when `--dlq` is set, or lost otherwise.

## Production checklist

| Item | Why |
|------|-----|
| `--rules` points to a versioned directory under config management. | Hot-reload should be a deliberate operation, not an accident. |
| `--pipeline` references either a builtin (`ecs_windows`, `sysmon`) or a versioned file in the same directory. | Same. |
| `--state-db` is set and points to durable storage. | Correlation state survives restarts. |
| `--dlq` is configured. | Parse errors and sink failures land somewhere you can audit. |
| `--api-addr` is bound to an internal interface (or behind a proxy). | The management API has no auth. Never expose it on the public internet. |
| The container runs read-only with capabilities dropped. | See the [Docker guide](../deployment/docker.md). |
| Prometheus scrapes `/metrics`. | Detect back-pressure, parse errors, DLQ events. |
| `/readyz` is wired to the orchestrator's startup probe. | Avoid sending traffic to a daemon that has not loaded rules yet. |

## See also

- [CLI reference: `engine daemon`](../cli/engine/daemon.md) for every flag.
- [NATS Streaming](nats-streaming.md) for auth, replay, consumer groups, and DLQ.
- [OTLP Integration](otlp-integration.md) for Alloy, Vector, Fluent Bit, and OTel Collector recipes.
- [Observability](observability.md) for `--log-format`, RUST_LOG targets, and tracing spans.
- [HTTP API](../reference/http-api.md) for the full endpoint reference.
- [Prometheus metrics](../reference/metrics.md) for the 27-metric catalog.
- [Docker](../deployment/docker.md) for hardened production containers.
