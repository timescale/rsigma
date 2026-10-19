# Streaming Detection

`rsigma engine daemon` runs RSigma as a long-running service: it keeps a compiled engine in memory, reads events from a continuous source, writes detections to one or more sinks, and exposes a small HTTP API for health checks, metrics, and management. Use it when you need state to survive restarts, hot-reload across rule changes, or a Prometheus-scrapeable detection engine.

This page covers the daemon's lifecycle, input and output options, hot-reload, state persistence, and the HTTP API surface. For NATS-specific operations (auth, replay, consumer groups, DLQ) see [NATS Streaming](nats-streaming.md). For OTLP ingestion see [OTLP Integration](otlp-integration.md).

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

Start with `--input http` so the process stays up while you probe it. Detections go to stdout by default; the management API binds `--api-addr` (default `0.0.0.0:9090`):

```bash
rsigma engine daemon -r rules/ --input http --api-addr 127.0.0.1:9090
```

Wait until rules are loaded, which happens almost instantly, then post an NDJSON event and check readiness:

```bash
curl -sS http://127.0.0.1:9090/readyz
# ok

curl -sS -X POST http://127.0.0.1:9090/api/v1/events \
  -H 'Content-Type: application/x-ndjson' \
  --data '{"CommandLine":"whoami /priv"}'
# {"accepted":1}
```

Matching detections appear on the daemon's stdout as NDJSON. Scrape `GET /metrics` or `GET /api/v1/status` for counters.

A fuller production-shaped start adds a pipeline, SQLite correlation state, and a file sink for fan-out:

```bash
rsigma engine daemon \
    --rules /etc/rsigma/rules/ \
    --pipeline /etc/rsigma/pipelines/ecs.yml \
    --input http \
    --output stdout \
    --output file:///var/log/rsigma/detections.ndjson \
    --state-db /var/lib/rsigma/state.db \
    --api-addr 127.0.0.1:9090
```

For one-shot pipes and batch replay, use [`engine eval`](evaluating-rules.md#stdin) instead. The daemon's default `--input stdin` is for a long-lived writer that keeps the pipe open (a collector process). If that writer closes stdin, the daemon treats the source as exhausted and shuts down after draining in-flight events; it does not stay up waiting for another pipe.

## Input sources

The `--input` flag selects the primary event source:

| Source | Flag | What it does |
|--------|------|--------------|
| stdin | `--input stdin` (default) | Read NDJSON from standard input. Intended for a long-lived writer; when stdin closes, the daemon drains and exits. Prefer `--input http` for interactive testing, and [`engine eval`](evaluating-rules.md#stdin) for one-shot pipes. |
| HTTP | `--input http` | Accept NDJSON `POST` requests on `/api/v1/events`. |
| NATS JetStream | `--input nats://host:port/subject` | Subscribe to a JetStream subject with at-least-once delivery. Requires the `daemon-nats` feature. |
| Unix socket | `--input unix:///path/to.sock` | Accept newline-delimited events over a Unix domain socket (Unix only). Co-located log shippers (rsyslog `omuxsock`, syslog-ng `unix-stream`, Vector, Fluent Bit) write to it directly without a TCP port. |

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

### Window modes

A correlation rule's optional `window` attribute controls how its `timespan` is anchored to the stream, and the engine evaluates each mode directly:

- `sliding` (the default, and what an absent `window` means): a trailing per-event window. When an event arrives at time `t`, the correlation is evaluated over `(t - timespan, t]`, so two events correlate whenever they are within `timespan` of each other regardless of any fixed boundary.
- `tumbling`: fixed, boundary-aligned, non-overlapping buckets of size `timespan`. The per-group state resets when an event lands in a new bucket. Use this when you genuinely want calendar-style buckets (for example a per-hour quota), accepting that events on opposite sides of a boundary are not compared.
- `session`: a dynamic window that stays open while consecutive in-group events are within `gap` of each other, and closes after `gap` of inactivity. It restarts once the total span would exceed `timespan` (the hard cap). This is the only mode that catches a low-and-slow chain whose steps are each close together but whose total span exceeds any fixed `timespan`.

`window` and `gap` are an RSigma extension (a portable-spec version was declined upstream), so the primary spelling is the `rsigma.*` engine-extension namespace and the bare keys are kept as aliases. Both of these are equivalent:

```yaml
# Primary: rsigma.* extension keys (top level, like rsigma.suppress)
rsigma.window: session
rsigma.gap: 5m
```

```yaml
# Alias: first-class keys under the correlation section
correlation:
    window: session
    gap: 5m
```

The `rsigma.*` spelling wins if both appear. The engine reads the resolved value either way.

Window decisions follow arrival order, the same contract as the existing sliding window: the engine reasons about the events currently retained per group, not a global watermark. One asymmetry is deliberate: a tumbling window discards a late event that belongs to an earlier, already-passed bucket rather than letting it reset the active bucket, so out-of-order stragglers cannot wipe an accumulating count. Window bookkeeping is derived from the per-group timestamps already tracked, so persisted state (`--state-db`) stays compatible and survives upgrades.

All three modes have the same per-event cost (the window decision is O(1)), so choosing `session` over `sliding` is free at evaluation time; what differs is how long state is retained per group. See [Performance Tuning](performance-tuning.md#memory-pressure-and-correlation-state) for the memory characteristics and the [Benchmarks](../benchmarks.md#window-mode-memory-stress) page for measured numbers under high-cardinality and long-lived-session stress.

## Output sinks

The `--output` flag is repeatable, which gives you fan-out for free. Each match is cloned to every configured sink via a bounded mpsc channel:

| Sink URI | Behavior |
|----------|----------|
| `stdout` | NDJSON to stdout. Default. Line sinks also accept `?format=ocsf` for [OCSF Detection Finding](ocsf-findings.md) JSON. |
| `file:///path/to/file.ndjson` | Append NDJSON to a file, rotating only if you wrap it externally (logrotate, etc.). |
| `nats://host:port/subject` | Publish via JetStream with server-confirmed persistence. Requires `daemon-nats`. |
| `otlp(s)://host:port` | Export detections over OTLP/gRPC (`s` = TLS). Each attempt has a `10s` deadline, tunable with `?timeout=`. {{ added "0.25.0" }} Requires `daemon-otlp`. |
| `otlphttp(s)://host:port` | Export detections over OTLP/HTTP to `/v1/logs` (`s` = TLS). Each attempt has a `10s` deadline, tunable with `?timeout=`. {{ added "0.25.0" }} Requires `daemon-otlp`. |
| `unix:///path/to.sock` | Write NDJSON to a collector listening on a Unix domain socket (Unix only). Reconnects once on a transient write failure. |

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
| `--batch-size` | 128 | Max events the engine pulls per mutex acquisition, capped at `--buffer-size`. Batches enable parallel detection and amortize lock contention under load. |
| `--drain-timeout` | 5 | Seconds the daemon waits for in-flight events on shutdown. |

For a 50 K/s ingest target, `--buffer-size 50000 --batch-size 64 --drain-timeout 10` is a reasonable starting point. The `rsigma_input_queue_depth`, `rsigma_output_queue_depth`, and `rsigma_back_pressure_events_total` metrics tell you when you are sized too small. See the [observability guide](observability.md) for details.

## Hot-reload

Three triggers cause the daemon to re-read its rules and pipelines, debounced at 500 ms:

1. A file system change to any `.yml` or `.yaml` file under the rules directory or to any pipeline file passed via `-p`.
2. A `SIGHUP` signal (Unix only). This also triggers re-resolution of dynamic pipeline sources.
3. A `POST /api/v1/reload` request.

If the new configuration fails to parse, the daemon keeps the old engine running and increments `rsigma_reloads_failed_total`. Successful reloads atomically swap the in-memory engine via `ArcSwap`, so in-flight events finish on the old engine and new events evaluate against the new one without dropping any.

Correlation windows carry over to the new engine for correlations that still exist after the reload. Rules load while events keep flowing through the old engine; the window state is then copied across and the engines swapped while ordered batches are briefly paused, so counts and windows include every event processed during the load.

Builtin pipelines (`ecs_windows`, `sysmon`) are embedded in the binary and are not file-watched.

## State persistence

Without `--state-db`, correlation state lives only in memory and is lost on restart. With `--state-db`:

```bash
rsigma engine daemon -r rules/ --state-db /var/lib/rsigma/state.db
```

The daemon loads any existing snapshot on startup, saves periodically (every 30 s by default, tunable with `--state-save-interval`), and saves on graceful shutdown. The database is a single SQLite file in WAL journal mode that holds one JSON snapshot row per kind of state (correlation, alert pipeline, risk, and dispositions). Each save captures all of them back to back and writes them in one transaction, so a crash mid-save leaves the previous save intact rather than a mix of old and new state. {{ added "0.25.0" }}

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

The daemon binds an HTTP API listener on `--api-addr` (default `0.0.0.0:9090`). It serves both REST and Prometheus endpoints, plus OTLP/gRPC and OTLP/HTTP when the feature is enabled. With the optional `daemon-tls` build feature and `--tls-cert`/`--tls-key`, the same listener terminates HTTPS for every protocol on one socket (ALPN negotiates `h2` and `http/1.1`). Every build refuses to start on a non-loopback TCP `--api-addr` without TLS or `--allow-plaintext`, and without authentication (bearer tokens or `--tls-client-ca`) or `--allow-unauthenticated`. {{ added "0.25.0" }} Loopback and `unix://` addresses need neither, for local development. See the [TLS reference](../reference/security.md#tls-termination-for-the-api-listener) for the flag table and hot-reload semantics.

Auth is off by default. Enable a single admin bearer token with `--api-token-env`, or configure per-token roles in `daemon.api.auth`. Pair non-loopback listeners with TLS or a TLS-terminating proxy so tokens are never sent in cleartext. See [HTTP API: Authentication](../reference/http-api.md#authentication).

The table below is a subset of the core surface. The full catalog (incidents, silences, risk, fields, correlations, dispositions, audit, and more) is in [HTTP API](../reference/http-api.md).

| Path | Method | Purpose |
|------|--------|---------|
| `/healthz` | GET | Liveness probe. Always 200 once the listener is up. |
| `/readyz` | GET | Readiness probe. 200 once rules are loaded, 503 otherwise. |
| `/metrics` | GET | Prometheus text format, {{ rsigma.metrics.names }} metric names under `--all-features` ({{ rsigma.metrics.always }} always-present + {{ rsigma.metrics.otlp }} OTLP + {{ rsigma.metrics.tls }} TLS gated on the matching build features). |
| `/api/v1/status` | GET | Counters, state-entry counts, uptime. |
| `/api/v1/rules` | GET | Rule counts and rules-directory path. |
| `/api/v1/reload` | POST | Trigger an immediate rules reload. |
| `/api/v1/events` | POST | Ingest events (only when `--input http`). NDJSON body. |
| `/api/v1/sources` | GET | Status of dynamic pipeline sources. |
| `/api/v1/sources/resolve` | POST | Force re-resolution of all (or some) dynamic sources. |
| `/api/v1/tap` | GET | Stream a bounded, redactable window of the live event stream as NDJSON. Disabled by default; enable with `daemon.tap.enabled: true`. See [`engine tap`](../cli/engine/tap.md). |
| `/api/v1/detections/stream` | GET | Stream live detections as NDJSON, with optional `level` / `rule` filters. Disabled by default; enable with `daemon.tail.enabled: true`. See [`engine tail`](../cli/engine/tail.md). |
| `/v1/logs` | POST | OTLP log ingestion (`application/x-protobuf` or `application/json`). |

Wire `/readyz` to your orchestrator's startup probe and `/healthz` to the liveness probe. Scrape `/metrics` at 15-30s intervals.

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
| `--api-addr` is bound to an internal interface or loopback, behind a TLS-terminating proxy, or paired with `--tls-cert`/`--tls-key` (and `--tls-client-ca` for agent pinning), and API auth is enabled (`--api-token-env` or `daemon.api.auth`). | Without auth, network position is the only guard. Never expose a plaintext management listener to the public internet. |
| The container runs read-only with capabilities dropped. | See the [Docker guide](../deployment/docker.md). |
| Prometheus scrapes `/metrics`. | Detect back-pressure, parse errors, DLQ events. |
| `/readyz` is wired to the orchestrator's startup probe. | Avoid sending traffic to a daemon that has not loaded rules yet. |

## See also

- [CLI reference: `engine daemon`](../cli/engine/daemon.md) for every flag.
- [NATS Streaming](nats-streaming.md) for auth, replay, consumer groups, and DLQ.
- [OTLP Integration](otlp-integration.md) for Alloy, Vector, Fluent Bit, and OTel Collector recipes.
- [Alert Pipeline](alert-pipeline.md), [Enrichers](enrichers.md), and [Webhooks](webhooks.md) for post-evaluation surfaces the daemon can attach.
- [Observability](observability.md) for `--log-format`, RUST_LOG targets, and tracing spans.
- [HTTP API](../reference/http-api.md) for the full endpoint reference and authentication.
- [Security](../reference/security.md) for TLS, API auth, and egress policy.
- [Prometheus metrics](../reference/metrics.md) for the {{ rsigma.metrics.names }}-metric catalog.
- [Docker](../deployment/docker.md) for hardened production containers.
