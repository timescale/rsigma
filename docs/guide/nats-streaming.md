# NATS Streaming

RSigma can read events from and write detections to [NATS JetStream](https://docs.nats.io/nats-concepts/jetstream). This page covers the daemon's NATS integration: authentication, at-least-once delivery, replay, consumer groups, and the dead-letter queue. For NATS-as-an-input fundamentals see [Streaming Detection](streaming-detection.md).

NATS support is feature-gated. Build the daemon with `daemon-nats`:

```bash
cargo install --locked rsigma --features daemon-nats
```

## Why JetStream

The daemon uses NATS JetStream (not core NATS) for two reasons:

- **At-least-once delivery**. JetStream persists every message until acknowledged. If the daemon crashes between receipt and sink delivery, the message redelivers after `ack_wait` expires. Core NATS publishes are fire-and-forget.
- **Server-confirmed publishes**. When the daemon writes a detection to NATS, the publish-ack arrives after the message lands in the stream. We never lose detections to a transient network blip.

The trade-off is a JetStream-enabled NATS server. Run `nats-server -js` or any NATS deployment with JetStream enabled. RSigma will not start with a `nats://` URL pointing at a core-NATS server.

## Source and sink URLs

The flags accept full URLs:

```bash
rsigma engine daemon -r rules/ \
    --input  nats://nats.internal:4222/events.> \
    --output nats://nats.internal:4222/detections
```

The subject after the host is the JetStream subject to subscribe to (input) or publish to (output). Wildcards (`*`, `>`) work for input. For output, the subject must be concrete.

The daemon manages JetStream resources for you. On startup it calls `get_or_create_stream` to ensure a stream named `rsigma-<sanitized-subject>` exists (covering the subject filter you passed), and `get_or_create_consumer` for the matching durable consumer. You do not need to pre-create the stream or consumer with the `nats` CLI; if you already have one whose subject filter overlaps the subject you pass to `--input`, JetStream rejects the conflict and the daemon refuses to start.

You can mix and match: read from NATS, write to stdout; or read from stdin, write to NATS; or fan out a single source to multiple sinks via repeated `--output`:

```bash
rsigma engine daemon -r rules/ \
    --input nats://localhost:4222/events.> \
    --output stdout \
    --output file:///var/log/rsigma/detections.ndjson \
    --output nats://localhost:4222/detections.urgent
```

## Authentication

Five auth methods are supported. They're mutually exclusive (the first configured one wins). All credentials can come from CLI flags or environment variables:

| Method | Flag | Env var |
|--------|------|---------|
| Credentials file (JWT + NKey) | `--nats-creds /path/to/file.creds` | `NATS_CREDS` |
| Token | `--nats-token TOKEN` | `NATS_TOKEN` |
| Username + password | `--nats-user U --nats-password P` | `NATS_USER`, `NATS_PASSWORD` |
| NKey | `--nats-nkey SEED` | `NATS_NKEY` |
| Mutual TLS | `--nats-tls-cert client.pem --nats-tls-key client-key.pem` | (none) |

Prefer environment variables for secrets in production so they do not show up in `ps aux` or shell history:

```bash
export NATS_CREDS=/etc/rsigma/nats.creds
rsigma engine daemon -r rules/ --input nats://nats.example.com:4222/events.>
```

To force TLS even when the server advertises it as optional, add `--nats-require-tls`:

```bash
rsigma engine daemon -r rules/ \
    --input nats://nats.internal:4222/events.> \
    --nats-tls-cert /etc/rsigma/client.pem \
    --nats-tls-key /etc/rsigma/client-key.pem \
    --nats-require-tls
```

## At-least-once delivery

When `--input nats://...` is used, the daemon switches from at-most-once to at-least-once semantics. Each message is wrapped in an `AckToken` that is held until the corresponding detection has been delivered to every output sink. A dedicated ack task resolves tokens after sink confirmation.

What this guarantees:

- If the daemon panics mid-processing, NATS redelivers after `ack_wait` (configured on the JetStream consumer).
- If a sink fails (file write error, NATS publish-ack timeout), the source message is NOT acked, so NATS redelivers.
- If a parse error happens before the engine, the failed event is routed to the [DLQ](#dead-letter-queue) and the source message IS acked, preventing infinite redelivery of unparseable data.

What this does NOT guarantee:

- Exactly-once. A redelivery can produce duplicate detections downstream. Plan for idempotent consumers.
- Order across reconnects. NATS redelivers in the order it sees fit.

## Replay

JetStream consumers can start anywhere in the stream history. The daemon exposes this through three mutually exclusive flags:

| Flag | Behaviour |
|------|-----------|
| `--replay-from-sequence N` | Start at stream sequence number `N`. Useful for resuming after a known checkpoint. |
| `--replay-from-time TIMESTAMP` | Start from a wall-clock time. ISO 8601 (`2026-05-15T10:00:00Z`). |
| `--replay-from-latest` | Start at the last message in the stream, then deliver new messages. Maps to JetStream's `DeliverLast` policy. |
| (none) | Resume from the consumer's last ack position. The default. |

```bash
rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
    --replay-from-sequence 42

rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
    --replay-from-time 2026-04-30T00:00:00Z

rsigma engine daemon -r rules/ --input nats://localhost:4222/events.> \
    --replay-from-latest
```

### State restore during replay

The daemon stores the last-acked NATS stream sequence and timestamp alongside the SQLite correlation snapshot. On restart, `decide_state_restore` compares the replay start point against the stored position:

| Situation | Decision |
|-----------|----------|
| Resume (no replay flag) | Restore state. |
| `--replay-from-sequence N` with N > stored sequence | Restore (forward catch-up, safe). |
| `--replay-from-sequence N` with N <= stored sequence | Clear (backward replay would double-count). |
| `--replay-from-time` past stored timestamp | Restore. |
| `--replay-from-time` at or before stored timestamp | Clear. |
| `--replay-from-latest` | Clear. |
| `--keep-state` (any replay) | Force restore. |
| `--clear-state` (any) | Force clear. |

The two override flags are mutually exclusive. Use them when you know better than the heuristic: `--keep-state` for forward catch-up across a partial outage, `--clear-state` for a clean forensic replay.

```bash
rsigma engine daemon -r rules/ \
    --input nats://localhost:4222/events.> \
    --replay-from-sequence 1001 \
    --state-db /var/lib/rsigma/state.db
```

## Consumer groups

For horizontal scaling, set `--consumer-group NAME` (or `RSIGMA_CONSUMER_GROUP=NAME`). Multiple daemon instances using the same group name share a single JetStream durable consumer, and NATS distributes messages across them for load balancing:

```bash
# On each of N nodes
RSIGMA_CONSUMER_GROUP=detection-workers \
    rsigma engine daemon -r rules/ --input nats://nats.internal:4222/events.>
```

Without `--consumer-group`, the daemon derives the consumer name from the subject. Two daemons with the same subject and no explicit group will share a consumer automatically, but you lose the explicit name in the JetStream UI.

Multi-node correlation state is NOT automatically partitioned by consumer group. Each daemon maintains its own SQLite correlation state. If your rules need cross-node correlation, you have two options:

- Route all events to a single daemon (no consumer group).
- Partition by `group_by` key upstream (e.g. one consumer-group subject per shard).

A distributed correlation engine across nodes is on the roadmap but not shipped yet.

## Dead-letter queue

Events that fail processing (parse errors, sink delivery failures, oversize messages) are routed to the DLQ instead of being silently dropped:

```bash
rsigma engine daemon -r rules/ \
    --input nats://localhost:4222/events.> \
    --dlq file:///var/log/rsigma/dlq.ndjson

rsigma engine daemon -r rules/ \
    --input nats://localhost:4222/events.> \
    --dlq nats://localhost:4222/dlq.rsigma

rsigma engine daemon -r rules/ \
    --input nats://localhost:4222/events.> \
    --dlq stdout
```

Each DLQ entry is a JSON object:

```json
{
  "original_event": "NOT JSON at all",
  "error": "parse error",
  "timestamp": "2026-05-18T14:19:42.697130+00:00"
}
```

The `rsigma_dlq_events_total` Prometheus counter tracks DLQ volume. Alert on rate-of-change to catch upstream encoding regressions early. See [Prometheus metrics reference](../reference/metrics.md).

## Connection lifecycle and reconnects

`async-nats` handles reconnection automatically with exponential backoff. The daemon logs each connect/disconnect/reconnect at `info` level via the `tracing` subscriber. While disconnected:

- Incoming messages buffer briefly in NATS's local buffer, then back-pressure propagates to the publisher.
- Outgoing sink writes block until reconnect.
- The `/healthz` endpoint returns 200 (the daemon process is alive).
- `/readyz` continues to return 200 (rules are still loaded).

`/api/v1/status` does not currently expose connection state, but the metrics endpoint emits `rsigma_back_pressure_events_total` increments when the input channel fills, which is a reliable proxy for upstream stalls.

## Tuning checklist

| Setting | Tune to |
|---------|---------|
| Stream `max_age`/`max_msgs` | Long enough to outlast any restart you care to replay across. |
| Consumer `ack_wait` | Short enough to redeliver quickly on a panic, long enough that legitimate slow processing does not trigger redelivery. 30 to 60 s is a good starting point. |
| Consumer `max_deliver` | Cap at 5 to 10. Beyond that, DLQ is more honest than infinite redelivery. |
| `--buffer-size` | Bounded mpsc capacity. Default 10000. Increase to 50000+ for bursty 50k/s ingest. |
| `--batch-size` | Events per engine mutex acquisition. Default 1. Set to 64 or 128 under load to amortise lock cost. |
| `--drain-timeout` | Seconds to wait for in-flight events on shutdown. Default 5. Raise to 30 in production so SIGTERM does not lose work. |
| `--state-save-interval` | Periodic SQLite snapshot interval. Default 30 s. Lower means less work to redo after a crash; higher means less disk I/O. |
| `--dlq` | Set in production. Never set means parse errors are silently dropped. |

## Example: production NATS deployment

```bash
RSIGMA_CONSUMER_GROUP=detection-workers \
NATS_CREDS=/etc/rsigma/nats.creds \
rsigma engine daemon \
    --rules /etc/rsigma/rules/ \
    --pipeline /etc/rsigma/pipelines/ecs.yml \
    --input nats://nats.internal:4222/events.> \
    --output nats://nats.internal:4222/detections \
    --output file:///var/log/rsigma/detections.ndjson \
    --dlq nats://nats.internal:4222/dlq.rsigma \
    --state-db /var/lib/rsigma/state.db \
    --state-save-interval 30 \
    --buffer-size 50000 \
    --batch-size 64 \
    --drain-timeout 30 \
    --nats-require-tls \
    --api-addr 0.0.0.0:9090
```

## See also

- [CLI reference: `engine daemon`](../cli/engine/daemon.md) for every flag including the NATS-specific ones.
- [Streaming Detection](streaming-detection.md) for the daemon overview, hot-reload, state persistence, and HTTP API.
- [Observability](observability.md) for the `RUST_LOG` targets that surface NATS lifecycle events.
- [Prometheus metrics reference](../reference/metrics.md) for the NATS-related counters.
- [Environment Variables reference](../reference/environment-variables.md) for `NATS_*` and `RSIGMA_CONSUMER_GROUP`.
