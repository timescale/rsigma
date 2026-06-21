# `rsigma engine tail`

Stream a running daemon's live detections to the terminal.

## Synopsis

```text
rsigma engine tail [OPTIONS]
```

## Description

`engine tail` answers "what is the daemon firing right now?" without standing up a sink or scraping `/metrics`. It opens a streaming connection to a running [`engine daemon`](daemon.md) on `GET /api/v1/detections/stream` and prints each detection and correlation result as it fires, in the same `EvaluationResult` shape the sinks emit, so `engine tail` and a saved sink file are the same format.

```bash
rsigma engine tail --level high --rule whoami
```

It is the detections-out counterpart to [`engine tap`](tap.md) (events-in). Where the tap records what the engine *received*, tail shows what it *fired*, after post-evaluation enrichment and regardless of which sinks are configured.

The stream is **lossy by design**: it can never apply backpressure to the sink task or stall the at-least-once ack-join. If a session's buffer fills under load, detections are dropped and counted, and the final summary record reports the gap.

Like [`engine status`](status.md) it is a read-only client over the admin API. It uses a synchronous HTTP client and does not need the `daemon` build feature, and it follows the same address convention as [`config reload`](../config/reload.md): `--addr` defaults to `daemon.api.addr`, and wildcard binds (`0.0.0.0`, `[::]`) map to loopback.

The tail is **disabled by default**. Enable it on the daemon with `daemon.tail.enabled: true` in the config (or `RSIGMA_DAEMON__TAIL__ENABLED=true`); otherwise the endpoint returns `503`.

### Filters

Two optional server-side filters keep a noisy daemon's tail readable:

- `--level <severity>`: minimum severity (`informational`, `low`, `medium`, `high`, `critical`). Results below it, or with no level, are excluded.
- `--rule <substring>`: a case-insensitive substring matched against the rule title or id.

Both are applied at the sink, so filtered-out results never cross the wire.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr <HOST:PORT or URL>` | from `daemon.api.addr` | Daemon API address as `host:port` or a full URL. `https://` URLs work for TLS deployments. |
| `--duration <D>` | unset | Capture window (humantime). Unset streams until interrupted or `--limit` is reached. |
| `--limit <N>` | unset | Stop after N detections, before the duration if reached first. |
| `--level <severity>` | unset | Minimum severity filter. |
| `--rule <substring>` | unset | Case-insensitive title/id substring filter. |
| `-c, --config <PATH>` | discovery chain | Explicit config file used to resolve the daemon address. |

Rendered through the global `--output-format` layer: a TTY-aware default (pretty `json` on a terminal, `ndjson` when piped) plus `csv`/`tsv` row streaming and a `table` view (buffered, so `table` suits a bounded `--duration`/`--limit` tail rather than an open-ended one). The global `--quiet` / `--no-stats` flags suppress the stderr stats line. See [Output Formats](../../reference/output.md).

## Examples

### Watch high-severity detections

```bash
rsigma engine tail --level high
```

### Follow a specific rule and pipe to jq

```bash
rsigma engine tail --rule "suspicious login" | jq '.matched_fields'
```

### Capture a fixed window to a file

```bash
rsigma engine tail --duration 5m --output-format ndjson > detections.ndjson
```

### Stop after the first N detections

```bash
rsigma engine tail --limit 20 --output-format table
```

## Output

The stream is NDJSON: one result per line, followed by a final summary record the client uses for the stats line and keeps out of the rendered output:

```json
{"rsigma_tail_summary":{"streamed":42,"dropped":0}}
```

A non-zero `dropped` means a session buffer filled under load; the tail missed detections.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The stream ended cleanly (even with zero detections). |
| `3` | The daemon could not be reached, returned a non-2xx status (e.g. `503` when the tail is disabled, `409` at the session cap, `400` for bad params), or sent an unreadable stream. |

## See also

- [`engine tap`](tap.md) for the events-in counterpart.
- [`engine daemon`](daemon.md) for the long-running service and the `daemon.tail.*` limits.
- [HTTP API: `GET /api/v1/detections/stream`](../../reference/http-api.md#live-detection-tail) for the raw endpoint, query params, and error semantics.
- [Streaming Detection](../../guide/streaming-detection.md) for the daemon overview.
