# `rsigma engine tap`

Record a bounded, optionally-redacted window of a running daemon's live event stream into a replayable NDJSON fixture.

## Synopsis

```text
rsigma engine tap [OPTIONS]
```

## Description

`engine tap` answers the question "what is the daemon actually seeing right now?" without re-plumbing production traffic by hand. It opens a streaming connection to a running [`engine daemon`](daemon.md) on `GET /api/v1/tap`, captures a bounded window of the events flowing through the engine, and writes them as NDJSON. The capture replays against candidate rules with the existing `engine eval` syntax:

```bash
rsigma engine tap --duration 30s --output fixture.ndjson --redact-fields user.email,src_ip
rsigma engine eval -r rules/ -e @fixture.ndjson
```

The capture is **lossy by design**: it can never apply backpressure to detection. If a session's buffer fills under load, events are dropped and counted, and the final summary record reports the gap.

Like [`engine status`](status.md) it is a read-only client over the admin API. It uses a synchronous HTTP client and does not need the `daemon` build feature, and it follows the same address convention as [`config reload`](../config/reload.md): `--addr` defaults to `daemon.api.addr`, and wildcard binds (`0.0.0.0`, `[::]`) map to loopback.

The tap is **disabled by default** because it exfiltrates raw events. Enable it on the daemon with the `--enable-tap` flag or `daemon.tap.enabled: true` in the config, ideally only behind mTLS; otherwise the endpoint returns `503`.

### Capture stages

The `--stage` flag selects where on the decode path the capture happens:

- `decoded` (default): post-parse, post-event-filter. The capture is exactly what the engine evaluated, so it is always valid NDJSON and replays with a plain `engine eval -e @fixture.ndjson`, with no need to repeat the daemon's `--input-format` / `--jq` / `--jsonpath` flags. This is the right default for reproducing a missed detection.
- `raw`: the input line as received, before parsing. Use it to debug the parse/filter step itself (syslog timezone issues, jq extraction bugs). The raw stage records every non-empty line, including ones that fail to parse, except on a daemon started with `--dlq`, which routes unparseable lines to the dead-letter queue before the tap sees them. Replay requires the same input-selection flags the daemon runs with, which the client prints as a hint after capture (with `-o`).

### Redaction

`--redact-fields` takes comma-separated dotted paths (e.g. `user.email,src_ip`). Redaction is **server-side**: the raw values for redacted fields never cross the wire, not even to the tapping operator's machine. Each value is replaced with a deterministic per-session token (`rsigma:redacted:<hex>`), so equal values still match across the fixture (correlation group keys and joins line up on replay) while the per-session salt prevents dictionary reversal and cross-fixture linkage.

Paths are navigated like the [enrichment template engine](../../guide/enrichers.md): object keys descend into objects, numeric segments index arrays. One safety divergence: when a non-numeric segment meets an array, redaction fans out to every element (a fixture that leaks one array element is a leak). On the `raw` stage, redaction applies only to JSON-parseable lines; a line that fails to parse is dropped from a redacting raw capture and counted.

!!! warning "The tap exfiltrates raw events"
    Anyone with admin API access can read live traffic through the tap. It is disabled by default; enable it (`daemon.tap.enabled: true` or `--enable-tap`) only behind mTLS, and use `--redact-fields` for sensitive fields. See [Security](../../reference/security.md#live-event-tap).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr <HOST:PORT or URL>` | from `daemon.api.addr` | Daemon API address as `host:port` or a full URL. `https://` URLs work for TLS deployments. |
| `--duration <D>` | `30s` | Capture window (humantime). The server caps this at `daemon.tap.max_duration`. |
| `--limit <N>` | unset | Stop after N events, before the duration if reached first. |
| `-o, --output <PATH>` | stdout | Fixture destination. |
| `--redact-fields <a,b,...>` | unset | Comma-separated dotted paths, redacted server-side. |
| `--stage <decoded\|raw>` | `decoded` | Capture stage (see above). |
| `-c, --config <PATH>` | discovery chain | Explicit config file used to resolve the daemon address. |

The global `--quiet` / `--no-stats` flags suppress the stderr stats line; see [Output Formats](../../reference/output.md).

## Examples

### Capture 30 seconds to a fixture

```bash
rsigma engine tap --duration 30s --output fixture.ndjson
```

### Redact sensitive fields server-side

```bash
rsigma engine tap --duration 1m --redact-fields user.email,src_ip -o fixture.ndjson
```

### Stop after a fixed number of events

```bash
rsigma engine tap --limit 1000 -o sample.ndjson
```

### Debug the parse step with the raw stage

```bash
rsigma engine tap --stage raw --duration 10s -o raw.ndjson
```

### Reproduce a missed detection locally

```bash
rsigma engine tap --duration 1m -o fixture.ndjson
rsigma engine eval -r candidate-rules/ -e @fixture.ndjson
```

## Output

The stream is NDJSON: one event per line, followed by a final summary record the client uses for the stats line and keeps out of the fixture:

```json
{"rsigma_tap_summary":{"captured":842,"dropped":3,"duration_ms":30000,"stage":"decoded"}}
```

A non-zero `dropped` means the session buffer filled under load (or a redacting raw line failed to parse); the fixture has gaps.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The capture completed (even with zero events). |
| `3` | The daemon could not be reached, returned a non-2xx status (e.g. `503` when the tap is disabled, `409` at the session cap, `400` for bad params), or sent an unreadable stream. |

## See also

- [`engine daemon`](daemon.md) for the long-running service and the `daemon.tap.*` limits.
- [`engine eval`](eval.md) for replaying a captured fixture.
- [HTTP API: `GET /api/v1/tap`](../../reference/http-api.md#live-event-tap) for the raw endpoint, query params, and error semantics.
- [Security](../../reference/security.md#live-event-tap) for the exfiltration warning and mTLS guidance.
