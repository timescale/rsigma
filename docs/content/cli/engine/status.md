---
description: "Reference for rsigma engine status: fetch a running daemon's counters, such as rules loaded, events processed, detections fired, and uptime, in one snapshot."
---

# `rsigma engine status`

{{ added "0.17.0" }}

Query a running daemon's `/api/v1/status` endpoint and render the snapshot through the shared output layer.

## Synopsis

```text
rsigma engine status [OPTIONS]
```

## Description

Fetches a one-shot snapshot of engine counters (rules loaded, events processed, detections fired, correlation state entries, uptime, and the dynamic-source summary when configured) from a running [`engine daemon`](daemon.md) and prints it. It is the read-only client counterpart to the daemon: the same information served at `GET /api/v1/status`, formatted for a human instead of `curl`.

The command uses a synchronous HTTP client and does not need the `daemon` build feature, so a lightweight build can still inspect a remote daemon. It follows the same address convention as [`config reload`](../config/reload.md): `--addr` defaults to `daemon.api.addr` from the resolved config (compiled default `0.0.0.0:9090`), and wildcard bind addresses (`0.0.0.0`, `[::]`) are mapped to loopback so the client can connect to a daemon that advertised every interface.

The client does not send an `Authorization` header. Against a daemon with [API authentication](../../reference/http-api.md#authentication) enabled, either leave the API open, grant anonymous `status:read` (or a broader read role), or query the endpoint with `curl` and a bearer token. HTTP 401/403 still exit `3`.

For continuous monitoring, scrape [`/metrics`](../../reference/metrics.md) instead; `engine status` is for a quick interactive check.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr <HOST:PORT or URL>` | from `daemon.api.addr` | Daemon API address as `host:port` or a full URL. `https://` URLs work for TLS deployments. |
| `-c, --config <PATH>` | discovery chain | Explicit config file used to resolve the daemon address. |

The global `--output-format`, `--color`, `--quiet`, and `--no-stats` flags apply; see [Output Formats](../../reference/output.md). The default is TTY-aware: pretty `json` on a terminal, `ndjson` when piped. `table`, `csv`, and `tsv` render a `METRIC | VALUE` view.

`json` and `ndjson` echo the raw API body (including `uptime_seconds` and any future fields). The tabular views flatten known counters and humanize uptime as `uptime` (for example `5m 12s`); when `dynamic_sources` is present they append `dynamic_sources.total`, `dynamic_sources.resolves_total`, `dynamic_sources.errors_total`, and `dynamic_sources.cache_hits`.

## Examples

### Quick check against the default address

```bash
rsigma engine status
```

### A specific daemon, table view

```bash
rsigma engine status --addr 10.0.0.5:9090 --output-format table
```

```text
METRIC                     VALUE
-------------------------  -------
status                     running
detection_rules            22
correlation_rules          2
correlation_state_entries  0
events_processed           1248
detection_matches          37
correlation_matches        4
uptime                     5m 12s
```

### A TLS deployment

```bash
rsigma engine status --addr https://daemon.internal:9443
```

### Machine-readable snapshot for a script

```bash
rsigma engine status --output-format json | jq '.events_processed'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The daemon responded and the snapshot was printed. |
| `3` | The daemon could not be reached, returned a non-2xx status (including auth failure), or sent an unparseable response. |

## See also

- [`engine daemon`](daemon.md) for the long-running service this command queries.
- [HTTP API: `GET /api/v1/status`](../../reference/http-api-state.md#status-and-counters) for the raw endpoint and response shape.
- [HTTP API: Authentication](../../reference/http-api.md#authentication) when the daemon requires bearer tokens.
- [`config reload`](../config/reload.md) for the sibling daemon-client command that shares the `--addr` convention.
- [Prometheus Metrics](../../reference/metrics.md) for continuous monitoring of the same counters.
