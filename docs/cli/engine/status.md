# `rsigma engine status`

Query a running daemon's `/api/v1/status` endpoint and render the snapshot through the shared output layer.

## Synopsis

```text
rsigma engine status [OPTIONS]
```

## Description

Fetches a one-shot snapshot of engine counters (rules loaded, events processed, detections fired, correlation state entries, uptime, and the dynamic-source summary when configured) from a running [`engine daemon`](daemon.md) and prints it. It is the read-only client counterpart to the daemon: the same information served at `GET /api/v1/status`, formatted for a human instead of `curl`.

The command uses a synchronous HTTP client and does not need the `daemon` build feature, so a lightweight build can still inspect a remote daemon. It follows the same address convention as [`config reload`](../config/reload.md): `--addr` defaults to `daemon.api.addr` from the resolved config, and wildcard bind addresses (`0.0.0.0`, `[::]`) are mapped to loopback so the client can connect to a daemon that advertised every interface.

For continuous monitoring, scrape [`/metrics`](../../reference/metrics.md) instead; `engine status` is for a quick interactive check.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr <HOST:PORT or URL>` | from `daemon.api.addr` | Daemon API address as `host:port` or a full URL. `https://` URLs work for TLS deployments. |
| `-c, --config <PATH>` | discovery chain | Explicit config file used to resolve the daemon address. |

The global `--output-format` / `--color` / `--quiet` / `--no-stats` flags apply; see [Output Formats](../../reference/output.md). The default is TTY-aware: pretty `json` on a terminal, `ndjson` when piped. `table`, `csv`, and `tsv` render a `METRIC | VALUE` view.

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
| `3` | The daemon could not be reached, returned a non-2xx status, or sent an unparseable response. |

## See also

- [`engine daemon`](daemon.md) for the long-running service this command queries.
- [HTTP API: `GET /api/v1/status`](../../reference/http-api.md#status-and-counters) for the raw endpoint and response shape.
- [`config reload`](../config/reload.md) for the sibling daemon-client command that shares the `--addr` convention.
- [Prometheus Metrics](../../reference/metrics.md) for continuous monitoring of the same counters.
