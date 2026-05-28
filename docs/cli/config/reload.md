# `rsigma config reload`

Ask a running daemon to hot-reload its rules, pipelines, enrichers, and TLS material.

## Synopsis

```text
rsigma config reload [--addr <ADDR>] [--config <PATH>]
```

## Description

Sends an empty `POST /api/v1/reload` to the daemon's HTTP API. The request goes through the daemon's central debounced reload task, the same path used by `SIGHUP` on unix and the file watcher. Cross-platform (works on Windows, where `SIGHUP` does not exist).

The address comes from `--addr` or from the `daemon.api.addr` field of the resolved config. Wildcard bind addresses (`0.0.0.0`, `[::]`) are mapped to the corresponding loopback address so the client can connect.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr <ADDR>` | resolved `daemon.api.addr` | `host:port` or full URL of the daemon API. |
| `-c, --config <PATH>` | discovery chain | Config file used to resolve `daemon.api.addr`. |

## Examples

Default: use the address from the config:

```bash
rsigma config reload
# reload requested: http://127.0.0.1:9090/api/v1/reload
```

Override the address:

```bash
rsigma config reload --addr daemon.internal:9090
```

Reload a TLS-protected daemon:

```bash
rsigma config reload --addr https://daemon.internal:9443
```

On unix, you can also send `SIGHUP` directly:

```bash
kill -HUP $(pgrep -f "rsigma engine daemon")
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The daemon accepted the reload request. |
| `3` | The daemon could not be reached or returned a non-success status. |

## See also

- [`engine daemon`](../engine/daemon.md) — the long-running command this reloads.
- [HTTP API reference](../../reference/http-api.md) — the `POST /api/v1/reload` semantics.
