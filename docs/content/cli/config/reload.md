---
description: "Reference for rsigma config reload: ask a running rsigma daemon to hot-reload its Sigma rules, pipelines, enrichers, and TLS material without a restart."
---

# `rsigma config reload`

{{ added "0.14.0" }}

Ask a running daemon to hot-reload its rules, pipelines, enrichers, and TLS material.

## Synopsis

```text
rsigma config reload [--addr <ADDR>] [--config <PATH>]
```

## Description

Sends an empty `POST /api/v1/reload` to the daemon's HTTP API. The request goes through the daemon's central debounced reload task, the same path used by `SIGHUP` on Unix and the file watcher. Cross-platform (works on Windows, where `SIGHUP` does not exist).

The address comes from `--addr` or from the `daemon.api.addr` field of the resolved config. Wildcard bind addresses (`0.0.0.0`, `[::]`) are mapped to the corresponding loopback address so the client can connect.

Like [`engine status`](../engine/status.md), this command does not send an `Authorization` header. When the daemon has authentication enabled, `POST /api/v1/reload` requires `reload:execute` (built-in `admin`). Grant that via `anonymous_permissions`, or call the endpoint with an explicit bearer token.

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

On Unix, you can also send `SIGHUP` directly:

```bash
kill -HUP $(pgrep -f "rsigma engine daemon")
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The daemon accepted the reload request (2xx). |
| `3` | The daemon could not be reached, or returned a non-success status (including `401`/`403` when authentication is required). |

## See also

- [`engine daemon`](../engine/daemon.md) for the long-running command this reloads.
- [HTTP API: `POST /api/v1/reload`](../../reference/http-api.md) for reload semantics.
- [HTTP API: Authentication](../../reference/http-api.md#authentication) when the daemon requires bearer tokens.
- [`engine status`](../engine/status.md) for another daemon-client command that shares the `--addr` convention.
