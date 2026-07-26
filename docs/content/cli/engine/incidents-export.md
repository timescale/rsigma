# `rsigma engine incidents export`

Pull one incident's bundle from a running daemon and write it to stdout or a file.

## Synopsis

```text
rsigma engine incidents export <INCIDENT_ID> [OPTIONS]
```

## Description

An incident groups many detections under one id, and the grouped view alone does not say much: it carries rule *keys*, counts, and grouping values, not what those rules were looking for or why they matter. A bundle is that incident joined to the [ADS](../../guide/detection-strategy.md) documentation of every rule that contributed and the risk entities it overlaps, in one self-contained document. It is what you attach to a ticket, hand to an on-call engineer, or keep as the record of what the detection stack knew at the time.

The command is the client side of [`GET /api/v1/incidents/{id}/bundle`](../../reference/http-api.md#get-apiv1incidentsidbundle). Incident ids come from [`GET /api/v1/incidents`](../../reference/http-api.md#get-apiv1incidents) or from an emitted incident's `incident_id`.

Like [`engine status`](status.md), it uses a synchronous HTTP client and does not need the `daemon` build feature, so a lightweight build can pull a bundle from a remote daemon. `--addr` follows the same convention: it defaults to `daemon.api.addr` from the resolved config, and a wildcard bind address (`0.0.0.0`, `[::]`) is mapped to loopback.

The daemon renders the bundle, so the global `--output-format` has no say in how it looks. `--bundle-format` is the only control, and passing an output format prints a warning and is otherwise ignored.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `<INCIDENT_ID>` | required | The incident to export. |
| `--bundle-format <FORMAT>` | `json` | `json` for the full structured document, `markdown` for a human-readable report. |
| `-o, --output <PATH>` | stdout | Write the bundle here. The file is replaced only after the whole bundle has arrived, so a failed export leaves a previous one intact. |
| `--addr <HOST:PORT or URL>` | from `daemon.api.addr` | Daemon API address as `host:port` or a full URL. `https://` URLs work for TLS deployments. |
| `-c, --config <PATH>` | discovery chain | Explicit config file used to resolve the daemon address. |
| `--auth-token-env <VAR>` | `RSIGMA_API_TOKEN` | Environment variable holding the API bearer token. |

## Authentication

The bundle route requires the `incident-bundles:read` permission when the daemon has [API authentication](../../reference/security.md#daemon-api-authentication) enabled. That permission is deliberately separate from the `incidents:read` that gates the incident list, because a bundle hands out rule documentation and risk entities as well.

The token is read from an environment variable and never taken as an argument, so it does not appear in the process list or in shell history. An unset or empty variable sends no `Authorization` header at all, which against an authenticated daemon fails with a `401` rather than silently exporting nothing.

```bash
export RSIGMA_API_TOKEN="$(cat /run/secrets/rsigma-token)"
rsigma engine incidents export f8bcd62a829b1126
```

## Examples

### Export to stdout and pick the bundle apart

```bash
rsigma engine incidents export f8bcd62a829b1126 | jq '.rules[] | {key, count, resolution}'
```

```json
{"key": "Suspicious PowerShell Download", "count": 4, "resolution": "unique"}
{"key": "a1b2c3d4-0000-0000-0000-000000000001", "count": 2, "resolution": "missing"}
```

`resolution` reports how the incident's rule key resolved against the rule set loaded *now*: `unique`, `ambiguous` when several loaded rules carry the key with differing documentation, and `missing` when the rule set changed while the incident was open.

### A Markdown report for a ticket

```bash
rsigma engine incidents export f8bcd62a829b1126 \
  --bundle-format markdown \
  --output incident-f8bcd62a.md
```

### A remote TLS daemon

```bash
rsigma engine incidents export f8bcd62a829b1126 --addr https://daemon.internal:9443
```

### Export every open incident

```bash
curl -sS http://127.0.0.1:9090/api/v1/incidents \
  | jq -r '.incidents[] | select(.bundle_ready) | .incident_id' \
  | while read -r id; do
      rsigma engine incidents export "$id" --output "bundles/$id.json"
    done
```

The `bundle_ready` filter skips incidents still inside `group_wait`; those return `409` because their contents can still change.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The bundle was fetched and written. |
| `3` | The daemon could not be reached, returned a non-2xx status, or the output file could not be written. |

A non-2xx response is reported with its status and the daemon's own explanation, so the reason is visible without a second request:

```text
incident export failed: http://127.0.0.1:9090/api/v1/incidents/nope/bundle?format=json returned HTTP 404
no such open incident
(the id is unknown, or the incident has already resolved and been evicted)
```

## See also

- [HTTP API: incident bundles](../../reference/http-api.md#get-apiv1incidentsidbundle) for the raw endpoint, the bundle schema, and the status codes.
- [Alert Pipeline](../../guide/alert-pipeline.md) for how incidents are grouped in the first place.
- [Detection Strategy](../../guide/detection-strategy.md) for the ADS sections a bundle carries.
- [Risk-Based Alerting](../../guide/risk-based-alerting.md) for the risk entities a bundle joins.
- [`engine daemon`](daemon.md) for the service this command queries.
