# OTLP Integration

The daemon can ingest logs over [OpenTelemetry Protocol](https://opentelemetry.io/docs/specs/otlp/) (OTLP). This is the recommended way to wire RSigma into a modern log pipeline: every major agent and SDK speaks OTLP, the daemon flattens LogRecord into the same JSON the engine expects, and the same endpoint accepts both HTTP and gRPC.

This page covers the daemon's OTLP server, the LogRecord mapping, and minimal copy-paste recipes for the four agents we test against: Grafana Alloy, Vector, Fluent Bit, and the OpenTelemetry Collector.

## When OTLP is the right choice

OTLP is the right input format when:

- Your fleet is already running OTel-instrumented services or an OTel-compatible collector.
- You want a vendor-neutral wire format that survives migrations between log backends.
- You want gRPC or HTTP/2 multiplexing on the same port that serves the management API.

Pick something else when:

- You only have one event source and it speaks NATS or stdin. Use those.
- You need at-least-once delivery semantics for which OTLP has no first-class story. Use [NATS Streaming](nats-streaming.md) with JetStream.

## Enabling OTLP

OTLP is feature-gated. Prebuilt release archives and the GHCR Docker image are built with `--all-features`, so they include OTLP. From source or `cargo install`, enable `daemon-otlp`:

```bash
cargo install --locked rsigma --features daemon-otlp
```

With the feature compiled in, the OTLP endpoints are always active, regardless of `--input`. You can pair OTLP ingestion with another primary source (`--input nats://...` or `--input http`) on the same daemon. OTLP logs and the primary source feed into the same engine.

```bash
rsigma engine daemon -r rules/ --input http --api-addr 127.0.0.1:9090
```

Agents on other hosts need a routable `--api-addr`, which requires TLS (or `--allow-plaintext`) and authentication: a bearer token with `events:ingest`, client certificates, or `--allow-unauthenticated`. {{ added "0.25.0" }} See [Daemon network exposure](../reference/security.md#daemon-network-exposure).

## Endpoints

OTLP is exposed on the same `--api-addr` port as the rest of the daemon's HTTP API. The same TCP listener serves HTTP/1.1 REST, HTTP/2 gRPC, and OTLP/HTTP. With `daemon-otlp`, the gRPC `LogsService` is folded into the axum router so one listener handles all three.

| Endpoint | Method | Content-Type | Purpose |
|----------|--------|--------------|---------|
| `/v1/logs` | POST | `application/x-protobuf` | OTLP/HTTP protobuf. The standard. |
| `/v1/logs` | POST | `application/json` | OTLP/HTTP JSON. Useful for debugging. |
| gRPC `LogsService/Export` | (HTTP/2) | (protobuf framed) | OTLP/gRPC unary export. |

Both transports support `Content-Encoding: gzip` (HTTP) or gRPC gzip compression for compressed payloads.

Both transports cap a decompressed request at 4 MiB. Over HTTP, a gzip body that inflates past the cap is rejected with `413 Payload Too Large` and counted as `rsigma_otlp_errors_total{reason="body_too_large"}`; uncompressed HTTP bodies are limited to 2 MiB. Keep agent batches under these limits. {{ added "0.25.0" }}

When no `Content-Type` is provided on a POST to `/v1/logs`, protobuf is assumed, matching the OTLP/HTTP specification default.

## LogRecord to JSON mapping

OTLP `LogRecord` carries data across several fields: timestamp, severity, body, attributes, plus nested Resource and InstrumentationScope. RSigma flattens every record into one JSON event before evaluating rules:

| OTLP field | JSON key | Notes |
|------------|----------|-------|
| `time_unix_nano` | `timestamp` | ISO 8601. |
| `observed_time_unix_nano` | `observed_timestamp` | ISO 8601. |
| `severity_text` | `severity_text` | As-is. |
| `severity_number` | `severity_number` | As-is. |
| `body` (string) | `body` | Plain string. |
| `body` (map) | top-level keys | Map entries become top-level fields. `{"EventID": 4625}` becomes `EventID: 4625`. |
| `body` (array) | `body` | JSON array. |
| `trace_id` | `trace_id` | Hex string. |
| `span_id` | `span_id` | Hex string. |
| `attributes[].key` | `<key>` (top-level) | Unprefixed. Primary detection target. |
| `Resource.attributes[].key` | `resource.<key>` | Prefixed. |
| `InstrumentationScope.name` | `scope.name` | As-is. |
| `InstrumentationScope.version` | `scope.version` | As-is. |

The map-body flattening is the important part. It means a rule that selects `EventID: 4625` against your Sysmon events works whether the agent ships them via OTLP, NATS, or stdin. You do not need an OTLP-specific pipeline.

## Agent recipes

Each recipe is intentionally minimal: just enough config to forward logs to RSigma. Real production setups will add labels, filters, and routing on top. Refer to each agent's own documentation for those.

Every recipe below was verified end-to-end against a daemon built with `daemon-otlp`. Replace `rsigma.internal:9090` with the actual address you bind RSigma to.

### Grafana Alloy

[Grafana Alloy](https://grafana.com/docs/alloy/latest/) (the successor to Grafana Agent Flow). The native `otelcol.receiver.filelog` component plus an `otelcol.exporter.otlphttp` aimed at `/v1/logs`:

```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://rsigma.internal:9090"
    }
}

otelcol.receiver.filelog "app" {
    include   = ["/var/log/app.json"]
    start_at  = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

`otelcol.receiver.filelog` is marked `public-preview` in current Alloy docs, so start Alloy with `--stability.level=public-preview`:

```bash
alloy run --stability.level=public-preview /etc/alloy/config.alloy
```

The `json_parser` operator (with `parse_to: body`) flattens each JSON log line into a map body, which lands on the RSigma side as top-level fields ready for Sigma rules. For gRPC, swap `otelcol.exporter.otlphttp` for `otelcol.exporter.otlp`.

### Vector

[Vector's](https://vector.dev/) `opentelemetry` sink is purpose-built for OTel-to-OTel passthrough: it requires data from a matching `opentelemetry` source with `use_otlp_decoding: true` and `encoding.codec: otlp`. For arbitrary file or syslog sources, the practical path is RSigma's HTTP NDJSON endpoint (`POST /api/v1/events`), which RSigma exposes when started with `--input http`:

```yaml
data_dir: /var/lib/vector

sources:
  app_logs:
    type: file
    include: [/var/log/app.json]
    read_from: beginning

transforms:
  parse_json:
    type: remap
    inputs: [app_logs]
    source: |
      . = parse_json!(.message)

sinks:
  rsigma:
    type: http
    inputs: [parse_json]
    uri: http://rsigma.internal:9090/api/v1/events
    encoding:
      codec: json
    framing:
      method: newline_delimited
    request:
      headers:
        Content-Type: application/x-ndjson
```

Use the `opentelemetry` sink only when Vector is forwarding OTLP it received from an `opentelemetry` source, in which case `protocol.uri: http://rsigma.internal:9090/v1/logs` and `encoding.codec: otlp` are the right settings (see [Vector OpenTelemetry source docs](https://vector.dev/docs/reference/configuration/sources/opentelemetry/)).

### Fluent Bit

[Fluent Bit](https://fluentbit.io/) ships an `opentelemetry` output plugin that produces real OTLP envelopes. Pair it with the `tail` input plus a JSON parser so each line lands as a map body:

```ini
[SERVICE]
    Flush        1
    Parsers_File parsers.conf

[INPUT]
    Name    tail
    Path    /var/log/app.json
    Tag     app
    Parser  json
    Read_from_Head On

[OUTPUT]
    Name      opentelemetry
    Match     *
    Host      rsigma.internal
    Port      9090
    Logs_uri  /v1/logs
    tls       off
```

```ini
# parsers.conf
[PARSER]
    Name   json
    Format json
```

Set `tls on` (and configure `tls.ca_file`, `tls.crt_file`, `tls.key_file`) to encrypt the wire.

### OpenTelemetry Collector

The reference Collector configuration. Both `otlp_http` and `otlp` (gRPC) exporters work; `otlp_http` is friendlier through proxies:

```yaml
receivers:
  file_log:
    include: [/var/log/app.json]
    start_at: beginning
    operators:
      - type: json_parser
        parse_to: body

exporters:
  otlp_http/rsigma:
    endpoint: http://rsigma.internal:9090
    compression: none

service:
  pipelines:
    logs:
      receivers: [file_log]
      exporters: [otlp_http/rsigma]
```

Verified with `otelcol-contrib` v0.152. The previous aliases (`filelog`, `otlphttp`) still work in v0.152 but emit deprecation warnings; the underscored names are the future-proof ones. The `json_parser` operator flattens each JSON line into a map body so Sigma rules match its top-level fields.

## TLS

Build the daemon with the `daemon-tls` feature and pass `--tls-cert`/`--tls-key` to have it terminate TLS in-process for OTLP/HTTP, OTLP/gRPC, and the rest of the API on the same socket. ALPN advertises `h2` and `http/1.1`, so the same listener handles legacy REST clients and modern HTTP/2 gRPC clients.

```bash
rsigma engine daemon -r rules/ \
    --api-addr 0.0.0.0:9090 \
    --tls-cert /etc/rsigma/tls/server.crt \
    --tls-key  /etc/rsigma/tls/server.key \
    --tls-client-ca /etc/rsigma/tls/agents-ca.crt
```

`--tls-client-ca` requires every agent to present a CA-signed client cert, which also authenticates them, so a public bind needs no bearer token. Without it, configure a token with `events:ingest` and set it in each agent's exporter `headers`. See [TLS termination](../reference/security.md#tls-termination-for-the-api-listener) for the full reference, including SIGHUP-triggered hot-reload of the certificate.

When `daemon-tls` is not compiled in (or the operator prefers an external TLS terminator), put a reverse proxy in front of the daemon: Caddy, nginx, Envoy, and Traefik all work. The proxy speaks TLS outbound and forwards HTTP/2 + HTTP/1.1 to the daemon's plain socket on a private network.

### Agent recipes with TLS

Each of the four agents documented above can be pointed at an `https://` endpoint:

- **Grafana Alloy**: add a `tls { ca_pem = file("/etc/alloy/rsigma-ca.pem") }` block to the `otelcol.exporter.otlphttp` `client` argument. For mTLS, set `cert_pem` and `key_pem` to the agent's client cert.
- **Vector**: under the `opentelemetry` sink, add `tls { ca_file = "/etc/vector/rsigma-ca.pem", verify_certificate = true }`. For mTLS, also set `crt_file` and `key_file`.
- **Fluent Bit**: set `tls On`, `tls.ca_file /etc/fluent-bit/rsigma-ca.pem`. For mTLS, add `tls.crt_file` and `tls.key_file`.
- **OpenTelemetry Collector**: under the `otlp_http/rsigma` exporter, add `tls: { ca_file: /etc/otelcol/rsigma-ca.pem }`. For mTLS, add `cert_file` and `key_file`.

## Authentication

When API auth is enabled (`--api-token-env` or a `daemon.api.auth` config block), `POST /v1/logs` and the gRPC `LogsService/Export` require the `events:ingest` permission. Agents send a bearer token via the usual `Authorization: Bearer <token>` header (or gRPC `authorization` metadata). Off by default, the listener is open and network position is the only guard.

For agent-to-daemon pinning without tokens, use mutual TLS via `--tls-client-ca` so every agent presents a CA-signed client cert at the handshake. Auth and TLS complement each other: see [Daemon API authentication](../reference/security.md#daemon-api-authentication) and [TLS termination](../reference/security.md#tls-termination-for-the-api-listener).

## Observability

OTLP traffic surfaces in three places:

| Where | What |
|-------|------|
| Prometheus metric `rsigma_otlp_requests_total{transport, encoding}` | Counter of OTLP export requests received. Labels: `transport` (`http` or `grpc`) and `encoding` (`protobuf` or `json`). Gzip is decompressed before the encoding label is recorded. |
| Prometheus metric `rsigma_otlp_log_records_total` | Counter of LogRecords ingested. |
| Prometheus metric `rsigma_otlp_errors_total{transport, reason}` | Errors by transport and reason (`unsupported_content_type`, `decompression`, `body_too_large`, `decode`, `channel_closed`). |
| `RUST_LOG=info,rsigma=debug` | Per-request `otlp_ingest` span on both HTTP and gRPC handlers, with `record_count` after decoding. |

See [Prometheus metrics reference](../reference/metrics.md) for the full set, and [Observability](observability.md) for the `RUST_LOG` filter targets.

## Mixing OTLP with another input

The OTLP endpoint is always active when the feature is compiled in. The `--input` flag selects one **primary** source (stdin, HTTP REST `/api/v1/events`, NATS, or unix). OTLP logs go through a separate path but feed into the same engine and produce the same `EvaluationResult` output.

So a daemon can accept OTLP from `/v1/logs` while also reading from one primary source, for example:

- OTLP plus `--input http` for ad-hoc `POST /api/v1/events`.
- OTLP plus `--input nats://...` for JetStream ingest.
- OTLP plus stdin (the default) for a Helr NDJSON pipe.

For consistency, prefer to standardize on one source per environment. Mixing is supported but makes the data flow harder to reason about.

## See also

- [CLI reference: `engine daemon`](../cli/engine/daemon.md) for the full flag table.
- [Streaming Detection](streaming-detection.md) for the daemon overview.
- [Input Formats](input-formats.md) for the LogRecord-to-JSON mapping in more detail and the other six input formats.
- [Prometheus metrics reference](../reference/metrics.md) for `rsigma_otlp_*` counters.
- [HTTP API reference](../reference/http-api.md) for `/v1/logs` request and response shapes.
- [Feature Flags reference](../reference/feature-flags.md) for `daemon-otlp`.
