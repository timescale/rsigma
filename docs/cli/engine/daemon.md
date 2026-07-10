# `rsigma engine daemon`

Run as a long-running daemon with hot-reload, health checks, and Prometheus metrics.

## Synopsis

```text
rsigma engine daemon [OPTIONS] --rules <RULES>
```

## Description

Loads rules and pipelines, opens an event source, evaluates events as they arrive, fans the detections out to one or more sinks, and stays alive until it receives `SIGTERM`/`SIGINT`. Reloads rules and pipelines on file change, `SIGHUP`, or `POST /api/v1/reload`. Exposes Prometheus metrics, REST control endpoints, and OTLP log ingestion on the same `--api-addr`.

This is the long-running counterpart of [`engine eval`](eval.md). Use it when you need state to survive restarts, hot-reload across rule changes, or a Prometheus-scrapeable detection engine.

For narrative coverage see [Streaming Detection](../../guide/streaming-detection.md). For NATS-specific operations (auth, replay, consumer groups, DLQ) see [NATS Streaming](../../guide/nats-streaming.md).

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-r, --rules <RULES>` | Path to a Sigma rule file or directory of rules (recursive). May also be supplied via `daemon.rules` in a config file. |

### Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the [discovery chain](../../reference/configuration.md#discovery). CLI flags still take precedence over file values. |
| `--dry-run` | off | Print the effective `daemon` section (defaults < file < env) and exit `0` without binding any port. |

### Event input

| Flag | Default | Description |
|------|---------|-------------|
| `--input <URL>` | `stdin` | Event source. Schemes: `stdin`, `http` (accepts `POST /api/v1/events`), `nats://<host>:<port>/<subject>`, and on Unix `unix:///path/to.sock` (newline-delimited events over a Unix domain socket). |
| `--input-format <FORMAT>` | `auto` | Input log format: `auto`, `json`, `syslog`, `plain`. With features: `logfmt`, `cef`. |
| `--syslog-tz <OFFSET>` | `+00:00` | Timezone offset for RFC 3164 syslog (`+HH:MM` or `-HH:MM`). |
| `--syslog-strip-bom <BOOL>` | `true` | Strip a leading UTF-8 BOM (`U+FEFF`) from RFC 5424 syslog messages. RFC 5424 treats the BOM as an encoding marker, not content. Pass `--syslog-strip-bom false` to keep it byte-for-byte. |
| `--jq <JQ>` | unset | `jq` filter to extract the event payload from each JSON object. Mutually exclusive with `--jsonpath`. |
| `--jsonpath <JSONPATH>` | unset | JSONPath ([RFC 9535](https://www.rfc-editor.org/rfc/rfc9535)) query to extract the event payload. |

### Output sinks and DLQ

| Flag | Default | Description |
|------|---------|-------------|
| `--output <URL>` | `stdout` | Detection sink. Schemes: `stdout`, `file://<path>`, `nats://<host>:<port>/<subject>`, `otlp(s)://<host>:<port>` (OTLP/gRPC), `otlphttp(s)://<host>:<port>` (OTLP/HTTP, posts to `/v1/logs`); the `s` variants use TLS. On Unix, `unix:///path/to.sock` writes NDJSON to a local collector socket. Repeatable for fan-out. Query params: `?on_full=drop` (best-effort), `?compression=gzip` (OTLP), and for TLS `?ca=`, `?client_cert=`, `?client_key=` (PEM paths, the last two for mutual TLS) and `?tls_domain=` (SNI override). OTLP schemes require the `daemon-otlp` build. |
| `--dlq <URL>` | unset | Dead-letter queue for events that fail parsing or sink delivery. Same schemes as `--output`. When unset, failed events are logged and discarded. |
| `--include-event` | off | Embed the full event JSON in every detection match. |
| `--match-detail <LEVEL>` | `off` | Match-detail verbosity: `off` (field + value only), `summary` (adds matcher kind, selection, case sensitivity, and reports keyword/absence matches), or `full` (also records the matched pattern). Also settable via `daemon.engine.match_detail`. See [Evaluating Rules](../../guide/evaluating-rules.md#match-detail). |
| `--pretty` | off | Pretty-print JSON output. |
| `--sink-retry-max <N>` | `3` | Max delivery retries per sink before routing the result to the DLQ. |
| `--sink-backoff-base-ms <MS>` | `100` | Base backoff for the first sink delivery retry. |
| `--sink-backoff-max-ms <MS>` | `5000` | Backoff ceiling for sink delivery retries. |
| `--sink-batch-max <N>` | `64` | Max results drained into one sink delivery batch. |
| `--sink-batch-flush-ms <MS>` | `50` | Max time a partial sink batch waits before flushing. |

Each `--output` sink runs its own bounded queue and worker: results are delivered with bounded exponential-backoff retry, and a result is sent to the DLQ only after retries are exhausted. Fan-out is isolated up to each sink's queue depth, so a slow sink does not immediately stall the others; a slow durable sink eventually applies backpressure, the cost of preserving at-least-once delivery. An acknowledgment is released to the source only once every sink has committed the result, and `?on_full=drop` opts a sink out of that contract in favor of never stalling.

Acknowledgment guarantees differ by transport. NATS is durable at-least-once: results un-acked at shutdown are redelivered on restart. The HTTP and OTLP push receivers are at-most-once on ingest, since the request is accepted as soon as the event is queued.

### Pipelines and dynamic sources

| Flag | Description |
|------|-------------|
| `-p, --pipeline <PIPELINES>` | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `sysmon`) or YAML file paths. Repeatable. |
| `--source <FILE_OR_DIR>` | External source file(s) or directory of source files. Repeatable. Loads dynamic source declarations independently of any pipeline file. A file path loads one YAML file with a top-level `sources:` block; a directory path loads all `*.yml`/`*.yaml` files in it, alphabetically. Source IDs must be unique across every `--source` file (pipeline-embedded `sources:` blocks were removed in v1.0; see [Dynamic Pipeline Sources](../../reference/dynamic-sources.md)). |
| `--allow-remote-include` | Allow `include:` directives in pipelines to reference remote (HTTP/NATS) sources. Off by default for security. |
| `--egress-policy <default\|strict\|permissive>` | HTTP egress policy applied to dynamic-source and enrichment HTTP clients. `default` (the default) blocks link-local (`169.254.0.0/16`, `fe80::/10`, includes cloud-metadata `169.254.169.254`) and known cloud-metadata IPv6 (`fd00:ec2::254`). `strict` additionally blocks loopback and RFC1918 private. `permissive` allows everything. Enforced at DNS resolution time so DNS rebinding cannot defeat host-string checks. See [Security](../../reference/security.md#http-egress-policy-ssrf-defense). |

### Post-evaluation enrichment

| Flag | Description |
|------|-------------|
| `--enrichers <PATH>` | YAML file declaring post-evaluation enrichers. Hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; failed reloads keep the previous pipeline active. See [Enrichers](../../guide/enrichers.md) for the schema, the four primitives, and the recipes catalog. |
| `--alert-pipeline <PATH>` | YAML file declaring the alert pipeline. It runs after enrichment and before the sinks: it silences results matching operator-defined matchers, inhibits lower-priority results while a matching source is active, deduplicates by a configurable fingerprint (first fire passes, duplicates fold, re-emit on `repeat_interval`, resolve after `resolve_timeout`), and groups survivors into incidents (`group_by` equality or an opt-in `entity_graph` union-find), annotating each pass-through result with its `incident_id` and emitting an `IncidentResult` on the `group_wait` / `group_interval` / `repeat_interval` timers. Open incidents are readable at `GET /api/v1/incidents`; silences are managed at `/api/v1/silences`. Hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; failed reloads keep the previous pipeline active. Selector, matcher, and scope errors reject the daemon at startup. See [Alert Pipeline](../../guide/alert-pipeline.md). |
| `--risk <PATH>` | YAML file declaring the risk-based alerting layer. It runs after enrichment and before the alert pipeline: it annotates each in-scope firing with a risk score and one or more risk objects (entities) under the reserved `risk.score` / `risk.objects` enrichment keys, accumulates risk per entity over a sliding window, and emits a high-fidelity `RiskIncidentResult` when an entity crosses the score or ATT&CK-tactic-count threshold (subject to a per-entity cooldown). Open entities are readable at `GET /api/v1/risk`. Hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; failed reloads keep the previous config active. Selector, scope, and score errors reject the daemon at startup. See [Risk-Based Alerting](../../guide/risk-based-alerting.md). |
| `--webhook <FILE_OR_DIR>` | Webhook config file (or directory of `*.yml`/`*.yaml` files) declaring template-driven HTTP output sinks. Repeatable. Each detection or correlation matching a webhook's `kind` and `scope` renders a templated URL, headers, and JSON body and POSTs it. Webhooks are best-effort (at-most-once): undeliverable results land in the `--dlq` and never block the durable sinks. Validated at startup; not hot-reloaded. See [Webhooks](../../guide/webhooks.md). |

The enrichers file accepts `max_concurrent_enrichments: <N>` at the top level (default `16`) plus a list of enricher entries, each declaring `kind: detection | correlation`, a primitive `type:` (`template` / `lookup` / `http` / `command`), an `inject_field`, and primitive-specific keys (`template`, `url` / `headers` / `cache_ttl`, `command`, `source` / `extract` / `default`, ...). Cross-namespace template references are rejected at startup with a clear error pointing at the offending field.

The webhooks file (also settable as the `daemon.output.webhooks` path list) declares a list of `webhooks:` entries, each with an `id`, `kind: detection | correlation`, a `url`, optional `headers` / `body` templates, and optional `timeout`, `retry`, `rate_limit`, `scope`, and `queue_size`. Secrets are referenced via `${ENV_VAR}` rather than stored in the file. See [Webhooks](../../guide/webhooks.md) for the schema and the Slack/Teams/Discord/PagerDuty recipe catalog.

### API server

| Flag | Default | Description |
|------|---------|-------------|
| `--api-addr <ADDR>` | `0.0.0.0:9090` | Bind address for `/healthz`, `/readyz`, `/metrics`, `/api/v1/*`, and (with the `daemon-otlp` feature) `/v1/logs`. A TCP `host:port`, or on Unix `unix:///path/to.sock` for a permission-gated local socket. A `unix://` address cannot be combined with TLS (the socket file is the trust boundary) and is exempt from the plaintext-bind refusal. |
| `--api-token-env <ENV_VAR>` | unset | Require bearer-token authentication on the API, with the named environment variable holding the single accepted token (full `admin` permissions). The flag names the variable, so the secret never appears on the command line; an unset or empty variable fails startup. `GET /healthz` and `GET /readyz` stay open. Mutually exclusive with the `daemon.api.auth` config block, which adds per-token roles and granular `resource:action` permissions; see [HTTP API: Authentication](../../reference/http-api.md#authentication). |

### Authentication

Off by default: without `--api-token-env` or a `daemon.api.auth` config block, every route is open and network position (TLS/mTLS, reverse proxy, loopback, or a `unix://` socket) is the only guard.

For anything beyond the single admin token, configure the `daemon.api.auth` block (config-file-only, like the tap and tail tuning keys): named roles as `resource:action` permission lists, per-token role assignment with env-resolved secrets, and `anonymous_permissions` for requests without a token (for example `["metrics:read"]` keeps Prometheus scraping token-free). Built-in roles: `reader`, `operator`, `ingest`, `admin`. The per-route permission table, role definitions, and failure semantics (401 vs 403, the `rsigma_api_auth_failures_total` counter) are documented in [HTTP API: Authentication](../../reference/http-api.md#authentication); the threat-model discussion is in [Security: Daemon API authentication](../../reference/security.md#daemon-api-authentication).

```yaml
daemon:
  api:
    auth:
      anonymous_permissions: ["metrics:read"]
      tokens:
        - name: grafana
          role: reader
          token_env: RSIGMA_API_TOKEN_GRAFANA
        - name: shipper
          role: ingest
          token_env: RSIGMA_API_TOKEN_SHIPPER
```

On a non-loopback TCP listener, pair authentication with TLS (below) or a TLS-terminating proxy so tokens are never sent in cleartext.

### TLS (requires the `daemon-tls` build feature)

When TLS is configured, the daemon terminates TLS in-process for every protocol on `--api-addr` (HTTP REST API, `/metrics`, OTLP/HTTP, OTLP/gRPC). The negotiation advertises both `h2` and `http/1.1` via ALPN so legacy REST clients and modern gRPC clients share one socket.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--tls-cert <PATH>` | unset | unset | PEM-encoded leaf certificate (with any intermediates) for the API listener. Requires `--tls-key`. |
| `--tls-key <PATH>` | unset | unset | PEM-encoded private key. PKCS#8, PKCS#1 (RSA), and SEC1 (EC) formats are accepted. Requires `--tls-cert`. |
| `--tls-key-password <PASS>` | `RSIGMA_TLS_KEY_PASSWORD` | unset | Password for an encrypted `--tls-key`. Currently rejected at startup with a clear error; decrypt with `openssl rsa -in key.pem -out key-decrypted.pem` first. |
| `--tls-client-ca <PATH>` | unset | unset | PEM bundle of trusted CA certificates used to verify inbound client certificates. Enables mutual TLS: clients without a cert signed by one of the listed CAs are rejected during the handshake. |
| `--tls-min-version <1.2\|1.3>` | unset | `1.3` | Minimum TLS protocol version. Drop to `1.2` only for legacy agents that cannot negotiate TLS 1.3. |
| `--allow-plaintext` | unset | off | Permit plaintext on a non-loopback `--api-addr`. Without this flag (and without `--tls-cert`/`--tls-key`) the daemon refuses to start on any public address. Loopback (`127.0.0.0/8`, `::1`) always allows plaintext for local development. |

Hot-reload: every reload trigger funnels through the daemon's central debounced reload task, so a single `POST /api/v1/reload` (cross-platform, including Windows), `kill -HUP <pid>` (Unix), or a YAML file change picked up by the file watcher rotates rules, pipelines, enrichers, and the TLS certificate in one pass. The active `rustls::ServerConfig` is swapped atomically via `Arc<ArcSwap<…>>`, so new handshakes pick up the rotated material without dropping inflight TLS connections. Failed reloads keep the previous certificate active, bump `rsigma_reloads_failed_total`, and log an error so a typo in the cert path cannot black-hole the listener.

Observability: the `/metrics` endpoint exposes `rsigma_tls_certificate_expiry_seconds` (signed; negative once the cert has expired) and `rsigma_tls_active_connections`. A single WARN is logged at startup (and after every reload) if the active certificate expires within 30 days.

See [TLS deployment](../../reference/security.md#tls-termination-for-the-api-listener) for a deeper dive, including ACME / sidecar reverse proxy alternatives that this feature replaces.

### Correlation behavior

| Flag | Default | Description |
|------|---------|-------------|
| `--suppress <DURATION>` | unset | Suppress duplicate correlation alerts within the window (`5m`, `1h`, `30s`). |
| `--action <ACTION>` | `alert` | Post-fire action: `alert` (keep state, re-alert on next match) or `reset` (clear window state). |
| `--no-detections` | off | Suppress detection output for correlation-only base rules. |
| `--correlation-event-mode <MODE>` | `none` | `none`, `full` (deflate-compressed full bodies), `refs` (timestamp + ID only). |
| `--max-correlation-events <N>` | `10` | Cap on stored events per correlation window. |
| `--max-state-entries <N>` | `100000` | Hard cap on correlation state entries across all correlations and group keys. When reached, the stalest entries are evicted to 90% capacity and a warning is logged. |
| `--max-group-entries <N>` | unset | Cap on retained entries within a single correlation group's window state. Bounds within-window growth of chatty groups; oldest entries are dropped (session windows keep their span anchor). Unset = unbounded. |
| `--timestamp-field <FIELD>` | unset | Field name to prepend to the timestamp extraction list. Repeatable. |
| `--timestamp-fallback <MODE>` | `wallclock` | Behavior when no timestamp is found: `wallclock` (use wall clock time) or `skip` (skip correlation state for that event). Use `skip` for forensic replay. |

### State persistence

| Flag | Default | Description |
|------|---------|-------------|
| `--state-db <PATH>` | unset | SQLite database for persisting correlation, alert-pipeline, and risk-accumulator state across restarts. When set, state is loaded on startup and saved periodically and on shutdown. |
| `--state-save-interval <SECONDS>` | `30` | Periodic snapshot interval. No effect without `--state-db`. |
| `--clear-state` | off | Clear stored state on startup. With `--replay-from-*`, forces a clean slate even if the replay starts after the stored position. |
| `--keep-state` | off | Force restore stored state even during replay. Use for forward catch-up where you want to preserve cross-boundary correlation windows. Mutually exclusive with `--clear-state`. |

### Throughput

| Flag | Default | Description |
|------|---------|-------------|
| `--buffer-size <N>` | `10000` | Bounded mpsc capacity for source→engine and engine→sink queues. |
| `--batch-size <N>` | `1` | Maximum events per engine lock acquisition. Raise to 64 or 128 under load to amortize mutex overhead. |
| `--drain-timeout <SECONDS>` | `5` | Seconds to wait for in-flight events to drain on shutdown. |

### NATS (requires the `daemon-nats` build feature)

| Flag | Env | Description |
|------|-----|-------------|
| `--nats-creds <FILE>` | `NATS_CREDS` | NATS credentials file (`.creds`) for JWT + NKey authentication. |
| `--nats-token <TOKEN>` | `NATS_TOKEN` | NATS authentication token. |
| `--nats-user <USER>` | `NATS_USER` | NATS username (requires `--nats-password`). |
| `--nats-password <PASS>` | `NATS_PASSWORD` | NATS password (requires `--nats-user`). |
| `--nats-nkey <SEED>` | `NATS_NKEY` | NATS NKey seed. |
| `--nats-tls-cert <FILE>` | unset | TLS client certificate for mutual TLS with NATS. |
| `--nats-tls-key <FILE>` | unset | TLS client private key for mutual TLS with NATS. |
| `--nats-require-tls` | off | Refuse to connect to a NATS server that does not negotiate TLS. |
| `--replay-from-sequence <SEQ>` | unset | Replay from a specific JetStream sequence number. |
| `--replay-from-time <TIMESTAMP>` | unset | Replay from a wall-clock time (ISO 8601: `2026-05-15T10:00:00Z`). |
| `--replay-from-latest` | off | Start from the last existing message in the stream, then deliver new ones. |
| `--consumer-group <NAME>` | `RSIGMA_CONSUMER_GROUP` | Consumer group name for JetStream load balancing across daemon instances. |

The auth methods are mutually exclusive. See [NATS Streaming](../../guide/nats-streaming.md) for the full operational guide.

### Performance (advanced)

| Flag | Default | Description |
|------|---------|-------------|
| `--bloom-prefilter` | off | Enable per-field bloom over positive substring needles. See [Performance Tuning](../../guide/performance-tuning.md#bloom-pre-filter-for-substring-heavy-rule-sets). |
| `--bloom-max-bytes <BYTES>` | `1048576` | Memory budget for the bloom index (1 MiB default). No effect without `--bloom-prefilter`. |
| `--cross-rule-ac` | off | Enable cross-rule Aho-Corasick. Available with the `daachorse-index` build feature. See [Performance Tuning](../../guide/performance-tuning.md#cross-rule-aho-corasick-pre-filter). |

### Field observability (advanced)

| Flag | Default | Description |
|------|---------|-------------|
| `--observe-fields` | off | Record the field keys of every event evaluated by the engine task so the `/api/v1/fields/*` endpoints can report which event fields no rule references (gap signal) and which rule fields have never appeared in an event (broken-coverage signal). Off by default; when off the engine task does not iterate event fields at all. |
| `--observe-fields-max-keys <N>` | `10000` | Hard ceiling on distinct field names tracked. Existing keys keep counting after the cap is hit; new keys are dropped and surfaced via `rsigma_fields_observer_overflow_dropped_total`. No effect without `--observe-fields`. |
| `--observe-schemas` | off | Classify every event by schema (ECS, Sysmon, Windows Event Log, CEF, OCSF, ...) and surface the per-schema breakdown and unknown rate via `GET /api/v1/schemas` and the `rsigma_events_by_schema_total` / `rsigma_events_unknown_schema_total` metrics. Off by default; when off the engine task does not classify events at all. |
| `--discover-schemas` | off | Enable schema signature discovery sampling (implies `--observe-schemas`). Records redacted, keys-only shapes of unrecognized events so `GET /api/v1/schemas/suggestions` can mine candidate signatures and the `rsigma_unknown_schema_clusters` gauge tracks how many schemas discovery would propose. Adds a per-event field-key walk for each unrecognized event, so it is not free on high-`generic_json` streams; the sample is capped, and `DELETE /api/v1/schemas` refreshes it. See [`engine discover-schemas`](discover-schemas.md) for the offline, value-aware equivalent. |
| `--schema-config <PATH>` | unset | YAML with user-defined schema signatures (merged over the built-ins) and, with `--schema-routing`, the `routing:` bindings. Used by `--observe-schemas` and `--schema-routing`. See [`engine classify`](classify.md#user-signatures) for the signature format and [Schema Routing](../../guide/schema-routing.md) for the bindings. |
| `--schema-routing` | off | Classify each event and route it to its schema's bound pipeline-set (instead of applying one pipeline set to every event); detections feed one shared correlation store, so the same entity correlates across schemas. Bindings come from the `routing:` section of `--schema-config`. |
| `--schema-partition-rules` | off | Gated: compile each platform-locked per-schema engine with only the rules whose product can apply, cutting the N-copies memory cost. Off by default. See [Per-schema rule partitioning](../../guide/schema-routing.md#per-schema-rule-partitioning). |
| `--on-unknown <POLICY>` | `warn` | Policy for events that match no schema: `warn`, `drop`, `passthrough`, or `error`. Overrides the config value. Used with `--schema-routing`. |

These schema flags may also be supplied via the `daemon.schema` block in a [config file](../../reference/configuration.md) (`observe`, `routing`, `config`, `on_unknown`); a flag always wins over the file.

| Flag | Default | Description |
|------|---------|-------------|
| `--logsource-routing` | off | Enable conflict-based logsource pruning: skip rules whose `product`/`service`/`category` conflicts with the event's declared logsource. Fail-open. See [Logsource-Aware Evaluation](../../guide/logsource-routing.md). |
| `--logsource-field-map <MAP>` | `product=product,service=service,category=category` | Event field names each dimension is read from, as `product=...,service=...,category=...`. |
| `--event-logsource <LOGSOURCE>` | unset | Static event logsource applied when the field is absent, as `product=windows,...`, for a single-source pipeline. |

These logsource flags may also be supplied via the `daemon.logsource_routing` block in a [config file](../../reference/configuration.md) (`enabled`, `field_map`, `event_logsource`); a flag always wins over the file.

See [Observability: detection coverage](../../guide/observability.md#detection-coverage-with-observe-fields) for the operator workflow, and [HTTP API](../../reference/http-api.md#field-observability) for the endpoint payloads.

### Live event tap

The daemon serves [`GET /api/v1/tap`](../../reference/http-api.md#live-event-tap) (the endpoint behind [`rsigma engine tap`](tap.md)), which records a bounded window of the live event stream as a replayable NDJSON fixture. It is **disabled by default** because it can exfiltrate raw event traffic; enable it with `daemon.tap.enabled: true` and expose it only behind mTLS.

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-tap` | off | Enable the tap for this run; `GET /api/v1/tap` then accepts sessions. Equivalent to `daemon.tap.enabled: true`. |

The other keys are config-file-only under `daemon.tap` (there is no flag for them):

| Key | Default | Description |
|-----|---------|-------------|
| `daemon.tap.enabled` | `false` | Accept tap sessions. Opt-in; also enabled by `--enable-tap`. |
| `daemon.tap.buffer_events` | `8192` | Per-session bounded buffer. A full buffer drops events (counted) rather than ever applying backpressure to the engine. |
| `daemon.tap.max_sessions` | `2` | Maximum concurrent capture sessions. A session over the cap is rejected with `409`. |
| `daemon.tap.max_duration` | `5m` | Largest accepted capture window. A longer `?duration` is rejected with `400`. |

The tap can exfiltrate raw events; expose the admin API only behind mTLS and redact sensitive fields. See [Security: live event tap](../../reference/security.md#live-event-tap).

### Live detection tail

The daemon also serves [`GET /api/v1/detections/stream`](../../reference/http-api.md#live-detection-tail) (the endpoint behind [`rsigma engine tail`](tail.md)), which streams live detections as NDJSON. It is **disabled by default**; enable it with `daemon.tail.enabled: true`.

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-tail` | off | Enable the tail for this run; `GET /api/v1/detections/stream` then accepts sessions. Equivalent to `daemon.tail.enabled: true`. |

The other keys are config-file-only under `daemon.tail`:

| Key | Default | Description |
|-----|---------|-------------|
| `daemon.tail.enabled` | `false` | Accept tail sessions. Opt-in; also enabled by `--enable-tail`. |
| `daemon.tail.buffer_events` | `8192` | Per-session bounded buffer. A full buffer drops detections (counted) rather than ever applying backpressure to the sink task. |
| `daemon.tail.max_sessions` | `2` | Maximum concurrent tail sessions. A session over the cap is rejected with `409`. |

## Triage feedback loop

The daemon serves [`POST`/`GET /api/v1/dispositions`](../../reference/http-api.md#dispositions), which ingest analyst verdicts and expose a per-rule false-positive ratio. It is **disabled by default**; enable it with `--enable-dispositions`, `daemon.dispositions.enabled: true`, or a configured pull source.

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-dispositions` | off | Enable the loop for this run; the disposition endpoints then accept requests. Equivalent to `daemon.dispositions.enabled: true`. |
| `--disposition-source <PATH>` | none | Pull dispositions from a dynamic-source file (file, HTTP, or NATS), the same format as `--source`, whose payload is the disposition records (NDJSON or a JSON array). Refreshed per the source's policy; redelivery is idempotent. Implies the loop is enabled. Overrides `daemon.dispositions.source`. See [Disposition Source Recipes](../../guide/disposition-recipes.md) for tested TheHive/Jira/GitHub Issues configs. |

The tuning keys are config-file-only under `daemon.dispositions`:

| Key | Default | Description |
|-----|---------|-------------|
| `daemon.dispositions.enabled` | `false` | Accept disposition requests and compute the ratio. Opt-in; also enabled by `--enable-dispositions` or a configured `source`. |
| `daemon.dispositions.source` | none | Pull-source file (overridden by `--disposition-source`). |
| `daemon.dispositions.window` | `30d` | Rolling window over which dispositions are counted. |
| `daemon.dispositions.numerator` | `fp_only` | Whether benign true positives count toward the ratio numerator: `fp_only` or `fp_and_btp`. |
| `daemon.dispositions.min_sample` | `5` | Minimum dispositions a rule needs before its ratio is published. |

See the [Triage Feedback Loop](../../guide/triage-feedback.md) guide.

## Examples

### Minimal daemon: stdin → stdout

```bash
rsigma engine daemon -r rules/
```

Reads NDJSON from stdin, writes detections to stdout. Default API on `0.0.0.0:9090`.

### HTTP ingest with persistent state

```bash
rsigma engine daemon -r rules/ \
    --input http \
    --state-db /var/lib/rsigma/state.db \
    --pipeline ecs_windows
```

Accepts `POST /api/v1/events` for ingest; correlation state survives restarts.

### NATS source + sink + DLQ

```bash
NATS_CREDS=/etc/rsigma/nats.creds \
rsigma engine daemon -r /etc/rsigma/rules/ \
    --input "nats://nats.internal:4222/events.>" \
    --output "nats://nats.internal:4222/detections" \
    --dlq "file:///var/log/rsigma/dlq.ndjson" \
    --state-db /var/lib/rsigma/state.db \
    --buffer-size 50000 \
    --batch-size 128 \
    --drain-timeout 30 \
    --nats-require-tls \
    --api-addr 0.0.0.0:9090
```

### Multi-output fan-out

```bash
rsigma engine daemon -r rules/ \
    --output stdout \
    --output "file:///var/log/rsigma/detections.ndjson" \
    --output "nats://nats.internal:4222/detections.urgent"
```

### Export detections to an OpenTelemetry collector

Each result becomes one OTLP log record (Sigma level mapped to OTLP severity, rule title as the body, the full result as attributes). Requires a `daemon-otlp` build.

```bash
# OTLP/gRPC (default port 4317)
rsigma engine daemon -r rules/ --input http \
    --output "otlp://otel-collector:4317"

# OTLP/HTTP protobuf with gzip (default port 4318)
rsigma engine daemon -r rules/ --input http \
    --output "otlphttp://otel-collector:4318?compression=gzip"

# OTLP/gRPC over TLS, verifying the collector against a private CA
rsigma engine daemon -r rules/ --input http \
    --output "otlps://otel-collector:4317?ca=/etc/rsigma/tls/ca.pem"

# OTLP/HTTP over mutual TLS (client cert + key)
rsigma engine daemon -r rules/ --input http \
    --output "otlphttps://otel-collector:4318?ca=/etc/rsigma/tls/ca.pem&client_cert=/etc/rsigma/tls/client.pem&client_key=/etc/rsigma/tls/client.key"

# Post alerts to webhooks while keeping a durable NATS record
rsigma engine daemon -r rules/ --input http \
    --output "nats://nats.internal:4222/detections" \
    --webhook /etc/rsigma/webhooks/ \
    --dlq "file:///var/log/rsigma/dlq.ndjson"
```

TLS uses the bundled public (webpki) roots by default; pass `?ca=` to verify against a private CA instead. Supplying both `?client_cert=` and `?client_key=` enables mutual TLS. Use `?tls_domain=` to override the verified server name when dialing by IP.

### HTTPS with mutual TLS

```bash
rsigma engine daemon -r rules/ \
    --input http \
    --api-addr 0.0.0.0:9090 \
    --tls-cert /etc/rsigma/tls/server.crt \
    --tls-key  /etc/rsigma/tls/server.key \
    --tls-client-ca /etc/rsigma/tls/clients-ca.crt
```

Clients connecting to `https://daemon:9090/v1/logs` (OTLP/HTTP) or `https://daemon:9090/api/v1/events` (REST) must present a certificate signed by `clients-ca.crt` or the handshake is rejected. Rotate the server cert with `cp new.crt /etc/rsigma/tls/server.crt && kill -HUP $(pidof rsigma)` on Unix, or `cp new.crt … && curl -X POST https://daemon:9090/api/v1/reload` on any platform (including Windows, where SIGHUP does not exist).

### Forensic replay from a NATS sequence

```bash
rsigma engine daemon -r rules/ \
    --input "nats://localhost:4222/events.>" \
    --replay-from-sequence 1001 \
    --state-db /var/lib/rsigma/replay-state.db \
    --timestamp-fallback skip
```

`--timestamp-fallback skip` prevents wall-clock contamination of correlation windows when replaying old events.

## Health and readiness

| Endpoint | Returns | Probe wiring |
|----------|---------|--------------|
| `/healthz` | 200 once the listener is up. | Liveness probe. |
| `/readyz` | 200 once rules + pipelines are loaded; 503 during startup or after a failed reload. | Readiness probe. Drain traffic when 503. |
| `/metrics` | Prometheus text format. ~20 metrics at startup; up to 27 once dynamic sources and OTLP fire. | Scrape every 15-30 s. |

Full HTTP API reference: [HTTP API](../../reference/http-api.md). All metric definitions: [Prometheus metrics](../../reference/metrics.md).

## Shutdown

`SIGTERM` and `SIGINT` trigger a graceful drain bounded by `--drain-timeout`. In-flight events are processed and acknowledged before the daemon exits. With `--state-db`, the final correlation state snapshot is written during shutdown.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Normal shutdown. |
| `2` | Rules path could not be read at startup. |
| `3` | Configuration error: bad `-p`, malformed `--suppress`, invalid `--input` URL, etc. |

## See also

- [Streaming Detection](../../guide/streaming-detection.md) for the daemon walkthrough.
- [NATS Streaming](../../guide/nats-streaming.md) for auth, replay, consumer groups, and DLQ details.
- [OTLP Integration](../../guide/otlp-integration.md) for the OTLP receiver and agent recipes.
- [Performance Tuning](../../guide/performance-tuning.md) for `--bloom-prefilter`, `--cross-rule-ac`, `--batch-size`, and `--buffer-size`.
- [Observability](../../guide/observability.md) for the RUST_LOG targets, tracing spans, and metric alerting recipes.
- [`engine eval`](eval.md) for the one-shot evaluation counterpart.
