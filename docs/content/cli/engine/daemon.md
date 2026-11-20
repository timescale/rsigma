---
description: "Reference for rsigma engine daemon: run Sigma detection as a long-running service with hot-reload, health checks, Prometheus metrics, and persistent state."
---

# `rsigma engine daemon`

{{ added "0.12.0" }}

Run as a long-running daemon with hot-reload, health checks, and Prometheus metrics.

## Synopsis

```text
rsigma engine daemon [OPTIONS] [--rules <RULES> | --ruleset <NAME> [--ruleset <NAME> ...]]
```

## Description

Loads rules and pipelines, opens an event source, evaluates events as they arrive, fans the detections out to one or more sinks, and stays alive until it receives `SIGTERM`/`SIGINT`. Reloads rules and pipelines on file change, `SIGHUP`, or `POST /api/v1/reload`. Exposes Prometheus metrics, REST control endpoints, and OTLP log ingestion on the same `--api-addr`.

This is the long-running counterpart of [`engine eval`](eval.md). Use it when you need state to survive restarts, hot-reload across rule changes, or a Prometheus-scrapeable detection engine.

For narrative coverage see [Streaming Detection](../../guide/streaming-detection.md). For NATS-specific operations (auth, replay, consumer groups, DLQ) see [NATS Streaming](../../guide/nats-streaming.md).

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-r, --rules <RULES>` | Path to a Sigma rule file or directory of rules (recursive). May also be supplied via `daemon.rules` in a config file. Conflicts with `--ruleset`. |
| `--ruleset <NAME>` | Named rulesets from the configuration, evaluated side by side. Repeatable. May also be supplied via `daemon.rulesets` (with optional `when` schema bindings). Conflicts with `--rules`. {{ added "unreleased" }} |

### Several rulesets

{{ added "unreleased" }}

Repeat `--ruleset` to run several named rulesets side by side. Each ruleset keeps its own engines, pipelines, and correlation state, and every result carries a `ruleset` field. The configuration can supply the list with schema bindings:

```yaml
rulesets:
  win_a:
    sources: [rules/windows]
  cloud:
    sources: [rules/cloud]

daemon:
  rulesets:
    - win_a
    - name: cloud
      when:
        schemas: [aws_cloudtrail]
```

`when` binds a ruleset to classified schema names. Events with no classified schema reach only unbound rulesets. A CLI `--ruleset` list replaces the configured list and carries no `when`. The ruleset list and definitions are read once at startup; changing them needs a restart. Rule, overlay, and pipeline files hot-reload. `--schema-routing` is allowed with exactly one ruleset and only when it declares no pipelines.

`GET /api/v1/status` and `GET /api/v1/rules` gain a `rulesets` array with per-ruleset rule counts and `when` bindings; `rules_path` is omitted in ruleset mode. `rsigma engine status` renders the same values. The daemon exports `rsigma_ruleset_rules_loaded`, `rsigma_ruleset_matches_total`, and `rsigma_ruleset_events_skipped_total`.

### Rule loading

| Flag | Default | Description |
|------|---------|-------------|
| `--strict-rules` | off | Refuse to load a rule set in which any rule fails to parse. Config-file equivalent: `daemon.engine.strict_rules`. {{ added "0.26.0" }} |

Rules that fail to parse are logged, left out of the loaded rule set, and counted on `rsigma_rule_parse_errors`. A load in which every rule fails to parse is refused, and so is any load with a parse error under `--strict-rules`. A refused path-mode load at startup exits with code `2`, the same as a compile error; a refused ruleset-mode load exits with code `3`. A refused reload keeps the current rules active and increments `rsigma_reloads_failed_total`. A rules path with no rules and no parse errors still loads, with a warning. {{ added "0.26.0" }}

### Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the [discovery chain](../../reference/configuration.md#discovery). CLI flags still take precedence over file values. Unlike a discovered `./rsigma.yaml` or `.rsigmarc`, this file may set sources, enrichers, sinks, webhooks, API auth, and the other keys listed in [Project config trust](../../reference/configuration.md#project-config-trust). {{ added "0.27.0" }} |
| `--dry-run` | off | Print the effective `daemon` section (defaults < file < env) and exit `0` without binding any port. |

### Event input

| Flag | Default | Description |
|------|---------|-------------|
| `--input <URL>` | `stdin` | Event source. Schemes: `stdin`, `http` (accepts `POST /api/v1/events`), `nats://<host>:<port>/<subject>`, and on Unix `unix:///path/to.sock` (newline-delimited events over a Unix domain socket). |
| `--stdin-mode <MODE>` | `batch` | How a stdin input ends (config `daemon.input.stdin_mode`). `batch` exits at end of input and reports the [batch result](#batch-runs) in the exit code. `stream` keeps the daemon running after end of input until a shutdown signal, restores state like the other inputs, and exits `0`. Ignored for other inputs. {{ added "unreleased" }} |
| `--input-format <FORMAT>` | `auto` | Input log format: `auto`, `json`, `syslog`, `plain`. With features: `logfmt`, `cef`. |
| `--syslog-tz <OFFSET>` | `+00:00` | Timezone offset for RFC 3164 syslog (`+HH:MM` or `-HH:MM`). |
| `--syslog-strip-bom <BOOL>` | `true` | Strip a leading UTF-8 BOM (`U+FEFF`) from RFC 5424 syslog messages. RFC 5424 treats the BOM as an encoding marker, not content. Pass `--syslog-strip-bom false` to keep it byte-for-byte. |
| `--jq <JQ>` | unset | `jq` filter to extract the event payload from each JSON object. Mutually exclusive with `--jsonpath`. The `env` builtin is not available. {{ added "0.27.0" }} |
| `--jsonpath <JSONPATH>` | unset | JSONPath ([RFC 9535](https://www.rfc-editor.org/rfc/rfc9535)) query to extract the event payload. |

### Output sinks and DLQ

| Flag | Default | Description |
|------|---------|-------------|
| `--output <URL>` | `stdout` | Detection sink. Schemes: `stdout`, `file://<path>`, `nats://<host>:<port>/<subject>`, `otlp(s)://<host>:<port>` (OTLP/gRPC), `otlphttp(s)://<host>:<port>` (OTLP/HTTP, posts to `/v1/logs`); the `s` variants use TLS. On Unix, `unix:///path/to.sock` writes NDJSON to a local collector socket. Repeatable for fan-out. Query params: `?on_full=drop` (best-effort), `?format=ndjson\|ocsf` (line and OTLP sinks; see [OCSF Findings](../../guide/ocsf-findings.md)), `?ocsf_version=<v>` (only with `format=ocsf`; default `1.1.0`), `?ocsf_incident_class=2004\|2005` {{ added "unreleased" }} (only with `format=ocsf`; `2005` emits incidents as [Incident Findings](../../guide/ocsf-findings.md#incident-finding-class-2005), default `2004`; `2005` also requires `?ocsf_assignee_group=<name>`, which is rejected on class 2004 and on OTLP), `?compression=gzip` (OTLP), `?timeout=<duration>` {{ added "0.25.0" }} (OTLP per-attempt export deadline, default `10s`), and for TLS `?ca=`, `?client_cert=`, `?client_key=` (PEM paths, the last two for mutual TLS) and `?tls_domain=` (SNI override). OTLP schemes require the `daemon-otlp` build. |
| `--dlq <URL>` | unset | Dead-letter queue for events that fail parsing or sink delivery. Same schemes as `--output`. When unset, parse failures are counted on `rsigma_events_parse_errors_total` and discarded, and delivery failures are discarded with a rate-limited `warn` log that carries how many were dropped. {{ added "0.25.0" }} |
| `--include-event` | off | Embed the full event JSON in every detection match. |
| `--match-detail <LEVEL>` | `off` | Match-detail verbosity: `off` (field + value only), `summary` (adds matcher kind, selection, case sensitivity, and reports keyword/absence matches), or `full` (also records the matched pattern). Also settable via `daemon.engine.match_detail`. See [Evaluating Rules](../../guide/evaluating-rules.md#match-detail). |
| `--pretty` | off | Pretty-print JSON output. |
| `--sink-retry-max <N>` | `3` | Max delivery retries per sink before routing the result to the DLQ. |
| `--sink-backoff-base-ms <MS>` | `100` | Base backoff for the first sink delivery retry. |
| `--sink-backoff-max-ms <MS>` | `5000` | Backoff ceiling for sink delivery retries. |
| `--sink-batch-max <N>` | `64` | Max results drained into one sink delivery batch. |
| `--sink-batch-flush-ms <MS>` | `50` | Max time a partial sink batch waits before flushing. |

Each sink serializes in its own wire format. The default is RSigma's native NDJSON; `?format=ocsf` emits [OCSF Detection Finding](../../guide/ocsf-findings.md) (class 2004) JSON instead, one finding per line. The parameter is accepted on `stdout`, `file://`, `nats://`, and `unix://` sinks only, and `format=` on an OTLP spec, the `--dlq`, or the `daemon.api.audit.sink` fails startup, as does an unknown value.

Each `--output` sink runs its own bounded queue and worker: results are delivered with bounded exponential-backoff retry, and a result is sent to the DLQ only after retries are exhausted. Fan-out is isolated up to each sink's queue depth, so a slow sink does not immediately stall the others; a slow durable sink eventually applies backpressure, the cost of preserving at-least-once delivery. An acknowledgment is released to the source only once every sink has committed the result, and `?on_full=drop` opts a sink out of that contract in favor of never stalling. A sink commits a failed result by handing it to the DLQ writer, so the ack does not wait for the DLQ sink's write; a failed DLQ write is logged and counted on `rsigma_dlq_write_failures_total`. {{ added "0.25.0" }} The file and `unix://` sinks write each result's lines in one go and do not repeat lines a failed attempt already wrote when they retry it; a line a failed file write cut off is ended before anything else is appended. {{ added "0.25.0" }}

Acknowledgment guarantees differ by transport. NATS is durable at-least-once: results un-acked at shutdown are redelivered on restart. The HTTP and OTLP push receivers are at-most-once on ingest, since the request is accepted as soon as the event is queued.

### Pipelines and dynamic sources

| Flag | Description |
|------|-------------|
| `-p, --pipeline <PIPELINES>` | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `ecs_linux`, `fibratus_windows`, `sysmon`) or YAML file paths. Repeatable. |
| `--source <FILE_OR_DIR>` | External source file(s) or directory of source files. Repeatable. Loads reusable dynamic source declarations for pipelines and `lookup` enrichers independently of any pipeline file. A file path loads one YAML file with a top-level `sources:` block; a directory path loads all `*.yml`/`*.yaml` files in it, alphabetically. Source IDs must be unique across every `--source` file (pipeline-embedded `sources:` blocks were removed in v0.19.0; see [Dynamic Sources](../../reference/dynamic-sources.md)). |
| `--allow-remote-include` | Allow `include:` directives in pipelines to reference remote (HTTP/NATS) sources. Off by default for security. |
| `--egress-policy <default\|strict\|permissive>` | HTTP egress policy applied to dynamic-source and enrichment HTTP clients. `default` (the default) blocks link-local (`169.254.0.0/16`, `fe80::/10`, includes cloud-metadata `169.254.169.254`) and known cloud-metadata addresses (`fd00:ec2::254`, `fd20:ce::254`, `100.100.100.200`). `strict` additionally blocks loopback and RFC1918 private. `permissive` allows everything. Enforced at DNS resolution time so DNS rebinding cannot defeat host-string checks, and on IP-literal request URLs and every redirect hop, which skip DNS. {{ added "0.27.0" }} Behind an HTTP proxy (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`) the proxy resolves hostnames, so only IP literals and redirect targets are checked. See [Security](../../reference/security.md#http-egress-policy-ssrf-defense). |

### Post-evaluation enrichment

| Flag | Description |
|------|-------------|
| `--enrichers <PATH>` | YAML file declaring post-evaluation enrichers. Hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; failed reloads keep the previous pipeline active. See [Enrichers](../../guide/enrichers.md) for the schema, the seven primitives, and the recipes catalog. |
| `--stix-store <DIR>` | Local [`FsStore`](../../library/rstix.md#rstix-graph-marking-store) root for enrichers with `type: stix` (`stix-enrich` feature). Same layout as [`taxii sync`](../../cli/taxii/sync.md). Reloaded from disk on enricher hot-reload. Config-file equivalent: `daemon.stix_store`. {{ added "0.23.0" }} |
| `--stix-store-allow-custom` | Parse MITRE ATT&CK and other custom SDOs (`x_*` types) when loading `--stix-store` (`stix-enrich` feature). Required when the store was populated with `taxii sync --allow-custom` or `taxii store --allow-custom`. Config-file equivalent: `daemon.stix_store_allow_custom`. {{ added "0.23.0" }} |
| `--alert-pipeline <PATH>` | YAML file declaring the alert pipeline. It runs after enrichment and before the sinks: it silences results matching operator-defined matchers, inhibits lower-priority results while a matching source is active, deduplicates by a configurable fingerprint (first fire passes, duplicates fold, re-emit on `repeat_interval`, resolve after `resolve_timeout`), and groups survivors into incidents (`group_by` equality or an opt-in `entity_graph` union-find), annotating each pass-through result with its `incident_id` and emitting an `IncidentResult` on the `group_wait`, `group_interval`, and `repeat_interval` timers. Open incidents are readable at `GET /api/v1/incidents`; silences are managed at `/api/v1/silences`, which needs this flag and bounds API silences by `max_silence_duration` and `allow_broad_silences`. {{ added "0.27.0" }} Hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; failed reloads keep the previous pipeline active. Selector, matcher, and scope errors reject the daemon at startup. See [Alert Pipeline](../../guide/alert-pipeline.md). |
| `--risk <PATH>` | YAML file declaring the risk-based alerting layer. It runs after enrichment and before the alert pipeline: it annotates each in-scope firing with a risk score and one or more risk objects (entities) under the reserved `risk.score` and `risk.objects` enrichment keys, accumulates risk per entity over a sliding window, and emits a high-fidelity `RiskIncidentResult` when an entity crosses the score or ATT&CK-tactic-count threshold (subject to a per-entity cooldown). Open entities are readable at `GET /api/v1/risk`. Hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; failed reloads keep the previous config active. Selector, scope, and score errors reject the daemon at startup. See [Risk-Based Alerting](../../guide/risk-based-alerting.md). |
| `--webhook <FILE_OR_DIR>` | Webhook config file (or directory of `*.yml`/`*.yaml` files) declaring template-driven HTTP output sinks. Repeatable. Each detection or correlation matching a webhook's `kind` and `scope` renders a templated URL, headers, and JSON body and POSTs it. Webhooks are best-effort (at-most-once): undeliverable results land in the `--dlq` and never block the durable sinks. Validated at startup; not hot-reloaded. See [Webhooks](../../guide/webhooks.md). |

The enrichers file accepts `max_concurrent_enrichments: <N>` at the top level (default `16`) plus a list of enricher entries, each declaring `kind: detection | correlation`, a primitive `type:` (`template`/`lookup`/`http`/`command`/`stix`/`mmdb`/`dns`), an `inject_field`, and primitive-specific keys (`template`, `url`/`headers`/`cache_ttl`, `command`, `source`/`extract`/`default`, `stix_id`/`text_search`/`attack_technique`/`type_filter`, `db_path`/`fields`, `record_type`/`nameservers`/`negative_cache_ttl`/`cache_max_entries`, ...). Cross-namespace template references are rejected at startup with a clear error pointing at the offending field.

The webhooks file (also settable as the `daemon.output.webhooks` path list) declares a list of `webhooks:` entries, each with an `id`, `kind: detection | correlation`, a `url`, optional `headers` and `body` templates, and optional `timeout`, `retry`, `rate_limit`, `scope`, and `queue_size`. Secrets are referenced via `${ENV_VAR}` rather than stored in the file. See [Webhooks](../../guide/webhooks.md) for the schema and the Slack/Teams/Discord/PagerDuty recipe catalog.

### API server

| Flag | Default | Description |
|------|---------|-------------|
| `--api-addr <ADDR>` | `0.0.0.0:9090` | Bind address for `/healthz`, `/readyz`, `/metrics`, `/api/v1/*`, and (with the `daemon-otlp` feature) `/v1/logs`. A TCP `host:port`, or on Unix `unix:///path/to.sock` for a permission-gated local socket. A `unix://` address cannot be combined with TLS (the socket file is the trust boundary) and is exempt from the plaintext and unauthenticated bind refusals. |
| `--allow-plaintext` | off | Permit plaintext on a non-loopback TCP `--api-addr`. Without this flag (and without `--tls-cert`/`--tls-key`) the daemon refuses to start on any public address, in every build. {{ added "0.25.0" }} Loopback (`127.0.0.0/8`, `::1`) always allows plaintext for local development. Config-file equivalent: `daemon.api.tls.allow_plaintext`. |
| `--allow-unauthenticated` {{ added "0.25.0" }} | off | Permit an unauthenticated API on a non-loopback TCP `--api-addr`. Without this flag the daemon refuses to start on a public address unless bearer tokens (`--api-token-env` or `daemon.api.auth`) or client certificates (`--tls-client-ca`) authenticate callers. Use it only when an authenticating proxy or network policy fronts the daemon; a startup warning is logged. Config-file equivalent: `daemon.api.allow_unauthenticated`. |
| `--api-token-env <ENV_VAR>` | unset | Require bearer-token authentication on the API, with the named environment variable holding the single accepted token (full `admin` permissions). The flag names the variable, so the secret never appears on the command line; an unset or empty variable fails startup. `GET /healthz` and `GET /readyz` stay open. Mutually exclusive with the `daemon.api.auth` config block, which adds per-token roles and granular `resource:action` permissions; see [HTTP API: Authentication](../../reference/http-api.md#authentication). |

### Authentication

Off by default: without `--api-token-env` or a `daemon.api.auth` config block, every route is open. {{ added "0.25.0" }} The daemon accepts that only on loopback, on a `unix://` socket, on a listener that requires client certificates (`--tls-client-ca`), or with `--allow-unauthenticated`; any other non-loopback bind refuses to start.

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

Companion CLIs that talk to a running daemon differ in whether they send a bearer token: [`engine incidents export`](incidents-export.md) does (`RSIGMA_API_TOKEN` or `--auth-token-env`); [`engine status`](status.md), [`engine tap`](tap.md), and [`engine tail`](tail.md) do not. When authentication is enabled, grant those surfaces via `anonymous_permissions` or call the HTTP endpoints with an explicit `Authorization` header.

### Audit trail (config-file-only)

When `--state-db` is set, the daemon records control-plane mutations (reload, silences, dispositions, observer resets, and similar) and serves them at `GET /api/v1/audit`. Data-plane ingest is never recorded. Tune or disable with the `daemon.api.audit` block (`enabled`, `max_entries`, `max_age`, `max_body_bytes`, optional `sink`); enabling audit without a state database fails startup. The optional `sink` is a detection-style sink URL that receives audit JSON lines with `on_full=drop` appended when absent; `?format=` is rejected on it. See [HTTP API: Audit trail](../../reference/http-api-state.md#audit-trail).

### TLS (requires the `daemon-tls` build feature)

When TLS is configured, the daemon terminates TLS in-process for every protocol on `--api-addr` (HTTP REST API, `/metrics`, OTLP/HTTP, OTLP/gRPC). The negotiation advertises both `h2` and `http/1.1` via ALPN so legacy REST clients and modern gRPC clients share one socket.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--tls-cert <PATH>` | unset | unset | PEM-encoded leaf certificate (with any intermediates) for the API listener. Requires `--tls-key`. |
| `--tls-key <PATH>` | unset | unset | PEM-encoded private key. PKCS#8, PKCS#1 (RSA), and SEC1 (EC) formats are accepted. Requires `--tls-cert`. |
| `--tls-key-password <PASS>` | `RSIGMA_TLS_KEY_PASSWORD` | unset | Password for an encrypted `--tls-key`. Currently rejected at startup with a clear error; decrypt with `openssl rsa -in key.pem -out key-decrypted.pem` first. |
| `--tls-client-ca <PATH>` | unset | unset | PEM bundle of trusted CA certificates used to verify inbound client certificates. Enables mutual TLS: clients without a cert signed by one of the listed CAs are rejected during the handshake. Mutual TLS counts as authentication, so a public bind with it needs no bearer tokens. |
| `--tls-min-version <1.2\|1.3>` | unset | `1.3` | Minimum TLS protocol version. Drop to `1.2` only for legacy agents that cannot negotiate TLS 1.3. |

Hot-reload: every reload trigger funnels through the daemon's central debounced reload task, so a single `POST /api/v1/reload` (cross-platform, including Windows), `kill -HUP <pid>` (Unix), or a YAML file change picked up by the file watcher rotates rules, pipelines, enrichers, and the TLS certificate in one pass. The active `rustls::ServerConfig` is swapped atomically via `Arc<ArcSwap<…>>`, so new handshakes pick up the rotated material without dropping inflight TLS connections. Failed reloads keep the previous certificate active, bump `rsigma_reloads_failed_total`, and log an error so a typo in the cert path cannot black-hole the listener.

Observability: the `/metrics` endpoint exposes `rsigma_tls_certificate_expiry_seconds` (signed; negative once the cert has expired) and `rsigma_tls_active_connections`. A single WARN is logged at startup (and after every reload) if the active certificate expires within 30 days.

See [TLS deployment](../../reference/security.md#tls-termination-for-the-api-listener) for more detail, including the ACME and sidecar reverse proxy alternatives that this feature replaces.

### Correlation behavior

| Flag | Default | Description |
|------|---------|-------------|
| `--suppress <DURATION>` | unset | Suppress duplicate correlation alerts within the window (`5m`, `1h`, `30s`). |
| `--action <ACTION>` | `alert` | Post-fire action: `alert` (keep state, re-alert on next match) or `reset` (clear window state). |
| `--emit-detections` | off | Emit output for rules that only feed correlations, including correlations referenced by another correlation. By default, referenced rules are emitted only when a referencing correlation has top-level `generate: true`. {{ added "0.24.0" }} |
| `--no-detections` | off | Deprecated compatibility flag. Correlation-only detections are suppressed by default. |
| `--correlation-event-mode <MODE>` | `none` | `none`, `full` (deflate-compressed full bodies), `refs` (timestamp + ID only). |
| `--max-correlation-events <N>` | `10` | Cap on stored events per correlation window. |
| `--max-state-entries <N>` | `100000` | Hard cap on correlation state entries across all correlations and group keys. When reached, the stalest entries are evicted to 90% capacity and a warning is logged. |
| `--max-group-entries <N>` | unset | Cap on retained entries within a single correlation group's window state. Bounds within-window growth of chatty groups; oldest entries are dropped (session windows keep their span anchor). Unset = unbounded, and a correlation with a `timespan` longer than one hour and no `rsigma.max_group_entries` logs a warning at load. {{ added "0.25.0" }} |
| `--tenancy` | off | Enable logical multi-tenancy. Requires bearer-token auth and a tenant binding on every input source; startup refuses otherwise. Equivalent to `daemon.tenancy.enabled: true`. {{ added "unreleased" }} |
| `--max-tenant-state <N>` | unset | Per-tenant correlation state cap. At a tenant's cap, that tenant's own expired entries are evicted first, then its stalest entries. Requires tenancy. {{ added "unreleased" }} |
| `--timestamp-field <FIELD>` | unset | Field name to prepend to the timestamp extraction list. Repeatable. |
| `--timestamp-fallback <MODE>` | `wallclock` | Behavior when no timestamp is found: `wallclock` (use wall clock time) or `skip` (skip correlation state for that event). Use `skip` for forensic replay. |

### State persistence

| Flag | Default | Description |
|------|---------|-------------|
| `--state-db <PATH>` | unset | SQLite database for persisting correlation, alert-pipeline, risk-accumulator, and watchlist-indicator state across restarts. When set, state is loaded on startup and saved periodically and on shutdown. Watchlist rows are written before the HTTP response. A restart loads at most the source cap and logs how many saved indicators were left out. |
| `--state-save-interval <SECONDS>` | `30` | Periodic snapshot interval. No effect without `--state-db`. |
| `--clear-state` | off | Clear stored state on startup, including watchlist indicators. With `--replay-from-*`, forces a clean slate even if the replay starts after the stored position. In a stdin batch run, the only way to start fresh when the stored state cannot be restored. {{ added "unreleased" }} |
| `--keep-state` | off | Force restore stored state even during replay. Use for forward catch-up where you want to preserve cross-boundary correlation windows. Mutually exclusive with `--clear-state`. |

### Tenancy

See [Multi-tenancy](../../guide/multi-tenancy.md) for the binding model and the full refusal list. These keys are read at startup and are not hot-reloadable.

| Key | Default | Description |
|-----|---------|-------------|
| `daemon.tenancy.enabled` | `false` | Enable tenant isolation. Also enabled by `--tenancy`. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.correlation_state` | unset | Per-tenant correlation state cap. Also set by `--max-tenant-state`. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.active_alerts` | unset | Per-tenant active-alert cap. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.incidents` | unset | Per-tenant open-incident cap. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.risk_entities` | unset | Per-tenant risk-entity cap. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.silences` | unset | Per-tenant dynamic (API) silence cap. At the cap, `POST /api/v1/silences` returns `429`. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.inhibition_sources` | unset | Per-tenant inhibition-source cap. At the cap, a new source is not tracked and counts in `rsigma_inhibit_sources_refused_total`. {{ added "unreleased" }} |
| `daemon.tenancy.quotas.stream_sessions` | unset | Per-tenant concurrent tap and tail session cap, applied to each stream separately. At the cap, a new session returns `409`. {{ added "unreleased" }} |
| `daemon.tenancy.metrics_tenant_allowlist` | empty | Tenants whose match counts get their own metric label. Others count under `other`. {{ added "unreleased" }} |
| `daemon.input.tenant` | unset | Tenant to bind to the single selected pull source (`stdin`, `unix://`, or a NATS URL with a subject). {{ added "unreleased" }} |
| `daemon.input.nats_tenants` | empty | One tenant-bound NATS subscription per entry (`subject`, `tenant`, optional `credentials_file`). Requires a subject-less `nats://host:port` source. {{ added "unreleased" }} |
| `daemon.rulesets[].tenants` | empty | Tenants admitted to a named ruleset. Empty means every tenant. {{ added "unreleased" }} |
| sink `tenant=<id>` | unset | Only deliver results of one tenant to this findings sink. Refused on `--dlq` and `audit.sink`. {{ added "unreleased" }} |
| sink `{tenant}` | unset | Render a whole NATS subject token or a whole file path component per tenant, once per findings sink. Refused on other schemes, `--dlq`, and `audit.sink`. {{ added "unreleased" }} |
| file sink `?max_open=` | `64` | Maximum open per-tenant file handles. Only valid on a file path with `{tenant}`. {{ added "unreleased" }} |

Each `daemon.tenancy.quotas` value must be at least 1, and setting any quota (or `--max-tenant-state`) requires `daemon.tenancy.enabled`. {{ added "unreleased" }}

### Throughput

| Flag | Default | Description |
|------|---------|-------------|
| `--buffer-size <N>` | `10000` | Bounded mpsc capacity for source→engine and engine→sink queues. |
| `--batch-size <N>` | `128` | Maximum events per detection batch, capped at `--buffer-size`. Batches enable parallel detection across events. When the rule set has no correlation rules, the daemon may keep several batches in flight (see `RSIGMA_DETECT_INFLIGHT` in [Environment Variables](../../reference/environment-variables.md)); correlation engines stay one batch at a time. |
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
| `--observe-schemas` | off | Classify every event by schema (ECS, Sysmon, Windows Event Log, CEF, OCSF, ...) and surface the per-schema breakdown and unknown rate via `GET /api/v1/schemas` and the `rsigma_events_by_schema_total` and `rsigma_events_unknown_schema_total` metrics. Off by default; when off the engine task does not classify events at all. |
| `--discover-schemas` | off | Enable schema signature discovery sampling (implies `--observe-schemas`). Records redacted, keys-only shapes of unrecognized events so `GET /api/v1/schemas/suggestions` can mine candidate signatures and the `rsigma_unknown_schema_clusters` gauge tracks how many schemas discovery would propose. Adds a per-event field-key walk for each unrecognized event, so it is not free on high-`generic_json` streams; the sample is capped, and `DELETE /api/v1/schemas` refreshes it. See [`engine discover-schemas`](discover-schemas.md) for the offline, value-aware equivalent. |
| `--schema-config <PATH>` | unset | YAML with user-defined schema signatures (merged over the built-ins) and, with `--schema-routing`, the `routing:` bindings. Used by `--observe-schemas` and `--schema-routing`. See [`engine classify`](classify.md#user-signatures) for the signature format and [Schema Routing](../../guide/schema-routing.md) for the bindings. |
| `--schema-routing` | off | Classify each event and route it to its schema's bound pipeline-set (instead of applying one pipeline set to every event); detections feed one shared correlation store, so the same entity correlates across schemas. Bindings come from the `routing:` section of `--schema-config`. |
| `--schema-partition-rules` | off | Gated: compile each platform-locked per-schema engine with only the rules whose product can apply, cutting the N-copies memory cost. Off by default. See [Per-schema rule partitioning](../../guide/schema-routing.md#per-schema-rule-partitioning). |
| `--on-unknown <POLICY>` | `warn` | Policy for events that match no schema: `warn`, `drop`, `passthrough`, or `error`. Overrides the config value. Used with `--schema-routing`. |

These schema flags may also be supplied via the `daemon.schema` block in a [config file](../../reference/configuration.md) (`observe`, `discover`, `routing`, `config`, `partition_rules`, `on_unknown`); a flag always wins over the file.

| Flag | Default | Description |
|------|---------|-------------|
| `--logsource-routing` | off | Enable conflict-based logsource pruning: skip rules whose `product`/`service`/`category` conflicts with the event's declared logsource. Fail-open. See [Logsource-Aware Evaluation](../../guide/logsource-routing.md). |
| `--logsource-field-map <MAP>` | `product=product,service=service,category=category` | Event field names each dimension is read from, as `product=...,service=...,category=...`. |
| `--event-logsource <LOGSOURCE>` | unset | Static event logsource applied when the field is absent, as `product=windows,...`, for a single-source pipeline. |

These logsource flags may also be supplied via the `daemon.logsource_routing` block in a [config file](../../reference/configuration.md) (`enabled`, `field_map`, `event_logsource`); a flag always wins over the file.

See [Observability: detection coverage](../../guide/observability.md#detection-coverage-with-observe-fields) for the operator workflow, and [HTTP API](../../reference/http-api-observability.md#field-observability) for the endpoint payloads.

### Live event tap

The daemon serves [`GET /api/v1/tap`](../../reference/http-api-observability.md#live-event-tap) (the endpoint behind [`rsigma engine tap`](tap.md)), which records a bounded window of the live event stream as a replayable NDJSON fixture. It is **disabled by default** because it can exfiltrate raw event traffic; enable it with `daemon.tap.enabled: true` and expose it only behind mTLS.

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

The daemon also serves [`GET /api/v1/detections/stream`](../../reference/http-api-observability.md#live-detection-tail) (the endpoint behind [`rsigma engine tail`](tail.md)), which streams live detections as NDJSON. It is **disabled by default**; enable it with `daemon.tail.enabled: true`.

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

The daemon serves [`POST`/`GET /api/v1/dispositions`](../../reference/http-api-state.md#dispositions), which ingest analyst verdicts and expose a per-rule false-positive ratio. It is **disabled by default**; enable it with `--enable-dispositions`, `daemon.dispositions.enabled: true`, or a configured pull source.

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

## Verdict-driven capture

{{ added "0.22.0" }}

The daemon can retain admitted detection events for `group_by` incidents and write TP/FP corpus bundles after an accepted disposition. It is **disabled by default** and **startup-only**: changing any `daemon.capture.*` key requires a restart. Enabling it requires dispositions, a `group.mode: group_by` alert pipeline, and `daemon.capture.spool_dir`. See [Verdict-Driven Corpora](../../guide/verdict-to-corpus.md).

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-capture` | off | Enable the capture ring and disposition spool for this run. Equivalent to `daemon.capture.enabled: true`. Bounds and `spool_dir` stay config-file-only. |

The remaining keys are config-file-only under `daemon.capture`:

| Key | Default | Description |
|-----|---------|-------------|
| `daemon.capture.enabled` | `false` | Retain admitted detections and spool accepted verdicts. Also enabled by `--enable-capture`. |
| `daemon.capture.spool_dir` | none | Required when enabled. Destination for `tp/` and `fp/` bundles. |
| `daemon.capture.max_captured_incidents` | `1000` | Open incidents held in the ring. |
| `daemon.capture.max_events_per_incident` | `1000` | Events retained per incident. |
| `daemon.capture.max_event_bytes` | `1048576` | Encoded size of one event. Oversized events are dropped whole. |
| `daemon.capture.max_bytes_per_incident` | `16777216` | Encoded size of one incident. |
| `daemon.capture.max_capture_bytes` | `268435456` | Encoded size of the whole ring. |
| `daemon.capture.ttl` | `24h` | How long a ring generation is kept after last admission. |
| `daemon.capture.max_spool_bytes` | `10737418240` | Completed-bundle disk budget. A larger bundle fails before commit. |
| `daemon.capture.spool_queue_capacity` | `128` | In-flight spool jobs. |

When capture is enabled, detection event payloads are retained internally even without `--include-event`, then stripped before sink delivery unless `--include-event` was also set.

## Examples

### Minimal daemon: HTTP ingest + curl

```bash
rsigma engine daemon -r rules/ --input http --api-addr 127.0.0.1:9090
```

```bash
curl -sS http://127.0.0.1:9090/readyz
curl -sS -X POST http://127.0.0.1:9090/api/v1/events \
  -H 'Content-Type: application/x-ndjson' \
  --data '{"CommandLine":"whoami /priv"}'
```

Accepts `POST /api/v1/events`; detections write to stdout. Default `--input stdin` is for a long-lived writer; closing stdin drains and exits the daemon unless `--stdin-mode stream` is set. Use [`engine eval`](eval.md) for one-shot evaluation without state, and [Batch runs](#batch-runs) for stateful batches that carry correlation windows between runs. See [Streaming Detection: Start the daemon](../../guide/streaming-detection.md#start-the-daemon).

### HTTP ingest with persistent state

```bash
rsigma engine daemon -r rules/ \
    --input http \
    --state-db /var/lib/rsigma/state.db \
    --pipeline ecs_windows
```

Correlation state survives restarts.

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
    --api-addr 127.0.0.1:9090
```

### Multi-output fan-out

```bash
rsigma engine daemon -r rules/ \
    --output stdout \
    --output "file:///var/log/rsigma/detections.ndjson" \
    --output "nats://nats.internal:4222/detections.urgent"
```

### Export detections to an OpenTelemetry collector

Each result becomes one OTLP log record (Sigma level mapped to OTLP severity, rule title as the body, the full result as attributes). With `?format=ocsf`, the body is the [OCSF finding](../../guide/ocsf-findings.md#otlp-log-bodies) and the record carries no attributes. {{ added "unreleased" }} Requires a `daemon-otlp` build.

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

{{ added "0.25.0" }}

Every OTLP export attempt is bounded by a deadline, `10s` by default, so a collector that accepts the connection but never answers cannot stall the sink task (and, under the default `on_full=block`, every other sink behind it). A timed-out attempt is retried under `--sink-retry-max` and then routed to the DLQ like any other transient failure. Override the deadline per sink with a humantime duration, for example `otlp://otel-collector:4317?timeout=3s`; zero and unparsable values are rejected at startup. Connection setup is separately capped at 10 seconds, and gRPC channels send HTTP/2 keepalive pings so a silently dropped connection is detected.

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
| `/metrics` | Prometheus text format. {{ rsigma.metrics.names }} metric names under `--all-features` ({{ rsigma.metrics.always }} always-present + {{ rsigma.metrics.otlp }} OTLP + {{ rsigma.metrics.tls }} TLS + {{ rsigma.metrics.stix }} STIX source, gated on the matching build features). A startup scrape shows a subset; the rest appear as their surfaces are exercised. | Scrape every 15-30 s. |

Full HTTP API reference: [HTTP API](../../reference/http-api.md). All metric definitions: [Prometheus metrics](../../reference/metrics.md).

## Batch runs
{{ added "unreleased" }}

With `--input stdin` (or `--input stdin://`) and the default `--stdin-mode batch`, `engine daemon` is a one-shot batch runner: it reads stdin to end of input, evaluates every event, drains every sink and the dead-letter queue, saves `--state-db`, and exits. A correlation window that spans batches fires in the run that completes it, because the stored state is restored at startup.

The recommended shape for a serverless invocation or a cron job:

```bash
rsigma engine daemon -r rules/ --input stdin --state-db state.db --api-addr 127.0.0.1:0 --timestamp-fallback skip < batch.ndjson
```

`--api-addr 127.0.0.1:0` binds an ephemeral loopback port so concurrent runs never clash. `--timestamp-fallback skip` leaves events without a timestamp out of correlation windows instead of stamping them with the run time, which would collapse every event in a batch into the same window. Use `--output` for the findings; stdout is the default sink.

After a clean exit, `state.db` is a single file with no `-wal` or `-shm` sidecar, so copy it as one unit. Treat the exit code as the batch result. On `0`, keep the new state file and checkpoint the input position. On `4`, discard the new state and replay the batch from the previous position. On `2` or `3`, the run did not start and the stored state is unchanged, so a replay fails the same way until the rules, the configuration, or the stored state are fixed.

A generic caller that restores the last good state, runs, and keeps the new state only on success:

```sh
rm -f state.db state.db-wal state.db-shm
if [ -f last-good.db ]; then
  cp last-good.db state.db
fi
rsigma engine daemon -r rules/ --input stdin --state-db state.db --api-addr 127.0.0.1:0 --timestamp-fallback skip < batch.ndjson
code=$?
if [ "$code" -eq 0 ]; then
  cp state.db last-good.db
fi
exit "$code"
```

Removing the old files first keeps a failed run's state, or a sidecar left by a killed process, from leaking into the next run.

A run exits `3` when the stored state cannot be restored, because the snapshot version is not supported, its ruleset layout cannot be mapped onto the loaded rulesets (for example, state saved by a single engine loaded into several rulesets), or the stored JSON cannot be read. Nothing is written in that case, so the stored snapshot is left for inspection. Pass `--clear-state` to start fresh on purpose; the next save overwrites the stored snapshots. A run exits `4` (`RUNTIME_ERROR`) when it did not complete cleanly: a signal stopped it before end of input, reading stdin failed, output reached neither its sink nor the DLQ, the final state save failed, or a pipeline task panicked. The shutdown save still runs on an incomplete run, so the caller decides whether to keep it.

Callers whose input can be redelivered should store the input position next to the state file, so a replay starts where the previous batch ended. Lines that fail to parse are counted on the parse metrics and do not fail the run when no `--dlq` is set, and `on_full=drop` queue drops are the configured lossy policy, not a failure.

See [Serverless](../../deployment/serverless.md) for an AWS Lambda handler and a wrapper for scheduled container jobs.

### Long-running stdin

`--stdin-mode stream` turns the batch contract off for a writer that is not a batch, such as `tail -F app.log | rsigma engine daemon --stdin-mode stream`. The daemon keeps running after stdin ends, so the API, metrics, hot reload, and periodic state saves stay up until `SIGTERM` or `SIGINT`. A stored snapshot that cannot be restored logs a warning and starts fresh, and a signal exits `0`, the same as the HTTP, NATS, and unix-socket inputs.

## Shutdown

`SIGTERM` and `SIGINT` trigger a graceful drain bounded by `--drain-timeout`. In-flight events are processed and acknowledged before the daemon exits. With `--state-db`, the final correlation state snapshot is written during shutdown.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Normal shutdown (including `--dry-run`). |
| `2` | Initial rules could not be loaded or compiled. |
| `3` | Configuration error: missing `--rules`/`daemon.rules`, bad `-p`, malformed `--suppress`, invalid `--input` URL, TLS/auth/audit misconfiguration, and similar startup failures. In a stdin batch run, also stored state that cannot be restored. {{ added "unreleased" }} |
| `4` | `RUNTIME_ERROR`: a stdin batch run that did not complete cleanly, because a signal stopped it before end of input, a stdin read failed, output reached neither a sink nor the DLQ, the final state save failed, or a pipeline task panicked. {{ added "unreleased" }} |

## See also

- [Streaming Detection](../../guide/streaming-detection.md) for the daemon walkthrough.
- [NATS Streaming](../../guide/nats-streaming.md) for auth, replay, consumer groups, and DLQ details.
- [OTLP Integration](../../guide/otlp-integration.md) for the OTLP receiver and agent recipes.
- [HTTP API](../../reference/http-api.md) for the REST surface served on `--api-addr`.
- [Prometheus Metrics](../../reference/metrics.md) for the full metric catalog.
- [Performance Tuning](../../guide/performance-tuning.md) for `--bloom-prefilter`, `--cross-rule-ac`, `--batch-size`, and `--buffer-size`.
- [Observability](../../guide/observability.md) for the RUST_LOG targets, tracing spans, and metric alerting recipes.
- [`engine eval`](eval.md) for the one-shot evaluation counterpart.
- [`engine status`](status.md), [`engine tap`](tap.md), [`engine tail`](tail.md), and [`engine incidents export`](incidents-export.md) for client commands against a running daemon.
