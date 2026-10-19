# Helr (HTTP API log collector)

[Helr](https://github.com/timescale/helr) is a sister project to RSigma: a single-binary HTTP API log collector that polls audit-log endpoints (Okta, Google Workspace, GitHub, Slack, 1Password, Tailscale, and any HTTP API that returns a JSON array with cursor / Link-header / page pagination) and emits NDJSON to stdout, a file, an HTTP endpoint, or a NATS subject.

It exists because the streaming side of RSigma (`engine daemon`) wants NDJSON in and Sigma matches out, but it does not poll SaaS APIs itself. Helr is the missing collector, designed to feed straight into rsigma without an intermediate log shipper if you do not already run one. Background and design rationale: [Declarative Audit Log Collection from HTTP APIs](https://mostafa.dev/declarative-audit-log-collection-from-http-apis-b0092185a63c).

## Where Helr fits

```text
┌───────────────────┐    ┌──────────────┐    ┌──────────────────┐    ┌───────────────┐
│  SaaS audit API   │    │              │    │                  │    │               │
│  Okta, GWS, ...   ├───▶│     Helr     ├───▶│    NATS / file   ├───▶│ rsigma engine │
│                   │    │  (polling)   │    │   stdout / HTTP  │    │    daemon     │
└───────────────────┘    └──────────────┘    └──────────────────┘    └───────────────┘
                              │                                               │
                         durable state                                 detection matches
                         (SQLite/Redis)                                 (stdout/NATS/etc)
```

Helr handles pagination, rate limits, OAuth refresh, watermarking, and back-pressure. RSigma handles Sigma rule evaluation, correlation, and pipeline transformations. Both binaries are stateful, both expose Prometheus metrics, both ship rootless container images.

## The minimal wire-up

The most direct pattern: Helr publishes NDJSON to a NATS JetStream subject, and the rsigma daemon consumes from it.

`helr.yaml`:

```yaml
global:
  log_format: json
  state:
    backend: sqlite
    path: /var/lib/helr/state.db
  api:
    enabled: true
    address: 0.0.0.0
    port: 8080

sources:
  - id: okta-audit
    type: okta-system-log
    base_url: https://${OKTA_DOMAIN}/api/v1/logs
    auth:
      type: bearer
      token_env: OKTA_TOKEN
    poll_interval_secs: 60
```

Run Helr with NATS output:

```bash
helr run --output nats://localhost:4222/helr.audit
```

Run the rsigma daemon as a consumer:

```bash
rsigma engine daemon \
  --input nats://localhost:4222/helr.audit \
  --rules /etc/rsigma/rules \
  --pipeline /etc/rsigma/pipelines/okta.yml \
  --output stdout \
  --api-addr 127.0.0.1:9090
```

You now have an end-to-end pipeline: Okta -> NATS -> Sigma rule evaluation -> stdout (or whatever sink you wire next). See [NATS streaming](../guide/nats-streaming.md) for consumer groups, replay, and authentication.

## Docker Compose

A complete reference stack (NATS, Helr, rsigma daemon) fits in one file. Add Prometheus and Grafana separately if you want dashboards for the metrics endpoints:

```yaml
services:
  nats:
    image: nats:2.10-alpine
    command: ["-js", "-m", "8222"]
    ports:
      - "4222:4222"
      - "8222:8222"

  helr:
    image: ghcr.io/timescale/helr:latest
    read_only: true
    cap_drop: [ALL]
    volumes:
      - ./helr.yaml:/etc/helr/helr.yaml:ro
      - helr-state:/var/lib/helr
    environment:
      OKTA_TOKEN: "${OKTA_TOKEN}"
      OKTA_DOMAIN: "${OKTA_DOMAIN}"
    command:
      - run
      - --config=/etc/helr/helr.yaml
      - --output=nats://nats:4222/helr.audit
    depends_on: [nats]

  rsigma:
    image: ghcr.io/timescale/rsigma:latest
    read_only: true
    cap_drop: [ALL]
    user: "65534:65534"
    volumes:
      - ./rules:/etc/rsigma/rules:ro
      - ./pipelines:/etc/rsigma/pipelines:ro
    command:
      - engine
      - daemon
      - --input=nats://nats:4222/helr.audit
      - --rules=/etc/rsigma/rules
      - --pipeline=/etc/rsigma/pipelines/okta.yml
      - --output=stdout
      - --api-addr=0.0.0.0:9090
      - --allow-plaintext
      - --api-token-env=RSIGMA_API_TOKEN
    environment:
      RSIGMA_API_TOKEN: "${RSIGMA_API_TOKEN:?set RSIGMA_API_TOKEN to the API bearer token}"
    ports:
      - "9090:9090"
    depends_on: [nats]

volumes:
  helr-state:
```

Events flow Okta -> Helr -> NATS -> rsigma daemon -> stdout (or whatever next sink). Both services expose Prometheus metrics; both ship signed multi-arch images. The Docker hardening flags (`read_only`, `cap_drop: [ALL]`, non-root user `65534`) match the [Docker deployment guidance](../deployment/docker.md) for rsigma. `--allow-plaintext` is required because the compose example binds a non-loopback `--api-addr` without TLS, and the API token is required because a non-loopback bind refuses to serve an unauthenticated API. {{ added "0.25.0" }} Events arrive over NATS, so only the metrics and control API use the token.

## Alternatives to NATS as the glue

NATS JetStream is the recommended transport because it provides at-least-once delivery, replay, and back-pressure naturally. If you do not run NATS, two simpler options:

| Transport | Helr side | rsigma side | Trade-off |
|-----------|-----------|-------------|-----------|
| stdout pipe | `helr run` (default) | `rsigma engine daemon --input stdin` | Lowest overhead, but requires both processes to be co-supervised (one died -> the other dies). |
| File + pipe | `--output /var/log/helr/events.ndjson` | `tail -F /var/log/helr/events.ndjson \| rsigma engine daemon --input stdin` | Disk-buffered and simple. The daemon has no native file-tail input, so a follow-pipe is required. A restart of either side can still drop in-flight lines without external journaling. |
| HTTP POST | `--output http://rsigma:9090/api/v1/events` | `--input http --api-addr 0.0.0.0:9090 --allow-plaintext`, plus `--allow-unauthenticated` when only Helr can reach the port | Decoupled lifecycle. RSigma applies channel back-pressure on HTTP ingest; there is no durable replay without NATS. |

Pick NATS for production, stdout for testing, HTTP for "I cannot run NATS but I want loose coupling".

## Field mapping

Helr emits NDJSON with the SaaS provider's native field names. Most Sigma rules in the SigmaHQ corpus assume ECS or a normalized schema. Use an rsigma processing pipeline to translate. A small Okta example:

```yaml
name: helr_okta
priority: 30
transformations:
  - id: okta_to_ecs
    type: field_name_mapping
    mapping:
      eventType: event.action
      actor.alternateId: user.name
      client.ipAddress: source.ip
      outcome.result: event.outcome
    rule_conditions:
      - type: logsource
        product: okta
```

Drop the pipeline at `pipelines/okta.yml`, point `rsigma engine daemon --pipeline pipelines/okta.yml` at it, and your ECS-keyed Sigma rules now match Helr-emitted Okta events.

The same pattern works for every SaaS Helr supports. The [Processing pipelines guide](../guide/processing-pipelines.md) covers the full transformation grammar.

## What Helr does that RSigma does not

| Concern | Helr | rsigma |
|---------|------|--------|
| Polling SaaS APIs with auth and pagination. | Yes (declarative + optional JS hooks). | No. |
| Rate-limit handling, OAuth refresh. | Yes. | No. |
| Durable cursor / watermark state. | Yes (SQLite, Redis, or Postgres). | No (rsigma's state is correlation state, not source state). |
| Sigma rule evaluation. | No. | Yes. |
| Backend query generation. | No. | Yes. |

The two are deliberately orthogonal. Pair them when you need both ends; use either standalone otherwise.

## See also

- [Helr on GitHub](https://github.com/timescale/helr) for the full source-tracked README, supported integrations, and JS-hook examples.
- [Declarative Audit Log Collection from HTTP APIs](https://mostafa.dev/declarative-audit-log-collection-from-http-apis-b0092185a63c) for the design article.
- [NATS streaming guide](../guide/nats-streaming.md) for the rsigma side of the NATS transport.
- [Streaming detection guide](../guide/streaming-detection.md) for the daemon shape that consumes Helr's output.
- [Processing pipelines guide](../guide/processing-pipelines.md) for the field-mapping pattern shown above.
- [Docker deployment](../deployment/docker.md) for hardened container flags and image tags.
