---
title: Multi-tenancy
description: Isolate detections, correlation state, incidents, and API reads per tenant in one daemon.
---

# Multi-tenancy

{{ added "unreleased" }}

A single daemon can serve several tenants while keeping their state apart. The tenant of an event comes only from an operator binding: the bearer token that authenticated an ingest request, the configured tenant of a pull source, or a NATS subscription declared for one tenant. Event fields, request headers, NATS message headers, and OTLP attributes are never identity.

## Why event fields are not identity

A client controls the payload it sends. A `tenant` field in an event, or an `X-Rsigma-Tenant` header, is a label the client chose, not a fact the daemon verified. If those could name a tenant, a client could read or write another tenant's state by changing one string. The daemon therefore binds a tenant only where it authenticated the request or where the operator configured the source.

## Bindings

The daemon accepts four bindings:

- `tenant` on an API token. A token with `tenant: tenant-a` can ingest as `tenant-a`, read `tenant-a` state, and write silences and dispositions for `tenant-a`.
- `all_tenants: true` on an API token. It sees every tenant but has no tenant of its own, so it cannot ingest. It can narrow reads with `?tenant=`.
- `daemon.input.tenant` on the single selected pull source (`stdin`, `unix://`, or a NATS URL). Every event from that source belongs to that tenant.
- `daemon.input.nats_tenants`, one exact subject and tenant per subscription. Every message from a subscription belongs to its tenant.

A tenant id is 1 to 64 ASCII letters, digits, `_`, and `-`, and starts with a letter or digit. A `.` is refused, so an id is always exactly one NATS subject token and one path component.

`daemon.input.nats_tenants` needs a subject-less `nats://host:port` source. A subscriber never sees the publisher's authenticated user, so the broker, not the daemon, must enforce the subject-to-tenant binding. The recommended layout is one NATS account per tenant exporting its stream into the daemon's account under `tenants.<id>.`.

## Example

```yaml
# Loaded with: rsigma engine daemon --config /etc/rsigma/daemon.yaml
rulesets:
  shared_baseline:
    sources: [/etc/rsigma/rules/shared]
  tenant_a_custom:
    sources: [/etc/rsigma/rules/tenant-a]
daemon:
  rulesets:
    - shared_baseline
    - name: tenant_a_custom
      tenants: [tenant-a]
  tenancy:
    enabled: true
    quotas:
      correlation_state: 50000
      active_alerts: 5000
      incidents: 2000
      risk_entities: 10000
      silences: 100
      inhibition_sources: 1000
      stream_sessions: 1
    metrics_tenant_allowlist: [tenant-a]
  input:
    source: nats://nats.internal:4222
    nats_tenants:
      - subject: tenants.tenant-a.events.>
        tenant: tenant-a
      - subject: tenants.tenant-b.events.>
        tenant: tenant-b
        credentials_file: /etc/rsigma/nats/tenant-b.creds
  output:
    sinks:
      - nats://nats.internal:4222/detections.{tenant}
      - file:///var/log/rsigma/tenant-a.ndjson?tenant=tenant-a
  api:
    auth:
      tokens:
        - name: tenant-a-ingest
          role: ingest
          token_env: TENANT_A_INGEST_TOKEN
          tenant: tenant-a
        - name: tenant-a-analyst
          role: operator
          token_env: TENANT_A_ANALYST_TOKEN
          tenant: tenant-a
        - name: soc-admin
          role: admin
          token_env: SOC_ADMIN_TOKEN
          all_tenants: true
```

A single-tenant source:

```yaml
daemon:
  tenancy:
    enabled: true
  input:
    source: nats://nats.internal:4222/tenants.tenant-a.events.>
    tenant: tenant-a
  api:
    auth:
      tokens:
        - name: soc-admin
          role: admin
          token_env: SOC_ADMIN_TOKEN
          all_tenants: true
```

## NATS account layout

A subscriber cannot see the publisher's authenticated user. Bind each tenant in the broker, not in the daemon. One NATS account per tenant can export its events into the daemon's account under a tenant prefix:

```conf
accounts {
  TENANT_A {
    exports [
      { stream: "tenants.tenant-a.events.>" }
    ]
  }
  TENANT_B {
    exports [
      { stream: "tenants.tenant-b.events.>" }
    ]
  }
  RSIGMA {
    imports [
      { stream: { account: TENANT_A, subject: "tenants.tenant-a.events.>" } }
      { stream: { account: TENANT_B, subject: "tenants.tenant-b.events.>" } }
    ]
  }
}
```

The daemon's `nats_tenants` entries then name those exact subjects. The entries may not overlap, and two entries may not name the same tenant.

## What is isolated

Every stateful key includes the tenant: correlation windows, dedup fingerprints, incident ids and entity join keys, inhibition sources, silences, risk entities, disposition buckets, and capture bundles. Rulesets can be bound to tenants, so a tenant's ruleset sees only that tenant's events. API reads are scoped to the token's tenant.

## What is not isolated

Tenants share one process, CPU, memory, and the operator-global enrichment caches: dynamic sources, watchlists, STIX indicator sources, MMDB databases, and DNS caches. Their values do not depend on the tenant. Deploy one daemon per tenant when process-level or CPU-level isolation matters.

## Startup refusals

With tenancy enabled, the daemon refuses to start when:

- `daemon.api.auth` is absent or declares no tokens.
- `--api-token-env` is used; its implicit `default` token has no tenant.
- `anonymous_permissions` is non-empty.
- A token sets both `tenant` and `all_tenants: true`, or neither.
- A token's secret is shorter than 32 bytes. Generate secrets with `openssl rand -hex 32`.
- A configured tenant id is invalid.
- Two configured tenant ids differ only by case, such as `Acme` and `acme`. They would share a `{tenant}` file on a case-insensitive filesystem.
- A `daemon.tenancy.quotas` value is 0.
- The source is anything other than `http` (including the `--input` flag) and neither `daemon.input.tenant` nor `daemon.input.nats_tenants` binds it. A subject-less NATS URL subscribes to every subject, so it needs one of the two as well.
- The source is `http` and `daemon.input.tenant` is set.
- `daemon.dispositions.source` (or `--disposition-source`) is set. A disposition source has no tenant binding, and a record's own `tenant` field is not identity; post dispositions to `/api/v1/dispositions` with a tenant token instead.
- `daemon.input.nats_tenants` is set on a source that is not a subject-less NATS URL, or alongside `daemon.input.tenant`.
- Two `nats_tenants` subjects overlap, or two entries name the same tenant.
- A project config layer (`./rsigma.yaml`, `./rsigma.yml`, `.rsigmarc`) was loaded.
- A ruleset `tenants` binding names a tenant that no token, `input.tenant`, or `nats_tenants` entry can produce.

With tenancy disabled, the daemon refuses to start when a token sets `tenant` or `all_tenants`, a `daemon.tenancy.quotas` value or `--max-tenant-state` is set, `daemon.input.tenant` or `daemon.input.nats_tenants` is set, a ruleset `tenants` binding is set, a sink spec or NATS subject contains `{tenant}` or `tenant=`, or a webhook or enricher `scope.tenants` is non-empty.

## API scoping

A token's [role](../reference/http-api.md#authentication) and its tenant binding are separate checks, and a request must pass both. The role decides what the token may do; the binding decides which tenants it reaches. A tenant-bound `admin` token still gets `403` on operator-only routes such as reload, an `all_tenants` `admin` token still cannot ingest, and an `all_tenants` `reader` token reads every tenant but writes nothing.

Every API route has a tenancy class. Tenant tokens get `403` on operator-only routes, which span tenants: `/metrics`, `/api/v1/status`, field and schema observers, dynamic sources, watchlists, STIX sources, and reload. On tenant-scoped reads, including the tap and the detection stream, a tenant token is filtered to its tenant. `?tenant=` may only narrow: a tenant token naming another tenant is `403`. A resource id owned by another tenant is `404`, so ids do not leak existence. With tenancy disabled, `?tenant=` is `400`.

Silences and dispositions written by a tenant token are bound to its tenant. A body `tenant` naming another tenant is `403`. An `all_tenants` token must send `tenant` on a write, or it is `400`.

An MCP bridge (`rsigma mcp serve --daemon-url`) acts with the reach of its daemon token, and incident content carries event fields that a tenant's sources control. Give each tenant's agent its own bridge with a token bound to that tenant. Keep a bridge that holds an `all_tenants` token read-only: give it a `reader` token and leave out `--allow-operate-writes`, so text injected through one tenant's events cannot steer the agent into silencing another tenant's alerts.

## Ruleset bindings

A `daemon.rulesets` entry can list `tenants` next to `when`. A bound ruleset receives only events whose tenant is listed. An unbound ruleset receives every tenant's events, with its state still keyed per tenant. Path mode (`--rules`) means every rule is shared.

## Quotas

`daemon.tenancy.quotas` caps correlation state, active alerts, incidents, and risk entities per tenant. At a tenant's cap, a new entry evicts that tenant's own expired entries first, then its stalest entries; a result that joins an open incident or an existing entry evicts nothing. A restore or reload trims each tenant to its quota. The global caps remain as a backstop.

Three more quotas refuse new entries instead of evicting, so a tenant cannot take another tenant's share of a shared control. `silences` caps a tenant's dynamic silences, and `POST /api/v1/silences` returns `429` at the cap. `inhibition_sources` caps a tenant's inhibition sources; a new source over the cap is not tracked, counts in `rsigma_inhibit_sources_refused_total`, and a restore or reload trims each tenant to the quota. `stream_sessions` caps a tenant's concurrent sessions on `GET /api/v1/tap` and on `GET /api/v1/detections/stream`, and a new session returns `409` at the cap. Sessions and silences of an `all_tenants` token that names no tenant count only against the global caps.

Disposition idempotency ids are kept per tenant, and `max_seen_ids` applies to each tenant's set, so one tenant's volume cannot evict another tenant's ids and let a redelivered disposition count twice. Ingest itself is a shared queue: the daemon has no per-tenant ingest rate limit, so put one in front of the push receivers, or give each tenant its own NATS subject with broker-side limits.

## Sink routing

A sink can filter by tenant with `tenant=<id>`, route NATS subjects with `{tenant}` as a whole dot-separated token, and route file paths with `{tenant}` as a whole path component. `{tenant}` may appear once, and only in a file path or a NATS subject; the alert pipeline and risk `nats_subject` keys follow the same rule. A `{tenant}` NATS subject publishes into one JetStream stream whose subject has `*` in place of `{tenant}`. File sinks create the tenant's directory on first write, open one handle per tenant, and keep at most `max_open` (default 64); `max_open` is refused on any other sink. The DLQ and audit sinks carry no result tenant, so `{tenant}`, `tenant=`, and `max_open=` are refused there. A result without a tenant on a `{tenant}` subject or path is a permanent delivery failure and reaches the DLQ. OTLP sinks carry `tenant_id` as a log-record attribute automatically.

## Metrics

Three families report tenancy: `rsigma_tenant_rejected_total`, `rsigma_tenant_quota_evictions_total`, and `rsigma_detection_matches_by_tenant_total`. Tenants outside `daemon.tenancy.metrics_tenant_allowlist` count under `other`, so the label set stays bounded. `rsigma_rule_false_positive_ratio` has no tenant label, so it sums each rule's dispositions across tenants; read a tenant's own ratios from `GET /api/v1/dispositions`.

## Running with `--config`

Tenancy settings, tokens, `nats_tenants`, and ruleset tenant bindings are read at startup and are not hot-reloadable. Run the daemon with `engine daemon --config <PATH>`; an explicit config replaces discovery, so no project layer is loaded and the project-layer refusal cannot trigger.
