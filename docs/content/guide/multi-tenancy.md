---
title: Multi-tenancy
description: Isolate detections, correlation state, incidents, and API reads per tenant in one daemon.
---

# Multi-tenancy

A single daemon can serve several tenants while keeping their state apart. The
tenant of an event comes only from an operator binding: the bearer token that
authenticated an ingest request, the configured tenant of a pull source, or a
NATS subscription declared for one tenant. Event fields, request headers, NATS
message headers, and OTLP attributes are never identity. {{ added "unreleased" }}

## Why event fields are not identity

A client controls the payload it sends. A `tenant` field in an event, or an
`X-Rsigma-Tenant` header, is a label the client chose, not a fact the daemon
verified. If those could name a tenant, a client could read or write another
tenant's state by changing one string. The daemon therefore binds a tenant only
where it authenticated the request or where the operator configured the source.

## Bindings

The daemon accepts four bindings:

- `tenant` on an API token. A token with `tenant: tenant-a` can ingest as
  `tenant-a`, read `tenant-a` state, and write silences and dispositions for
  `tenant-a`.
- `all_tenants: true` on an API token. It sees every tenant but has no tenant
  of its own, so it cannot ingest. It can narrow reads with `?tenant=`.
- `daemon.input.tenant` on the single selected pull source (`stdin`,
  `unix://`, or a NATS URL with a subject). Every event from that source
  belongs to that tenant.
- `daemon.input.nats_tenants`, one exact subject and tenant per subscription.
  Every message from a subscription belongs to its tenant.

`daemon.input.nats_tenants` needs a subject-less `nats://host:port` source. A
subscriber never sees the publisher's authenticated user, so the broker, not
the daemon, must enforce the subject-to-tenant binding. The recommended layout
is one NATS account per tenant exporting its stream into the daemon's account
under `tenants.<id>.`.

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

A subscriber cannot see the publisher's authenticated user. Bind each tenant
in the broker, not in the daemon. One NATS account per tenant can export its
events into the daemon's account under a tenant prefix:

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

The daemon's `nats_tenants` entries then name those exact subjects. The entries
may not overlap, and two entries may not name the same tenant.

## What is isolated

Every stateful key includes the tenant: correlation windows, dedup
fingerprints, incident ids and entity join keys, inhibition sources, silences,
risk entities, disposition buckets, and capture bundles. Rulesets can be bound
to tenants, so a tenant's ruleset sees only that tenant's events. API reads are
scoped to the token's tenant.

## What is not isolated

Tenants share one process, CPU, memory, and the operator-global enrichment
caches: dynamic sources, watchlists, STIX indicator sources, MMDB databases,
and DNS caches. Their values do not depend on the tenant. Deploy one daemon per
tenant when process-level or CPU-level isolation matters.

## Startup refusals

With tenancy enabled, the daemon refuses to start when:

- `daemon.api.auth` is absent or declares no tokens.
- `--api-token-env` is used; its implicit `default` token has no tenant.
- `anonymous_permissions` is non-empty.
- A token sets both `tenant` and `all_tenants: true`, or neither.
- A configured tenant id is invalid.
- The pull source is `stdin`, `unix://`, or a NATS URL with a subject and
  `daemon.input.tenant` is absent.
- The source is `http` and `daemon.input.tenant` is set.
- `daemon.input.nats_tenants` is set on a source that is not a subject-less
  NATS URL, or alongside `daemon.input.tenant`.
- Two `nats_tenants` subjects overlap, or two entries name the same tenant.
- A project config layer (`./rsigma.yaml`, `./rsigma.yml`, `.rsigmarc`) was
  loaded.
- A ruleset `tenants` binding names a tenant that no token, `input.tenant`, or
  `nats_tenants` entry can produce.

With tenancy disabled, the daemon refuses to start when a token sets `tenant`
or `all_tenants`, `daemon.input.tenant` or `daemon.input.nats_tenants` is set,
a ruleset `tenants` binding is set, a sink spec or NATS subject contains
`{tenant}` or `tenant=`, or a webhook or enricher `scope.tenants` is non-empty.

## API scoping

Every API route has a tenancy class. Tenant tokens get `403` on operator-only
routes (`/metrics`, `/api/v1/status`, field and schema observers, dynamic
sources, watchlists, STIX sources, reload, and the tap and detection-stream
routes that span tenants). On tenant-scoped reads a tenant token is filtered to
its tenant. `?tenant=` may only narrow: a tenant token naming another tenant is
`403`. A resource id owned by another tenant is `404`, so ids do not leak
existence. With tenancy disabled, `?tenant=` is `400`.

Silences and dispositions written by a tenant token are bound to its tenant. A
body `tenant` naming another tenant is `403`. An `all_tenants` token must send
`tenant` on a write, or it is `400`.

## Ruleset bindings

A `daemon.rulesets` entry can list `tenants` next to `when`. A bound ruleset
receives only events whose tenant is listed. An unbound ruleset receives every
tenant's events, with its state still keyed per tenant. Path mode (`--rules`)
means every rule is shared.

## Quotas

`daemon.tenancy.quotas` caps correlation state, active alerts, incidents, and
risk entities per tenant. At a tenant's cap, that tenant's own expired entries
are evicted first, then its stalest entries. The global caps remain as a
backstop.

## Sink routing

A sink can filter by tenant with `tenant=<id>`, route NATS subjects with
`{tenant}` as a whole dot-separated token, and route file paths with
`{tenant}` as a whole path component. File sinks open one handle per tenant and
keep at most `max_open` (default 64). A result without a tenant on a
`{tenant}` subject or path is a permanent delivery failure and reaches the
DLQ. OTLP sinks carry `tenant_id` as a log-record attribute automatically.

## Metrics

Three families report tenancy: `rsigma_tenant_rejected_total`,
`rsigma_tenant_quota_evictions_total`, and
`rsigma_detection_matches_by_tenant_total`. Tenants outside
`daemon.tenancy.metrics_tenant_allowlist` count under `other`, so the label set
stays bounded.

## Running with `--config`

Tenancy settings, tokens, `nats_tenants`, and ruleset tenant bindings are read
at startup and are not hot-reloadable. Run the daemon with
`engine daemon --config <PATH>`; an explicit config replaces discovery, so no
project layer is loaded and the project-layer refusal cannot trigger.
