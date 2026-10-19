# Cloud Collection Recipes

{{ added "0.20.0" }}

These recipes show how common log shippers, such as Vector, OpenTelemetry (OTel), and Grafana Alloy, deliver CloudTrail, Azure, GCP, M365, GitHub, Okta, OneLogin, Kubernetes audit, Docker, and osquery events in a structured JSON shape that [schema classification](../reference/schema-signatures.md) recognizes automatically, and which routing binding to use when a schema needs a field-mapping pipeline.

All examples target `rsigma engine daemon` with `--schema-routing`. Each recipe maps to one of the built-in schemas defined in [Schema Signatures](../reference/schema-signatures.md); no user-defined `schemas:` block is needed because every source ships as a built-in. Use `--schema-config` when you need a `routing:` section (per-schema pipeline bindings, `on_unknown`, or `default_pipelines`).

Vector examples POST JSON to `/api/v1/events` (`--input http`). OpenTelemetry Collector and Grafana Alloy examples use OTLP HTTP (`/v1/logs`); build or install the daemon with `daemon-otlp` (release archives already include it). OTLP is active whenever that feature is compiled in, regardless of `--input`. See [OTLP Integration](otlp-integration.md) for the LogRecord mapping and TLS variants.

## Built-in schemas (quick reference)

| Schema | Signature name | Implied logsource | Recipe |
|--------|---------------|-------------------|--------|
| AWS CloudTrail | `aws_cloudtrail` | `aws / cloudtrail` | [Recipe](cloud-collection-platforms.md#aws-cloudtrail) |
| AWS VPC Flow Logs (JSON) | `aws_vpcflow` | `aws` + custom `{source: vpcflow}` | |
| Azure Activity Logs | `azure_activitylogs` | `azure / activitylogs` | [Recipe](cloud-collection-platforms.md#azure-event-hubs-management-activity-api) |
| Azure Audit Logs | `azure_auditlogs` | `azure / auditlogs` | [Recipe](cloud-collection-platforms.md#azure-event-hubs-management-activity-api) |
| Azure SignIn Logs | `azure_signinlogs` | `azure / signinlogs` | [Recipe](cloud-collection-platforms.md#azure-event-hubs-management-activity-api) |
| GCP Cloud Audit | `gcp_audit` | `gcp / gcp.audit` | [Recipe](cloud-collection-platforms.md#gcp-cloud-audit-logs) |
| Microsoft 365 unified audit log | `m365_audit` | `m365 / audit` | [Recipe](cloud-collection-identity-saas.md#microsoft-365-entra) |
| GitHub Audit | `github_audit` | `github / audit` | [Recipe](cloud-collection-identity-saas.md#github-audit-log) |
| Okta System Log | `okta_system_log` | `okta / okta` | [Recipe](cloud-collection-identity-saas.md#okta-system-log) |
| OneLogin | `onelogin_events` | `onelogin / onelogin.events` | [Recipe](cloud-collection-identity-saas.md#onelogin-events-api) |
| Kubernetes Audit | `k8s_audit` | custom `{platform: kubernetes, source: k8s.audit}` | [Recipe](cloud-collection-containers-hosts.md#kubernetes-audit-log) |
| Docker Events | `docker_events` | custom `{platform: docker, source: docker.events}` | [Recipe](cloud-collection-containers-hosts.md#docker-events) |
| osquery Result | `osquery_result` | custom `{platform: osquery, source: osquery.result}` | [Recipe](cloud-collection-containers-hosts.md#osquery) |

The recipes are grouped by source type:

- [Cloud Platform Recipes](cloud-collection-platforms.md): AWS CloudTrail, Azure Event Hubs and the Management Activity API, and GCP Cloud Audit Logs.
- [Identity and SaaS Recipes](cloud-collection-identity-saas.md): Microsoft 365 and Entra, GitHub, Okta, and OneLogin.
- [Container and Host Recipes](cloud-collection-containers-hosts.md): Kubernetes audit logs, Docker events, and osquery.

## A combined example

One daemon that accepts Vector on `/api/v1/events` and OTLP agents on `/v1/logs`, with schema routing and the GCP pipeline binding:

```yaml
# /etc/rsigma/rsigma.yaml
version: 1

daemon:
  rules: /etc/rsigma/rules
  api:
    addr: "127.0.0.1:8952"   # shippers on the same host; a routable bind needs TLS and authentication
  input:
    source: http
  output:
    sinks: [stdout]
  schema:
    routing: true
    config: /etc/rsigma/schema-routing.yml
```

```bash
rsigma engine daemon --config /etc/rsigma/rsigma.yaml
```

The shipper recipes in this guide post to `localhost`, so the daemon binds loopback. {{ added "0.25.0" }} To accept shippers on other hosts, bind a routable address and configure TLS (or `tls.allow_plaintext`) and an `ingest` token in `daemon.api.auth`; see [Daemon network exposure](../reference/security.md#daemon-network-exposure).

`schema-routing.yml`:

```yaml
routing:
  on_unknown: warn
  default_pipelines: []
  bindings:
    # GCP AuditLog needs the field-mapping pipeline; other cloud schemas match native fields with an empty pipeline-set.
    - schema: gcp_audit
      pipelines: [gcp_audit]
```

No `schemas:` entries are needed. Every Cloud, SaaS, and Container source in this guide ships as a built-in. The only binding required is the `gcp_audit` pipeline mapping (since SigmaHQ rules expect `data.*` field names, not native `protoPayload.*`). Built-in implied logsources already supply the SigmaHQ `product`/`service` tokens for pruning when [logsource routing](logsource-routing.md) is also enabled.

## See also

- [Schema Routing](schema-routing.md) for bindings, aliases, and schema-derived logsource pruning.
- [Schema Signatures](../reference/schema-signatures.md) for the built-in catalog and signature grammar.
- [OTLP Integration](otlp-integration.md) for `/v1/logs`, LogRecord flattening, and agent recipes.
- [HTTP API](../reference/http-api.md) for `POST /api/v1/events`.
- [Configuration](../reference/configuration.md) for the `daemon.schema` config block.
- [Streaming Detection](streaming-detection.md) for daemon lifecycle and inputs.
